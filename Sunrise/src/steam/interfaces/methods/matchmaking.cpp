#include <Windows.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "../../../core/logging/log.h"
#include "../../../core/settings/settings.h"
#include "../internal.h"
#include "../server_link.h"

namespace sunrise::steam::interfaces::methods {
namespace {

/** Monotonic call counter shared by the lobby trace; ORDER across tables is the finding. */
std::atomic<std::uint64_t> g_lobbySequence{0};

/**
 * Counts ONLY create_lobby calls, and is the key both machines pair on.
 *
 * g_lobbySequence cannot serve: join and chat calls bump it too, so a single extra chat on
 * one machine would shift that machine's ordinals and pair its first lobby against the
 * peer's second - silently wiring two unrelated sessions together.
 */
std::atomic<std::uint64_t> g_createSequence{0};

/**
 * INSTRUMENT (FINDINGS 20.42): emits one client-channel line for a lobby call. The
 * serialized-networking trace showed the peer-contact attempt never reaches that table, and
 * the published descriptor names a Steam lobby - so the lobby surface is the next suspect.
 * @param text Rendered line.
 * @param length Line length.
 */
void emit(const char* text, std::size_t length) noexcept {
    core::log::write(core::log::Channel::client, core::log::Level::info, {text, length});
}

/** @return The next call number, starting at one, ordered against the other tables' traces. */
std::uint64_t next_sequence() noexcept {
    return g_lobbySequence.fetch_add(1, std::memory_order_relaxed) + 1;
}

/** Steam callback id for a finished lobby entry. */
constexpr int kLobbyEnterCallback = 504;
/** Steam callback id for a finished lobby creation. */
constexpr int kLobbyCreatedCallback = 513;
/** Steam result code for success. */
constexpr int kResultOk = 1;
/** Steam lobby-entry response for a successful join. */
constexpr DWORD kLobbyEnterSuccess = 1;
/** Made-up lobby ids use Steam's chat-lobby account-type prefix. */
constexpr std::uint64_t kLobbySteamIdPrefix = 0x0109000000000000ULL;
/**
 * Odd 32-bit multiplier that spreads the call number across the account-id field.
 *
 * FINDINGS 20.83: the lobby id WAS `prefix | call`, and `call` is a per-process counter that
 * starts identically on every machine - so both clients invented the SAME two lobby ids
 * (0x0109000000000002 fireteam, ...0003 posse), and a managed session's platform id IS its
 * lobby id. The client's join-gate table (.data 0x141FECDE0) carries
 * `target_fireteam_is_not_ours`, and a peer whose fireteam id equals your own fails it: the
 * rig released the mac with peer-link reason 1, `tried-to-join-self`, on exactly this.
 *
 * This is 20.40's bug one layer up. That entry made the USER identity per-instance and left
 * every id DERIVED from a process counter alone.
 *
 * ADD would be wrong here and it is worth saying why: the two authored accounts differ by 1
 * and consecutive calls differ by 1, so `account + call` collides across machines on the very
 * first pair it sees. XOR against a multiplied stride cannot line up that way.
 */
constexpr std::uint32_t kLobbyCallStride = 0x9E3779B9U;
/** Padding aligns the response field after the one-byte lock flag. */
constexpr std::size_t kLobbyLockPadding = 3;
/** Steam's lobby-entry callback is 24 bytes. */
constexpr std::size_t kLobbyEnterSize = 24;
/** Steam's lobby-created callback is 16 bytes. */
constexpr std::size_t kLobbyCreatedSize = 16;

/** Steam lobby-entry callback payload layout. */
struct LobbyEnter {
    std::uint64_t lobby{};
    DWORD permissions{};
    bool locked{};
    std::array<std::byte, kLobbyLockPadding> padding{};
    DWORD response{};
};

/** Steam lobby-created callback payload layout. */
struct LobbyCreated {
    int result{};
    DWORD padding{};
    std::uint64_t lobby{};
};

static_assert(sizeof(LobbyEnter) == kLobbyEnterSize);
static_assert(sizeof(LobbyCreated) == kLobbyCreatedSize);

/**
 * SHARED-LOBBY CLAIM (p2(67), FINDINGS 20.101 steps 1-2).
 *
 * The managed session's membership IS a Steam lobby, and each client was inventing its own
 * id - so the two sessions were disjoint by construction and "Adding player" could only
 * ever name the caller's own xuid. Here the Nth create_lobby of each boot is claimed on the
 * server: the first machine to claim ordinal N keeps its id, the second is handed that same
 * id, and both managed sessions then name ONE lobby.
 *
 * THE WORK IS ASYNCHRONOUS, and that is not a nicety - Steam's CreateLobby contract is
 * already async (it returns a call handle and delivers LobbyCreated_t later), so doing the
 * HTTP on a worker matches the interface instead of fighting it, and no socket ever touches
 * the game's thread.
 *
 * FALLBACK IS TODAY'S BEHAVIOUR: if the server does not answer within kClaimAttempts, the
 * callbacks are queued with the locally invented id, which is byte-for-byte what p2(66)
 * did. A dead server degrades to the old split-lobby boot rather than to a hang.
 */
constexpr std::size_t kMaxPendingClaims = 8;
constexpr unsigned kClaimAttempts = 10;
constexpr DWORD kClaimRetryMilliseconds = 300;

struct PendingClaim {
    std::uint64_t sequence{};
    std::uint64_t candidate{};
    ApiCall call{};
    unsigned attempts{};
    bool active{};
    /** Cleared once the callbacks are queued; the row keeps polling for the peer after. */
    bool settled{};
};

/** Steam callback id for a lobby membership change. */
constexpr int kLobbyChatUpdateCallback = 506;
/** EChatMemberStateChange: the member entered. */
constexpr DWORD kChatMemberEntered = 0x0001;
/** Steam's lobby chat-update callback is 32 bytes. */
constexpr std::size_t kLobbyChatUpdateSize = 32;

/** Steam lobby chat-update callback payload layout. */
struct LobbyChatUpdate {
    std::uint64_t lobby{};
    std::uint64_t userChanged{};
    std::uint64_t makingChange{};
    DWORD stateChange{};
    DWORD padding{};
};
static_assert(sizeof(LobbyChatUpdate) == kLobbyChatUpdateSize);

/**
 * MEMBERSHIP, learned from the server (FINDINGS 20.102).
 *
 * p2(67) put both clients in one lobby and the roster still named only self, because
 * neither client was ever told a second member existed and so never asked. These are the
 * answers to the asking, plus the event that provokes it.
 */
constexpr std::size_t kMaxMembers = 4;
SRWLOCK g_memberLock{SRWLOCK_INIT};
std::uint64_t g_lobbyId{};
std::array<std::uint64_t, kMaxMembers> g_members{};
std::size_t g_memberCount{};

SRWLOCK g_claimLock{SRWLOCK_INIT};
std::array<PendingClaim, kMaxPendingClaims> g_claims{};
std::atomic<bool> g_claimWorkerStarted{false};

void log_claim(core::log::Level level, const char* format, ...) noexcept {
    std::array<char, core::log::kLineCapacity> line{};
    va_list arguments;
    va_start(arguments, format);
    const int written = std::vsnprintf(line.data(), line.size(), format, arguments);
    va_end(arguments);
    if (written > 0) {
        core::log::write(core::log::Channel::client, level,
                         {line.data(), static_cast<std::size_t>(written)});
    }
}

/** Names one membership answer. These sit on a polled path, so log per distinct answer. */
void log_member_query(const char* stage, std::uint64_t lobby, int index,
                      std::uint64_t answer) noexcept {
    static SRWLOCK lock = SRWLOCK_INIT;
    static char last[160]{};
    char line[160]{};
    const int written = std::snprintf(line, sizeof line,
                                      "ev=steamnet stage=%s lobby=0x%016llX index=%d "
                                      "answer=0x%llX",
                                      stage, static_cast<unsigned long long>(lobby), index,
                                      static_cast<unsigned long long>(answer));
    if (written <= 0) {
        return;
    }
    AcquireSRWLockExclusive(&lock);
    const bool changed = std::strcmp(line, last) != 0;
    if (changed) {
        std::snprintf(last, sizeof last, "%s", line);
    }
    ReleaseSRWLockExclusive(&lock);
    if (changed) {
        core::log::write(core::log::Channel::client, core::log::Level::info,
                         {line, static_cast<std::size_t>(written)});
    }
}

/** Queues the created+entered pair for one settled claim. */
void settle(std::uint64_t sequence, ApiCall call, std::uint64_t lobby, const char* how) noexcept {
    log_claim(core::log::Level::info,
              "ev=steamnet stage=lobby_claim seq=%llu lobby=0x%016llX result=%s",
              static_cast<unsigned long long>(sequence),
              static_cast<unsigned long long>(lobby), how);
    const LobbyCreated created{kResultOk, 0, lobby};
    const LobbyEnter entered{lobby, 0, false, {}, kLobbyEnterSuccess};
    if (!queue_callback(kLobbyCreatedCallback, call, &created, sizeof(created))) {
        return;
    }
    // Entry follows creation, so a reader sees a valid lobby first.
    (void)queue_callback(kLobbyEnterCallback, 0, &entered, sizeof(entered));
}

/** What one claim attempt achieved. */
struct ClaimOutcome {
    /** The server answered, so the created/entered callbacks are queued by now. */
    bool answered{};
    /** A member other than us is known, so there is nothing left to poll for. */
    bool paired{};
};

/** Runs one claim over HTTP. */
ClaimOutcome resolve_claim(PendingClaim& claim) noexcept {
    char target[144]{};
    const int written = std::snprintf(target, sizeof target,
                                      "/lobby/claim?seq=%llx&lobby=%llx&xuid=%llx",
                                      static_cast<unsigned long long>(claim.sequence),
                                      static_cast<unsigned long long>(claim.candidate),
                                      static_cast<unsigned long long>(
                                          core::settings::get().steam.user.steamId));
    if (written <= 0 || written >= static_cast<int>(sizeof target)) {
        return {};
    }
    char body[192]{};
    const unsigned status = interfaces::http_exchange("POST", target, body, sizeof body);
    unsigned long long winner = 0;
    if (status != 200 || std::sscanf(body, "%llx", &winner) != 1 || winner == 0) {
        return {};
    }

    // "<winner> <member> <member>..." - walk past the winner and take the members.
    std::array<std::uint64_t, kMaxMembers> seen{};
    std::size_t seenCount = 0;
    const char* cursor = std::strchr(body, ' ');
    while (cursor != nullptr && seenCount < kMaxMembers) {
        unsigned long long member = 0;
        if (std::sscanf(cursor, " %llx", &member) != 1 || member == 0) {
            break;
        }
        seen[seenCount++] = member;
        cursor = std::strchr(cursor + 1, ' ');
    }

    // Fire an entry event for every member we had not seen before, INCLUDING on re-polls:
    // the machine that claimed first is not told about the peer until the peer claims, so
    // discovery necessarily happens after that machine's own callbacks were queued.
    std::array<std::uint64_t, kMaxMembers> arrivals{};
    std::size_t arrivalCount = 0;
    const std::uint64_t own = core::settings::get().steam.user.steamId;
    AcquireSRWLockExclusive(&g_memberLock);
    g_lobbyId = winner;
    for (std::size_t i = 0; i < seenCount; ++i) {
        bool known = false;
        for (std::size_t k = 0; k < g_memberCount; ++k) {
            known = known || g_members[k] == seen[i];
        }
        if (!known && g_memberCount < kMaxMembers) {
            g_members[g_memberCount++] = seen[i];
            if (seen[i] != own) {
                arrivals[arrivalCount++] = seen[i];
            }
        }
    }
    const std::size_t total = g_memberCount;
    ReleaseSRWLockExclusive(&g_memberLock);

    if (!claim.settled) {
        settle(claim.sequence, claim.call, winner,
               winner == claim.candidate ? "host" : "join");
    }
    for (std::size_t i = 0; i < arrivalCount; ++i) {
        const LobbyChatUpdate update{winner, arrivals[i], arrivals[i], kChatMemberEntered, 0};
        const bool queued =
            queue_callback(kLobbyChatUpdateCallback, 0, &update, sizeof(update));
        log_claim(core::log::Level::info,
                  "ev=steamnet stage=lobby_member_entered lobby=0x%016llX xuid=0x%llX "
                  "members=%zu queued=%d",
                  static_cast<unsigned long long>(winner),
                  static_cast<unsigned long long>(arrivals[i]), total, queued ? 1 : 0);
    }
    // Answered, but keep the row alive until the peer is known - see the comment above.
    return ClaimOutcome{true, total > 1};
}

DWORD WINAPI claim_worker(void*) noexcept {
    for (;;) {
        for (std::size_t i = 0; i < kMaxPendingClaims; ++i) {
            PendingClaim work{};
            AcquireSRWLockExclusive(&g_claimLock);
            const bool taken = g_claims[i].active;
            if (taken) {
                work = g_claims[i];
                ++g_claims[i].attempts;
            }
            ReleaseSRWLockExclusive(&g_claimLock);
            if (!taken) {
                continue;
            }
            const ClaimOutcome outcome = resolve_claim(work);
            // ANSWERED, not paired, drives `settled`: resolve_claim queues the callbacks
            // the first time the server answers, and the peer usually has not claimed yet
            // at that point. Keying this on `paired` would re-queue LobbyCreated on every
            // poll until the peer showed up.
            bool exhausted = false;
            AcquireSRWLockExclusive(&g_claimLock);
            g_claims[i].settled = g_claims[i].settled || outcome.answered;
            exhausted = !g_claims[i].settled && work.attempts + 1 >= kClaimAttempts;
            if (outcome.paired || exhausted) {
                g_claims[i].active = false;
            }
            ReleaseSRWLockExclusive(&g_claimLock);
            if (exhausted) {
                // Server never answered at all. Degrade to p2(66): host our own lobby.
                settle(work.sequence, work.call, work.candidate, "fallback_unclaimed");
            }
        }
        Sleep(kClaimRetryMilliseconds);
    }
}

/** Records a claim for the worker. @return True when a slot was free. */
bool enqueue_claim(std::uint64_t sequence, std::uint64_t candidate, ApiCall call) noexcept {
    bool queued = false;
    AcquireSRWLockExclusive(&g_claimLock);
    for (std::size_t i = 0; i < kMaxPendingClaims && !queued; ++i) {
        if (!g_claims[i].active) {
            g_claims[i] = PendingClaim{sequence, candidate, call, 0, true};
            queued = true;
        }
    }
    ReleaseSRWLockExclusive(&g_claimLock);
    if (!queued) {
        return false;
    }
    bool expected = false;
    if (g_claimWorkerStarted.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        const HANDLE thread = CreateThread(nullptr, 0, claim_worker, nullptr, 0, nullptr);
        if (thread == nullptr) {
            g_claimWorkerStarted.store(false, std::memory_order_release);
            log_claim(core::log::Level::warn, "ev=steamnet stage=lobby_claim_worker result=fail");
            return false;
        }
        (void)CloseHandle(thread);
        log_claim(core::log::Level::info, "ev=steamnet stage=lobby_claim_worker result=ok");
    }
    return true;
}

} // namespace

/**
 * Makes up a lobby, then queues the created and entered callbacks.
 * @return API call id, or zero when either callback cannot be queued.
 */
ApiCall create_lobby([[maybe_unused]] void* self,
                     int lobbyType,
                     int maxMembers) noexcept {
    const ApiCall call = next_api_call();
    // The account-id field must be unique ACROSS MACHINES, not merely within this process:
    // it is what the client compares when it asks whether a target fireteam is its own.
    const auto account =
        static_cast<std::uint32_t>(core::settings::get().steam.user.steamId & 0xFFFFFFFFULL);
    const auto identity =
        static_cast<std::uint64_t>(account ^ (static_cast<std::uint32_t>(call) * kLobbyCallStride));
    const std::uint64_t lobby = kLobbySteamIdPrefix | identity;
    const std::uint64_t ordinal = g_createSequence.fetch_add(1, std::memory_order_relaxed) + 1;
    // INSTRUMENT: the published descriptor's lobby id is this call's number, so the trace
    // ties each advertisement to the create_lobby that invented it. `create` is the pairing
    // key the peer claims against; `seq` stays the cross-table ordering trace.
    {
        std::array<char, 160> line{};
        const int written = std::snprintf(line.data(),
                                          line.size(),
                                          "ev=steamnet seq=%llu create=%llu stage=lobby_create "
                                          "type=%d max=%d "
                                          "result=%u lobby=0x%016llX account=0x%08X",
                                          static_cast<unsigned long long>(next_sequence()),
                                          static_cast<unsigned long long>(ordinal),
                                          lobbyType,
                                          maxMembers,
                                          static_cast<unsigned>(call),
                                          static_cast<unsigned long long>(lobby),
                                          static_cast<unsigned>(account));
        if (written > 0) {
            emit(line.data(), static_cast<std::size_t>(written));
        }
    }
    // The callbacks are queued by the claim worker once the server names the winner, so
    // both machines' Nth lobby settles on ONE id. Steam's CreateLobby is async anyway.
    if (enqueue_claim(ordinal, lobby, call)) {
        return call;
    }
    // No claim slot and no worker: queue the local id immediately, exactly as p2(66) did.
    const LobbyCreated created{kResultOk, 0, lobby};
    const LobbyEnter entered{lobby, 0, false, {}, kLobbyEnterSuccess};
    if (!queue_callback(kLobbyCreatedCallback, call, &created, sizeof(created))) {
        return 0;
    }
    // Entry follows creation, so a reader sees a valid lobby first.
    if (!queue_callback(kLobbyEnterCallback, 0, &entered, sizeof(entered))) {
        return 0;
    }
    return call;
}

/**
 * Queues a successful entry for an existing nonzero lobby.
 * @return API call id, or zero when the lobby id is zero or the queue is full.
 */
ApiCall join_lobby([[maybe_unused]] void* self, std::uint64_t lobby) noexcept {
    if (lobby == 0) {
        return 0;
    }
    std::array<char, 112> line{};
    const int written = std::snprintf(line.data(),
                                      line.size(),
                                      "ev=steamnet seq=%llu stage=lobby_join lobby=0x%016llX",
                                      static_cast<unsigned long long>(next_sequence()),
                                      static_cast<unsigned long long>(lobby));
    if (written > 0) {
        emit(line.data(), static_cast<std::size_t>(written));
    }
    const ApiCall call = next_api_call();
    const LobbyEnter entered{lobby, 0, false, {}, kLobbyEnterSuccess};
    return queue_callback(kLobbyEnterCallback, call, &entered, sizeof(entered)) ? call : 0;
}

/**
 * @return How many members the shim knows in @p lobby.
 *
 * ISteamMatchmaking009 slot 17. That ordinal is an INFERENCE FROM FOUR CONFIRMED POINTS in
 * this same table, not the blind header-guess that sank the friends lane (20.100): slots
 * 13 CreateLobby, 14 JoinLobby, 26 SendLobbyChatMsg and 27 GetLobbyChatEntry are already
 * bound here and demonstrably working - create_lobby ran twice at slot 13 in the p2(67)
 * boot - and all four match the documented layout exactly.
 *
 * It is also crash-proof if that inference is wrong: the signature takes only integers and
 * dereferences nothing, so a mismatched caller gets a wrong number rather than a fault.
 */
int get_num_lobby_members([[maybe_unused]] void* self, std::uint64_t lobby) noexcept {
    AcquireSRWLockShared(&g_memberLock);
    const int count = (lobby == g_lobbyId || lobby == 0)
                          ? static_cast<int>(g_memberCount)
                          : 0;
    ReleaseSRWLockShared(&g_memberLock);
    log_member_query("num_lobby_members", lobby, 0, static_cast<std::uint64_t>(count));
    return count;
}

/** @return The member at @p index, or zero. ISteamMatchmaking009 slot 18; see slot 17. */
std::uint64_t get_lobby_member_by_index([[maybe_unused]] void* self,
                                        std::uint64_t lobby,
                                        int index) noexcept {
    std::uint64_t member = 0;
    AcquireSRWLockShared(&g_memberLock);
    if ((lobby == g_lobbyId || lobby == 0) && index >= 0
        && static_cast<std::size_t>(index) < g_memberCount) {
        member = g_members[static_cast<std::size_t>(index)];
    }
    ReleaseSRWLockShared(&g_memberLock);
    log_member_query("lobby_member_by_index", lobby, index, member);
    return member;
}

/** Drops a lobby chat payload. Nothing is kept. @return True for a size of zero or more. */
bool send_lobby_chat([[maybe_unused]] void* self,
                     std::uint64_t lobby,
                     const void* data,
                     int size) noexcept {
    const std::uint64_t sequence = next_sequence();
    std::array<char, 136> line{};
    const int written = std::snprintf(line.data(),
                                      line.size(),
                                      "ev=steamnet seq=%llu stage=chat_send lobby=0x%016llX "
                                      "ptr=%d size=%d",
                                      static_cast<unsigned long long>(sequence),
                                      static_cast<unsigned long long>(lobby),
                                      data != nullptr ? 1 : 0,
                                      size);
    if (written > 0) {
        emit(line.data(), static_cast<std::size_t>(written));
    }
    // THE load-bearing dump: peer signalling through lobby chat would ride these bytes.
    if (data != nullptr && size > 0) {
        constexpr std::size_t kChunkBytes = 128;
        static constexpr char kDigits[] = "0123456789ABCDEF";
        const auto* bytes = static_cast<const unsigned char*>(data);
        const std::size_t total = static_cast<std::size_t>(size);
        const std::size_t shown = total < 512 ? total : std::size_t{512};
        for (std::size_t offset = 0; offset < shown; offset += kChunkBytes) {
            const std::size_t count =
                shown - offset < kChunkBytes ? shown - offset : kChunkBytes;
            std::array<char, kChunkBytes * 2 + 1> hex{};
            for (std::size_t index = 0; index < count; ++index) {
                hex[index * 2] = kDigits[bytes[offset + index] >> 4];
                hex[(index * 2) + 1] = kDigits[bytes[offset + index] & 0x0F];
            }
            std::array<char, 320> part{};
            const int partWritten =
                std::snprintf(part.data(),
                              part.size(),
                              "ev=steamnet seq=%llu stage=chat_send off=%zu hex=%s",
                              static_cast<unsigned long long>(sequence),
                              offset,
                              hex.data());
            if (partWritten <= 0) {
                break;
            }
            emit(part.data(), static_cast<std::size_t>(partWritten));
        }
        if (shown < total) {
            std::array<char, 112> truncated{};
            const int truncatedWritten =
                std::snprintf(truncated.data(),
                              truncated.size(),
                              "ev=steamnet seq=%llu stage=chat_send truncated=1 shown=%zu "
                              "total=%zu",
                              static_cast<unsigned long long>(sequence),
                              shown,
                              total);
            if (truncatedWritten > 0) {
                emit(truncated.data(), static_cast<std::size_t>(truncatedWritten));
            }
        }
    }
    return size >= 0;
}

/** @return Zero. The shim keeps no lobby chat history. */
int get_lobby_chat_entry([[maybe_unused]] void* self,
                         std::uint64_t lobby,
                         int messageIndex,
                         [[maybe_unused]] std::uint64_t* sender,
                         void* data,
                         int dataCapacity,
                         [[maybe_unused]] int* entryType) noexcept {
    const std::uint64_t sequence = next_sequence();
    std::array<char, 168> line{};
    const int written = std::snprintf(
        line.data(),
        line.size(),
        "ev=steamnet seq=%llu stage=chat_read lobby=0x%016llX entry=%d out=%d cap=%d",
        static_cast<unsigned long long>(sequence),
        static_cast<unsigned long long>(lobby),
        messageIndex,
        data != nullptr ? 1 : 0,
        dataCapacity);
    if (written > 0) {
        emit(line.data(), static_cast<std::size_t>(written));
    }
    return 0;
}

} // namespace sunrise::steam::interfaces::methods
