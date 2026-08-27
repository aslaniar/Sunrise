#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>

#include "../../../core/logging/log.h"
#include "../../../core/settings/settings.h"
#include "../internal.h"

namespace sunrise::steam::interfaces::methods {
namespace {

/** Monotonic call counter shared by the lobby trace; ORDER across tables is the finding. */
std::atomic<std::uint64_t> g_lobbySequence{0};

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
    // INSTRUMENT: the published descriptor's lobby id is this call's number, so the trace
    // ties each advertisement to the create_lobby that invented it.
    {
        std::array<char, 128> line{};
        const int written = std::snprintf(line.data(),
                                          line.size(),
                                          "ev=steamnet seq=%llu stage=lobby_create type=%d max=%d "
                                          "result=%u lobby=0x%016llX account=0x%08X",
                                          static_cast<unsigned long long>(next_sequence()),
                                          lobbyType,
                                          maxMembers,
                                          static_cast<unsigned>(call),
                                          static_cast<unsigned long long>(lobby),
                                          static_cast<unsigned>(account));
        if (written > 0) {
            emit(line.data(), static_cast<std::size_t>(written));
        }
    }
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
