#include <WS2tcpip.h>
#include <WinSock2.h>
#include <Windows.h>

#include <array>
#include <atomic>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string_view>

#include "../../../core/logging/log.h"
#include "../../../core/settings/settings.h"
#include "../../../client/network/consumer.h"
#include "../internal.h"
#include "../server_link.h"

namespace sunrise::steam::interfaces::methods {
namespace {

/**
 * FRIENDS RICH-PRESENCE CROSS-INTRODUCTION (FINDINGS 20.96/20.97), p2(64).
 *
 * Slots bound per the REAL ISteamFriends017 vtable order (sdk/steam/isteamfriends.h,
 * Detanup01/gbe_fork 87bb497e): indices are 0-based from GetPersonaName.
 *   2  GetFriendCount(flags) -> int
 *   3  GetFriendByIndex(i, flags) -> CSteamID(u64)
 *   5  GetFriendPersonaState(id) -> EPersonaState
 *   6  GetFriendPersonaName(id) -> const char*
 *  36  RequestUserInformation(id, bool) -> bool
 *  41  SetRichPresence(key, value) -> bool          <- STORE
 *  43  GetFriendRichPresence(id, key) -> const char*<- READ PEER
 *  46  RequestFriendRichPresence(id)                <- accept silently
 *
 * p2(62)/p2(63) froze because slots 64/65 carried these bodies while the real ABI has
 * GetFriendMessage(64) and GetFollowerCount(65) there - both run during early sign-in
 * stats flow on every machine. This build binds ONLY verified indices.
 *
 * PARKED as of FINDINGS 20.101: the census boot proved destiny2 calls only friends
 * slots 3, 5 and 43 (a few times each) and that slot 64 is NOT SetRichPresence - no
 * string-pair setter is called on this interface at all. Nothing here is bound any more.
 * The code stays because the transport underneath it is reused by the lobby lane.
 *
 * TRANSPORT, p2(65) (FINDINGS 20.99). p2(64) relayed through
 * client::network::consume_http, which does NOT leave this process: the one in-process
 * consumer the Client DLL registers is server::http::consume, and that answers "/SignOn"
 * and returns false for every other URL. So every store was silently dropped and every
 * fetch returned nothing - the cross-introduction could not have worked at any slot
 * mapping. The routes now ride the standalone server's PLAINTEXT admin listener (8099),
 * verified reachable from both machines; 8443 is not usable (its handshake fails with
 * SEC_E_UNSUPPORTED_FUNCTION).
 *
 * The socket work happens on a DEDICATED WORKER THREAD and the interface methods only
 * ever read the local table. Friends methods sit on the Client's hot path (the vtable
 * audit measured 33 calls at one offset alone); a blocking connect there would hitch or
 * hang the title, which is the failure class that already cost two boots.
 */

/** Presence rows: one per (owner,key). */
struct PresenceRow {
    std::uint64_t owner{};
    char key[48]{};
    char value[160]{};
};
constexpr std::size_t kMaxRows = 32;
SRWLOCK g_lock{SRWLOCK_INIT};
std::array<PresenceRow, kMaxRows> g_rows{};
std::size_t g_rowCount{};

std::uint64_t own_xuid() noexcept {
    return core::settings::get().steam.user.steamId;
}

std::size_t find_row(std::uint64_t owner, std::string_view key) noexcept {
    for (std::size_t i = 0; i < g_rowCount && i < kMaxRows; ++i) {
        if (g_rows[i].owner == owner && key == g_rows[i].key) {
            return i;
        }
    }
    return static_cast<std::size_t>(-1);
}

std::size_t insert_row(std::uint64_t owner, const char* key) noexcept {
    std::size_t index = find_row(owner, key);
    if (index != static_cast<std::size_t>(-1)) {
        return index;
    }
    if (g_rowCount >= kMaxRows) {
        return static_cast<std::size_t>(-1);
    }
    index = g_rowCount++;
    g_rows[index].owner = owner;
    std::snprintf(g_rows[index].key, sizeof g_rows[index].key, "%s", key);
    return index;
}

/** Distinct non-self owners currently stored. */
std::size_t foreign_owner_count() noexcept {
    std::uint64_t seen[8]{};
    std::size_t count = 0;
    for (std::size_t i = 0; i < g_rowCount && i < kMaxRows; ++i) {
        const std::uint64_t owner = g_rows[i].owner;
        if (owner == own_xuid()) {
            continue;
        }
        bool known = false;
        for (std::size_t k = 0; k < count && k < 8; ++k) {
            known = known || seen[k] == owner;
        }
        if (!known && count < 8) {
            seen[count++] = owner;
        }
    }
    return count;
}

std::uint64_t foreign_owner(std::size_t index) noexcept {
    std::uint64_t seen[8]{};
    std::size_t count = 0;
    for (std::size_t i = 0; i < g_rowCount && i < kMaxRows; ++i) {
        const std::uint64_t owner = g_rows[i].owner;
        if (owner == own_xuid()) {
            continue;
        }
        bool known = false;
        for (std::size_t k = 0; k < count && k < 8; ++k) {
            known = known || seen[k] == owner;
        }
        if (!known) {
            if (count == index) {
                return owner;
            }
            if (count < 8) {
                seen[count++] = owner;
            }
        }
    }
    return 0;
}

/**
 * @return True when @p candidate points at a readable NUL-terminated string no longer
 *         than @p limit.
 *
 * Slot 64 is bound on RUNTIME EVIDENCE (it is where the '/connect:' publish arrives,
 * t=2662 every boot) but its identity is not proven: the competing reading is that 64 is
 * GetFriendMessage, whose second argument is a CSteamID. Handed an integer like
 * 0x0110000130AA9EC5 as a char*, an unguarded snprintf would fault and take the title with
 * it - the exact failure class that cost p2(62) and p2(63). VirtualQuery turns that into a
 * logged no-op, so this binding can be TESTED rather than gambled on.
 */
bool readable_string(const char* candidate, std::size_t limit) noexcept {
    if (candidate == nullptr) {
        return false;
    }
    MEMORY_BASIC_INFORMATION region{};
    if (VirtualQuery(candidate, &region, sizeof region) != sizeof region) {
        return false;
    }
    if (region.State != MEM_COMMIT) {
        return false;
    }
    constexpr DWORD kReadable = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY
                                | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE
                                | PAGE_EXECUTE_WRITECOPY;
    if ((region.Protect & kReadable) == 0 || (region.Protect & PAGE_GUARD) != 0) {
        return false;
    }
    // Stay inside the queried region: the NUL must land before the mapping ends.
    const auto* base = static_cast<const char*>(region.BaseAddress);
    const std::size_t remaining = region.RegionSize - static_cast<std::size_t>(candidate - base);
    const std::size_t bound = remaining < limit ? remaining : limit;
    for (std::size_t i = 0; i < bound; ++i) {
        if (candidate[i] == '\0') {
            return true;
        }
    }
    return false;
}

/** Worker cadence. Fast enough that a peer appears within a Tower load, cheap enough to ignore. */
constexpr DWORD kWorkerIntervalMilliseconds = 1000;

std::atomic<bool> g_workerStarted{false};
/** Set by set_rich_presence, cleared by the worker once every own row has been relayed. */
std::atomic<bool> g_publishPending{false};
/** Peer rows merged by the last fetch. Read by the log line only. */
std::atomic<std::size_t> g_peerRows{0};

void log_line(core::log::Level level, const char* format, ...) noexcept {
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

/** Distinct answers a hot-path instrument may hold before it starts overwriting. */
constexpr std::size_t kHotSlots = 8;
constexpr std::size_t kHotLineBytes = 256;
SRWLOCK g_hotLock{SRWLOCK_INIT};
char g_hotLast[kHotSlots][kHotLineBytes]{};

/**
 * Logs a hot-path line ONLY when its text changed since the last call for that slot.
 *
 * get_friend_count and get_rich_presence sit where the vtable audit measured 33 calls at
 * a single offset (20.97). Logging every call would put file I/O on the Client's own
 * thread and bury the boot's answer in thousands of identical lines. One line per
 * DISTINCT answer is exactly what the boot brief needs to read and costs nothing.
 */
void log_on_change(std::size_t slot, core::log::Level level, const char* format, ...) noexcept {
    char line[kHotLineBytes]{};
    va_list arguments;
    va_start(arguments, format);
    const int written = std::vsnprintf(line, sizeof line, format, arguments);
    va_end(arguments);
    if (written <= 0 || slot >= kHotSlots) {
        return;
    }
    AcquireSRWLockExclusive(&g_hotLock);
    const bool changed = std::strcmp(line, g_hotLast[slot]) != 0;
    if (changed) {
        std::snprintf(g_hotLast[slot], sizeof g_hotLast[slot], "%s", line);
    }
    ReleaseSRWLockExclusive(&g_hotLock);
    if (changed) {
        core::log::write(core::log::Channel::client, level,
                         {line, static_cast<std::size_t>(written)});
    }
}

/** Relays every own row to the server. Worker thread only. */
void publish_own_rows() noexcept {
    PresenceRow pending[kMaxRows]{};
    std::size_t count = 0;
    const std::uint64_t own = own_xuid();
    AcquireSRWLockShared(&g_lock);
    for (std::size_t i = 0; i < g_rowCount && i < kMaxRows; ++i) {
        if (g_rows[i].owner == own) {
            pending[count++] = g_rows[i];
        }
    }
    ReleaseSRWLockShared(&g_lock);

    for (std::size_t i = 0; i < count; ++i) {
        char target[320]{};
        const int written = std::snprintf(target, sizeof target,
                                          "/presence/store?xuid=%llx&key=%s&value=%s",
                                          static_cast<unsigned long long>(own),
                                          pending[i].key,
                                          pending[i].value);
        if (written <= 0 || written >= static_cast<int>(sizeof target)) {
            continue;
        }
        const unsigned status = interfaces::http_exchange("POST", target, nullptr, 0);
        // ABSENCE NEGATIVE (L13): a dropped relay must be LOUD. p2(64) discarded this.
        log_on_change(5, status == 200 ? core::log::Level::info : core::log::Level::warn,
                 "ev=steamnet stage=rich_presence_relay key=%s value=%s http=%u result=%s",
                 pending[i].key, pending[i].value, status, status == 200 ? "ok" : "fail");
    }
}

/** Fetches every stored peer row from the server. Worker thread only. */
void fetch_peer_values() noexcept {
    char buffer[2048]{};
    const unsigned status = interfaces::http_exchange("GET", "/presence", buffer, sizeof buffer);
    if (status != 200) {
        log_on_change(4, core::log::Level::warn,
                      "ev=steamnet stage=presence_fetch http=%u result=fail", status);
        return;
    }

    std::size_t merged = 0;
    const std::uint64_t own = own_xuid();
    AcquireSRWLockExclusive(&g_lock);
    char* contextLine = nullptr;
    for (char* line = strtok_r(buffer, "\n", &contextLine); line != nullptr;
         line = strtok_r(nullptr, "\n", &contextLine)) {
        unsigned long long xuid = 0;
        char key[48]{};
        char value[160]{};
        if (std::sscanf(line, "%llu %47s %159s", &xuid, key, value) != 3 || xuid == 0
            || xuid == own) {
            continue;
        }
        const std::size_t index = insert_row(xuid, key);
        if (index != static_cast<std::size_t>(-1)) {
            std::snprintf(g_rows[index].value, sizeof g_rows[index].value, "%s", value);
            ++merged;
        }
    }
    const std::size_t owners = foreign_owner_count();
    ReleaseSRWLockExclusive(&g_lock);

    g_peerRows.store(merged, std::memory_order_release);
    // The distinguishing instrument for boot-brief branch 2: rows=0 means the peer never
    // published (or the server lost them), NOT that our friend slots are wrong.
    log_on_change(3, core::log::Level::info,
                  "ev=steamnet stage=presence_fetch http=200 rows=%zu peers=%zu result=ok",
                  merged, owners);
}

DWORD WINAPI presence_worker(void*) noexcept {
    for (;;) {
        if (g_publishPending.exchange(false, std::memory_order_acq_rel)) {
            publish_own_rows();
        }
        fetch_peer_values();
        Sleep(kWorkerIntervalMilliseconds);
    }
}

/** Starts the worker on the first friends call. Never blocks the caller. */
void ensure_worker() noexcept {
    bool expected = false;
    if (!g_workerStarted.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        return;
    }
    const HANDLE thread = CreateThread(nullptr, 0, presence_worker, nullptr, 0, nullptr);
    if (thread == nullptr) {
        g_workerStarted.store(false, std::memory_order_release);
        log_line(core::log::Level::warn, "ev=steamnet stage=presence_worker result=fail");
        return;
    }
    (void)CloseHandle(thread);
    log_line(core::log::Level::info, "ev=steamnet stage=presence_worker result=ok");
}

} // namespace

bool set_rich_presence(void* /*self*/, const char* key, const char* value) noexcept {
    if (!readable_string(key, 48) || !readable_string(value, 160)) {
        // Not a (key, value) pair - so slot 64 is not SetRichPresence after all. Say so
        // once and return harmlessly; the census in the same log names the real callers.
        log_on_change(6, core::log::Level::warn,
                      "ev=steamnet stage=rich_presence_store result=not_a_string_pair "
                      "arg1=%p arg2=%p",
                      static_cast<const void*>(key), static_cast<const void*>(value));
        return false;
    }
    AcquireSRWLockExclusive(&g_lock);
    const std::size_t index = insert_row(own_xuid(), key);
    bool ok = index != static_cast<std::size_t>(-1);
    if (ok) {
        std::snprintf(g_rows[index].value, sizeof g_rows[index].value, "%s", value);
    }
    ReleaseSRWLockExclusive(&g_lock);
    if (ok) {
        g_publishPending.store(true, std::memory_order_release);
        ensure_worker();
        log_line(core::log::Level::info,
                 "ev=steamnet stage=rich_presence_store key=%s value=%s result=ok", key, value);
    }
    return ok;
}

const char* get_rich_presence(void* /*self*/, std::uint64_t friendId, const char* key) noexcept {
    if (key == nullptr) {
        return "";
    }
    ensure_worker();
    AcquireSRWLockShared(&g_lock);
    static thread_local char returnValue[160];
    const std::size_t index = find_row(friendId, key);
    if (index == static_cast<std::size_t>(-1)) {
        returnValue[0] = '\0';
    } else {
        std::snprintf(returnValue, sizeof returnValue, "%s", g_rows[index].value);
    }
    ReleaseSRWLockShared(&g_lock);
    if (friendId != own_xuid()) {
        // The boot contract's step 2 is "the peer's 'connect' key was READ". Without this
        // line an empty answer and a never-asked question look identical in the log.
        log_on_change(0, core::log::Level::info,
                 "ev=steamnet stage=peer_rich_presence friend=%llx key=%s value=%s result=%s",
                 static_cast<unsigned long long>(friendId), key, returnValue,
                 returnValue[0] == '\0' ? "empty" : "ok");
    }
    return returnValue;
}

int get_friend_count(void* /*self*/, int /*iFriendFlags*/) noexcept {
    ensure_worker();
    AcquireSRWLockShared(&g_lock);
    const int result = static_cast<int>(foreign_owner_count());
    ReleaseSRWLockShared(&g_lock);
    log_on_change(1, core::log::Level::info,
                  "ev=steamnet stage=friend_count count=%d result=ok", result);
    return result;
}

std::uint64_t get_friend_by_index(void* /*self*/,
                                  [[maybe_unused]] int index,
                                  [[maybe_unused]] int flags) noexcept {
    AcquireSRWLockShared(&g_lock);
    const std::uint64_t owner = foreign_owner(static_cast<std::size_t>(index));
    ReleaseSRWLockShared(&g_lock);
    log_on_change(2, core::log::Level::info,
                  "ev=steamnet stage=friend_by_index index=%d friend=%llx result=%s",
                  index, static_cast<unsigned long long>(owner), owner == 0 ? "absent" : "ok");
    return owner;
}

int get_friend_persona_state(void* /*self*/, std::uint64_t friendId) noexcept {
    // 1 = Online in EPersonaState. Only known owners are reported anyway.
    return friendId == 0 ? 0 : 1;
}

const char* get_friend_persona_name(void* /*self*/, std::uint64_t friendId) noexcept {
    // Persona names come from Core settings; the peer's label matches its authored slot.
    static thread_local char nameBuffer[64];
    const std::uint64_t own = own_xuid();
    if (friendId == own) {
        std::snprintf(nameBuffer, sizeof nameBuffer, "%s",
                      core::settings::get().steam.user.personaName.data());
    } else {
        const bool lowerSlot = (friendId & 0xFF) < (own & 0xFF);
        std::snprintf(nameBuffer, sizeof nameBuffer, "guardian-%s",
                      lowerSlot ? "one" : "two");
    }
    return nameBuffer;
}

bool request_user_information(void* /*self*/, std::uint64_t /*friendId*/,
                              bool /*requireNameOnly*/) noexcept {
    return false;
}

bool request_friend_rich_presence(void* /*self*/, std::uint64_t /*friendId*/) noexcept {
    // Fetch-on-read already keeps values fresh; nothing further required.
    return true;
}

const char* persona_name(void* /*self*/) noexcept {
    return core::settings::get().steam.user.personaName.data();
}

} // namespace sunrise::steam::interfaces::methods
