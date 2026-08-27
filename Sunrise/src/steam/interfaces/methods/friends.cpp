#include <Windows.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string_view>

#include "../../../core/logging/log.h"
#include "../../../core/settings/settings.h"
#include "../../../client/network/consumer.h"
#include "../internal.h"

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
 * Presence values: own publishes stored locally AND relayed through the Server
 * (/presence/store); the single paired peer's values fetched lazily from /presence on
 * friend queries (GET /presence returns "xuid key value" lines).
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
 * Relays one stored own-key to the Server so the peer's shim can read it.
 * POST /presence/store?xuid=<hex>&key=<name> with the value as body.
 */
void relay_to_server(std::string_view key, std::string_view value) noexcept {
    char url[128]{};
    const int written = std::snprintf(url,
                                      sizeof url,
                                      "/presence/store?xuid=%llx&key=%s",
                                      static_cast<unsigned long long>(own_xuid()),
                                      std::string_view{key}.substr(0, 40).data());
    if (written <= 0 || written >= static_cast<int>(sizeof url)) {
        return;
    }
    client::network::HttpRequest request{
        .url = url,
        .contentType = "text/plain",
        .body = {},
        .response = {},
    };
    // Copy the value into request-owned bytes: consumer borrows .body directly.
    static thread_local char payload[160];
    std::snprintf(payload, sizeof payload, "%.*s",
                  static_cast<int>(value.size()), value.data());
    request.body = {reinterpret_cast<std::byte*>(payload), std::strlen(payload)};
    client::network::HttpResponse response{};
    static_cast<void>(client::network::consume_http(request, response));
}

void fetch_peer_values() noexcept {
    char buffer[1024]{};
    client::network::HttpRequest request{
        .url = "/presence",
        .contentType = "text/plain",
        .body = {},
        .response = {reinterpret_cast<std::byte*>(buffer), sizeof buffer - 1},
    };
    client::network::HttpResponse response{};
    if (!client::network::consume_http(request, response)) {
        return;
    }
    buffer[response.size < sizeof buffer ? response.size : sizeof buffer - 1] = '\0';

    AcquireSRWLockExclusive(&g_lock);
    char* contextLine = nullptr;
    for (char* line = strtok_r(buffer, "\n", &contextLine); line != nullptr;
         line = strtok_r(nullptr, "\n", &contextLine)) {
        unsigned long long xuid = 0;
        char key[48]{};
        char value[160]{};
        if (std::sscanf(line, "%llu %47s %159s", &xuid, key, value) != 3 || xuid == 0
            || xuid == own_xuid()) {
            continue;
        }
        const std::size_t index = insert_row(xuid, key);
        if (index != static_cast<std::size_t>(-1)) {
            std::snprintf(g_rows[index].value, sizeof g_rows[index].value, "%s", value);
        }
    }
    ReleaseSRWLockExclusive(&g_lock);
}

} // namespace

bool set_rich_presence(void* /*self*/, const char* key, const char* value) noexcept {
    if (key == nullptr || value == nullptr) {
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
        relay_to_server(key, value);
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         "ev=steamnet stage=rich_presence_store result=ok");
    }
    return ok;
}

const char* get_rich_presence(void* /*self*/, std::uint64_t friendId, const char* key) noexcept {
    if (key == nullptr) {
        return "";
    }
    if (friendId != own_xuid()) {
        fetch_peer_values();
    }
    AcquireSRWLockShared(&g_lock);
    static thread_local char returnValue[160];
    const std::size_t index = find_row(friendId, key);
    if (index == static_cast<std::size_t>(-1)) {
        returnValue[0] = '\0';
    } else {
        std::snprintf(returnValue, sizeof returnValue, "%s", g_rows[index].value);
    }
    ReleaseSRWLockShared(&g_lock);
    return returnValue;
}

int get_friend_count(void* /*self*/, int /*iFriendFlags*/) noexcept {
    fetch_peer_values();
    AcquireSRWLockShared(&g_lock);
    const int result = static_cast<int>(foreign_owner_count());
    ReleaseSRWLockShared(&g_lock);
    core::log::write(core::log::Channel::client,
                     core::log::Level::info,
                     "ev=steamnet stage=friend_count result=ok");
    return result;
}

std::uint64_t get_friend_by_index(void* /*self*/,
                                  [[maybe_unused]] int index,
                                  [[maybe_unused]] int flags) noexcept {
    AcquireSRWLockShared(&g_lock);
    const std::uint64_t owner = foreign_owner(static_cast<std::size_t>(index));
    ReleaseSRWLockShared(&g_lock);
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
