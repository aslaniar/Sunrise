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
 * FRIENDS RICH-PRESENCE CROSS-INTRODUCTION (FINDINGS 20.96), p2(63) hardening.
 *
 * p2(62) froze both clients before the title screen: it reported two friends from the
 * first GetFriendCount, with a PHANTOM peer id (own id XOR 1 - not an existing account),
 * so the client's friend-index loop dereferenced session state for a user that had no
 * records. This build reports ONLY friends whose presence arrived through the presence
 * store, and only after that store has live data: GetFriendCount starts at 1 (self) and
 * grows by one per DISTINCT foreign xuid seen in GET /presence snapshots.
 */

/** Presence rows: one per (owner,key). Owner 0 rows are impossible (xuid nonzero). */
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
        for (std::size_t k = 0; k < count; ++k) {
            if (seen[k] == owner) {
                known = true;
                break;
            }
        }
        if (!known && count < 8) {
            seen[count++] = owner;
        }
    }
    return count;
}

/** @return The nth distinct foreign owner, or zero. */
std::uint64_t foreign_owner(std::size_t index) noexcept {
    std::uint64_t seen[8]{};
    std::size_t count = 0;
    for (std::size_t i = 0; i < g_rowCount && i < kMaxRows; ++i) {
        const std::uint64_t owner = g_rows[i].owner;
        if (owner == own_xuid()) {
            continue;
        }
        bool known = false;
        for (std::size_t k = 0; k < count; ++k) {
            if (seen[k] == owner) {
                known = true;
                break;
            }
        }
        if (!known) {
            if (count == index) {
                return owner;
            }
            if (count < 8) {
                seen[count++] = owner;
            } else {
                break;
            }
        }
    }
    return 0;
}

} // namespace

bool set_rich_presence(void* /*self*/, const char* key, const char* value) noexcept {
    if (key == nullptr || value == nullptr) {
        return false;
    }
    AcquireSRWLockExclusive(&g_lock);
    std::size_t index = find_row(own_xuid(), key);
    if (index == static_cast<std::size_t>(-1)) {
        if (g_rowCount >= kMaxRows) {
            ReleaseSRWLockExclusive(&g_lock);
            return true;
        }
        index = g_rowCount++;
        g_rows[index].owner = own_xuid();
        std::snprintf(g_rows[index].key, sizeof g_rows[index].key, "%s", key);
    }
    std::snprintf(g_rows[index].value, sizeof g_rows[index].value, "%s", value);
    ReleaseSRWLockExclusive(&g_lock);
    core::log::write(core::log::Channel::client,
                     core::log::Level::info,
                     "ev=steamnet stage=rich_presence_store result=ok");
    return true;
}

void refresh_peer_presence() noexcept {
    char body[1024]{};
    client::network::HttpRequest request{
        .url = "/presence",
        .contentType = "text/plain",
        .body = {},
        .response = {reinterpret_cast<std::byte*>(body), sizeof body - 1},
    };
    client::network::HttpResponse response{};
    if (!client::network::consume_http(request, response)) {
        return;
    }
    body[response.size < sizeof body ? response.size : sizeof body - 1] = '\0';

    AcquireSRWLockExclusive(&g_lock);
    char* contextLine = nullptr;
    for (char* line = strtok_r(body, "\n", &contextLine); line != nullptr;
         line = strtok_r(nullptr, "\n", &contextLine)) {
        unsigned long long xuid = 0;
        char key[48]{};
        char value[160]{};
        if (std::sscanf(line, "%llu %47s %159s", &xuid, key, value) != 3 || xuid == 0
            || xuid == own_xuid()) {
            continue;
        }
        std::size_t index = find_row(xuid, key);
        if (index == static_cast<std::size_t>(-1)) {
            if (g_rowCount >= kMaxRows) {
                break;
            }
            index = g_rowCount++;
            g_rows[index].owner = xuid;
            std::snprintf(g_rows[index].key, sizeof g_rows[index].key, "%s", key);
        }
        std::snprintf(g_rows[index].value, sizeof g_rows[index].value, "%s", value);
    }
    ReleaseSRWLockExclusive(&g_lock);
}

const char* get_rich_presence([[maybe_unused]] void* self,
                              std::uint64_t friendId,
                              const char* key) noexcept {
    if (key == nullptr) {
        return "";
    }
    AcquireSRWLockShared(&g_lock);
    const std::size_t index = find_row(friendId, key);
    static thread_local char returnValue[160];
    if (index == static_cast<std::size_t>(-1)) {
        returnValue[0] = '\0';
    } else {
        std::snprintf(returnValue, sizeof returnValue, "%s", g_rows[index].value);
    }
    ReleaseSRWLockShared(&g_lock);
    return returnValue;
}

int get_friend_count(void* /*self*/) noexcept {
    refresh_peer_presence();
    AcquireSRWLockShared(&g_lock);
    // +1: SteamFriends counts exclude self? No - retail GetFriendCount is FRIENDS ONLY.
    // It never includes self. Start at the foreign count; with no peer yet this returns
    // zero, which is the safe pre-introduction state the client handles natively.
    const int result = static_cast<int>(foreign_owner_count());
    ReleaseSRWLockShared(&g_lock);
    core::log::write(core::log::Channel::client,
                     core::log::Level::info,
                     "ev=steamnet stage=friend_count result=ok");
    return result;
}

std::uint64_t get_friend_by_index([[maybe_unused]] void* self, int index) noexcept {
    AcquireSRWLockShared(&g_lock);
    const std::uint64_t owner = foreign_owner(static_cast<std::size_t>(index));
    ReleaseSRWLockShared(&g_lock);
    return owner; // zero when out of range: caller treats as end of list and stops.
}

int get_friend_persona_state([[maybe_unused]] void* self, std::uint64_t friendId) noexcept {
    // Only ever called for ids returned above; any known owner is online(3).
    return friendId == 0 ? 0 : 3;
}

bool request_user_information([[maybe_unused]] void* self, std::uint64_t) noexcept {
    return false;
}

const char* persona_name([[maybe_unused]] void* self) noexcept {
    return core::settings::get().steam.user.personaName.data();
}

} // namespace sunrise::steam::interfaces::methods
