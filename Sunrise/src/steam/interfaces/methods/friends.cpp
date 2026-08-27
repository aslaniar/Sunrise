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
 * FRIENDS RICH-PRESENCE CROSS-INTRODUCTION (FINDINGS 20.96).
 *
 * Retail hands each client a join target through friends rich presence: every client
 * publishes key 'connect' = "/connect:" + little-endian own-xuid bytes, and reads its
 * friends' keys to learn where they are. Both halves previously failed in this shim:
 * SetRichPresence (slot 64) returned true but stored nothing, and friend reads
 * (slots 3/5/43) returned zeros, so no client ever learned another machine's target.
 *
 * This module gives the shim one REAL peer: the other provisioned account. Own
 * publishes are stored locally; the peer's values arrive through the presence store
 * served by our HTTP server (server/http/presence_state.*), fetched lazily on read.
 */

/** The single peer this shim knows about: the other provisioned steam id. */
std::uint64_t peer_xuid() noexcept {
    const auto self = core::settings::get().steam.user.steamId;
    // The paired machine runs the sibling authored account; both ids live in
    // accounts[0]/[1] bands 0x...ec5/0x...ec6 (FINDINGS 20.64). The peer is whichever
    // is not ours: flip the lowest bit of the low dword as authored pairs differ by 1.
    return self ^ 1ULL;
}

/** Own xuid, cached from settings. */
std::uint64_t own_xuid() noexcept {
    return core::settings::get().steam.user.steamId;
}

/** Local presence keys. One row per key per owner (0 = self). */
struct PresenceRow {
    std::uint64_t owner{};
    char key[48]{};
    char value[160]{};
};
constexpr std::size_t kMaxRows = 16;
SRWLOCK g_lock{SRWLOCK_INIT};
std::array<PresenceRow, kMaxRows> g_rows{};
std::atomic<std::size_t> g_rowCount{0};

/** @return Row index for (owner,key), or kNoRow. */
std::size_t find_row(std::uint64_t owner, std::string_view key) noexcept {
    const std::size_t count = g_rowCount.load(std::memory_order_acquire);
    for (std::size_t i = 0; i < count && i < kMaxRows; ++i) {
        if (g_rows[i].owner == owner && key == g_rows[i].key) {
            return i;
        }
    }
    return static_cast<std::size_t>(-1);
}

} // namespace

/** Stores one OWN rich-presence key (SteamFriends SetRichPresence, slot 64). */
bool set_rich_presence(void* /*self*/, const char* key, const char* value) noexcept {
    if (key == nullptr || value == nullptr) {
        return false;
    }
    AcquireSRWLockExclusive(&g_lock);
    std::size_t index = find_row(own_xuid(), key);
    if (index == static_cast<std::size_t>(-1)) {
        const std::size_t count = g_rowCount.load(std::memory_order_relaxed);
        if (count >= kMaxRows) {
            ReleaseSRWLockExclusive(&g_lock);
            return true; // Steam semantics: failure is invisible; never block the client.
        }
        index = count;
        g_rowCount.store(count + 1, std::memory_order_release);
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

/** Fetches the peer's snapshot from OUR server and merges it into local rows. */
void refresh_peer_presence() noexcept {
    // The server answers GET /presence with lines "xuid key value". Request it through
    // the client HTTP consumer so the request rides the external-server redirect like
    // every other client fetch; response lands in a stack buffer.
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
            const std::size_t count = g_rowCount.load(std::memory_order_relaxed);
            if (count >= kMaxRows) {
                break;
            }
            index = count;
            g_rowCount.store(count + 1, std::memory_order_release);
            g_rows[index].owner = xuid;
            std::snprintf(g_rows[index].key, sizeof g_rows[index].key, "%s", key);
        }
        std::snprintf(g_rows[index].value, sizeof g_rows[index].value, "%s", value);
    }
    ReleaseSRWLockExclusive(&g_lock);
}

/** Reads one rich-presence value (own or peer's) into the caller buffer. */
const char* get_rich_presence([[maybe_unused]] void* self,
                              std::uint64_t friendId,
                              const char* key) noexcept {
    if (key == nullptr) {
        return "";
    }
    if (friendId != own_xuid()) {
        refresh_peer_presence();
    }
    AcquireSRWLockShared(&g_lock);
    const std::size_t index = find_row(friendId, key);
    // Static one-row return buffer: the Client copies the string immediately.
    static thread_local char returnValue[160];
    if (index == static_cast<std::size_t>(-1)) {
        std::memcpy(returnValue, "", 1);
    } else {
        std::snprintf(returnValue, sizeof returnValue, "%s", g_rows[index].value);
    }
    ReleaseSRWLockShared(&g_lock);
    return returnValue;
}

/** Friend count: self plus the one configured peer when both exist. */
int get_friend_count(void* /*self*/) noexcept {
    refresh_peer_presence();
    return 2;
}

/** Returns the peer's (or own) SteamId for friend-index reads. */
std::uint64_t get_friend_by_index([[maybe_unused]] void* self, int index) noexcept {
    return index == 0 ? own_xuid() : peer_xuid();
}

/** Persona state: the peer counts as online (3) once it exists at all. */
int get_friend_persona_state([[maybe_unused]] void* self, std::uint64_t friendId) noexcept {
    return friendId == own_xuid() ? 3 : 3;
}

/** Name resolution gate: report full information for ourselves and the peer. */
bool request_user_information([[maybe_unused]] void* self, std::uint64_t) noexcept {
    return false; // false = persona info already available, no callback coming.
}

} // namespace sunrise::steam::interfaces::methods

namespace sunrise::steam::interfaces::methods {

/** @return Persona name from settings. It lasts for the whole process. */
const char* persona_name([[maybe_unused]] void* self) noexcept {
    return core::settings::get().steam.user.personaName.data();
}

} // namespace sunrise::steam::interfaces::methods
