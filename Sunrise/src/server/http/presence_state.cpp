#include "presence_state.h"

#include <cstdio>
#include <cstring>

namespace sunrise::server::http::presence {
namespace {

SRWLOCK g_lock{SRWLOCK_INIT};
std::array<Entry, kMaxPeers * 4> g_entries{};
std::size_t g_count{};

/** @return Index of the (xuid,key) row, or kNoIndex. */
std::size_t find_index(std::uint64_t xuid, std::string_view key) noexcept {
    for (std::size_t i = 0; i < g_count; ++i) {
        if (g_entries[i].xuid == xuid && key == g_entries[i].key) {
            return i;
        }
    }
    return static_cast<std::size_t>(-1);
}

} // namespace

bool store(std::uint64_t xuid, std::string_view key, std::string_view value) noexcept {
    if (xuid == 0 || key.empty() || key.size() >= kMaxKeyBytes
        || value.size() >= kMaxValueBytes) {
        return false;
    }
    AcquireSRWLockExclusive(&g_lock);
    std::size_t index = find_index(xuid, key);
    if (index == static_cast<std::size_t>(-1)) {
        if (g_count >= g_entries.size()) {
            ReleaseSRWLockExclusive(&g_lock);
            return false;
        }
        index = g_count++;
        g_entries[index].xuid = xuid;
        std::memcpy(g_entries[index].key, key.data(), key.size());
        g_entries[index].key[key.size()] = '\0';
    }
    std::memcpy(g_entries[index].value, value.data(), value.size());
    g_entries[index].value[value.size()] = '\0';
    ReleaseSRWLockExclusive(&g_lock);
    return true;
}

std::size_t snapshot(char* output, std::size_t capacity) noexcept {
    AcquireSRWLockShared(&g_lock);
    std::size_t used = 0;
    for (std::size_t i = 0; i < g_count && used < capacity; ++i) {
        const int written = std::snprintf(output + used, capacity - used,
                                          "%llu %s %s\n",
                                          static_cast<unsigned long long>(g_entries[i].xuid),
                                          g_entries[i].key,
                                          g_entries[i].value);
        if (written <= 0 || static_cast<std::size_t>(written) >= capacity - used) {
            break;
        }
        used += static_cast<std::size_t>(written);
    }
    ReleaseSRWLockShared(&g_lock);
    return used;
}


namespace {

/** One claimed lobby ordinal. */
struct LobbyClaim {
    std::uint64_t sequence{};
    std::uint64_t lobby{};
};
SRWLOCK g_lobbyLock{SRWLOCK_INIT};
std::array<LobbyClaim, kMaxLobbySlots> g_lobbies{};
std::size_t g_lobbyCount{};

} // namespace

std::uint64_t claim_lobby(std::uint64_t sequence, std::uint64_t candidate) noexcept {
    if (sequence == 0 || candidate == 0) {
        return candidate;
    }
    AcquireSRWLockExclusive(&g_lobbyLock);
    std::uint64_t winner = candidate;
    bool found = false;
    for (std::size_t i = 0; i < g_lobbyCount; ++i) {
        if (g_lobbies[i].sequence == sequence) {
            winner = g_lobbies[i].lobby;
            found = true;
            break;
        }
    }
    if (!found && g_lobbyCount < g_lobbies.size()) {
        g_lobbies[g_lobbyCount].sequence = sequence;
        g_lobbies[g_lobbyCount].lobby = candidate;
        ++g_lobbyCount;
    }
    ReleaseSRWLockExclusive(&g_lobbyLock);
    return winner;
}

std::size_t lobby_snapshot(char* output, std::size_t capacity) noexcept {
    AcquireSRWLockShared(&g_lobbyLock);
    std::size_t used = 0;
    for (std::size_t i = 0; i < g_lobbyCount && used < capacity; ++i) {
        const int written = std::snprintf(output + used, capacity - used, "%llu %llu\n",
                                          static_cast<unsigned long long>(g_lobbies[i].sequence),
                                          static_cast<unsigned long long>(g_lobbies[i].lobby));
        if (written <= 0 || static_cast<std::size_t>(written) >= capacity - used) {
            break;
        }
        used += static_cast<std::size_t>(written);
    }
    ReleaseSRWLockShared(&g_lobbyLock);
    return used;
}

}
