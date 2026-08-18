#include "unlocks_runtime.h"

#include <Windows.h>

#include <span>

namespace sunrise::state::unlocks {
namespace {

Table g_table{};
SRWLOCK g_lock{SRWLOCK_INIT};

} // namespace

/** Publishes the immutable unlock policy for this process. */
void publish(const Table& table) noexcept {
    AcquireSRWLockExclusive(&g_lock);
    g_table = table;
    ReleaseSRWLockExclusive(&g_lock);
}

/** @return The active unlock policy, or an empty policy when none was published. */
const Table& get() noexcept {
    return g_table;
}

/** Restores the empty unlock policy. */
void clear() noexcept {
    AcquireSRWLockExclusive(&g_lock);
    g_table = Table{};
    ReleaseSRWLockExclusive(&g_lock);
}

/** Sets one inclusive flag range in the active policy behind the lock. */
bool mutate_flags(std::string_view scope,
                  std::size_t first,
                  std::size_t last,
                  std::uint8_t value) noexcept {
    if (first > last) {
        return false;
    }
    AcquireSRWLockExclusive(&g_lock);
    std::span<std::uint8_t> bank{};
    if (scope == "account") {
        bank = g_table.accountFlags;
    } else if (scope == "profile") {
        bank = g_table.profileFlags;
    } else if (scope == "character") {
        bank = g_table.characterFlags;
    } else if (scope == "character_object") {
        bank = g_table.characterObjectFlags;
    }
    if (bank.empty() || last >= bank.size()) {
        ReleaseSRWLockExclusive(&g_lock);
        return false;
    }
    for (std::size_t index = first; index <= last; ++index) {
        bank[index] = value;
    }
    ReleaseSRWLockExclusive(&g_lock);
    return true;
}

} // namespace sunrise::state::unlocks
