#include "../../runtime/storage/internal.h"
#include "../runtime.h"
#include "internal.h"

#include <array>
#include <cstdio>
#include "../../../core/logging/log.h"

namespace sunrise::state::activity {

/** Frees one committed activity-session record. */
bool release_session(std::uint64_t sessionId) noexcept {
    if (sessionId == kAbsentSessionId) {
        return false;
    }
    AcquireSRWLockExclusive(&runtime::storage::g_stateLock);
    ActivityState& state = runtime::storage::g_activity;
    const std::size_t slot = transactions::find_session(state, sessionId);
    // A retained record is still named by a live consumer's binding; freeing it would strand it.
    const bool released = slot < kSessionCapacity && state.sessions[slot].bindingRetainCount == 0;
    if (released) {
        // The revision bump retires every plan prepared against this record.
        state.sessions[slot] = {};
        ++state.stateRevision;
    }
    ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
    // p2-211 (20.338 R4): the mac's activity sessions churn - 6-9 wire snapshots
    // each, then replaced - while the rig's carries 456, and that asymmetry is why
    // the mac is fed almost no peer rows. Nothing recorded WHO tears a session down,
    // so the churn could never be attributed. One line per release attempt (rare).
    {
        std::array<char, 128> line{};
        const int n = std::snprintf(line.data(), line.size(),
            "ev=activity stage=session_release session=0x%llX result=%s",
            static_cast<unsigned long long>(sessionId),
            released ? "released" : "kept");
        if (n > 0) {
            core::log::write(core::log::Channel::state,
                             core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(n)});
        }
    }
    return released;
}

} // namespace sunrise::state::activity
