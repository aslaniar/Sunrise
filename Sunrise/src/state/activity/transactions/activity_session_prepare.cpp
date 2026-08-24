#include <Windows.h>

#include "../../runtime/runtime.h"
#include "../../runtime/storage/internal.h"
#include "../destination/activity_destination_validation.h"
#include "../runtime.h"
#include "internal.h"

namespace sunrise::state::activity {
namespace {

/** Account half of every soid this account owns, which the activity session shares. */
constexpr std::uint64_t kAccountMask = 0xFFFFFFFF00000000ULL;

/**
 * Reads the account half the published session soid carries.
 * Called before the State lock is taken, because the account snapshot takes that same lock.
 * @return Account half, or zero while no account is loaded.
 */
[[nodiscard]] std::uint64_t session_soid_base() noexcept {
    // ARCHITECTURAL, not a keying oversight (FINDINGS 20.22): the activity plane is
    // SINGLE-ACCOUNT by construction - both prepare_session overloads below read
    // `g_states[kLegacyAccount].activity` outright, so there is one activity state shared by
    // every peer. Keying this one read would only make the soid base disagree with the state
    // it feeds. The slot is named explicitly here so the limitation is visible instead of
    // implied by a default. Giving each peer its own activity state is the distinct-guardian
    // front's problem, and it is a design change, not an argument.
    const AccountState account = account_snapshot(core::settings::kLegacyAccount);
    return account.primarySoid & kAccountMask;
}

/**
 * Captures one checked destination and the allocator snapshot under the State read lock.
 * @param state Activity State, guarded by the root shared lock.
 * @param selection Destination that must commit with the picked id.
 * @param sessionId Cleared, then receives the picked nonzero id.
 * @param allocation Cleared, then receives the captured transaction data.
 * @return True when the fixed table and rising allocator can take one more record.
 */
[[nodiscard]] bool prepare_locked(const ActivityState& state,
                                  const destination::DestinationSelection& selection,
                                  std::uint64_t soidBase,
                                  std::uint64_t& sessionId,
                                  PendingAllocation& allocation) noexcept {
    if (!destination::valid(selection) || !transactions::allocation_available(state)) {
        return false;
    }

    PendingAllocation prepared{};
    prepared.destination = selection;
    // The allocator counter stays the record index. Only the published soid carries the account
    // half and the class.
    prepared.soidBase = soidBase;
    prepared.sessionId = transactions::compose_session_soid(soidBase, state.nextSessionId);
    prepared.expectedStateRevision = state.stateRevision;
    prepared.expectedAllocatorRevision = state.allocatorRevision;
    prepared.expectedNextSessionId = state.nextSessionId;
    prepared.targetSlot = transactions::select_target(state);
    prepared.prepared = true;
    sessionId = prepared.sessionId;
    allocation = prepared;
    return true;
}

} // namespace

/** Prepares one allocation with State's fixed default destination, without changing State. */
bool prepare_session(std::uint64_t& sessionId, PendingAllocation& allocation) noexcept {
    sessionId = kAbsentSessionId;
    allocation = {};
    const std::uint64_t soidBase = session_soid_base();
    AcquireSRWLockShared(&runtime::storage::g_stateLock);
    const ActivityState& state = runtime::storage::g_states[core::settings::kLegacyAccount].activity;
    const bool ready = prepare_locked(
        state, state.defaults.defaultDestination.selection, soidBase, sessionId, allocation);
    ReleaseSRWLockShared(&runtime::storage::g_stateLock);
    return ready;
}

/** Prepares one allocation with an explicit checked scalar destination. */
bool prepare_session(const destination::DestinationSelection& selection,
                     std::uint64_t& sessionId,
                     PendingAllocation& allocation) noexcept {
    sessionId = kAbsentSessionId;
    allocation = {};
    if (!destination::valid(selection)) {
        return false;
    }

    const std::uint64_t soidBase = session_soid_base();
    AcquireSRWLockShared(&runtime::storage::g_stateLock);
    const bool ready = prepare_locked(
        runtime::storage::g_states[core::settings::kLegacyAccount].activity, selection, soidBase, sessionId, allocation);
    ReleaseSRWLockShared(&runtime::storage::g_stateLock);
    return ready;
}

} // namespace sunrise::state::activity
