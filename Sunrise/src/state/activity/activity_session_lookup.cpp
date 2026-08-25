#include <Windows.h>

#include <limits>

#include "../runtime/storage/internal.h"
#include "runtime.h"
#include "transactions/internal.h"

namespace sunrise::state::activity {

namespace {

/** @return True when every scalar and captured descriptor field is identical. */
[[nodiscard]] bool same_destination(const destination::DestinationSelection& left,
                                    const destination::DestinationSelection& right) noexcept {
    return left.packageName == right.packageName
           && left.packageNameLength == right.packageNameLength && left.reason == right.reason
           && left.previousActivityIndex == right.previousActivityIndex
           && left.activityIndex == right.activityIndex && left.elementIndex == right.elementIndex
           && left.arrivalBubbleHash == right.arrivalBubbleHash
           && left.spawnSetHash == right.spawnSetHash
           && left.hasElementIndex == right.hasElementIndex
           && left.hasArrivalBubbleHash == right.hasArrivalBubbleHash
           && left.hasSpawnSetHash == right.hasSpawnSetHash
           && left.arrivalBubbleOverride == right.arrivalBubbleOverride
           && left.hasArrivalBubbleOverride == right.hasArrivalBubbleOverride
           && left.sliceSetOverride == right.sliceSetOverride
           && left.hasSliceSetOverride == right.hasSliceSetOverride
           && left.spawnSetOverride == right.spawnSetOverride
           && left.hasSpawnSetOverride == right.hasSpawnSetOverride
           && left.descriptorBits == right.descriptorBits
           && left.descriptorBitLength == right.descriptorBitLength
           && left.descriptorNameBit == right.descriptorNameBit
           && left.hasDescriptorName == right.hasDescriptorName;
}

/**
 * Peer test for cross-client membership: two sessions are peers when they occupy the same
 * ACTIVITY of the same destination PACKAGE. Arrival bubbles, spawn sets, slice overrides and
 * descriptor-name details are per-join facts - retail fireteam members do not carry identical
 * arrival selections either (FINDINGS 20.47: strict equality rejected two live Tower sessions
 * that both printed dest=city_tower_social_d2).
 */
[[nodiscard]] bool same_peer_destination(
    const destination::DestinationSelection& left,
    const destination::DestinationSelection& right) noexcept {
    return left.packageName == right.packageName
           && left.packageNameLength == right.packageNameLength
           && left.activityIndex == right.activityIndex;
}

/** @return True when the record is the exact generation the binding names. */
[[nodiscard]] bool record_matches(const SessionRecord& record,
                                  const SessionBinding& binding) noexcept {
    return record.occupied && binding.sessionId != kAbsentSessionId
           && binding.createdRevision != kInvalidRevision && record.sessionId == binding.sessionId
           && record.createdRevision == binding.createdRevision
           && same_destination(record.destination, binding.destination);
}

} // namespace


/** Tests whether a nonzero activity-session id is still in the bounded table. */
bool contains(std::uint64_t sessionId) noexcept {
    if (sessionId == kAbsentSessionId) {
        return false;
    }
    AcquireSRWLockShared(&runtime::storage::g_stateLock);
    const ActivityState& state = runtime::storage::g_activity;
    bool found = false;
    for (const SessionRecord& record : state.sessions) {
        if (record.occupied && record.sessionId == sessionId) {
            found = true;
            break;
        }
    }
    ReleaseSRWLockShared(&runtime::storage::g_stateLock);
    return found;
}

/** Tests whether a committed activity-session id has finished a join. */
bool is_joined(std::uint64_t sessionId) noexcept {
    if (sessionId == kAbsentSessionId) {
        return false;
    }
    AcquireSRWLockShared(&runtime::storage::g_stateLock);
    const ActivityState& state = runtime::storage::g_activity;
    bool joined = false;
    for (const SessionRecord& record : state.sessions) {
        if (record.occupied && record.sessionId == sessionId) {
            joined = record.joined && record.joinedRevision != kInvalidRevision;
            break;
        }
    }
    ReleaseSRWLockShared(&runtime::storage::g_stateLock);
    return joined;
}


/** Copies one session's immutable binding identity. */
bool snapshot_binding(std::uint64_t sessionId, SessionBinding& output) noexcept {
    output = {};
    if (sessionId == kAbsentSessionId) {
        return false;
    }
    AcquireSRWLockShared(&runtime::storage::g_stateLock);
    const ActivityState& state = runtime::storage::g_activity;
    const std::size_t slot = transactions::find_session(state, sessionId);
    const bool found = slot < kSessionCapacity;
    if (found) {
        const SessionRecord& record = state.sessions[slot];
        output.destination = record.destination;
        output.sessionId = record.sessionId;
        output.createdRevision = record.createdRevision;
    }
    ReleaseSRWLockShared(&runtime::storage::g_stateLock);
    return found;
}

/** Tests whether the exact bound record generation is still committed. */
bool binding_matches(const SessionBinding& binding) noexcept {
    AcquireSRWLockShared(&runtime::storage::g_stateLock);
    const ActivityState& state = runtime::storage::g_activity;
    const std::size_t slot = transactions::find_session(state, binding.sessionId);
    const bool matches = slot < kSessionCapacity && record_matches(state.sessions[slot], binding);
    ReleaseSRWLockShared(&runtime::storage::g_stateLock);
    return matches;
}

/** Copies another joined session's published identity from the same destination. */
bool foreign_member_identity(const std::uint64_t ownSessionId,
                             membership::Identity& output,
                             ForeignPeerReason& reason) noexcept {
    output = {};
    reason = ForeignPeerReason::none_joined;
    if (ownSessionId == kAbsentSessionId) {
        return false;
    }
    AcquireSRWLockShared(&runtime::storage::g_stateLock);
    const ActivityState& state = runtime::storage::g_activity;
    const std::size_t own = transactions::find_session(state, ownSessionId);
    bool found = false;
    if (own < kSessionCapacity) {
        const SessionRecord& ownRecord = state.sessions[own];
        for (const SessionRecord& record : state.sessions) {
            if (record.sessionId == ownSessionId || !record.occupied || !record.joined) {
                continue;
            }
            // Same peer destination or not a peer at all: two players in different
            // destinations must never see each other's membership rows.
            if (!same_peer_destination(record.destination, ownRecord.destination)) {
                // A joined session outside this destination is still evidence the table is
                // not empty, so it outranks none_joined when nothing better appears.
                if (reason == ForeignPeerReason::none_joined) {
                    reason = ForeignPeerReason::destination_mismatch;
                }
                continue;
            }
            if (!record.membership.hasIdentity) {
                reason = ForeignPeerReason::identity_missing;
                continue;
            }
            output = record.membership.identity;
            reason = ForeignPeerReason::found;
            found = true;
            break;
        }
    }
    ReleaseSRWLockShared(&runtime::storage::g_stateLock);
    return found;
}

/** Retains an exact record generation against release and allocator eviction. */
bool retain_binding(const SessionBinding& binding) noexcept {
    AcquireSRWLockExclusive(&runtime::storage::g_stateLock);
    ActivityState& state = runtime::storage::g_activity;
    const std::size_t slot = transactions::find_session(state, binding.sessionId);
    bool retained = slot < kSessionCapacity && record_matches(state.sessions[slot], binding);
    if (retained) {
        SessionRecord& record = state.sessions[slot];
        retained = record.bindingRetainCount
                   != (std::numeric_limits<decltype(record.bindingRetainCount)>::max)();
        if (retained) {
            ++record.bindingRetainCount;
        }
    }
    ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
    return retained;
}

/** Releases one retain only when the exact record generation still matches. */
void release_binding(const SessionBinding& binding) noexcept {
    AcquireSRWLockExclusive(&runtime::storage::g_stateLock);
    ActivityState& state = runtime::storage::g_activity;
    const std::size_t slot = transactions::find_session(state, binding.sessionId);
    if (slot < kSessionCapacity && record_matches(state.sessions[slot], binding)
        && state.sessions[slot].bindingRetainCount != 0) {
        --state.sessions[slot].bindingRetainCount;
    }
    ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
}

} // namespace sunrise::state::activity
