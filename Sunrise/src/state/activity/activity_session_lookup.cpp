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

/**
 * Collects every joined machine in the caller's destination, caller's own row first.
 * See runtime.h for why this deliberately does NOT apply the roster's same_client /
 * same_account guards: those answer "is this a renderable peer"; this answers "which
 * machines need an entity-index block", and index supply is not a rendering decision.
 */
std::size_t member_identities(const std::uint64_t ownSessionId,
                              std::span<membership::Identity> output) noexcept {
    if (ownSessionId == kAbsentSessionId || output.empty()) {
        return 0;
    }
    AcquireSRWLockShared(&runtime::storage::g_stateLock);
    const ActivityState& state = runtime::storage::g_activity;
    const std::size_t own = transactions::find_session(state, ownSessionId);
    std::size_t count = 0;
    if (own < kSessionCapacity) {
        const SessionRecord& ownRecord = state.sessions[own];
        // The joiner keeps row 0 - v1's only row - so an existing client's block base
        // never moves when a second machine appears.
        if (ownRecord.membership.hasIdentity) {
            output[count] = ownRecord.membership.identity;
            ++count;
        }
        for (const SessionRecord& record : state.sessions) {
            if (count >= output.size()) {
                break;
            }
            if (record.sessionId == ownSessionId || !record.occupied || !record.joined) {
                continue;
            }
            if (!same_peer_destination(record.destination, ownRecord.destination)) {
                continue;
            }
            if (!record.membership.hasIdentity) {
                continue;
            }
            // One row per MACHINE. Sibling BAP sessions of one client share a member
            // key (20.53); giving each its own index block would hand one machine
            // several and shrink everyone else's share of a 64-slot table.
            bool duplicate = false;
            for (std::size_t index = 0; index < count; ++index) {
                if (output[index].memberKey == record.membership.identity.memberKey) {
                    duplicate = true;
                    break;
                }
            }
            if (duplicate) {
                continue;
            }
            output[count] = record.membership.identity;
            ++count;
        }
    }
    ReleaseSRWLockShared(&runtime::storage::g_stateLock);
    return count;
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
            // A SIBLING SESSION OF THE SAME CLIENT is not a peer. One client holds several
            // BAP connections, so the session-id test above lets its own other session
            // through, and the client is then told it is its own fireteam member - it renders
            // a second copy of the local guardian, named "You". The member key is what
            // distinguishes machines: two sessions of one client share it, two machines do
            // not. Same fix as FINDINGS 20.37 made for matchmaking's foreign_advertisement.
            if (ownRecord.membership.hasIdentity
                && record.membership.identity.memberKey
                       == ownRecord.membership.identity.memberKey) {
                reason = ForeignPeerReason::same_client;
                continue;
            }
            // TWO CHARACTERS OF ONE ACCOUNT ARE NOT PEERS EITHER, even on two machines with
            // distinct Steam identities, distinct sign-on slots and distinct member keys -
            // all three were true the night this cost two hard client freezes. The client
            // refuses such a roster and NAMES the reason: it released our reservation citing
            // `tried-to-join-self` from its own peer-link failure enum, with both machines
            // publishing acct=0x9EAA300100100100 (FINDINGS 20.64).
            //
            // The member-key test above cannot catch it. Member keys are per-session and
            // differed; the ACCOUNT is what the client compares. Guarding here turns a freeze
            // on both machines into one log line, and is the reason it must stay even after
            // the account routing itself is fixed - a regression there would otherwise be
            // silent again.
            if (ownRecord.membership.hasIdentity
                && record.membership.identity.accountSoid != 0
                && record.membership.identity.accountSoid
                       == ownRecord.membership.identity.accountSoid) {
                reason = ForeignPeerReason::same_account;
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

/**
 * Resolves one member key to the committed session that joined with it.
 * The 20.74.4 peer-advertisement delivery needs the foreign host's own record: its
 * advertisement travels in THIS body's region block, and its join endpoint comes from
 * ITS binding, not ours.
 * @param memberKey Member key the target session bound at join.
 * @param output Cleared, then receives the immutable binding identity.
 * @return True when a committed+joined session carries this exact key.
 */
[[nodiscard]] bool session_binding_for_member(
    const std::uint64_t memberKey,
    state::activity::SessionBinding& output) noexcept {
    output = {};
    AcquireSRWLockShared(&runtime::storage::g_stateLock);
    const ActivityState& state = runtime::storage::g_activity;
    for (const SessionRecord& record : state.sessions) {
        if (record.occupied && record.joined && record.memberKey == memberKey) {
            ReleaseSRWLockShared(&runtime::storage::g_stateLock);
            return snapshot_binding(record.sessionId, output);
        }
    }
    ReleaseSRWLockShared(&runtime::storage::g_stateLock);
    return false;
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
