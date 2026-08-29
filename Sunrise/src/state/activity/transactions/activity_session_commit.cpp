#include "../../runtime/storage/internal.h"
#include "../../../core/logging/log.h"
#include "../../../core/settings/settings.h"
#include "../destination/activity_destination_validation.h"
#include "../membership/definition.h"
#include "../runtime.h"
#include "internal.h"

namespace sunrise::state::activity {
namespace {

/** Account half of every soid this account owns, which the activity session shares. */
constexpr std::uint64_t kAccountSoidMask = 0xFFFFFFFF00000000ULL;

} // namespace


/** Commits one prepared activity-session allocation when its revisions still match. */
bool commit(PendingAllocation& allocation) noexcept {
    // Take the plan first so no transaction can replay, pass or fail.
    const PendingAllocation prepared = allocation;
    allocation = {};
    if (!prepared.prepared || prepared.sessionId == kAbsentSessionId
        || prepared.expectedStateRevision == kInvalidRevision
        || prepared.expectedAllocatorRevision == kInvalidRevision
        || prepared.sessionId
               != transactions::compose_session_soid(prepared.soidBase,
                                                     prepared.expectedNextSessionId)
        || prepared.targetSlot >= kSessionCapacity || !destination::valid(prepared.destination)) {
        return false;
    }

    AcquireSRWLockExclusive(&runtime::storage::g_stateLock);
    ActivityState& state = runtime::storage::g_activity;
    if (!transactions::allocation_available(state)
        || state.stateRevision != prepared.expectedStateRevision
        || state.allocatorRevision != prepared.expectedAllocatorRevision
        || state.nextSessionId != prepared.expectedNextSessionId) {
        ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
        return false;
    }

    // Pick again under the write lock so stale plan data cannot redirect State.
    const std::size_t target = transactions::select_target(state);
    if (target != prepared.targetSlot) {
        ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
        return false;
    }

    std::uint64_t seedFromSession = 0;
    std::int32_t seedRegion = -1;    SessionRecord& record = state.sessions[target];
    // A full reset clears the evicted record and restores each field's own unset value.
    record = {};
    ++state.stateRevision;
    record.destination = prepared.destination;
    record.sessionId = prepared.sessionId;
    record.createdRevision = state.stateRevision;
    record.recordRevision = state.stateRevision;
    record.occupied = true;
    // FINDINGS 20.147: a re-targeting client loses its reported region here - the report
    // lived on the record this commit replaces, and the fresh one falls back to the arrival
    // slice set. The client reports its desired region once and never repeats it after a
    // re-target, so the churned session could never reach the public region again: no
    // citizen join, no second BAP link, and the Tower load hangs. The player did not move;
    // only the session id did. Seed the fresh record with the account's last client-
    // reported region, matched by the account half of the session soid (session_soid_base).
    if (core::settings::get().server.gameplay.activityRegionSurvivesChurn) {
        const SessionRecord* best = nullptr;
        for (const SessionRecord& prior : state.sessions) {
            if (!prior.occupied || prior.sessionId == record.sessionId) {
                continue;
            }
            if ((prior.sessionId & kAccountSoidMask) != prepared.soidBase) {
                continue;
            }
            if (prior.membership.region.index <= membership::kAbsentRegionIndex) {
                continue;
            }
            if (best == nullptr || prior.recordRevision > best->recordRevision) {
                best = &prior;
            }
        }
        if (best != nullptr) {
            record.membership.region = best->membership.region;
            seedFromSession = best->sessionId;
            seedRegion = best->membership.region.index;
        }
    }
    transactions::advance_allocator(state);
    const std::uint64_t committedSessionId = record.sessionId;
    ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
    // Liveness instrument (L13): logged AFTER the lock release. Zero lines with the switch
    // on means no account ever churned a session this boot - a different finding from a
    // seed that fired and did not help.
    if (core::settings::get().server.gameplay.activityRegionSurvivesChurn) {
        std::array<char, 160> line{};
        const int written =
            seedFromSession != 0
                ? std::snprintf(line.data(),
                                line.size(),
                                "ev=activity stage=session_seed result=seeded "
                                "session=0x%llX from=0x%llX region=%d",
                                static_cast<unsigned long long>(committedSessionId),
                                static_cast<unsigned long long>(seedFromSession),
                                seedRegion)
                : std::snprintf(line.data(),
                                line.size(),
                                "ev=activity stage=session_seed result=none "
                                "session=0x%llX",
                                static_cast<unsigned long long>(committedSessionId));
        if (written > 0) {
            core::log::write(core::log::Channel::state,
                             core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(written)});
        }
    }
    return true;
}

} // namespace sunrise::state::activity
