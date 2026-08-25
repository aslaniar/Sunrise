#include "service_outcome_commit.h"

#include "../../../../state/activity/runtime.h"
#include "../push/activity/activity_arrival.h"
#include "../../../gameplay/group/group_host_sessions.h"
#include "../../../gameplay/gameplay_advertisement.h"
#include "../../../../state/matchmaking/matchmaking_state.h"
#include "../internal.h"

namespace sunrise::server::bap::encrypted::transactions {

/**
 * Commits at most one delayed State transaction.
 * @param outcome Checked service result whose pending transaction is used up.
 * @param publication Gets connection fields to publish after the output copy.
 * @return True when there is no transaction, or the one transaction commits.
 */
bool commit(ServiceOutcome& outcome, Publication& publication) noexcept {
    publication = {};
    // No exclusivity guard: ServiceOutcome::Transaction is a variant, so "a service route may
    // never combine independently versioned State transactions" is now a property of the type.
    if (auto* allocation = transaction_if<state::activity::PendingAllocation>(outcome)) {
        const std::uint64_t sessionId = allocation->sessionId;
        if (sessionId == state::activity::kAbsentSessionId
            || !state::activity::commit(*allocation)) {
            return false;
        }
        publication.activitySessionId = sessionId;
        publication.hasActivitySessionBinding = true;
        // EAGER HOST ROW (FINDINGS 20.32). The client decides its activity host 43 ms after the
        // join reply and never re-evaluates, so the citizen descriptor has to be IN the join
        // burst. That burst is staged BEFORE this commit runs (encrypted_runtime.cpp:198 vs
        // :214) precisely so state becomes visible only once every frame fits - which means
        // claiming the host row lazily, on the first advertisement query, always lands one frame
        // late and then waits a full 5 s keepalive.
        //
        // The activity session is allocated in an EARLIER request than the join
        // (BodyCodec::activityHostManagerResponse vs ::activityMessageRequest), so claiming and
        // filling the row here gives it a whole request cycle to reach `ready`.
        //
        // Legal here, and this is the constraint upstream names: the allocation "must never run
        // inside a staged push. That push would fail its own revision guard." This is not inside
        // one - the staged frame above is already encoded bytes, and this branch's own
        // prepare/commit pair closed on the line above. Nothing after this point commits State.
        //
        // Fail-safe: if any step declines, the row simply stays lazy and behaviour is unchanged.
        state::activity::SessionBinding source{};
        if (state::activity::snapshot_binding(sessionId, source)) {
            // The query itself claims the row, and retains/releases its own generation.
            static_cast<void>(server::gameplay::advertisement_state(
                source, push::activity::effective_region(sessionId).index));
            server::gameplay::group::allocate_claimed_host_sessions();
        }
        return true;
    }
    if (auto* plan = transaction_if<activity_message::ActivityPlan>(outcome)) {
        if (plan->mutationDomain == activity_message::MutationDomain::entitySlots) {
            return state::activity::entity_slots::commit(plan->entitySlotMutation);
        }
        if (plan->mutationDomain == activity_message::MutationDomain::membership) {
            return state::activity::membership::commit(plan->membershipMutation);
        }
        // The retained patch epoch is connection state, so it commits nothing here.
        return plan->mutationDomain == activity_message::MutationDomain::patchEpoch;
    }
    if (auto* matchmaking = transaction_if<state::matchmaking::PendingMutation>(outcome)) {
        return state::matchmaking::commit(*matchmaking);
    }
    // The queuez transactions commit on the staging path, not here.
    return true;
}

} // namespace sunrise::server::bap::encrypted::transactions
