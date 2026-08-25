#include "service_outcome_commit.h"

#include "../../../../state/activity/runtime.h"
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
