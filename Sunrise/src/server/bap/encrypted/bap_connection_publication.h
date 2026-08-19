#pragma once

#include <cstdint>

#include "../internal.h"
#include "internal.h"
#include "queuez/queuez_state_validation.h"
#include "transactions/definition.h"

namespace sunrise::server::bap::encrypted {

/** Connection fields one request may publish, captured before its transaction commits. */
struct ConnectionFields {
    middleware::bap::activity_message::patch_epoch::PatchEpoch patchEpoch{};
    /** The join carries the only member key the client ever sends. */
    std::uint64_t joinMemberKey{};
    /** The join also names the character the player signed in on. */
    std::uint64_t joinCharacterSoid{};
    bool retainsPatchEpoch{};
    /** Set by a join or a transition-token change, which are the client starting a load. */
    bool opensTransitionWindow{};
    /** Set by a join alone, which re-arms the roster warm-up the new container needs. */
    bool joinsActivity{};
};

/**
 * Captures the connection fields one service outcome carries.
 * @param outcome Prepared outcome, still holding its uncommitted mutations.
 * @return The fields to publish once the transaction commits.
 */
[[nodiscard]] ConnectionFields connection_fields(const ServiceOutcome& outcome) noexcept;

/**
 * Publishes the captured connection fields after a successful commit.
 * @param session Connection-owned activity binding and epoch.
 * @param publication Committed State bindings.
 * @param fields Fields captured before the commit.
 */
void publish_connection_fields(Session& session,
                               const transactions::Publication& publication,
                               const ConnectionFields& fields) noexcept;

/**
 * Arms the owed Family-4 and banner re-pushes when the queuez publication asks for them.
 * @param session Connection-owned re-push timers.
 * @param queuezPublication Staged queuez publication.
 */
void arm_repushes(Session& session, const queuez::StagedPublication& queuezPublication) noexcept;

/**
 * Arms the delayed ability-refresh pair (the appearance + the roster re-send) when the
 * publication asks for it — the fork's deferral of the ability-bucket rebuild's settle.
 * @param session Connection-owned re-push timers.
 * @param queuezPublication Staged queuez publication.
 */
void arm_ability_refresh(Session& session,
                         const queuez::StagedPublication& queuezPublication) noexcept;

/**
 * Arms the join's own family-4 refresh (the tower's slice-set waits on the requirement
 * evaluation the swap's traffic otherwise has to wake by accident).
 * @param session Connection-owned re-push timers.
 * @param fields Fields captured before the commit (the join flag).
 */
void arm_join_refresh(Session& session, const ConnectionFields& fields) noexcept;

} // namespace sunrise::server::bap::encrypted
