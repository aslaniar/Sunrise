#pragma once

#include "../../../core/settings/provisioning.h"

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
    /** Set when the join named a session this server advertised, not the link's own. */
    bool bindsPublicTarget{};
    /** Group session behind the advertised host row. */
    std::uint64_t publicGroupSession{};
    /** Activity session the public link binds to. */
    std::uint64_t publicTargetSession{};
    /** L8b (FINDINGS 20.132): join named an advertised host row, same-id case included. */
    bool namesPublicHostRow{};
    /** That row's session id, which the public membership body is addressed to. */
    std::uint64_t publicHostSession{};
};

/**
 * Captures the connection fields one service outcome carries.
 * @param outcome Prepared outcome, still holding its uncommitted mutations.
 * @return The fields to publish once the transaction commits.
 */
[[nodiscard]] ConnectionFields connection_fields(const ServiceOutcome& outcome) noexcept;

/**
 * Records this account's PRIVATE activity session, for links that have none of their own.
 *
 * L8c (FINDINGS 20.138): the client's PUBLIC activity link (`OUT GAHN`) must be served the
 * member table of the PRIVATE link OF THE SAME ACCOUNT, and no identity on the public link
 * names that session. The member key cannot do it - the two links read the SAME identity
 * blob at DIFFERENT WINDOWS (private `blob[0..7]`, public `blob[5..12]`, measured: they
 * share only 3 bytes), so keying on it resolves nothing. The BAP account slot does: it is
 * the same on both of a client's links and distinct per machine, and the public link's slot
 * is provably correct because frames sealed with `state::bap(accountKey).sessionKey` on it
 * were decrypted and acknowledged by the client (p2(88)).
 * @param accountKey Provisioned account slot the connection authenticated as.
 * @param sessionId The account's private activity session, or absent to clear it.
 */
void note_private_activity_session(core::settings::AccountKey accountKey,
                                   std::uint64_t sessionId) noexcept;

/**
 * @param accountKey Provisioned account slot.
 * @return That account's private activity session, or zero when none has been recorded.
 */
[[nodiscard]] std::uint64_t private_activity_session(
    core::settings::AccountKey accountKey) noexcept;

/**
 * Records the character SOID the account's private join named, parallel to the session
 * registry. The peer-participation seeding reads it to bind the peer's own identity the
 * same way the local player key is resolved.
 * @param accountKey Provisioned account slot the connection authenticated as.
 * @param characterSoid Character SOID the join carried, or zero to clear it.
 */
void note_private_activity_character(core::settings::AccountKey accountKey,
                                     std::uint64_t characterSoid) noexcept;

/**
 * @param accountKey Provisioned account slot.
 * @return The character SOID the account's last private join named, or zero when none.
 */
[[nodiscard]] std::uint64_t private_activity_character_soid(
    core::settings::AccountKey accountKey) noexcept;

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
