#pragma once

#include <span>

#include <cstdint>

#include "../../core/settings/provisioning.h"
#include "definition.h"
#include "entity_slots/runtime.h"

namespace sunrise::state::activity {

/**
 * Prepares one allocation with State's fixed default destination, without changing State.
 * @param key Provisioned slot whose account band roots the published session soid.
 * @param sessionId Cleared, then receives the picked nonzero id.
 * @param allocation Cleared, then receives the captured allocation data.
 * @return True when the picked record and allocator revisions can be committed.
 */
[[nodiscard]] bool prepare_session(core::settings::AccountKey key,
                                   std::uint64_t& sessionId,
                                   PendingAllocation& allocation) noexcept;

/**
 * Prepares one allocation with an explicit checked scalar destination.
 * @param key Provisioned slot whose account band roots the published session soid.
 * @param selection Caller-owned destination, copied into the read-only allocation plan.
 * @param sessionId Cleared, then receives the picked nonzero id.
 * @param allocation Cleared, then receives the captured allocation data.
 * @return True when the destination and allocator snapshot can be committed together.
 */
[[nodiscard]] bool prepare_session(core::settings::AccountKey key,
                                   const destination::DestinationSelection& selection,
                                   std::uint64_t& sessionId,
                                   PendingAllocation& allocation) noexcept;

/**
 * Commits one prepared activity-session allocation when its revisions still match.
 * @param allocation Prepared plan. Always cleared before this function returns.
 * @return True when the allocation committed in one step.
 */
[[nodiscard]] bool commit(PendingAllocation& allocation) noexcept;

/**
 * Frees one committed activity-session record.
 * Nothing else clears one. A host that allocates per region must release them, or the table
 * fills and the oldest record is evicted.
 * @param sessionId Public activity session id from an earlier allocation.
 * @return True when a record held that id and is now free.
 */
bool release_session(std::uint64_t sessionId) noexcept;

/**
 * Tests whether a nonzero activity session id is still in the fixed-size table.
 * @param sessionId Public activity session id from an earlier allocation.
 * @return True when the id is in a committed record.
 */
[[nodiscard]] bool contains(std::uint64_t sessionId) noexcept;

/**
 * Copies one session's immutable binding identity.
 * @param sessionId Committed activity session.
 * @param output Cleared, then receives the immutable binding identity.
 * @return True when the session is still committed.
 */
[[nodiscard]] bool snapshot_binding(std::uint64_t sessionId, SessionBinding& output) noexcept;

/** @return True when the exact bound record generation is still committed. */
[[nodiscard]] bool binding_matches(const SessionBinding& binding) noexcept;

/**
 * Reason codes for a missed foreign member, logged so a boot record names the broken link
 * instead of leaving silence between "no push ran" and "the query refused".
 */
enum class ForeignPeerReason : std::uint8_t {
    found,
    /** No other occupied+joined session exists right now. */
    none_joined,
    /** Another joined session exists but has not published its identity yet. */
    identity_missing,
    /** A joined+published session exists, but outside this caller's destination. */
    destination_mismatch,
    /**
     * Every candidate belonged to the SAME CLIENT as the caller.
     *
     * One client holds several BAP connections and therefore several sessions, so excluding
     * the caller's own session id is not enough - a sibling session passes that test and the
     * client is handed ITSELF as its fireteam member. Observed live: with only one machine
     * booted, a second guardian rendered in the Tower carrying the caller's own member key.
     * This is the same mistake FINDINGS 20.37 fixed in matchmaking and it was never fixed
     * here.
     */
    same_client,
    /**
     * Every candidate belonged to the SAME ACCOUNT as the caller.
     *
     * One level up from `same_client`, and the level neither earlier fix reached. Two
     * MACHINES with distinct Steam identities, distinct sign-on slots and distinct member
     * keys can still be playing two characters of ONE account - and then they are not peers
     * either. The client says so itself: FINDINGS 20.64 caught it releasing our reservation
     * with reason 1, `tried-to-join-self`, out of its own peer-link failure enum, and both
     * machines had published `acct=0x9EAA300100100100`.
     *
     * Publishing such a row costs a hard client freeze on BOTH machines. Refusing it costs
     * this log line. 20.37 fixed this shape on session id, p2(45) on member key; the account
     * is where it actually lives.
     */
    same_account,
};

/**
 * Copies another joined session's published client identity, for cross-client membership.
 * The candidate record must be occupied, joined, hold a published identity, and sit in the
 * SAME destination as the caller's session - two players in different destinations are not
 * peers. Ties resolve to the lowest table slot, which is stable while both stay joined.
 * @param ownSessionId The caller's committed activity session.
 * @param output Cleared, then receives the other session's published identity.
 * @param reason Receives why no peer was found when false is returned.
 * @return True when exactly such a peer was found.
 */
[[nodiscard]] bool foreign_member_identity(std::uint64_t ownSessionId,
                                           membership::Identity& output,
                                           ForeignPeerReason& reason) noexcept;

/**
 * Resolves one member key to the committed session that joined with it.
 * Used by the peer-advertisement delivery (20.74.4): the foreign host's join endpoint
 * comes from ITS binding, so a push carrying its row must also carry its endpoint.
 * @param memberKey Member key the target session bound at join.
 * @param output Cleared, then receives the immutable binding identity.
 * @return True when a committed+joined session carries this exact key.
 */
/**
 * Collects EVERY joined machine in the caller's destination, caller first.
 *
 * Written for the type-20 entity-index allocation's cross-member map (20.336 R6).
 * The allocation's v1 named only the joining member - `{&member, 1}` - so a peer's
 * index block has never been published, while the encoder has always accepted up to
 * kParticipantSlots (64) rows.
 *
 * DELIBERATELY NOT the same filter as foreign_member_identity. That function answers
 * "who is a renderable PEER" and so applies the same_client and same_account guards
 * that exist against a client freeze on a roster naming one account twice (20.64).
 * This answers "which machines need index blocks", which is a different question: the
 * ROSTER's guards do not belong on the SUPPLY message. Sibling BAP sessions of one
 * client are still collapsed, because they share a member key and one machine needs
 * one block - that dedupe is by memberKey, which is exactly what distinguishes
 * machines (20.53's fix).
 *
 * @param ownSessionId The caller's committed activity session.
 * @param output Receives one identity per distinct member key, caller's own first.
 * @return How many rows were written; 0 when the session is unknown.
 */
[[nodiscard]] std::size_t member_identities(
    std::uint64_t ownSessionId,
    std::span<membership::Identity> output) noexcept;

[[nodiscard]] bool session_binding_for_member(std::uint64_t memberKey,
                                              SessionBinding& output) noexcept;

/**
 * Retains an exact record generation against release and allocator eviction.
 * @param binding Immutable identity a consumer intends to hold.
 * @return True when the binding still matches and its retain count can advance.
 */
[[nodiscard]] bool retain_binding(const SessionBinding& binding) noexcept;

/** Releases one retain taken by retain_binding. @param binding The retained identity. */
void release_binding(const SessionBinding& binding) noexcept;

/**
 * Tests whether a committed activity session id has finished a join.
 * @param sessionId Public activity session id from an earlier allocation.
 * @return True when the current record has a committed join revision.
 */
[[nodiscard]] bool is_joined(std::uint64_t sessionId) noexcept;

/** How far the client has got through the current destination load. */
enum class WorldPhase : std::uint8_t {
    /** No destination load is running. Orbit sits here, and the spawn is never held. */
    idle,
    /** The step that arms the black fade has started and the in-world step has not been reached. */
    transitioning,
    /** The in-world step is entered, so the fade is armed and a spawn now releases it. */
    arrived,
};

/**
 * Records how far the current destination load has got.
 * Entering transitioning from any other phase resets the load's start tick.
 * @param phase Phase the client's own boot-flow step maps to.
 */
void note_world_phase(WorldPhase phase) noexcept;

/** @return How far the client has got through the current destination load. */
[[nodiscard]] WorldPhase world_phase() noexcept;

/** @return Milliseconds since the running load started, or zero when none is running. */
[[nodiscard]] std::uint64_t world_transition_age() noexcept;

} // namespace sunrise::state::activity
