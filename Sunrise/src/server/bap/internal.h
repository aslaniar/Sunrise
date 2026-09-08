#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "../../client/network/consumer.h"
#include "../../middleware/bap/activity_message/activity_patch_epoch_parser.h"
#include "../../middleware/bap/frame.h"
#include "../../state/activity/bubble_authority/definition.h"
#include "../../state/build_data/scenarios/definition.h"
#include "../../core/settings/provisioning.h"
#include "../../state/runtime/state.h"
#include "encrypted/queuez/definition.h"

namespace sunrise::server::bap {

/** One session per transport peer slot, so a connection id indexes this array directly. */
inline constexpr std::size_t kSessionCount = client::network::kBapConnectionCount;

/** Fixed scratch storage owned by the lock, kept off the Client thread's stack. */
struct Scratch {
    std::array<std::byte, client::network::kBapFrameCapacity> plaintext{};
    std::array<std::byte, client::network::kBapFrameCapacity> responseBody{};
    std::array<std::byte, client::network::kBapFrameCapacity> responsePayload{};
    std::array<std::byte, client::network::kBapFrameCapacity> sealed{};
    std::array<std::byte, client::network::kBapFrameCapacity> framed{};
    /** Roster groups the outbound body's slot spans point into. */
    std::array<state::build_data::scenarios::RosterGroup,
               state::build_data::scenarios::kDestinationGroupCapacity>
        rosterGroups{};
};

/**
 * What one staged roster body owes State, and the counters to put back if it is discarded.
 * A bubble is offered once, and the state byte rebuilds every object the roster owns. Both may
 * move only once the frame reaches the caller.
 */
struct RosterPublication {
    state::activity::bubble_authority::Grant grant{};
    std::uint32_t priorGroups{};
    std::uint8_t priorSends{};
    std::uint8_t priorState{};
    /** Set when the staged body carried a bubble grant that State has not recorded yet. */
    bool hasGrant{};
    /** Set while a roster body is staged and its outcome is undecided. */
    bool staged{};
};

/** Which half of the client's activity link pair one BAP link is. */
enum class ActivityClientRole : std::uint8_t {
    none,
    /** The link the client allocated for itself; it carries the citizen advertisement. */
    privateCurrent,
    /** A link bound to a session THIS server advertised; it carries the membership body. */
    publicTarget,
};

/** Mutable transport state owned by one BAP connection. */
struct Session {
    std::uint32_t id{};
    bool authenticated{};
    /** The 8-byte prefix of the session token this connection echoed at server
     *  hello (p2-204 v3): the per-client key that is STABLE ACROSS RECONNECTS
     *  (measured: mac CF0A98397F164482 over conns 1/2/3, rig 945602D41E66AC20
     *  over conns 4/5/6, p2-204 v2). Set by the svc25 identity stamp; zero
     *  until then. The identity store keys on this value (capture + push),
     *  because account slots are shared across machines (p2-203) and every
     *  join spawns a fresh session while ads stick to the first (p2-204). */
    std::uint64_t identityEcho{};
    std::array<std::byte, state::kBapNonceSize> sendNonce{};
    std::array<std::byte, state::kBapNonceSize> receiveNonce{};
    /** Opaque State handle taken only after the server hello authenticates. */
    state::matchmaking::ContextHandle matchmakingContext{};
    /** Activity capability allocated and published through this authenticated session. */
    std::uint64_t activitySessionId{};
    /** Tick count after which the activity link owes its next keepalive write. */
    std::uint64_t activityKeepaliveDueTick{};
    /** Client member key from the join request. It seeds the membership id. */
    std::uint64_t activityMemberKey{};
    /**
     * Character the join request named, or zero when it carried none.
     * The roster's participation key must be the character the client signed in on. The client
     * binds its player by matching that value.
     */
    std::uint64_t activityCharacterSoid{};
    /** Tick count after which the activity link owes its next roster update. */
    std::uint64_t activityRosterDueTick{};
    /**
     * Tick count until which the client is loading, so the roster runs at its faster cadence.
     * A join and a transition-token change are the only two things that open it.
     */
    std::uint64_t activityTransitionUntilTick{};
    /** The client's own patch epoch, from message 52. The roster body splices it verbatim. */
    middleware::bap::activity_message::patch_epoch::PatchEpoch activityPatchEpoch{};
    /** Group set the last roster update published, folded into one comparable value. */
    std::uint32_t activityRosterGroups{};
    /** Roster updates sent on this connection, capped once the warm-up bumps are spent. */
    std::uint8_t activityRosterSends{};
    /** Per-entry state byte the last roster update carried. */
    std::uint8_t activityRosterState{};
    /** Set once message 52 has arrived, which is what makes a roster update sendable. */
    bool activityPatchEpochSeen{};
    /**
     * Set when this link's first binding came from joining a session it did not allocate.
     * Such a link carries the keepalive alone. A roster or membership push on it stalls the load.
     */
    bool activityJoinedForeignSession{};
    /**
     * Region the last delivered citizen advertisement named. -1 until one has gone out.
     * It moves only on a frame that reached the client and carried a descriptor. Anything else
     * leaves the region-change trigger armed for the next poll.
     */
    std::int32_t activityAdvertisedRegion{-1};
    /**
     * Reason code of the last logged roster outcome.
     * The push runs every second, so a refusal is logged only when the reason changes. One flag
     * for every reason hides the second failure behind the first.
     */
    std::uint8_t activityRosterReason{};
    /** What one staged roster body owes, and what to put back if it never reaches the caller. */
    RosterPublication activityRosterStaged{};
    /** Queuez versions and residents published only through this authenticated peer. */
    encrypted::queuez::SessionState queuez{};
    /** Tick count after which the owed Family-4 re-push may go out. */
    std::uint64_t family4RepushDueTick{};
    /** Root the owed re-push must use. */
    std::uint64_t family4RepushRoot{};
    /** True while one Family-4 re-push is still owed to this peer. */
    bool family4RepushArmed{};
    /** Tick count after which the owed banner re-push may go out. */
    std::uint64_t bannerRepushDueTick{};
    /** Root the owed banner re-push must use. */
    std::uint64_t bannerRepushRoot{};
    /** True while one banner re-push is still owed to this peer. */
    bool bannerRepushArmed{};
    /** Tick count after which the delayed ability-refresh pair may go out. */
    std::uint64_t abilityRefreshDueTick{};
    /** True while the appearance + roster refreshes owe their delayed re-send. */
    bool abilityRefreshArmed{};
    /** Provisioned slot this peer authenticated against (stamped at svc-25). */
    core::settings::AccountKey accountKey{core::settings::kLegacyAccount};
    /**
     * Which half of the client's activity pair this link is.
     * The client holds TWO activity links: the private one it allocated for itself, and - once
     * it joins a session this server advertised - a public one bound to that host session. Only
     * the public link may carry the membership body that makes the client bind a world
     * container, which is what turns its instance from PRIVATE into PUBLIC.
     */
    ActivityClientRole activityRole{ActivityClientRole::none};
    /**
     * Shared activity-host session this link's client joined as its PUBLIC target (L8b,
     * FINDINGS 20.132). Held beside `activitySessionId`, never instead of it: the private
     * activity client keeps the link's own session and its whole stream is unchanged.
     */
    std::uint64_t activityPublicRowSession{};
    /** Membership bodies already addressed to that session, capped by the settings value. */
    std::uint16_t activityPublicRowBodiesSent{};
    /** Group session the public link joined, or zero. Names the host row that advertised it. */
    std::uint64_t activityPublicGroupSession{};
    /** Cleared once the public link has published its single membership body. */
    bool activityPublicMembershipSent{};
    /**
     * FINDINGS 20.48: the client drops a repeated revision even when its content changed, so
     * whenever this link's published membership gains or loses the peer row, the revision
     * must advance first. This flag remembers what the last shipped body contained.
     */
    bool activityPeerWasPublished{};
    /**
     * Keepalives since the last membership reseed on this link (FINDINGS 20.287/20.288).
     * Counted only on the private activity link's own keepalive, inside the
     * membership_reseed_interval gate; when it reaches the interval the membership
     * snapshot is re-published under a fresh revision so the client's claim path
     * re-fires under the current container state. Zero-initialized like every
     * Session field, so the default setting (interval 0) never touches it.
     */
    std::uint32_t activityReseedCounter{};
    /** Latest shared-account generation this peer has received. */
    std::uint64_t accountGeneration{};
    /** Newest shared-account generation owed as a full cross-peer refresh. */
    std::uint64_t accountResyncGeneration{};
    /** Set by encrypted processing only after one account mutation commits and is copied out. */
    bool accountMutationPublished{};
    /** True while another peer's account mutation still needs a full local refresh. */
    bool accountResyncArmed{};
};

namespace plaintext {

/**
 * Handles plaintext bootstrap services, arms encryption after service 25, and routes the rest.
 * @param session Auth and nonce state owned by the connection.
 * @param scratch Transform buffers owned by the lock, kept off the Client thread stack.
 * @param outer Parsed outer frame carrying the service id and its body.
 * @param response Whole-frame storage owned by the caller.
 * @param written Gets the encoded response size in bytes.
 * @return True when the service owes no reply, or its response is encoded.
 */
[[nodiscard]] bool consume(Session& session,
                           Scratch& scratch,
                           const middleware::bap::OuterFrame& outer,
                           std::span<std::byte> response,
                           std::size_t& written) noexcept;

} // namespace plaintext

namespace encrypted {

/**
 * Authenticates and routes one encrypted post-bootstrap service frame.
 * @param session Auth and nonce state owned by the connection.
 * @param scratch Transform buffers owned by the lock, kept off the Client thread stack.
 * @param outer Validated encrypted outer frame.
 * @param response Whole-frame storage owned by the caller.
 * @param written Gets the encoded response size in bytes.
 * @return True when routing works, any response fits, State commits and the nonce is published.
 */
[[nodiscard]] bool consume(Session& session,
                           Scratch& scratch,
                           const middleware::bap::OuterFrame& outer,
                           std::span<std::byte> response,
                           std::size_t& written) noexcept;

/**
 * Sends the owed Family-4 re-push once its delay has passed.
 * @param session Auth, nonce and queuez state owned by the connection.
 * @param scratch Transform buffers owned by the lock, kept off the Client thread stack.
 * @param response Whole-frame storage owned by the caller.
 * @param written Gets the encoded notification size in bytes.
 * @param touchesScratch Set before any scratch buffer is used.
 * @return True when a whole Family-4 notification is published.
 */
[[nodiscard]] bool consume_deferred(Session& session,
                                    Scratch& scratch,
                                    std::span<std::byte> response,
                                    std::size_t& written,
                                    bool& touchesScratch) noexcept;

} // namespace encrypted

/** One session's ladder read for the admin surface. */
struct LadderRow {
    std::uint32_t id{};
    bool authenticated{};
    bool family4Active{};
    std::int32_t family4Version{};
    std::int32_t family0Version{};
    std::uint64_t family4RootSoid{};
    bool family4RepushArmed{};
};

/**
 * Copies the per-session queuez mirrors into caller storage behind the BAP lock — the
 * admin /ladder and /state reads.
 * @param rows Caller-owned storage sized for the session count.
 * @return The filled row count.
 */
[[nodiscard]] std::size_t ladder_snapshot(std::span<LadderRow> rows) noexcept;

/**
 * Arms the deferred Family-4 re-push on every authenticated session whose mirror is
 * active — the admin /repush verb (the manual release test for the tower-gating).
 * @return The armed session count.
 */
[[nodiscard]] std::size_t arm_deferred_repush() noexcept;

} // namespace sunrise::server::bap
