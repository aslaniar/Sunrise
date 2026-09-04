#include "activity_keepalive_push.h"

#include <Windows.h>

#include <array>
#include <cstdio>
#include <limits>

#include "../../../../../core/logging/log.h"
#include "../../../../../core/settings/settings.h"
#include "../../../../../state/activity/definition.h"
#include "../../../../../state/activity/membership/activity_membership_query.h"
#include "../../../../../state/runtime/runtime.h"
#include "../../../../gameplay/gameplay_advertisement.h"
#include "../../../../../state/activity/runtime.h"
#include "../../activity_message/definition.h"
#include "../../bap_connection_publication.h"
#include "activity_arrival.h"
#include "activity_global_state_push.h"
#include "activity_membership_push.h"
#include "activity_roster_push.h"
#include "internal.h"

namespace sunrise::server::bap::encrypted::push::activity {
namespace {

/**
 * Keepalive cadence. The client tears the session down after 20.5 seconds of server silence, so
 * 5 seconds leaves 3 writes of margin.
 */
constexpr std::uint64_t kKeepaliveIntervalMs = 5'000;
/**
 * Roster burst cadence, used only while the client is loading. Outside that window the roster
 * rides the keepalive.
 */
constexpr std::uint64_t kRosterBurstIntervalMs = 1'000;
/** -1 asks for the membership snapshot without naming a bubble. */
constexpr std::int32_t kNoBubble = -1;
/** A refresh re-send carries the current revision instead of asking for an older one. */
constexpr std::uint32_t kCurrentRevision = 0;

/**
 * Copies one staged frame to the caller and publishes its nonce.
 * @param session Connection-owned send nonce.
 * @param scratch Lock-owned staging storage.
 * @param response Caller-owned complete-frame storage.
 * @param written Receives the published byte count.
 * @param framedSize Staged byte count.
 * @param nextSendNonce Nonce to publish once the copy finishes.
 * @param published True when at least one notification was staged.
 * @return True when the caller received a complete frame.
 */
[[nodiscard]] bool publish_frame(Session& session,
                                 Scratch& scratch,
                                 std::span<std::byte> response,
                                 std::size_t& written,
                                 std::size_t framedSize,
                                 const std::array<std::byte, state::kBapNonceSize>& nextSendNonce,
                                 bool published) noexcept {
    if (!published || framedSize == 0 || framedSize > response.size()) {
        // Nothing left, so a roster staged into the discarded body is offered again next push.
        discard_staged_roster(session);
        return false;
    }
    for (std::size_t index = 0; index < framedSize; ++index) {
        response[index] = scratch.framed[index];
    }
    written = framedSize;
    session.sendNonce = nextSendNonce;
    // Settled only here: the grant and the state byte may move only on a delivered frame.
    commit_staged_roster(session);
    return true;
}

} // namespace

/** Writes the periodic activity-link keepalive when one is due. */
bool consume_activity_keepalive(Session& session,
                                Scratch& scratch,
                                std::span<std::byte> response,
                                std::size_t& written,
                                bool& touchesScratch) noexcept {
    written = 0;
    const std::uint64_t now = GetTickCount64();
    // The burst runs only while the client is loading. A join or a transition-token change opens
    // that window. Outside it the roster goes out on the keepalive alone.
    const bool burstDue = !session.activityJoinedForeignSession
                          && now < session.activityTransitionUntilTick
                          && now >= session.activityRosterDueTick;
    const bool keepaliveDue = now >= session.activityKeepaliveDueTick;
    // A region change cannot wait for the keepalive. The client claims the next region almost at
    // once. Only the reported field is read here, because this runs on every pump.
    const std::int32_t reportedRegion =
        session.activitySessionId == 0
            ? -1
            : state::activity::membership::reported_region(session.activitySessionId);
    const bool regionChanged = !session.activityJoinedForeignSession && reportedRegion >= 0
                               && reportedRegion != session.activityAdvertisedRegion;

    // ---- L8b (FINDINGS 20.132/20.133): serve the SHARED activity host. ----
    // MEASURED, p2(88) run 2: the client runs TWO BAP connections, one per activity client, and
    // `session_for(connectionId)` gives each its own Session. The PUBLIC half's join binds the
    // host row on ITS connection; that connection carries no activity session of its own, so it
    // bails on the `activitySessionId == 0` test below and never reaches the body it is owed.
    // 14 `public_row_gate` lines, every one of them the PRIVATE connection
    // (`rowsession=0x0 activesession=0x...00200001`), against 2 binds naming 0x...00200003.
    // That is why the shared host has never been addressed and its activity client sits at MEM-0.
    //
    // Served HERE, ahead of that bail, and sourced from the PRIVATE session's table via
    // `live_region_session` - the same helper, for the same reason, as the legacy `publicTarget`
    // branch below: the public connection cannot read a table it does not own, and only the
    // private snapshot carries a member the client matches as its local player.
    const std::uint16_t publicRowBudget =
        core::settings::get().server.gameplay.activityPublicRowMembershipBodies;
    // PER-ACCOUNT, not global (FINDINGS 20.134). `live_region_session` was the wrong query in
    // two separate ways, both measured: it is process-wide, so on a two-machine run it hands
    // one client's member table to the OTHER client's public link - and upstream is explicit
    // that a body carrying anything but the client's own private snapshot makes it prune the
    // member and destroy the player; and once the public client reports a region it returns
    // the PUBLIC session itself, which silenced this link the moment it started working. The
    // member key is the client's machine id, identical on both of ITS links and different on
    // every other machine's, so keying on it with the public session excluded names exactly
    // one session: this account's private one.
    // KEYED ON THE ACCOUNT SLOT, not the member key. p2(89) measured why the member key
    // cannot work: the private link reported member=0x32E4DCEEB92DF1FE and the public link
    // member=0x2DF1FE0138FBFC51 for the SAME machine - the same identity blob read at two
    // different windows (`blob[0..7]` vs `blob[5..12]`, sharing only 3 bytes), exactly the
    // window map recorded in BOOT_BRIEF_p2-87. Upstream's "the member key is the same on
    // both links" does not hold for this build's pair. The account slot does hold, and the
    // public link's slot is provably right: p2(88) sealed three bodies to it with that
    // slot's key and the client decrypted and acknowledged them.
    const std::uint64_t privateSessionId =
        private_activity_session(session.accountKey) != session.activityPublicRowSession
            ? private_activity_session(session.accountKey)
            : state::activity::kAbsentSessionId;
    // `activitySessionId == 0` is REQUIRED, not incidental: it is what makes this block
    // strictly additive. This path returns early on delivery, so arming it on a connection
    // that owns an activity session would preempt that connection's own keepalive - the FAH
    // link, the one that has always worked. Measured in p2(88): the row-bearing connection
    // always read `activesession=0x0` and the FAH ones always read `rowsession=0x0`, so the
    // two never overlap in practice; this makes it impossible rather than merely observed.
    const bool publicRowArmed = publicRowBudget != 0 && session.activityPublicRowSession != 0
                                && session.activitySessionId == state::activity::kAbsentSessionId
                                && privateSessionId != state::activity::kAbsentSessionId
                                && session.activityPublicRowSession != privateSessionId
                                && session.activityPublicRowBodiesSent < publicRowBudget;
    if (publicRowBudget != 0) {
        // U13: printed on EVERY pump of EVERY connection, before any bail, because the whole
        // defect above was invisible while this line sat behind a guard on one connection.
        std::array<char, 224> gateLine{};
        const int gateWritten = std::snprintf(
            gateLine.data(),
            gateLine.size(),
            "ev=activity stage=public_row_gate rowsession=0x%llX activesession=0x%llX "
            "private=0x%llX member=0x%llX slot=%u sent=%u budget=%u due=%u armed=%u",
            static_cast<unsigned long long>(session.activityPublicRowSession),
            static_cast<unsigned long long>(session.activitySessionId),
            static_cast<unsigned long long>(privateSessionId),
            static_cast<unsigned long long>(session.activityMemberKey),
            static_cast<unsigned>(session.accountKey),
            static_cast<unsigned>(session.activityPublicRowBodiesSent),
            static_cast<unsigned>(publicRowBudget),
            keepaliveDue ? 1U : 0U,
            publicRowArmed ? 1U : 0U);
        if (gateWritten > 0) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::info,
                             {gateLine.data(), static_cast<std::size_t>(gateWritten)});
        }
    }
    if (publicRowArmed && keepaliveDue) {
        touchesScratch = true;
        session.activityKeepaliveDueTick = now + kKeepaliveIntervalMs;
        auto publicNonce = session.sendNonce;
        std::size_t publicFramed = 0;
        state::activity::membership::PendingMutation publicRow{};
        const bool identityPublished =
            privateSessionId != state::activity::kAbsentSessionId
            && state::activity::membership::join_identity(privateSessionId) != 0;
        const bool hasPublicRow =
            identityPublished
            && state::activity::membership::prepare_refresh(
                privateSessionId, kCurrentRevision, kNoBubble, publicRow)
            && publicRow.hasSnapshot;
        bool appendedPublicRow = false;
        if (hasPublicRow) {
            activity_message::ActivityPlan plan{};
            plan.sessionId = session.activityPublicRowSession;
            plan.membershipMutation = publicRow;
            appendedPublicRow = append_membership_notification(scratch,
                                                              plan,
                                                              state::bap(session.accountKey).sessionKey,
                                                              publicNonce,
                                                              scratch.framed,
                                                              publicFramed);
            SecureZeroMemory(&plan, sizeof plan);
        }
        const bool publicDelivered = publish_frame(session,
                                                   scratch,
                                                   response,
                                                   written,
                                                   publicFramed,
                                                   publicNonce,
                                                   appendedPublicRow);
        if (publicDelivered
            && session.activityPublicRowBodiesSent
                   != (std::numeric_limits<std::uint16_t>::max)()) {
            ++session.activityPublicRowBodiesSent;
        }
        std::array<char, 224> rowLine{};
        const int rowWritten = std::snprintf(
            rowLine.data(),
            rowLine.size(),
            "ev=activity stage=public_row_membership result=%s host=0x%llX private=0x%llX "
            "bytes=%zu sent=%u revision=%u",
            publicDelivered ? "delivered"
                            : (appendedPublicRow ? "undelivered"
                                                 : (hasPublicRow ? "encode_fail" : "no_snapshot")),
            static_cast<unsigned long long>(session.activityPublicRowSession),
            static_cast<unsigned long long>(privateSessionId),
            publicFramed,
            static_cast<unsigned>(session.activityPublicRowBodiesSent),
            publicRow.snapshot.revision);
        if (rowWritten > 0) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::info,
                             {rowLine.data(), static_cast<std::size_t>(rowWritten)});
        }
        SecureZeroMemory(&publicRow, sizeof publicRow);
        if (publicDelivered) {
            return true;
        }
    }

    if (session.activitySessionId == 0 || (!burstDue && !keepaliveDue && !regionChanged)) {
        return false;
    }
    touchesScratch = true;

    // FINDINGS 20.48: the client drops a repeated revision even when its content changed.
    // A peer gain or loss is exactly such a change, so the revision advances once per flip
    // and the next body below carries the new revision instead of being ignored as a repeat.
    if (!session.activityJoinedForeignSession) {
        state::activity::membership::Identity peerProbe{};
        state::activity::ForeignPeerReason peerReason{};

        const bool havePeerNow =
            state::activity::foreign_member_identity(session.activitySessionId, peerProbe,
                                                     peerReason);
        if (havePeerNow != session.activityPeerWasPublished
            && state::activity::membership::republish(session.activitySessionId)) {
            session.activityPeerWasPublished = havePeerNow;
            core::log::write(core::log::Channel::server,
                             core::log::Level::info,
                             havePeerNow ? "ev=activity stage=membership_peer result=gained"
                                         : "ev=activity stage=membership_peer result=lost");
        }
    }

    auto nextSendNonce = session.sendNonce;
    std::size_t framedSize = 0;
    // P2-C1 fix (was state::bap() - the legacy default): the activity-link pushes must
    // seal under THIS peer's channel keys. A provisioned peer's link arms with its own
    // slot's keys, so the legacy default sealed a frame the client could not verify.
    const auto& key = state::bap(session.accountKey).sessionKey;
    bool published = false;
    // Held until the frame reaches the caller. Encoding alone does not spend the region trigger.
    std::int32_t stagedAdvertisedRegion = -1;
    // The burst is what step 36 waits on. When both timers fire together the roster goes out last,
    // because the type-13 key binds to the player message 12 creates.
    if (!keepaliveDue && !regionChanged) {
        session.activityRosterDueTick = now + kRosterBurstIntervalMs;
        published = append_roster_notification(
            session, scratch, key, nextSendNonce, scratch.framed, framedSize, true);
        return publish_frame(
            session, scratch, response, written, framedSize, nextSendNonce, published);
    }
    session.activityKeepaliveDueTick = now + kKeepaliveIntervalMs;
    published = append_global_state_notification(
        scratch, session.activitySessionId, key, nextSendNonce, scratch.framed, framedSize);
    if (session.activityJoinedForeignSession) {
        // This link exists only so the client's second activity instance sees traffic. A roster or
        // membership push on it leaves the transition running with no world entered.
        return publish_frame(
            session, scratch, response, written, framedSize, nextSendNonce, published);
    }
    if (session.activityRole == ActivityClientRole::publicTarget) {
        // This link owes exactly one membership body: the client's msg-12 handler is the only
        // writer of the flag that binds a world container to this ActivityClient, and until that
        // bind lands its join grant has no view - which is why the instance stayed PRIVATE
        // (FINDINGS 20.28).
        //
        // The body is the PRIVATE link's member table, sent verbatim on this envelope. Quoted
        // from upstream because getting it wrong destroys the player object:
        // "The client matches itself by the key at `client+27696`, which is its machine id and is
        // the same on both links, so only the private snapshot carries a member the client
        // recognises as the local player. A body carrying anything else makes the client prune the
        // member and destroy the player it holds."
        //
        // Read, never committed: prepare_refresh captures without changing State, and this link
        // must not move the private session's membership revision.
        state::activity::membership::PendingMutation staged{};
        bool appended = false;
        if (core::settings::get().server.activation.activityPublicMembership
            && !session.activityPublicMembershipSent) {
            const std::uint64_t privateSessionId = state::activity::membership::live_region_session(
                state::activity::kAbsentSessionId);
            // Zero until the private link's client publishes its identity; before that the table
            // holds only the seed placeholder, which the client does not match either.
            const bool identityPublished =
                privateSessionId != state::activity::kAbsentSessionId
                && state::activity::membership::join_identity(privateSessionId) != 0;
            const bool hasSnapshot =
                identityPublished
                && state::activity::membership::prepare_refresh(
                    privateSessionId, kCurrentRevision, kNoBubble, staged)
                && staged.hasSnapshot;
            if (hasSnapshot) {
                activity_message::ActivityPlan plan{};
                plan.sessionId = session.activitySessionId;
                plan.membershipMutation = staged;
                appended = append_membership_notification(
                    scratch, plan, key, nextSendNonce, scratch.framed, framedSize);
                published = appended || published;
            }
            SecureZeroMemory(&staged, sizeof staged);
        }
        // The public target owns its own epoch and roster; it must not advertise another target.
        published = append_roster_notification(
                        session, scratch, key, nextSendNonce, scratch.framed, framedSize, false)
                    || published;
        std::array<char, 128> line{};
        const int count = std::snprintf(line.data(),
                                        line.size(),
                                        "ev=activity stage=public_membership result=%s "
                                        "appended=%u sent=%u",
                                        published ? "ok" : "fail",
                                        appended ? 1U : 0U,
                                        session.activityPublicMembershipSent ? 1U : 0U);
        if (count > 0) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::debug,
                             {line.data(), static_cast<std::size_t>(count)});
        }
        const bool delivered = publish_frame(
            session, scratch, response, written, framedSize, nextSendNonce, published);
        if (delivered && appended) {
            // Latched on delivery, not at encode: an encoded body the client never saw is not a
            // send, and this link never acknowledges one.
            session.activityPublicMembershipSent = true;
        }
        return delivered;
    }

    // This link's own committed activity record is the advertisement's SOURCE - the target the
    // descriptor names must copy its destination. An uncommitted session leaves it cleared, and
    // the readiness queries below then answer `absent`, which is the correct fail-closed answer
    // (FINDINGS 20.31: binding to the source-LESS overload by accident silenced the descriptor).
    state::activity::SessionBinding advertisementSource{};
    static_cast<void>(
        state::activity::snapshot_binding(session.activitySessionId, advertisementSource));

    // The client applies one membership update per revision and drops repeats, so an already
    // acknowledged region change needs a new revision to land. Move it only when there is a real
    // advertisement, or an empty channel advances the revision on every poll.
    if (regionChanged
        && server::gameplay::advertisement_state(advertisementSource, reportedRegion)
               == server::gameplay::AdvertisementState::ready
        && state::activity::membership::acknowledged(session.activitySessionId)
        && state::activity::membership::republish(session.activitySessionId)) {
        core::log::write(core::log::Channel::server,
                         core::log::Level::info,
                         "ev=gameplay stage=membership result=republished reason=region");
    }
    // membership_reseed_interval (FINDINGS 20.287/20.288): force a FRESH membership revision
    // every Nth keepalive on this stable channel, so the client's claim path re-fires under
    // the session's CURRENT container state. The peer's reservation record OR-accumulates
    // the container bit at claim time; the membership landing is the one observed trigger
    // that re-enters that path (20.280). republish() is the same primitive the region path
    // uses to defeat the client's repeat-drop; acknowledged() is the same stability guard
    // the region path uses, so an empty channel cannot advance revisions on every poll.
    // Off-path (interval 0): this block never runs and every byte is unchanged.
    {
        const std::uint32_t reseedInterval =
            core::settings::get().server.membershipReseedInterval;
        if (reseedInterval != 0) {
            if (session.activityReseedCounter
                >= (std::numeric_limits<std::uint32_t>::max)() - 1U) {
                session.activityReseedCounter = 0;
            }
            ++session.activityReseedCounter;
            if (session.activityReseedCounter >= reseedInterval
                && state::activity::membership::acknowledged(session.activitySessionId)
                && state::activity::membership::republish(session.activitySessionId)) {
                session.activityReseedCounter = 0;
                std::array<char, 128> reseedLine{};
                const int reseedWritten = std::snprintf(
                    reseedLine.data(),
                    reseedLine.size(),
                    "ev=gameplay stage=membership_reseed result=republished "
                    "interval=%u session=%llu",
                    static_cast<unsigned>(reseedInterval),
                    static_cast<unsigned long long>(session.activitySessionId));
                if (reseedWritten > 0) {
                    core::log::write(core::log::Channel::server,
                                     core::log::Level::info,
                                     {reseedLine.data(),
                                      static_cast<std::size_t>(reseedWritten)});
                }
            }
        }
    }
    // Membership only becomes publishable after the client sends its identity, so it joins the
    // keepalive instead of the join reply.
    state::activity::membership::PendingMutation refresh{};
    bool hasMembership = state::activity::membership::prepare_refresh(
                             session.activitySessionId, kCurrentRevision, kNoBubble, refresh)
                         && refresh.hasSnapshot;
    if (!hasMembership
        && seed_identity(session.activitySessionId,
                         session.activityMemberKey,
                         session.activityCharacterSoid,
                         session.accountKey)) {
        SecureZeroMemory(&refresh, sizeof refresh);
        hasMembership = state::activity::membership::prepare_refresh(
                            session.activitySessionId, kCurrentRevision, kNoBubble, refresh)
                        && refresh.hasSnapshot;
    }
    // A client value wins; this only fills the token when nothing has published one.
    if (hasMembership && refresh.snapshot.transitionToken == 0
        && seed_transition_token(session.activitySessionId)) {
        SecureZeroMemory(&refresh, sizeof refresh);
        hasMembership = state::activity::membership::prepare_refresh(
                            session.activitySessionId, kCurrentRevision, kNoBubble, refresh)
                        && refresh.hasSnapshot;
    }
    // The citizen advertisement rides on this message. Without one more send per region the client
    // finds no ambassador in the next region, takes the role itself and matchmakes forever.
    // Re-sending a stable snapshot instead would make it rebuild every player snapshot.
    const bool publishesMembership =
        hasMembership
        && (regionChanged || !state::activity::membership::acknowledged(session.activitySessionId));
    // Resolved the way the body resolves it, not from the reported field. Before the first report
    // the arrival slice set stands in, and that first push carries a descriptor too.
    const server::gameplay::AdvertisementState advertisement =
        publishesMembership ? server::gameplay::advertisement_state(
                                  advertisementSource,
                                  effective_region(session.activitySessionId).index)
                            : server::gameplay::AdvertisementState::absent;
    if (publishesMembership && advertisement == server::gameplay::AdvertisementState::pending) {
        // The client applies one membership update per revision, so a push made while the
        // advertisement is still being allocated spends that revision on a region record with no
        // join descriptor. The allocation lands in the next service slice, so holding costs a poll.
        core::log::write(core::log::Channel::server,
                         core::log::Level::debug,
                         "ev=gameplay stage=membership result=held reason=no_host_session");
    } else if (publishesMembership) {
        activity_message::ActivityPlan plan{};
        plan.sessionId = session.activitySessionId;
        plan.membershipMutation = refresh;
        const bool sent = append_membership_notification(
            scratch, plan, key, nextSendNonce, scratch.framed, framedSize);
        // Only `pending` leaves the trigger armed, because only `pending` is transient. `absent`
        // means this channel advertises nothing, so re-arming there republishes on every poll.
        if (sent && reportedRegion >= 0) {
            stagedAdvertisedRegion = reportedRegion;
        }
        published = sent || published;
        SecureZeroMemory(&plan, sizeof plan);
    }
    // The mirrored host state is captured before the secure clear, because the report below shows
    // whether the client asked for a state this host must not publish.
    const int reportedSpawnState = static_cast<int>(refresh.snapshot.spawn.state);
    const int reportedTeleportState = static_cast<int>(refresh.snapshot.teleport.state);
    const std::int32_t reportedTeleportSlice = refresh.snapshot.teleport.sliceSetIndex;
    const std::uint8_t reportedToken = refresh.snapshot.transitionToken;
    // The client applies one membership update per revision, so the revision is what says whether a
    // push could have been read at all. Without it a correct body and a deduped one look the same.
    const std::uint32_t reportedRevision = refresh.snapshot.revision;
    SecureZeroMemory(&refresh, sizeof refresh);
    // The keepalive always carries the roster, in or out of a transition.
    session.activityRosterDueTick = now + kRosterBurstIntervalMs;
    published = append_roster_notification(
                    session, scratch, key, nextSendNonce, scratch.framed, framedSize, false)
                || published;

    std::array<char, core::log::kLineCapacity> line{};
    const int count =
        std::snprintf(line.data(),
                      line.size(),
                      "ev=activity stage=keepalive result=%s bytes=%zu membership=%u key=0x%llX "
                      "slot=%u "
                      "spawn_state=%d teleport_state=%d teleport_slice=%d token=%u revision=%u "
                      "advert=%u",
                      published ? "ok" : "fail",
                      framedSize,
                      hasMembership ? 1U : 0U,
                      static_cast<unsigned long long>(session.activityMemberKey),
                      static_cast<unsigned>(session.accountKey),
                      reportedSpawnState,
                      reportedTeleportState,
                      reportedTeleportSlice,
                      static_cast<unsigned>(reportedToken),
                      reportedRevision,
                      static_cast<unsigned>(advertisement));
    if (count > 0) {
        core::log::write(core::log::Channel::server,
                         core::log::Level::debug,
                         {line.data(), static_cast<std::size_t>(count)});
    }
    const bool delivered =
        publish_frame(session, scratch, response, written, framedSize, nextSendNonce, published);
    // A body the client never saw must advertise its region again on the next poll.
    if (delivered && stagedAdvertisedRegion >= 0) {
        session.activityAdvertisedRegion = stagedAdvertisedRegion;
    }
    return delivered;
}

} // namespace sunrise::server::bap::encrypted::push::activity
