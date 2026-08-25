#include "activity_membership_push.h"

#include <Windows.h>

#include <array>
#include <cstdio>

#include "../../../../../middleware/bap/activity_message/replicate_membership.h"
#include "../../../../../middleware/secure_channel/runtime.h"
#include "../../../../../core/logging/log.h"
#include "../../../../gameplay/gameplay_advertisement.h"
#include "../../../../../state/activity/runtime.h"
#include "../../../../../state/activity/membership/activity_membership_query.h"
#include "../../../../../core/settings/settings.h"
#include "../../../../gameplay/group/group_host_sessions.h"
#include "activity_arrival.h"
#include "activity_notification_frame.h"

namespace sunrise::server::bap::encrypted::push::activity {
namespace {

namespace message = middleware::bap::activity_message::replicate_membership;

/** The one published member always occupies slot zero of both top-level masks. */
constexpr std::uint8_t kLocalMemberSlot = 0;

/**
 * INSTRUMENT (Track A, 2026-08-25): the shapes member slot 1 is swept through.
 *
 * The known-ACCEPTED artifact is our own solo body; the known-REJECTED one is the full
 * mirrored row (FINDINGS 20.48). Everything between them is a cumulative build-up, so the
 * first shape the client acknowledges names the field that was breaking it.
 *
 * ORDER IS DELIBERATE. `solo` sits LAST because an acknowledgement STOPS the republish loop
 * and therefore ends the sweep: putting the known-good shape first would close the harness
 * before any peer-bearing shape was tried. Reaching `solo` at all means every peer shape was
 * refused, and whether the client then acks IS the meta-answer - if even our known-accepted
 * body goes unacknowledged mid-session, the acknowledgement is not content-gated and the
 * whole 20.48 reading needs revisiting.
 */
enum class PeerVariant : std::uint8_t {
    /** memberKey alone. Tests whether ANY second row is structurally acceptable. */
    keyOnly,
    /** + accountSoid. */
    keyAccount,
    /** + joinIdentity. */
    keyAccountJoin,
    /** + the two int32 opaques. */
    keyAccountJoinOpaquePair,
    /** Every field, byte-identical to p2(35). Known REJECTED - the negative control. */
    fullMirror,
    /** No peer row at all. Known ACCEPTED - the terminal positive control. */
    solo,
};

/** Shapes in the sweep. Kept beside the enum because both must move together. */
constexpr std::uint64_t kPeerVariantCount = 6;
/** Used when the configured dwell is zero. */
constexpr std::uint32_t kDefaultSweepDwellMs = 30'000;

/** @return Human-readable name of one swept shape, for the boot record. */
[[nodiscard]] const char* variant_name(PeerVariant variant) noexcept {
    switch (variant) {
    case PeerVariant::keyOnly:
        return "key_only";
    case PeerVariant::keyAccount:
        return "key_account";
    case PeerVariant::keyAccountJoin:
        return "key_account_join";
    case PeerVariant::keyAccountJoinOpaquePair:
        return "key_account_join_opaque";
    case PeerVariant::fullMirror:
        return "full_mirror";
    case PeerVariant::solo:
        return "solo";
    }
    return "unknown";
}

/**
 * Picks the shape this body publishes.
 * @param cycle Receives how many complete passes the sweep has made.
 * @return fullMirror whenever the sweep is off, which is p2(35) byte for byte.
 */
[[nodiscard]] PeerVariant sweep_variant(std::uint64_t& cycle) noexcept {
    cycle = 0;
    const core::settings::server::Settings& server = core::settings::get().server;
    if (!server.membershipSweep) {
        return PeerVariant::fullMirror;
    }
    // One process-wide phase rather than one per session: both machines' bodies then carry the
    // same shape at the same moment, which is what makes two logs comparable line for line.
    static std::uint64_t startTick = 0;
    const std::uint64_t now = GetTickCount64();
    if (startTick == 0) {
        startTick = now;
    }
    const std::uint32_t dwell = server.membershipSweepDwellMs == 0 ? kDefaultSweepDwellMs
                                                                  : server.membershipSweepDwellMs;
    const std::uint64_t step = (now - startTick) / dwell;
    cycle = step / kPeerVariantCount;
    return static_cast<PeerVariant>(step % kPeerVariantCount);
}

/**
 * Writes one swept shape into the body.
 * @param variant Shape to publish.
 * @param peer The other joined session's identity.
 * @param wire Receives the peer row and its presence flag.
 */
void apply_peer_variant(PeerVariant variant,
                        const state::activity::membership::Identity& peer,
                        message::MembershipSnapshot& wire) noexcept {
    wire.peer = {};
    wire.peerPresent = variant != PeerVariant::solo;
    if (!wire.peerPresent) {
        return;
    }
    // Cumulative by design: every case falls through to the next, so the shapes differ by
    // exactly one addition and the first acknowledged one names the field.
    wire.peer.memberKey = peer.memberKey;
    if (variant == PeerVariant::keyOnly) {
        return;
    }
    wire.peer.accountSoid = peer.accountSoid;
    if (variant == PeerVariant::keyAccount) {
        return;
    }
    wire.peer.field3 = peer.joinIdentity;
    if (variant == PeerVariant::keyAccountJoin) {
        return;
    }
    wire.peer.field1 = peer.smallOpaque;
    wire.peer.field2 = peer.signedOpaque;
    if (variant == PeerVariant::keyAccountJoinOpaquePair) {
        return;
    }
    wire.peer.field5 = peer.opaqueSoid;
    wire.peer.field6 = peer.secondaryOpaque;
}

/**
 * Maps a lock-consistent State snapshot into the fixed Middleware schema.
 * @param sessionId Joined activity session, used to resolve the advertised region.
 * @param mutation Prepared membership operation, whose region this body publishes.
 * @return Whole current membership encoder input.
 */
[[nodiscard]] message::MembershipSnapshot
make_wire_snapshot(std::uint64_t sessionId,
                   const state::activity::membership::PendingMutation& mutation) noexcept {
    const state::activity::membership::Snapshot& snapshot = mutation.snapshot;
    message::MembershipSnapshot wire{};
    wire.identity.memberKey = snapshot.identity.memberKey;
    wire.identity.field1 = snapshot.identity.smallOpaque;
    wire.identity.field2 = snapshot.identity.signedOpaque;
    wire.identity.field3 = snapshot.identity.joinIdentity;
    wire.identity.accountSoid = snapshot.identity.accountSoid;
    wire.identity.field5 = snapshot.identity.opaqueSoid;
    wire.identity.field6 = snapshot.identity.secondaryOpaque;
    wire.spawn.state = snapshot.spawn.state;
    wire.spawn.opaqueByte = snapshot.spawn.opaqueByte;
    wire.spawn.opaqueValue = snapshot.spawn.opaqueValue;
    wire.teleport.state = snapshot.teleport.state;
    wire.teleport.token = snapshot.teleport.token;
    wire.teleport.sliceSetIndex = snapshot.teleport.sliceSetIndex;
    wire.teleport.sliceSetHash = snapshot.teleport.sliceSetHash;
    wire.revision = snapshot.revision;
    wire.epoch = snapshot.epoch;
    wire.transitionToken = snapshot.transitionToken;
    // The region this body is about to commit, not the one State still holds. Staging runs before
    // the commit, so the region just left would leave the pending record empty for good.
    const EffectiveRegion region = planned_region(mutation, sessionId);
    // SOURCED, not source-less. The source-less overload is upstream's fail-closed stub - it
    // clears the output and reports `reason=no_source` - and binding to it by accident is what
    // silenced the citizen advertisement from f68f230 onward (FINDINGS 20.31). The source is
    // this session's own committed record, whose destination the advertised target must copy.
    state::activity::SessionBinding source{};
    std::uint64_t hostGeneration = 0;
    if (state::activity::snapshot_binding(sessionId, source)) {
        server::gameplay::build_advertisement(
            source,
            region.index,
            region.reported ? server::gameplay::RegionSource::reported
                            : server::gameplay::RegionSource::arrival,
            kLocalMemberSlot,
            wire.citizen,
            hostGeneration);
        // Released here rather than held on the Session: threading a generation through six
        // append_membership_notification call sites buys only eviction resistance, and the host
        // row is re-claimed by the next advertisement. The row stays claimed; only the retain
        // that pins it against LRU eviction is dropped. Every retain is balanced.
        if (hostGeneration != 0) {
            server::gameplay::group::release_host_session(hostGeneration);
        }
    } else {
        wire.citizen = {};
    }
    // FINDINGS 20.44: a second joined session in this destination publishes its identity as
    // member slot 1. Without it the client's peer table holds only the local player and no
    // contact attempt can ever name anyone.
    state::activity::membership::Identity peerIdentity{};
    state::activity::ForeignPeerReason peerReason{};
    const bool havePeer =
        state::activity::foreign_member_identity(sessionId, peerIdentity, peerReason);
    std::uint64_t sweepCycle = 0;
    const PeerVariant variant = sweep_variant(sweepCycle);
    if (havePeer) {
        apply_peer_variant(variant, peerIdentity, wire);
    }
    {
        // INSTRUMENT (FINDINGS 20.47): every type-12 body built anywhere converges here, so
        // this line is the boring-path proof the encoder input stage ran at all - its absence
        // means no membership body was due, which is a different finding from a refused one.
        std::array<char, 160> line{};
        int writtenLine = std::snprintf(line.data(),
                                        line.size(),
                                        "ev=activity stage=wire_snapshot session=%llu peer=%d",
                                        static_cast<unsigned long long>(sessionId),
                                        havePeer ? 1 : 0);
        if (!havePeer) {
            writtenLine = std::snprintf(line.data(),
                                        line.size(),
                                        "ev=activity stage=wire_snapshot session=%llu peer=0 "
                                        "reason=%s",
                                        static_cast<unsigned long long>(sessionId),
                                        peerReason == state::activity::ForeignPeerReason::
                                                           identity_missing
                                            ? "identity_missing"
                                            : (peerReason ==
                                                       state::activity::ForeignPeerReason::
                                                           destination_mismatch
                                                   ? "destination_mismatch"
                                                   : "none_joined"));
        }
        if (writtenLine > 0) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::debug,
                             {line.data(), static_cast<std::size_t>(writtenLine)});
        }
    }
    if (havePeer) {
        std::array<char, 224> line{};
        // ack= is the PREVIOUS body's verdict, which is exactly the correlation wanted: the
        // shape named here is the one the client was holding when it decided. A flip to ack=1
        // stops the republish loop, so the last shape logged before the log goes quiet is the
        // accepted one.
        const int includedLine =
            std::snprintf(line.data(),
                          line.size(),
                          "ev=activity stage=membership_peer result=included key=0x%016llX "
                          "variant=%s cycle=%llu ack=%d peer_row=%d",
                          static_cast<unsigned long long>(peerIdentity.memberKey),
                          variant_name(variant),
                          static_cast<unsigned long long>(sweepCycle),
                          state::activity::membership::acknowledged(sessionId) ? 1 : 0,
                          wire.peerPresent ? 1 : 0);
        if (includedLine > 0) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(includedLine)});
        }
    }
    return wire;
}

} // namespace

/** Appends one current membership svc9 notification and advances its local nonce. */
bool append_membership_notification(Scratch& scratch,
                                    const activity_message::ActivityPlan& activity,
                                    std::span<const std::byte, state::kAesKeySize> key,
                                    std::array<std::byte, state::kBapNonceSize>& nonce,
                                    std::span<std::byte> response,
                                    std::size_t& written) noexcept {
    if (written > response.size() || !activity.membershipMutation.hasSnapshot) {
        return false;
    }

    const std::size_t initialWritten = written;
    auto initialNonce = nonce;
    std::size_t messageSize = 0;
    const message::MembershipSnapshot snapshot =
        make_wire_snapshot(activity.sessionId, activity.membershipMutation);
    const bool encoded =
        message::encode_replicate_membership(snapshot, scratch.responseBody, messageSize)
        && append_notification_frame(scratch,
                                     activity.sessionId,
                                     message::kMessageType,
                                     std::span(scratch.responseBody).first(messageSize),
                                     key,
                                     nonce,
                                     response,
                                     written);
    if (!encoded) {
        // A refused body used to fail silently and read as "no push was due". Name it.
        core::log::write(core::log::Channel::server,
                         core::log::Level::warn,
                         "ev=activity stage=membership result=encode_fail");
    }
    SecureZeroMemory(scratch.responseBody.data(), message::encoded_size(snapshot));
    if (encoded) {
        middleware::secure_channel::advance_nonce(nonce);
    } else {
        if (written > initialWritten) {
            SecureZeroMemory(response.data() + initialWritten, written - initialWritten);
        }
        written = initialWritten;
        nonce = initialNonce;
    }
    SecureZeroMemory(&initialNonce, sizeof initialNonce);
    return encoded;
}

} // namespace sunrise::server::bap::encrypted::push::activity
