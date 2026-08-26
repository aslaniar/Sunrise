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
#include "membership_sweep.h"
#include "activity_notification_frame.h"

namespace sunrise::server::bap::encrypted::push::activity {
namespace {

namespace message = middleware::bap::activity_message::replicate_membership;

/** The one published member always occupies slot zero of both top-level masks. */
constexpr std::uint8_t kLocalMemberSlot = 0;

/**
 * Per-session place in the shape sweep.
 *
 * PER SESSION, not process-wide. The revision that carries a shape is per session, and a shape
 * change is only seen if its own session's revision advances with it - a shared phase would
 * advance the shape for a session whose revision had not moved, and the client would drop that
 * body as a repeat (Lane M). Independent slots also give two independent trials.
 */
struct SweepEntry final {
    std::uint64_t sessionId;
    SweepSlot slot;
    bool occupied;
};

/** Sessions that may be sweeping at once. Matches the activity session table's practical width. */
constexpr std::size_t kSweepEntryCapacity = 8;
/** Sweep slots. Touched only from the push path. */
SweepEntry g_sweepEntries[kSweepEntryCapacity]{};

/** @return This session's slot, claiming a free one on first use, or nullptr when full. */
[[nodiscard]] SweepSlot* sweep_slot(std::uint64_t sessionId) noexcept {
    SweepEntry* free = nullptr;
    for (SweepEntry& entry : g_sweepEntries) {
        if (entry.occupied && entry.sessionId == sessionId) {
            return &entry.slot;
        }
        if (!entry.occupied && free == nullptr) {
            free = &entry;
        }
    }
    if (free == nullptr) {
        return nullptr;
    }
    free->sessionId = sessionId;
    free->slot = {};
    free->occupied = true;
    return &free->slot;
}

/**
 * Writes the full mirrored peer row.
 *
 * The row shape is no longer a variable: it was swept across six shapes and made no
 * difference at all (FINDINGS 20.51), so the most complete row is published every time and
 * the sweep varies the trailing fields instead.
 *
 * @param peer The other joined session's identity.
 * @param wire Receives the peer row.
 */
void apply_peer_row(const state::activity::membership::Identity& peer,
                    message::MembershipSnapshot& wire) noexcept {
    wire.peer = {};
    wire.peer.memberKey = peer.memberKey;
    wire.peer.field1 = peer.smallOpaque;
    wire.peer.field2 = peer.signedOpaque;
    wire.peer.field3 = peer.joinIdentity;
    wire.peer.accountSoid = peer.accountSoid;
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
    // Only a body that HAS a peer to publish advances the sweep - a solo body carries no shape
    // under test, and counting it would spend shapes on nothing.
    const core::settings::server::Settings& serverSettings = core::settings::get().server;
    TrailingVariant variant = TrailingVariant::maskMask;
    SweepDecision decision{};
    SweepSlot* slot = nullptr;
    if (havePeer && serverSettings.membershipSweep) {
        slot = sweep_slot(sessionId);
    }
    if (slot != nullptr) {
        decision = sweep_decide(*slot,
                                GetTickCount64(),
                                serverSettings.membershipSweepBodies,
                                serverSettings.membershipSweepDwellMs);
        variant = decision.variant;
    }
    const TrailingValues values = trailing_values(variant);
    if (havePeer && values.peerPresent) {
        apply_peer_row(peerIdentity, wire);
        wire.peerPresent = true;
        // Zero leaves the encoder on its historical value, which is what `solo` wants.
        wire.trailingFirst = values.first;
        wire.trailingSecond = values.second;
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
                          "variant=%s step=%llu ack=%d peer_row=%d first=0x%08X second=0x%08X",
                          static_cast<unsigned long long>(peerIdentity.memberKey),
                          variant_name(variant),
                          static_cast<unsigned long long>(slot == nullptr ? 0 : slot->step),
                          state::activity::membership::acknowledged(sessionId) ? 1 : 0,
                          wire.peerPresent ? 1 : 0,
                          values.first,
                          values.second);
        if (includedLine > 0) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(includedLine)});
        }
    }
    if (slot != nullptr) {
        const std::uint64_t now = GetTickCount64();
        sweep_apply(*slot, decision, now);
        // THE POINT OF THE FIX. The client applies one update per revision and drops every
        // repeat, so the next body's new shape must ride a new revision or it is discarded
        // unread. Advancing here - after this body is built - pairs (new shape, new revision)
        // on the NEXT body. The first sweep run lacked this and therefore measured exactly one
        // shape while appearing to measure two (FINDINGS 20.49/20.50).
        if (decision.advance && state::activity::membership::republish(sessionId)) {
            std::array<char, 128> retire{};
            const int retireLine =
                std::snprintf(retire.data(),
                              retire.size(),
                              "ev=activity stage=membership_sweep result=retired variant=%s "
                              "next=%s",
                              variant_name(decision.variant),
                              variant_name(static_cast<TrailingVariant>(
                                  slot->step % kTrailingVariantCount)));
            if (retireLine > 0) {
                core::log::write(core::log::Channel::server,
                                 core::log::Level::info,
                                 {retire.data(), static_cast<std::size_t>(retireLine)});
            }
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
