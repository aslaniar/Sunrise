#include "activity_membership_push.h"

#include <Windows.h>

#include <array>
#include <cstdio>

#include "../../../../../middleware/bap/activity_message/replicate_membership.h"
#include "../../../../../middleware/secure_channel/runtime.h"
#include "../../../../../core/logging/log.h"
#include "../../../../gameplay/gameplay_advertisement.h"
#include "../../../../../state/activity/runtime.h"
#include "../../../../gameplay/group/group_host_sessions.h"
#include "activity_arrival.h"
#include "activity_notification_frame.h"

namespace sunrise::server::bap::encrypted::push::activity {
namespace {

namespace message = middleware::bap::activity_message::replicate_membership;

/** The one published member always occupies slot zero of both top-level masks. */
constexpr std::uint8_t kLocalMemberSlot = 0;

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
    if (state::activity::foreign_member_identity(sessionId, peerIdentity)) {
        wire.peer.memberKey = peerIdentity.memberKey;
        wire.peer.field1 = peerIdentity.smallOpaque;
        wire.peer.field2 = peerIdentity.signedOpaque;
        wire.peer.field3 = peerIdentity.joinIdentity;
        wire.peer.accountSoid = peerIdentity.accountSoid;
        wire.peer.field5 = peerIdentity.opaqueSoid;
        wire.peer.field6 = peerIdentity.secondaryOpaque;
        wire.peerPresent = true;
        std::array<char, 128> line{};
        const int writtenLine =
            std::snprintf(line.data(),
                          line.size(),
                          "ev=activity stage=membership_peer result=included key=0x%016llX",
                          static_cast<unsigned long long>(peerIdentity.memberKey));
        if (writtenLine > 0) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(writtenLine)});
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
