#include "activity_message_push.h"

#include <Windows.h>

#include <algorithm>

#include "../../../../../core/settings/settings.h"
#include "../../../../../middleware/bap/activity_message/activity_join_result_encoder.h"
#include "../../../../../middleware/bap/activity_message/activity_entity_index_allocation_encoder.h"
#include "../../../../../middleware/bap/activity_message/activity_entity_index_grant_encoder.h"
#include "../../../../../middleware/bap/activity_message/entity_slots.h"
#include "../../../../../middleware/secure_channel/runtime.h"
#include "activity_global_state_push.h"
#include "activity_notification_frame.h"
#include "activity_world_population_push.h"

namespace sunrise::server::bap::encrypted::push::activity {
namespace {

namespace service = middleware::bap::activity_message;
namespace entity_index_allocation = middleware::bap::activity_message::entity_index_allocation;
namespace entity_index_grant = middleware::bap::activity_message::entity_index_grant;
namespace peer_contact = middleware::bap::activity_message::peer_contact;

/** Activity message type 4 accepts a pending join before any later push. */
constexpr std::uint32_t kJoinResultMessageType = 4;
/** Activity message type 54 publishes the bubble-host table. */
constexpr std::uint32_t kBubbleHostStateMessageType = 54;
/**
 * Activity message type 30 assigns the entity-index pool identity: the client's
 * runtime-registered handler 0x1404F34C0 decodes one u32 (schema 0x80808683) into
 * [pool+0x602b4], unblocking the manager's post-init local-mask sync (FINDINGS
 * 20.217 - its -1 default is why the host client's local mask stays empty).
 */
constexpr std::uint32_t kAssignmentMessageType = 30;
/**
 * Message 54 opens with a 6-bit host count, and a zero count carries no records, so the whole
 * encoded body is one zero byte.
 */
constexpr std::array<std::byte, 1> kEmptyBubbleHostState{};
/** 5 seconds stops the zero-hint keepalive flood seen locally. */
constexpr std::uint16_t kLocalKeepaliveHintMilliseconds = 5'000;

/**
 * Wipes the part of one scratch buffer that may hold written bytes.
 * @param buffer Lock-owned scratch storage.
 * @param size Largest prefix that may hold transformed bytes.
 */
void clear_prefix(std::span<std::byte> buffer, std::size_t size) noexcept {
    SecureZeroMemory(buffer.data(), (std::min)(buffer.size(), size));
}

} // namespace

/** Appends the ordered join-result and entity-slot svc9 notifications. */
bool append_join_notifications(Scratch& scratch,
                               const activity_message::ActivityPlan& activity,
                               std::span<const std::byte, state::kAesKeySize> key,
                               std::array<std::byte, state::kBapNonceSize>& nonce,
                               std::span<std::byte> response,
                               std::size_t& written) noexcept {
    if (written > response.size()) {
        return false;
    }
    const std::size_t initialWritten = written;
    auto initialNonce = nonce;
    std::size_t messageSize = 0;
    bool encoded = service::join_result::encode_join_result(activity.correlation,
                                                            activity.sessionId,
                                                            kLocalKeepaliveHintMilliseconds,
                                                            scratch.responseBody,
                                                            messageSize)
                   && append_notification_frame(scratch,
                                                activity.sessionId,
                                                kJoinResultMessageType,
                                                std::span(scratch.responseBody).first(messageSize),
                                                key,
                                                nonce,
                                                response,
                                                written);
    // What this host answered to the join, per boot: the client's PRIVATE/PUBLIC classification
    // hangs on the session id in this body (FINDINGS 20.69), so name it on every push.
    if (encoded) {
        std::array<char, 128> line{};
        const int logged = std::snprintf(
            line.data(),
            line.size(),
            "ev=activity stage=join_result push correlation=%u ah_sid=0x%llX status=accepted",
            activity.correlation,
            static_cast<unsigned long long>(activity.sessionId));
        if (logged > 0) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(logged)});
        }
    }
    clear_prefix(scratch.responseBody, messageSize);
    if (encoded) {
        middleware::secure_channel::advance_nonce(nonce);
        encoded = append_entity_slot_notification(scratch,
                                                  activity.sessionId,
                                                  activity.entitySlotMutation.mask,
                                                  key,
                                                  nonce,
                                                  response,
                                                  written);
    }
    // Type 30 after type 0: the pool ASSIGNMENT that unblocks the client's post-init
    // local-mask sync (0x14171BB50 gate on [pool+0x602b4], FINDINGS 20.217). Without
    // it the host client's manager sync always skips and every player_broadcast
    // creation returns -1. Its own switch so the burst stays byte-identical when off.
    if (encoded && core::settings::get().server.gameplay.entityIndexAssignment) {
        encoded = append_entity_index_assignment_notification(scratch,
                                                              activity.sessionId,
                                                              0,
                                                              key,
                                                              nonce,
                                                              response,
                                                              written);
    }
    // Type 20 after type 0: the lease names the slots this client HOLDS, and the
    // allocation names the indices it may create entities in (FINDINGS 20.212/20.213,
    // entity-index-allocation-schema.md). Behind a switch so the burst stays
    // byte-identical until the lane turns it on. v1 names only the joining member's
    // block, base 0; the cross-member map is deferred until decode is confirmed.
    if (encoded && core::settings::get().server.gameplay.entityIndexAllocation) {
        const entity_index_allocation::Member member{
            activity.entitySlotMutation.memberKey, 0};
        encoded = append_entity_index_allocation_notification(scratch,
                                                              activity.sessionId,
                                                              {&member, 1},
                                                              static_cast<std::uint32_t>(
                                                                  activity.entitySlotMutation.requestedCount),
                                                              key,
                                                              nonce,
                                                              response,
                                                              written);
    }
    // Type 21 after type 20: the grant the client's entity manager consumes
    // directly — the type-20 body provably reaches no mask (claim J), while the
    // type-21 bitmap feeds the pool the index allocator draws from (claims K/M).
    // The mask is the joiner's own lease, byte-identical to the type-0 body.
    // Its own switch so either push flips off without a rebuild.
    if (encoded && core::settings::get().server.gameplay.entityIndexGrant) {
        encoded = append_entity_index_grant_notification(scratch,
                                                         activity.sessionId,
                                                         activity.entitySlotMutation.mask,
                                                         key,
                                                         nonce,
                                                         response,
                                                         written);
    }
    // Message 1 comes after 0: 4 first because it is the only message the router's pre-join arm
    // accepts, and 1 after it because step 33 reads the activity name out of it. Message 54 closes
    // the set with its empty host table.
    if (encoded) {
        encoded = append_global_state_notification(
            scratch, activity.sessionId, key, nonce, response, written);
    }
    if (encoded) {
        encoded = append_notification_frame(scratch,
                                            activity.sessionId,
                                            kBubbleHostStateMessageType,
                                            kEmptyBubbleHostState,
                                            key,
                                            nonce,
                                            response,
                                            written);
        if (encoded) {
            middleware::secure_channel::advance_nonce(nonce);
        }
    }
    // S2-0 (spec §3.4): after the unchanged join burst, one static-entity baseline push
    // on the configured carrier, then the patch-epoch bump. Nothing is emitted while
    // server.worldPopulation is off, so the burst stays byte-identical by default.
    if (encoded && core::settings::get().server.worldPopulation) {
        encoded = append_world_population_notifications(
            scratch, activity.sessionId, key, nonce, response, written);
    }
    if (!encoded) {
        // Never show a first notification when the one that must follow cannot be staged.
        clear_prefix(response.subspan(initialWritten), written - initialWritten);
        written = initialWritten;
        nonce = initialNonce;
    }
    SecureZeroMemory(&initialNonce, sizeof initialNonce);
    return encoded;
}

/** Appends one entity-slot svc9 notification and advances its local nonce once. */
bool append_entity_slot_notification(Scratch& scratch,
                                     std::uint64_t sessionId,
                                     std::span<const std::byte> entitySlots,
                                     std::span<const std::byte, state::kAesKeySize> key,
                                     std::array<std::byte, state::kBapNonceSize>& nonce,
                                     std::span<std::byte> response,
                                     std::size_t& written) noexcept {
    if (written > response.size() || entitySlots.size() != service::entity_slots::kEncodedSize) {
        return false;
    }

    const std::size_t initialWritten = written;
    auto initialNonce = nonce;
    std::size_t messageSize = 0;
    const std::span<const std::byte, service::entity_slots::kEncodedSize> selected{
        entitySlots.data(), entitySlots.size()};
    const bool encoded =
        service::entity_slots::encode_entity_slots(selected, scratch.responseBody, messageSize)
        && append_notification_frame(scratch,
                                     sessionId,
                                     service::entity_slots::kNotificationMessageType,
                                     std::span(scratch.responseBody).first(messageSize),
                                     key,
                                     nonce,
                                     response,
                                     written);
    clear_prefix(scratch.responseBody, messageSize);
    if (encoded) {
        middleware::secure_channel::advance_nonce(nonce);
    } else {
        clear_prefix(response.subspan(initialWritten), written - initialWritten);
        written = initialWritten;
        nonce = initialNonce;
    }
    SecureZeroMemory(&initialNonce, sizeof initialNonce);
    return encoded;
}

/**
 * Appends one entity-index-pool ASSIGNMENT (activity type 30) svc9 notification and
 * advances its local nonce once. The body is schema 0x80808683 = one 32-bit value
 * (type-5, width 32, no presence), decoded by the client's runtime-registered handler
 * 0x1404F34C0 into [pool+0x602b4]. That field gates the entity manager's post-init
 * sync (0x14171BB50): while it reads -1 the sync SKIPS filling the manager's local
 * free-slot mask and every peer/player_broadcast creation fails with -1 (20.216/20.217:
 * the host client's 50x failure bursts). v1 emits 0, which decodes identically under
 * either byte-order convention, isolating "message arrives" from "value is right".
 */
bool append_entity_index_assignment_notification(
    Scratch& scratch,
    std::uint64_t sessionId,
    std::uint32_t assignment,
    std::span<const std::byte, state::kAesKeySize> key,
    std::array<std::byte, state::kBapNonceSize>& nonce,
    std::span<std::byte> response,
    std::size_t& written) noexcept {
    if (written > response.size() || scratch.responseBody.size() < 4) {
        return false;
    }

    const std::size_t initialWritten = written;
    auto initialNonce = nonce;
    // Type-5 value fields are MSB-first on the wire (LESSONS wire-field conventions).
    scratch.responseBody[0] = static_cast<std::byte>((assignment >> 24) & 0xFF);
    scratch.responseBody[1] = static_cast<std::byte>((assignment >> 16) & 0xFF);
    scratch.responseBody[2] = static_cast<std::byte>((assignment >> 8) & 0xFF);
    scratch.responseBody[3] = static_cast<std::byte>(assignment & 0xFF);
    const bool encoded =
        append_notification_frame(scratch,
                                  sessionId,
                                  kAssignmentMessageType,
                                  std::span(scratch.responseBody).first(4),
                                  key,
                                  nonce,
                                  response,
                                  written);
    SecureZeroMemory(scratch.responseBody.data(), 4);
    if (encoded) {
        middleware::secure_channel::advance_nonce(nonce);
    } else {
        clear_prefix(response.subspan(initialWritten), written - initialWritten);
        written = initialWritten;
        nonce = initialNonce;
    }
    SecureZeroMemory(&initialNonce, sizeof initialNonce);
    return encoded;
}

/**
 * Appends one peer-contact (type 45) svc9 notification naming the recipient's peer.
 * The body is schema 0x80808689: a 6-bit count then the machine id's 64 bits, LE byte
 * order, MSB-first packed (activity_peer_contact_encoder.h carries the derivation).
 * The client's handler 0x1404F3870 marks that tracking row contactable
 * (pool+0x602C4 = 1) - the evaluator 0x140C171F0's last missing input.
 */
bool append_peer_contact_notification(
    Scratch& scratch,
    std::uint64_t sessionId,
    std::span<const std::uint64_t> machineIds,
    std::span<const std::byte, state::kAesKeySize> key,
    std::array<std::byte, state::kBapNonceSize>& nonce,
    std::span<std::byte> response,
    std::size_t& written) noexcept {
    // Compact to the ids worth naming: drop zeros (no tracking row can hold one) and
    // duplicates (the two identities coincide in some session shapes, and a repeated key
    // would just re-mark the same row while consuming a count slot).
    std::array<std::uint64_t, peer_contact::kMaximumMachineIds> ids{};
    std::size_t count = 0;
    for (const std::uint64_t candidate : machineIds) {
        if (candidate == 0 || count >= ids.size()) {
            continue;
        }
        bool duplicate = false;
        for (std::size_t seen = 0; seen < count; ++seen) {
            duplicate = duplicate || ids[seen] == candidate;
        }
        if (!duplicate) {
            ids[count++] = candidate;
        }
    }
    // An empty list encodes a legal body that marks nothing; sending it would spend a
    // nonce to say nothing, so refuse instead.
    if (written > response.size() || count == 0) {
        return false;
    }

    const std::size_t initialWritten = written;
    auto initialNonce = nonce;
    std::size_t messageSize = 0;
    const bool encoded =
        peer_contact::encode({ids.data(), count}, scratch.responseBody, messageSize)
        && append_notification_frame(scratch,
                                     sessionId,
                                     peer_contact::kMessageType,
                                     std::span(scratch.responseBody).first(messageSize),
                                     key,
                                     nonce,
                                     response,
                                     written);
    SecureZeroMemory(scratch.responseBody.data(), messageSize);
    if (encoded) {
        middleware::secure_channel::advance_nonce(nonce);
    } else {
        clear_prefix(response.subspan(initialWritten), written - initialWritten);
        written = initialWritten;
        nonce = initialNonce;
    }
    SecureZeroMemory(&initialNonce, sizeof initialNonce);
    return encoded;
}

/** Appends one entity-index-allocation svc9 notification and advances its local nonce once. */
bool append_entity_index_allocation_notification(
    Scratch& scratch,
    std::uint64_t sessionId,
    std::span<const entity_index_allocation::Member> members,
    std::uint32_t freeSlots,
    std::span<const std::byte, state::kAesKeySize> key,
    std::array<std::byte, state::kBapNonceSize>& nonce,
    std::span<std::byte> response,
    std::size_t& written) noexcept {
    const std::size_t initialWritten = written;
    auto initialNonce = nonce;
    std::size_t messageSize = 0;
    const bool encoded =
        entity_index_allocation::encode(members, freeSlots, scratch.responseBody, messageSize)
        && append_notification_frame(scratch,
                                     sessionId,
                                     entity_index_allocation::kMessageType,
                                     std::span(scratch.responseBody).first(messageSize),
                                     key,
                                     nonce,
                                     response,
                                     written);
    clear_prefix(scratch.responseBody, messageSize);
    if (encoded) {
        middleware::secure_channel::advance_nonce(nonce);
        std::array<char, 128> line{};
        const int logged = std::snprintf(
            line.data(),
            line.size(),
            "ev=activity stage=index_allocation push members=%u bytes=%u",
            static_cast<unsigned>(members.size()),
            static_cast<unsigned>(messageSize));
        if (logged > 0) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(logged)});
        }
    } else {
        clear_prefix(response.subspan(initialWritten), written - initialWritten);
        written = initialWritten;
        nonce = initialNonce;
    }
    SecureZeroMemory(&initialNonce, sizeof initialNonce);
    return encoded;
}

/** Appends one entity-index-grant (type 21) svc9 notification and advances its local nonce once. */
bool append_entity_index_grant_notification(
    Scratch& scratch,
    std::uint64_t sessionId,
    std::span<const std::byte, middleware::bap::activity_message::entity_slots::kEncodedSize> mask,
    std::span<const std::byte, state::kAesKeySize> key,
    std::array<std::byte, state::kBapNonceSize>& nonce,
    std::span<std::byte> response,
    std::size_t& written) noexcept {
    const std::size_t initialWritten = written;
    auto initialNonce = nonce;
    std::size_t messageSize = 0;
    const bool flat = core::settings::get().server.gameplay.entityIndexGrantFlat;
    const bool encoded =
        (flat ? entity_index_grant::encode_flat(mask, scratch.responseBody, messageSize)
              : entity_index_grant::encode(mask, scratch.responseBody, messageSize))
        && append_notification_frame(scratch,
                                     sessionId,
                                     entity_index_grant::kMessageType,
                                     std::span(scratch.responseBody).first(messageSize),
                                     key,
                                     nonce,
                                     response,
                                     written);
    clear_prefix(scratch.responseBody, messageSize);
    if (encoded) {
        middleware::secure_channel::advance_nonce(nonce);
        std::array<char, 128> line{};
        const int logged = std::snprintf(
            line.data(),
            line.size(),
            "ev=activity stage=index_grant push bytes=%u mode=%s",
            static_cast<unsigned>(messageSize),
            flat ? "flat" : "raw");
        if (logged > 0) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(logged)});
        }
    } else {
        clear_prefix(response.subspan(initialWritten), written - initialWritten);
        written = initialWritten;
        nonce = initialNonce;
    }
    SecureZeroMemory(&initialNonce, sizeof initialNonce);
    return encoded;
}

} // namespace sunrise::server::bap::encrypted::push::activity
