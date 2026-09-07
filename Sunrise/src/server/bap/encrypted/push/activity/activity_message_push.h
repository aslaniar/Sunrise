#pragma once

#include <array>
#include <cstddef>
#include <span>

#include "../../../internal.h"
#include "../../activity_message/definition.h"
#include "../../../../../middleware/bap/activity_message/activity_entity_index_allocation_encoder.h"
#include "../../../../../middleware/bap/activity_message/activity_entity_index_grant_encoder.h"
#include "../../../../../middleware/bap/activity_message/entity_slots.h"
#include "../../../../../middleware/bap/activity_message/activity_peer_contact_encoder.h"

namespace sunrise::server::bap::encrypted::push::activity {

/**
 * Appends the ordered join-result and entity-slot svc9 notifications.
 * @param scratch Lock-owned transform buffers.
 * @param activity Join scalars and the exact lease mask State picked.
 * @param key Active AES-GCM session key.
 * @param nonce Local send nonce advanced once per staged notification.
 * @param response Lock-owned complete-frame staging storage.
 * @param written Existing staged byte count, updated only after both notifications exist.
 * @return True when both notifications encode atomically.
 */
[[nodiscard]] bool append_join_notifications(Scratch& scratch,
                                             const activity_message::ActivityPlan& activity,
                                             std::span<const std::byte, state::kAesKeySize> key,
                                             std::array<std::byte, state::kBapNonceSize>& nonce,
                                             std::span<std::byte> response,
                                             std::size_t& written) noexcept;

/**
 * Appends one entity-slot svc9 notification and advances its local nonce once.
 * @param scratch Lock-owned transform buffers.
 * @param sessionId Nonzero activity id echoed in the svc9 envelope.
 * @param entitySlots Exact byte-indexed lease mask State picked.
 * @param key Active AES-GCM session key.
 * @param nonce Local send nonce advanced only after the complete notification exists.
 * @param response Lock-owned complete-frame staging storage.
 * @param written Existing staged byte count, updated only after the notification exists.
 * @return True when the notification encodes atomically.
 */
[[nodiscard]] bool
append_entity_slot_notification(Scratch& scratch,
                                std::uint64_t sessionId,
                                std::span<const std::byte> entitySlots,
                                std::span<const std::byte, state::kAesKeySize> key,
                                std::array<std::byte, state::kBapNonceSize>& nonce,
                                std::span<std::byte> response,
                                std::size_t& written) noexcept;

/**
 * Appends one entity-index-pool assignment (type 30) svc9 notification and advances its
 * local nonce once. The body is one 32-bit value (schema 0x80808683) the client decodes
 * into [pool+0x602b4]; its -1 default blocks the manager's post-init local-mask sync
 * (FINDINGS 20.217). Gated on the entity_index_assignment settings switch.
 * @param scratch Lock-owned transform buffers.
 * @param sessionId Nonzero activity id echoed in the svc9 envelope.
 * @param assignment The pool identity value to publish (v1: 0).
 * @param key Active AES-GCM session key.
 * @param nonce Local send nonce advanced only after the complete notification exists.
 * @param response Lock-owned complete-frame staging storage.
 * @param written Existing staged byte count, updated only after the notification exists.
 * @return True when the notification encodes atomically.
 */
[[nodiscard]] bool
append_entity_index_assignment_notification(
    Scratch& scratch,
    std::uint64_t sessionId,
    std::uint32_t assignment,
    std::span<const std::byte, state::kAesKeySize> key,
    std::array<std::byte, state::kBapNonceSize>& nonce,
    std::span<std::byte> response,
    std::size_t& written) noexcept;

/**
 * Appends one entity-index-allocation (type 20) svc9 notification and advances its
 * local nonce once. The body is the schema-key-0x80809445 layout decoded in
 * RE_output/claims/entity-index-allocation-schema.md; gated on the
 * entity_index_allocation settings switch (FINDINGS 20.212/20.213).
 * @param scratch Lock-owned transform buffers.
 * @param sessionId Nonzero activity id echoed in the svc9 envelope.
 * @param members Participant rows (id + index block base), join order.
 * @param key Active AES-GCM session key.
 * @param nonce Local send nonce advanced only after the complete notification exists.
 * @param response Lock-owned complete-frame staging storage.
 * @param written Existing staged byte count, updated only after the notification exists.
 * @return True when the notification encodes atomically.
 */
[[nodiscard]] bool
append_entity_index_allocation_notification(
    Scratch& scratch,
    std::uint64_t sessionId,
    std::span<const middleware::bap::activity_message::entity_index_allocation::Member> members,
    std::uint32_t freeSlots,
    std::span<const std::byte, state::kAesKeySize> key,
    std::array<std::byte, state::kBapNonceSize>& nonce,
    std::span<std::byte> response,
    std::size_t& written) noexcept;

/**
 * Appends one start_activity_host (type 9) svc9 notification and advances its
 * local nonce once. The body is the 13-byte raw struct the client's decode
 * variant reads directly (mode 1, activity session id, value dword 4). The
 * client's apply runs its per-session host state-machine step; an unknown
 * session id is a client-side no-op. Gated behind the activityStartHostPush
 * settings switch so the default burst stays byte-identical.
 * @param scratch Lock-owned transform buffers.
 * @param sessionId Activity session id echoed in the envelope AND carried in the body.
 * @param key Active AES-GCM session key.
 * @param nonce Local send nonce advanced only after the complete notification exists.
 * @param response Lock-owned complete-frame staging storage.
 * @param written Existing staged byte count, updated only after the notification exists.
 * @return True when the notification encodes atomically.
 */
[[nodiscard]] bool
append_start_activity_host_notification(
    Scratch& scratch,
    std::uint64_t sessionId,
    std::span<const std::byte, state::kAesKeySize> key,
    std::array<std::byte, state::kBapNonceSize>& nonce,
    std::span<std::byte> response,
    std::size_t& written) noexcept;

/**
 * Appends one entity-index-grant (type 21) svc9 notification and advances its
 * local nonce once. The body is the 1029-byte free-slot mask the client's entity
 * manager consumes directly (claims K/M in
 * RE_output/claims/entity-index-allocation-schema.md); the mask is the joiner's
 * own lease — the same bytes the type-0 notification carries — and the shape is
 * selected by the entity_index_grant_flat switch, independent of the type-20
 * switch.
 * @param scratch Lock-owned transform buffers.
 * @param sessionId Nonzero activity id echoed in the svc9 envelope.
 * @param mask The joiner's lease mask in entity-slot wire order (1,024 bytes).
 * @param key Active AES-GCM session key.
 * @param nonce Local send nonce advanced only after the complete notification exists.
 * @param response Lock-owned complete-frame staging storage.
 * @param written Existing staged byte count, updated only after the notification exists.
 * @return True when the notification encodes atomically.
 */
[[nodiscard]] bool
append_entity_index_grant_notification(
    Scratch& scratch,
    std::uint64_t sessionId,
    std::span<const std::byte, middleware::bap::activity_message::entity_slots::kEncodedSize> mask,
    std::span<const std::byte, state::kAesKeySize> key,
    std::array<std::byte, state::kBapNonceSize>& nonce,
    std::span<std::byte> response,
    std::size_t& written) noexcept;

/**
 * Appends one peer-contact (type 45) svc9 notification and advances its local nonce
 * once. The body names EVERY machine id the recipient should treat as contactable, and
 * the client's handler 0x1404F3870 sets each matching tracking row's byte
 * (pool+0x602C4) to 1.
 *
 * p2-156 widened this from the peer alone to the whole known set. p2-155 PROVED the
 * write lands - the peer's row went 0x00 -> 0x01 on both machines (20.248 R1) - and
 * proved it changed nothing: the reader 0x1404F7680 kept returning 0 while being called
 * thousands of times, so the evaluator consults a row we did not mark (each client's OWN
 * row stayed 0; only the peer's was set) or one of the SECOND pool objects p2-155 found.
 * Naming every id makes "which row does it read" irrelevant by construction instead of
 * costing another instrument boot (20.248 R5).
 *
 * That byte is the last missing input of the per-tick peer evaluator 0x140C171F0
 * (FINDINGS 20.245 caught it aborting on the byte == 0; 20.246 R6 established the
 * evaluator's other probes are not gates). Gated on the pool_c4_mark_push settings
 * switch. Sending it repeatedly is safe and intended: the handler marks whatever rows
 * exist when the body lands, so re-sends cover the window before the client has
 * self-healed the peer's row (FINDINGS 20.242).
 * @param scratch Lock-owned transform buffers.
 * @param sessionId Nonzero activity id echoed in the svc9 envelope.
 * @param machineIds Machine ids to mark contactable, as the client keys its tracking
 *        array. Zero entries are skipped; an all-zero list sends nothing.
 * @param key Active AES-GCM session key.
 * @param nonce Local send nonce advanced only after the complete notification exists.
 * @param response Lock-owned complete-frame staging storage.
 * @param written Existing staged byte count, updated only after the notification exists.
 * @return True when the notification encodes atomically.
 */
[[nodiscard]] bool
append_peer_contact_notification(Scratch& scratch,
                                 std::uint64_t sessionId,
                                 std::span<const std::uint64_t> machineIds,
                                 std::span<const std::byte, state::kAesKeySize> key,
                                 std::array<std::byte, state::kBapNonceSize>& nonce,
                                 std::span<std::byte> response,
                                 std::size_t& written) noexcept;

} // namespace sunrise::server::bap::encrypted::push::activity
