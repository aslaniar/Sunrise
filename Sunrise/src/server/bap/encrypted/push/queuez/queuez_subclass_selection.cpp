#include "../../queuez/queuez_state_validation.h"
#include "../snapshot/internal.h"
#include "queuez_push_reporting.h"
#include "queuez_update_frame.h"

namespace sunrise::server::bap::encrypted::push {

/**
 * Appends the opcode-801 Family-4 character after-image as one above the peer's current
 * version. The selected ability fields live on the character record, so the frame carries the
 * re-encoded character — the same shape the subclass equip delivers.
 * @param scratch Lock-owned transform buffers.
 * @param selection Staged after-image and the resident character keys.
 * @param key Active AES-GCM session key.
 * @param nonce Push-direction nonce after the correlated svc-11 response.
 * @param response Caller-owned output containing the existing response prefix.
 * @param written Existing byte count, updated after the complete push is appended.
 * @return True when the character after-image frame fits.
 */
bool append_subclass_selection_notification(
    Scratch& scratch,
    const queuez::SubclassSelection& selection,
    std::span<const std::byte, state::kAesKeySize> key,
    std::span<const std::byte, state::kBapNonceSize> nonce,
    std::span<std::byte> response,
    std::size_t& written) noexcept {
    snapshot::Prepared prepared{};
    if (!snapshot::prepare_subclass_selection(scratch, selection, prepared)) {
        return false;
    }
    const std::size_t objectCount = prepared.family.objects.size();
    const std::size_t beforeBytes = written;
    if (!queuez_frame::append(scratch,
                              prepared.family,
                              prepared.rawClearSize,
                              prepared.compressedClearSize,
                              key,
                              nonce,
                              response,
                              written)) {
        return false;
    }
    queuez_report::push("subclass_select",
                        queuez::kAccountFamilyType,
                        objectCount,
                        written - beforeBytes,
                        1);
    return true;
}

/**
 * Appends the opcode-2100 Family-4 character after-image as one above the peer's current
 * version. Only reached when the ability-change mutate succeeded, so the character record
 * carries the new pick and the frame republishes it.
 * @param scratch Lock-owned transform buffers.
 * @param change Staged after-image and the resident character keys.
 * @param key Active AES-GCM session key.
 * @param nonce Push-direction nonce after the correlated svc-11 response.
 * @param response Caller-owned output containing the existing response prefix.
 * @param written Existing byte count, updated after the complete push is appended.
 * @return True when the character after-image frame fits.
 */
bool append_ability_change_notification(Scratch& scratch,
                                        const queuez::AbilityChange& change,
                                        std::span<const std::byte, state::kAesKeySize> key,
                                        std::span<const std::byte, state::kBapNonceSize> nonce,
                                        std::span<std::byte> response,
                                        std::size_t& written) noexcept {
    snapshot::Prepared prepared{};
    if (!snapshot::prepare_ability_change(scratch, change, prepared)) {
        return false;
    }
    const std::size_t objectCount = prepared.family.objects.size();
    const std::size_t beforeBytes = written;
    if (!queuez_frame::append(scratch,
                              prepared.family,
                              prepared.rawClearSize,
                              prepared.compressedClearSize,
                              key,
                              nonce,
                              response,
                              written)) {
        return false;
    }
    queuez_report::push("ability_change",
                        queuez::kAccountFamilyType,
                        objectCount,
                        written - beforeBytes,
                        1);
    return true;
}

} // namespace sunrise::server::bap::encrypted::push
