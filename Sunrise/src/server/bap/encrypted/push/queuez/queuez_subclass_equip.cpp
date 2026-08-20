#include "../../queuez/queuez_state_validation.h"
#include "../snapshot/internal.h"
#include "queuez_push_reporting.h"
#include "queuez_update_frame.h"

namespace sunrise::server::bap::encrypted::push {

/**
 * Appends the opcode-403 Family-4 increment as one above the peer's current version.
 * @param scratch Lock-owned transform buffers.
 * @param equip Staged after-image and the resident character keys.
 * @param key Active AES-GCM session key.
 * @param nonce Push-direction nonce after the correlated svc-11 response.
 * @param response Caller-owned output containing the existing response prefix.
 * @param written Existing byte count, updated after the complete push is appended.
 * @return True when the character-upsert frame fits.
 */
bool append_subclass_equip_notification(Scratch& scratch,
                                        const queuez::SubclassEquip& equip,
                                        std::span<const std::byte, state::kAesKeySize> key,
                                        std::span<const std::byte, state::kBapNonceSize> nonce,
                                        std::span<std::byte> response,
                                        std::size_t& written) noexcept {
    snapshot::Prepared prepared{};
    if (!snapshot::prepare_subclass_equip(scratch, equip, prepared)) {
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
    queuez_report::push(
        "subclass_equip", queuez::kAccountFamilyType, objectCount, written - beforeBytes, 1);
    return true;
}

} // namespace sunrise::server::bap::encrypted::push
