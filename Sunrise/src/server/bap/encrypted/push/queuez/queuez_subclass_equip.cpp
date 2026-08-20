#include "../../queuez/queuez_state_validation.h"
#include "../snapshot/internal.h"
#include "queuez_push_reporting.h"
#include "queuez_update_frame.h"

namespace sunrise::server::bap::encrypted::push {

/**
 * Appends the opcode-403 Family-4 increments — the synthetic reset→select two-frame
 * sequence (the reset at the staged version − 1, the select at the staged version).
 * @param scratch Lock-owned transform buffers.
 * @param equip Staged after-image and the resident character keys.
 * @param key Active AES-GCM session key.
 * @param nonce Push-direction nonce after the correlated svc-11 response.
 * @param response Caller-owned output containing the existing response prefix.
 * @param written Existing byte count, updated after the complete push is appended.
 * @return True when both item-republish frames fit.
 */
bool append_subclass_equip_notification(Scratch& scratch,
                                        const queuez::SubclassEquip& equip,
                                        std::span<const std::byte, state::kAesKeySize> key,
                                        std::span<const std::byte, state::kBapNonceSize> nonce,
                                        std::span<std::byte> response,
                                        std::size_t& written) noexcept {
    snapshot::Prepared resetPrepared{};
    snapshot::Prepared selectPrepared{};
    if (!snapshot::prepare_subclass_equip(scratch, equip, resetPrepared, selectPrepared)) {
        return false;
    }
    const std::size_t beforeBytes = written;
    if (!queuez_frame::append(scratch,
                              resetPrepared.family,
                              resetPrepared.rawClearSize,
                              resetPrepared.compressedClearSize,
                              key,
                              nonce,
                              response,
                              written)
        || !queuez_frame::append(scratch,
                                  selectPrepared.family,
                                  selectPrepared.rawClearSize,
                                  selectPrepared.compressedClearSize,
                                  key,
                                  nonce,
                                  response,
                                  written)) {
        return false;
    }
    queuez_report::push("subclass_equip",
                        queuez::kAccountFamilyType,
                        2,
                        written - beforeBytes,
                        1);
    return true;
}

} // namespace sunrise::server::bap::encrypted::push
