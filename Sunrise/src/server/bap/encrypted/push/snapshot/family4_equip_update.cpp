#include <algorithm>
#include <cstddef>
#include <optional>
#include <span>

#include "../../../../../middleware/datagen/family4/character/character_encoder.h"
#include "../../../../../middleware/datagen/family4/character/layout.h"
#include "../../../../../middleware/datagen/family4/instance/layout.h"
#include "../../../../../state/runtime/runtime.h"
#include "internal.h"
#include "snapshot_storage.h"

namespace sunrise::server::bap::encrypted::push::snapshot {
namespace {

namespace family4_datagen = middleware::datagen::family4;

} // namespace

/**
 * Builds the Family-4 increments for a subclass equip — the SYNTHETIC RESET→SELECT
 * two-frame sequence (the boot-M lane's fix, the census-proven missing surface). The
 * client's panel live-update keys on the kind-3 socket diff's MERGE class (the
 * multi-entry ready→active transition) — the equip's single frame never produced a
 * content delta (the pick-reset's sockets equal the store's record), so the equip now
 * publishes: frame 1 = the item RESET to the baseline socket states (absent/ready, no
 * active picks) at the staged version − 1; frame 2 = the item with the pick-reset's
 * sockets APPLIED at the staged version — frame 2's ready→active transitions = the
 * merge-class diff → the notify → the panel re-reads. The serials + the banner + the
 * roster + the delayed ability refresh stay (the upstream's grid-ordering model).
 */
bool prepare_subclass_equip(Scratch& scratch,
                            const queuez::SubclassEquip& equip,
                            Prepared& resetPrepared,
                            Prepared& selectPrepared) noexcept {
    queuez::SessionState resetAfter = equip.after;
    if (resetAfter.family4Version <= 1) {
        return report_failure("equip_reset_version");
    }
    resetAfter.family4Version = equip.after.family4Version - 1;
    if (!prepare_item_republish(scratch,
                                equip.itemSoid,
                                equip.characterSoid,
                                resetAfter,
                                resetPrepared,
                                /*clearedSockets=*/true)) {
        return report_failure("equip_reset_frame");
    }
    return prepare_item_republish(scratch,
                                  equip.itemSoid,
                                  equip.characterSoid,
                                  equip.after,
                                  selectPrepared);
}

} // namespace sunrise::server::bap::encrypted::push::snapshot
