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
 * Builds the Family-4 increment for a subclass equip — the opcode-801/2100 item-only
 * republish shape (the fix-A experiment). The client's ability-node display reads the
 * picked subclass item's 36-slot socket-entry state, and the item-only frames are the
 * boot-proven display-updating delivery (the 801/2100 flows). The two-object
 * character-plus-item frame (the boot-C shape) was accepted but never refreshed the
 * panel live — the census diff named the character object's presence as the context
 * perturbance — so the equip now publishes the same single item upsert the working
 * flows use, via the shared builder.
 */
bool prepare_subclass_equip(Scratch& scratch,
                            const queuez::SubclassEquip& equip,
                            Prepared& prepared) noexcept {
    return prepare_item_republish(scratch,
                                  equip.itemSoid,
                                  equip.characterSoid,
                                  equip.after,
                                  prepared);
}

} // namespace sunrise::server::bap::encrypted::push::snapshot
