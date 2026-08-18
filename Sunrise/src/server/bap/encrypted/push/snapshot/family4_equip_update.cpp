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
 * Builds the Family-4 increment that republishes the character after a subclass equip,
 * followed by the picked subclass item's instance upsert. The equip's pick-reset changes
 * the item's socket-entry state — the same surface the opcode-801 now republishes — so the
 * two-object frame refreshes the node display without an inventory exit/re-entry. (The
 * character after-image alone was boot-proven for the subclass slot; the item rides along
 * for the sockets the display reads.)
 */
bool prepare_subclass_equip(Scratch& scratch,
                            const queuez::SubclassEquip& equip,
                            Prepared& prepared) noexcept {
    const Reservation reservation = reserve_prior(scratch, prepared);
    if (reservation.rawWriteOffset > scratch.plaintext.size()
        || reservation.compressedWriteOffset > scratch.sealed.size()) {
        return report_failure("equip_reservation");
    }
    const state::AccountState account = state::account_snapshot();
    const std::optional<std::size_t> selectedIndex = find_character_index(account);
    Resolved selected{};
    if (!state::account::valid(account) || !selectedIndex.has_value()
        || !resolve(account, *selectedIndex, selected)
        || account.characters[selected.characterIndex].soid != equip.characterSoid) {
        return report_failure("equip_selection");
    }

    Prepared staged{};
    staged.rawClearSize = reservation.rawClearSize;
    staged.compressedClearSize = reservation.compressedClearSize;
    const auto rawStorage = std::span(scratch.plaintext).subspan(reservation.rawWriteOffset);
    std::size_t compressedExtent = reservation.compressedWriteOffset;
    if (family4_datagen::character::layout::kObjectSize > rawStorage.size()) {
        return report_failure("equip_character_storage");
    }
    const auto characterBytes =
        rawStorage.first(family4_datagen::character::layout::kObjectSize);
    if (!family4_datagen::character::encode(account.characters[selected.characterIndex],
                                            selected.loadout,
                                            selected.lightEvaluation,
                                            characterBytes)) {
        return report_failure("equip_character_object");
    }
    if (!append_object(scratch,
                       characterBytes,
                       equip.characterDefinitionId,
                       equip.characterSoid,
                       staged.objects[0],
                       compressedExtent)) {
        return report_failure("equip_character_object");
    }
    staged.rawClearSize = (std::max)(staged.rawClearSize,
                                     reservation.rawWriteOffset
                                         + family4_datagen::character::layout::kObjectSize);

    // The picked subclass item's re-resolved sockets are the display's source.
    family4_datagen::loadout::ResolvedInstances changed{};
    for (std::size_t index = 0; index < selected.loadout.itemCount; ++index) {
        const family4_datagen::loadout::ResolvedItem& item = selected.loadout.items[index];
        if (item.instance.instanceSoid != equip.itemSoid) {
            continue;
        }
        if (changed.itemCount != 0 || !item.equipped
            || !item.instance.socketEntryContentsResolved
            || item.instance.socketEntryListIndex
                   == family4_datagen::instance::layout::kEmptyDefinitionIndex
            || item.instance.socketEntryCount == 0) {
            return report_failure("equip_item_shape");
        }
        changed.items[0] =
            family4_datagen::loadout::SlottedInstance{item.equipmentSlot, item.instance};
        changed.itemCount = 1;
    }
    if (changed.itemCount != 1) {
        return report_failure("equip_item_missing");
    }
    std::size_t itemCursor = 0;
    if (!append_items(scratch,
                      rawStorage,
                      selected.itemInstanceObjectId,
                      changed,
                      1,
                      staged,
                      itemCursor,
                      compressedExtent)
        || itemCursor != 1) {
        clear_after(scratch, reservation);
        return report_failure("equip_item_object");
    }

    staged.compressedClearSize = (std::max)(reservation.compressedClearSize, compressedExtent);
    staged.family = middleware::queuez::Family{
        kAccountFamilyType,
        equip.after.family4RootSoid,
        equip.after.family4Version,
        0,
        std::span(staged.objects).first(2),
    };
    if (!commit(staged, prepared)) {
        clear_after(scratch, reservation);
        return report_failure("equip_commit");
    }
    return true;
}

} // namespace sunrise::server::bap::encrypted::push::snapshot
