#include <algorithm>
#include <cstddef>
#include <optional>
#include <span>

#include "../../../../../middleware/datagen/family4/instance/layout.h"
#include "../../../../../middleware/datagen/family4/loadout/definition.h"
#include "../../../../../state/runtime/runtime.h"
#include "internal.h"
#include "snapshot_storage.h"

namespace sunrise::server::bap::encrypted::push::snapshot {
namespace {

namespace family4_datagen = middleware::datagen::family4;

} // namespace

/**
 * Builds one Family-4 increment that republishes the SUBCLASS ITEM instance record at the
 * staged version — the community fork's exact shape for the opcode-801 (its
 * append_subclass_selection_notification publishes the subclass item upsert, never the
 * character). The client's ability-node display reads the item's 36-slot socket-entry
 * state, so the upsert is the record the display actually consults; the character-record
 * shape (the earlier port) was accepted but invisible to the display. The item's sockets
 * come from the already-committed mutation through the loadout resolve. SHARED by the
 * opcode-801 selection, the opcode-2100 ability change, and (the fix-A experiment) the
 * opcode-403 subclass equip — the three flows publish the identical item-only shape.
 */
bool prepare_item_republish(Scratch& scratch,
                            std::uint64_t subclassInstanceSoid,
                            std::uint64_t characterSoid,
                            const queuez::SessionState& after,
                            Prepared& prepared) noexcept {
    const Reservation reservation = reserve_prior(scratch, prepared);
    if (reservation.rawWriteOffset > scratch.plaintext.size()
        || reservation.compressedWriteOffset > scratch.sealed.size()) {
        return report_failure("item_republish_reservation");
    }
    const state::AccountState account = state::account_snapshot();
    const std::optional<std::size_t> selectedIndex = find_character_index(account);
    Resolved selected{};
    if (!state::account::valid(account) || !selectedIndex.has_value()
        || !resolve(account, *selectedIndex, selected)
        || account.characters[selected.characterIndex].soid != characterSoid
        || subclassInstanceSoid == 0) {
        return report_failure("item_republish_selection");
    }

    // One selected loadout row names the subclass instance; its resolved sockets are the
    // display's source. The item must be equipped and carry a resolved socket table.
    family4_datagen::loadout::ResolvedInstances changed{};
    for (std::size_t index = 0; index < selected.loadout.itemCount; ++index) {
        const family4_datagen::loadout::ResolvedItem& item = selected.loadout.items[index];
        if (item.instance.instanceSoid != subclassInstanceSoid) {
            continue;
        }
        if (changed.itemCount != 0 || !item.equipped
            || !item.instance.socketEntryContentsResolved
            || item.instance.socketEntryListIndex == family4_datagen::instance::layout::kEmptyDefinitionIndex
            || item.instance.socketEntryCount == 0) {
            return report_failure("item_republish_item_shape");
        }
        changed.items[0] =
            family4_datagen::loadout::SlottedInstance{item.equipmentSlot, item.instance};
        changed.itemCount = 1;
    }
    if (changed.itemCount != 1) {
        return report_failure("item_republish_item_missing");
    }

    const auto rawStorage = std::span(scratch.plaintext).subspan(reservation.rawWriteOffset);
    if (family4_datagen::instance::layout::kObjectSize > rawStorage.size()) {
        return report_failure("item_republish_item_storage");
    }
    Prepared staged{};
    staged.rawClearSize =
        (std::max)(reservation.rawClearSize,
                   reservation.rawWriteOffset + family4_datagen::instance::layout::kObjectSize);
    std::size_t compressedExtent = reservation.compressedWriteOffset;
    std::size_t itemCursor = 0;
    if (!append_items(scratch,
                      rawStorage,
                      selected.itemInstanceObjectId,
                      changed,
                      0,
                      staged,
                      itemCursor,
                      compressedExtent)
        || itemCursor != 1) {
        clear_after(scratch, reservation);
        return report_failure("item_republish_item_object");
    }
    staged.compressedClearSize = (std::max)(reservation.compressedClearSize, compressedExtent);
    staged.family = middleware::queuez::Family{
        kAccountFamilyType,
        after.family4RootSoid,
        after.family4Version,
        0,
        std::span(staged.objects).first(1),
    };
    if (!commit(staged, prepared)) {
        clear_after(scratch, reservation);
        return report_failure("item_republish_commit");
    }
    return true;
}

/** Builds the Family-4 increment that republishes the subclass item after an opcode-801
 *  selection — the fork's exact shape (one item upsert, the mutated sockets). */
bool prepare_subclass_selection(Scratch& scratch,
                                const queuez::SubclassSelection& selection,
                                Prepared& prepared) noexcept {
    return prepare_item_republish(scratch,
                                  selection.mutation.subclassInstanceSoid,
                                  selection.characterSoid,
                                  selection.after,
                                  prepared);
}

/** Builds the Family-4 increment that republishes the subclass item after an opcode-2100
 *  change whose mutate succeeded — the same item-upsert shape (the display's source). */
bool prepare_ability_change(Scratch& scratch,
                            const queuez::AbilityChange& change,
                            Prepared& prepared) noexcept {
    const state::AccountState account = state::account_snapshot();
    const std::optional<std::size_t> selectedIndex = find_character_index(account);
    if (!state::account::valid(account) || !selectedIndex.has_value()) {
        return report_failure("ability_change_selection");
    }
    const auto& slot =
        account.characters[*selectedIndex]
            .equipment.slots[static_cast<std::size_t>(
                state::account::inventory::EquipmentSlot::subclass)];
    if (!slot.has_value()) {
        return report_failure("ability_change_subclass");
    }
    return prepare_item_republish(scratch, slot->instanceSoid, change.characterSoid,
                                  change.after, prepared);
}

} // namespace sunrise::server::bap::encrypted::push::snapshot
