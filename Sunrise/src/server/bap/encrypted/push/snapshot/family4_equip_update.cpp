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
 * Builds the Family-4 increment for a subclass equip — the CHARACTER upsert (the revert of
 * fix-A). The item-only republish (the 801/2100 shape) carries no equipped state: the
 * character object is the only record that publishes both the equipped SOIDs and the
 * inventory-row mutation serials, so the equip's after-image goes out as one character
 * object keyed (characterDefinitionId, characterSoid), flags 0, at the staged +1 version.
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
    staged.compressedClearSize = (std::max)(reservation.compressedClearSize, compressedExtent);
    staged.family = middleware::queuez::Family{
        kAccountFamilyType,
        equip.after.family4RootSoid,
        equip.after.family4Version,
        0,
        std::span(staged.objects).first(1),
    };
    if (!commit(staged, prepared)) {
        clear_after(scratch, reservation);
        return report_failure("equip_commit");
    }
    return true;
}

} // namespace sunrise::server::bap::encrypted::push::snapshot
