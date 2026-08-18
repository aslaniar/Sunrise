#include <algorithm>
#include <cstddef>
#include <optional>
#include <span>

#include "../../../../../middleware/datagen/family4/character/character_encoder.h"
#include "../../../../../middleware/datagen/family4/character/layout.h"
#include "../../../../../state/runtime/runtime.h"
#include "internal.h"
#include "snapshot_storage.h"

namespace sunrise::server::bap::encrypted::push::snapshot {
namespace {

namespace family4_datagen = middleware::datagen::family4;

/**
 * Builds one Family-4 increment that republishes the resident character object at the staged
 * version. Shared by the subclass equip, the opcode-801 selection, and the opcode-2100 ability
 * change: every mutation of the character-level fields owes the Client exactly one delivered
 * frame at exactly one above its held version (the fork's stage_family4_refresh rule). The
 * deliverable frame is the character after-image — flags 0, exactly one object.
 */
bool prepare_character_republish(Scratch& scratch,
                                 std::uint32_t characterDefinitionId,
                                 std::uint64_t characterSoid,
                                 const queuez::SessionState& after,
                                 Prepared& prepared) noexcept {
    const Reservation reservation = reserve_prior(scratch, prepared);
    if (reservation.rawWriteOffset > scratch.plaintext.size()
        || reservation.compressedWriteOffset > scratch.sealed.size()) {
        return report_failure("republish_reservation");
    }
    const state::AccountState account = state::account_snapshot();
    const std::optional<std::size_t> selectedIndex = find_character_index(account);
    Resolved selected{};
    if (!state::account::valid(account) || !selectedIndex.has_value()
        || !resolve(account, *selectedIndex, selected)
        || account.characters[selected.characterIndex].soid != characterSoid) {
        return report_failure("republish_selection");
    }

    Prepared staged{};
    staged.rawClearSize = reservation.rawClearSize;
    staged.compressedClearSize = reservation.compressedClearSize;
    const auto rawStorage = std::span(scratch.plaintext).subspan(reservation.rawWriteOffset);
    std::size_t compressedExtent = reservation.compressedWriteOffset;
    if (family4_datagen::character::layout::kObjectSize > rawStorage.size()) {
        return report_failure("republish_character_storage");
    }
    const auto characterBytes =
        rawStorage.first(family4_datagen::character::layout::kObjectSize);
    if (!family4_datagen::character::encode(account.characters[selected.characterIndex],
                                            selected.loadout,
                                            selected.lightEvaluation,
                                            characterBytes)) {
        return report_failure("republish_character_object");
    }
    if (!append_object(scratch,
                       characterBytes,
                       characterDefinitionId,
                       characterSoid,
                       staged.objects[0],
                       compressedExtent)) {
        return report_failure("republish_character_object");
    }
    staged.rawClearSize = (std::max)(staged.rawClearSize,
                                     reservation.rawWriteOffset
                                         + family4_datagen::character::layout::kObjectSize);
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
        return report_failure("republish_commit");
    }
    return true;
}

} // namespace

/** Builds the Family-4 increment that republishes the character after an opcode-801 selection. */
bool prepare_subclass_selection(Scratch& scratch,
                                const queuez::SubclassSelection& selection,
                                Prepared& prepared) noexcept {
    return prepare_character_republish(scratch,
                                       selection.characterDefinitionId,
                                       selection.characterSoid,
                                       selection.after,
                                       prepared);
}

/** Builds the Family-4 increment that republishes the character after an opcode-2100 change. */
bool prepare_ability_change(Scratch& scratch,
                            const queuez::AbilityChange& change,
                            Prepared& prepared) noexcept {
    return prepare_character_republish(scratch,
                                       change.characterDefinitionId,
                                       change.characterSoid,
                                       change.after,
                                       prepared);
}

} // namespace sunrise::server::bap::encrypted::push::snapshot
