#include <algorithm>
#include <array>
#include <cstddef>
#include <optional>
#include <span>

#include "../../../../../state/build_data/items/details/item_detail_catalog.h"
#include "../../../../../core/logging/log.h"
#include <cstdio>
#include "../../../../../middleware/datagen/definitions.h"
#include "../../../../../middleware/datagen/family4/account/account_encoder.h"
#include "../../../../../middleware/datagen/family4/account/layout.h"
#include "../../../../../middleware/datagen/family4/character/character_encoder.h"
#include "../../../../../middleware/datagen/family4/character/layout.h"
#include "../../../../../middleware/datagen/family4/instance/layout.h"
#include "../../../../../middleware/datagen/family4/loadout/loadout_resolver.h"
#include "../../../../../state/runtime/runtime.h"
#include "internal.h"
#include "snapshot_storage.h"

namespace sunrise::server::bap::encrypted::push::snapshot {
namespace {

namespace family4_datagen = middleware::datagen::family4;

/**
 * Publishes the staged family metadata once every needed object is done.
 * @param subscription Family id the Client picked.
 * @param compressedExtent Size of the used prefix of the sealed buffer.
 * @param reservation Cleanup extent carried over from any prior live snapshot.
 * @param output Gets the family snapshot only on success.
 * @return True when the staged descriptors pass the ownership check.
 */
[[nodiscard]] bool publish(const middleware::queuez::Subscription& subscription,
                           std::size_t objectCount,
                           std::size_t compressedExtent,
                           const Reservation& reservation,
                           Prepared& staged,
                           Prepared& output) noexcept {
    staged.compressedClearSize = (std::max)(reservation.compressedClearSize, compressedExtent);
    staged.family = middleware::queuez::Family{
        kAccountFamilyType,
        subscription.familyRootSoid,
        kInitialFamilyVersion,
        middleware::queuez::kFullSnapshotFlag,
        std::span(staged.objects).first(objectCount),
    };
    return commit(staged, output);
}

} // namespace

/** Builds the Family-4 account, selected-character, and item-instance snapshot. */
bool prepare(Scratch& scratch,
             const middleware::queuez::Subscription& subscription,
             std::uint32_t accountObjectId,
             const Reservation& reservation,
             Prepared& prepared,
             core::settings::AccountKey accountKey) noexcept {
    if (reservation.rawWriteOffset > scratch.plaintext.size()
        || reservation.compressedWriteOffset > scratch.sealed.size()) {
        return report_failure("reservation");
    }
    const auto rawStorage = std::span(scratch.plaintext).subspan(reservation.rawWriteOffset);
    if (family4_datagen::account::layout::kObjectSize > rawStorage.size()) {
        return report_failure("account_storage");
    }
    const state::AccountState account = state::account_snapshot(accountKey);
    if (!state::account::valid(account)) {
        return report_failure("account_state");
    }

    const std::optional<std::size_t> selectedIndex = find_character_index(account);
    Resolved selected{};
    if (selectedIndex.has_value() && !resolve(account, *selectedIndex, selected)) {
        return report_failure("selection");
    }

    Prepared staged{};
    staged.rawClearSize =
        (std::max)(reservation.rawClearSize,
                   reservation.rawWriteOffset + family4_datagen::account::layout::kObjectSize);
    std::size_t compressedExtent = reservation.compressedWriteOffset;
    const auto accountBytes = rawStorage.first(family4_datagen::account::layout::kObjectSize);
    if (!family4_datagen::account::encode(account, accountBytes)) {
        return report_failure("account_object");
    }
    if (!append_object(scratch,
                       accountBytes,
                       accountObjectId,
                       account.primarySoid,
                       staged.objects[kAccountObjectIndex],
                       compressedExtent)) {
        return report_failure("account_object");
    }
    // The character object is the only descriptor a selection owns. With no selection it is absent
    // and the items move up behind the account object, keeping the published prefix contiguous.
    const std::size_t itemBaseIndex =
        selectedIndex.has_value() ? kFirstItemObjectIndex : kFirstItemObjectIndexUnselected;
    if (selectedIndex.has_value()) {
        staged.rawClearSize = (std::max)(staged.rawClearSize,
                                         reservation.rawWriteOffset
                                             + family4_datagen::character::layout::kObjectSize);
        if (family4_datagen::character::layout::kObjectSize > rawStorage.size()) {
            return report_failure("character_storage");
        }
        const auto characterBytes =
            rawStorage.first(family4_datagen::character::layout::kObjectSize);
        const state::CharacterState& selectedCharacter =
            account.characters[selected.characterIndex];
        if (!family4_datagen::character::encode(
                selectedCharacter, selected.loadout, selected.lightEvaluation, characterBytes)) {
            return report_failure("character_encode");
        }
        if (!append_object(scratch,
                           characterBytes,
                           selected.characterObjectId,
                           selectedCharacter.soid,
                           staged.objects[kCharacterObjectIndex],
                           compressedExtent)) {
            return report_failure("character_object");
        }
    }
    // Every character in the roster needs its item records. The equip-summary reader looks up an
    // instance with no null check, so a missing record is a null read.
    std::uint32_t itemInstanceObjectId = 0;
    if (!middleware::datagen::object_id(
            kAccountFamilyType, kItemDefinitionSlotIndex, itemInstanceObjectId)) {
        return report_failure("item_object_id");
    }
    std::size_t itemCursor = 0;
    for (std::size_t characterIndex = 0; characterIndex < account.characterCount;
         ++characterIndex) {
        family4_datagen::loadout::ResolvedInstances instances{};
        if (!family4_datagen::loadout::resolve_instances(account, characterIndex, instances)) {
            std::array<char, 128> line{};
            const int written =
                std::snprintf(line.data(), line.size(),
                              "ev=family4 stage=loadout context detailsCount=%zu "
                              "char=%zu",
                              state::build_data::items::details::count(),
                              characterIndex);
            if (written > 0) {
                core::log::write(core::log::Channel::server,
                                 core::log::Level::warn,
                                 {line.data(), static_cast<std::size_t>(written)});
            }
            // P2 diagnostic: dump the live configured-detail table identity at failure time.
            namespace bd = state::build_data;
            std::array<bd::items::details::Definition, 128> dump{};
            std::size_t dumpedCount = 0;
            const bool snapshotOk =
                bd::items::details::snapshot(std::span(dump), dumpedCount);
            bool hasKineticByIndex = false;
            bool hasKineticByHash = false;
            std::array<char, 32> indexList{};
            std::size_t indexCursor = 0;
            for (std::size_t i = 0; i < dumpedCount; ++i) {
                if (dump[i].definitionIndex == 6853) {
                    hasKineticByIndex = true;
                }
                if (dump[i].definitionHash == 0xE516CF40u) {
                    hasKineticByHash = true;
                }
                const int step = std::snprintf(indexList.data() + indexCursor,
                                               indexList.size() - indexCursor,
                                               "%s%u",
                                               indexCursor == 0 ? "" : ",",
                                               dump[i].definitionIndex);
                if (step <= 0
                    || static_cast<std::size_t>(step) >= indexList.size() - indexCursor) {
                    break;
                }
                indexCursor += static_cast<std::size_t>(step);
            }
            std::array<char, 320> dumpLine{};
            const int dumpWritten =
                std::snprintf(dumpLine.data(),
                              dumpLine.size(),
                              "ev=family4 stage=details_dump result=%s count=%zu "
                              "kineticByIndex=%d kineticByHash=%d indexes=[%s%s]",
                              snapshotOk ? "ok" : "snapfail",
                              dumpedCount,
                              hasKineticByIndex ? 1 : 0,
                              hasKineticByHash ? 1 : 0,
                              indexList.data(),
                              indexCursor >= indexList.size() - 1 ? "..." : "");
            if (dumpWritten > 0) {
                core::log::write(core::log::Channel::server,
                                 core::log::Level::warn,
                                 {dumpLine.data(), static_cast<std::size_t>(dumpWritten)});
            }
            {
                std::array<char, 128> ctxLine{};
                const int ctxWritten =
                    std::snprintf(ctxLine.data(),
                                  ctxLine.size(),
                                  "ev=family4 stage=loadout context detailsCount=%zu "
                                  "char=%zu",
                                  bd::items::details::count(),
                                  characterIndex);
                if (ctxWritten > 0) {
                    core::log::write(core::log::Channel::server,
                                     core::log::Level::warn,
                                     {ctxLine.data(), static_cast<std::size_t>(ctxWritten)});
                }
            }
            return report_failure("loadout");
        }
        if (instances.itemCount != 0
            && !append_items(scratch,
                             rawStorage,
                             itemInstanceObjectId,
                             instances,
                             itemBaseIndex,
                             staged,
                             itemCursor,
                             compressedExtent)) {
            return report_failure("items");
        }
    }

    const std::size_t objectCount = itemBaseIndex + itemCursor;
    if (itemCursor != 0) {
        staged.rawClearSize =
            (std::max)(staged.rawClearSize,
                       reservation.rawWriteOffset + family4_datagen::instance::layout::kObjectSize);
    }
    return publish(subscription, objectCount, compressedExtent, reservation, staged, prepared);
}

} // namespace sunrise::server::bap::encrypted::push::snapshot
