#include <Windows.h>

#include <cstddef>
#include <cstdint>
#include <limits>

#include "../build_data/runtime.h"
#include "runtime.h"
#include "state.h"
#include "storage/internal.h"

namespace sunrise::state {

/** Stores the active account key without publishing an incomplete account. */
bool set_primary_soid(std::uint64_t primarySoid) noexcept {
    if (primarySoid == 0) {
        return false;
    }
    AcquireSRWLockExclusive(&runtime::storage::g_stateLock);
    AccountState candidate = runtime::storage::g_state.account;
    candidate.primarySoid = primarySoid;
    // Characters belong to the account key the Client uses. The reference account and its
    // characters differ only in the low byte, so the authored rows are rebased onto that key.
    for (std::size_t index = 0; index < candidate.characterCount; ++index) {
        candidate.characters[index].soid = primarySoid + 1U + index;
    }
    if (!account::valid(candidate)) {
        ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
        return false;
    }
    // Publish only after the settings and identity rules hold together.
    runtime::storage::g_state.account = candidate;
    ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
    return true;
}

/** Moves the selection to one authored character. */
bool set_selected_character(std::uint64_t characterSoid, bool& changed) noexcept {
    changed = false;
    if (characterSoid == 0) {
        return false;
    }
    AcquireSRWLockExclusive(&runtime::storage::g_stateLock);
    AccountState candidate = runtime::storage::g_state.account;
    std::size_t picked = candidate.characterCount;
    for (std::size_t index = 0; index < candidate.characterCount; ++index) {
        if (candidate.characters[index].soid == characterSoid) {
            picked = index;
        }
    }
    if (picked == candidate.characterCount) {
        ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
        return false;
    }

    const bool alreadySelected = candidate.characters[picked].selected;
    for (CharacterState& character : candidate.characters) {
        character.selected = false;
    }
    candidate.characters[picked].selected = true;
    if (!account::valid(candidate)) {
        ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
        return false;
    }
    // Publish only after the whole account still meets its identity rules.
    runtime::storage::g_state.account = candidate;
    ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
    changed = !alreadySelected;
    return true;
}

/** @return A copy of the active account state, read under the lock. */
AccountState account_snapshot() noexcept {
    AcquireSRWLockShared(&runtime::storage::g_stateLock);
    const AccountState snapshot = runtime::storage::g_state.account;
    ReleaseSRWLockShared(&runtime::storage::g_stateLock);
    return snapshot;
}

namespace {
/** Native bucket id that names the subclass inventory bucket. */
constexpr std::uint8_t kSubclassBucketId = 16;

/** @return The selected character, or one past the end when none is selected. */
[[nodiscard]] std::size_t selected_index(const AccountState& account) noexcept {
    for (std::size_t index = 0; index < account.characterCount; ++index) {
        if (account.characters[index].selected) {
            return index;
        }
    }
    return account.characterCount;
}

/**
 * Checks the read-only half of the subclass-equip policy on one snapshot.
 * @return True when the item is a bucket-16 storage item the character owns.
 */
[[nodiscard]] bool subclass_equip_valid_on(const AccountState& account,
                                           std::uint64_t itemSoid) noexcept {
    const std::size_t characterIndex = selected_index(account);
    if (characterIndex >= account.characterCount) {
        return false;
    }
    const CharacterState& character = account.characters[characterIndex];
    for (std::size_t index = 0; index < character.storageItemCount; ++index) {
        const account::inventory::Item& item = character.storageItems[index];
        if (item.instanceSoid != itemSoid) {
            continue;
        }
        state::build_data::items::Definition definition{};
        return state::build_data::find_item_definition_hash(item.definitionHash, definition)
               && definition.bucketId == kSubclassBucketId;
    }
    return false;
}
} // namespace

/** Checks the subclass-equip request policy without touching State. */
bool subclass_equip_request_valid(std::uint64_t itemSoid) noexcept {
    if (itemSoid == 0) {
        return false;
    }
    AcquireSRWLockShared(&runtime::storage::g_stateLock);
    const bool validRequest = subclass_equip_valid_on(runtime::storage::g_state.account, itemSoid);
    ReleaseSRWLockShared(&runtime::storage::g_stateLock);
    return validRequest;
}

/** Equips one storage item onto the selected character's subclass slot. */
bool equip_subclass_item(std::uint64_t itemSoid, std::uint64_t& displacedSoid) noexcept {    displacedSoid = 0;
    if (itemSoid == 0) {
        return false;
    }
    AcquireSRWLockExclusive(&runtime::storage::g_stateLock);
    AccountState candidate = runtime::storage::g_state.account;
    const std::size_t characterIndex = selected_index(candidate);
    if (characterIndex >= candidate.characterCount
        || !subclass_equip_valid_on(candidate, itemSoid)) {
        ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
        return false;
    }
    CharacterState& character = candidate.characters[characterIndex];
    // Remove the picked item from storage, then swap it into the subclass semantic slot.
    account::inventory::Item picked{};
    bool found = false;
    for (std::size_t index = 0; index < character.storageItemCount; ++index) {
        if (!found && character.storageItems[index].instanceSoid == itemSoid) {
            picked = character.storageItems[index];
            found = true;
        }
        if (found && index + 1 < character.storageItemCount) {
            character.storageItems[index] = character.storageItems[index + 1];
        }
    }
    if (!found) {
        ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
        return false;
    }
    --character.storageItemCount;
    // THE SERIAL HAND-OFF (the upstream's 6164a3b rule, adapted to the swap shape): the mover
    // takes the freshest generation, and the displaced item keeps the mover's PRIOR serial —
    // the Client orders a bucket's grid by serial, so a fresh greatest serial would rebuild the
    // displaced item in the first grid cell instead of the clicked cell. A swap with a
    // displaced item consumes exactly two counter values; a first equip consumes one.
    constexpr std::uint32_t kMaximumInventorySerial =
        static_cast<std::uint32_t>((std::numeric_limits<std::int32_t>::max)());
    const std::int32_t pickedPriorSerial = picked.mutationSerial;
    const std::optional<account::inventory::Item>& previous =
        character.equipment.slots[static_cast<std::size_t>(
            account::inventory::EquipmentSlot::subclass)];
    const std::uint32_t consumed = previous.has_value() ? 2U : 1U;
    if (character.nextInventorySerial > kMaximumInventorySerial
        || consumed > kMaximumInventorySerial - character.nextInventorySerial) {
        ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
        return false;
    }
    picked.mutationSerial = static_cast<std::int32_t>(character.nextInventorySerial++);
    if (previous.has_value()) {
        if (character.storageItemCount >= character.storageItems.size()) {
            ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
            return false;
        }
        displacedSoid = previous->instanceSoid;
        account::inventory::Item displaced = *previous;
        displaced.mutationSerial = pickedPriorSerial;
        character.storageItems[character.storageItemCount++] = displaced;
        ++character.nextInventorySerial;
    }
    character.equipment.slots[static_cast<std::size_t>(
        account::inventory::EquipmentSlot::subclass)] = picked;
    // A fresh subclass starts on its own default ability picks: the previous subclass's
    // entry indices do not name the new list's entries, and the banner encode must always
    // find a catalog row. Retail models this per subclass; our character-level model
    // resets on the equip instead.
    character.movementAbilityEntry = kDefaultMovementAbilityEntry;
    character.grenadeAbilityEntry = kDefaultGrenadeAbilityEntry;
    character.superAbilityEntry = kDefaultSuperAbilityEntry;
    character.meleeAbilityEntry = kDefaultMeleeAbilityEntry;
    character.classAbilityEntry = kDefaultClassAbilityEntry;
    if (!account::valid(candidate)) {
        ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
        return false;
    }
    // Publish only after the whole account still meets its identity rules.
    runtime::storage::g_state.account = candidate;
    ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
    return true;
}

/** Applies one opcode-2100 ability change to the selected character. */
bool apply_ability_change(std::uint32_t definitionHash) noexcept {
    if (definitionHash == 0
        || definitionHash == state::build_data::socket_entry_lists::kNoPlugSource) {
        return false;
    }
    AcquireSRWLockExclusive(&runtime::storage::g_stateLock);
    AccountState candidate = runtime::storage::g_state.account;
    const std::size_t characterIndex = selected_index(candidate);
    if (characterIndex >= candidate.characterCount) {
        ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
        return false;
    }
    CharacterState& character = candidate.characters[characterIndex];
    // The equipped subclass's socket-entry list names the entries the hash must match.
    const auto& slot =
        character.equipment.slots[static_cast<std::size_t>(
            account::inventory::EquipmentSlot::subclass)];
    state::build_data::items::Definition item{};
    state::build_data::items::details::Definition detail{};
    if (!slot.has_value()
        || !state::build_data::find_item_definition_hash(slot->definitionHash, item)
        || !state::build_data::find_configured_item_detail(item.definitionIndex, detail)) {
        ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
        return false;
    }
    state::build_data::socket_entry_lists::EntryTable entries{};
    state::build_data::socket_entry_lists::Definition list{};
    if (!state::build_data::find_socket_entry_table(detail.socketEntryListIndex, entries)
        || !state::build_data::find_socket_entry_list(detail.socketEntryListIndex, list)) {
        ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
        return false;
    }
    // The target entry: the one whose plug source is the requested hash. The super lane
    // carries no plug source, so a hash that matches nothing is not a change we can place.
    std::uint8_t targetEntry = 0xFF;
    for (std::uint8_t index = 0; index < list.entryCount; ++index) {
        if (entries.entries[index].plugSource == definitionHash) {
            targetEntry = index;
            break;
        }
    }
    if (targetEntry == 0xFF) {
        ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
        return false;
    }
    // The entry's competition group names the lane; the lane's current pick moves to it.
    const std::uint8_t targetGroup = entries.entries[targetEntry].group;
    if (targetGroup == state::build_data::socket_entry_lists::kNoEntryGroup) {
        ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
        return false;
    }
    std::uint8_t* lane = nullptr;
    std::uint8_t lanes[5] = {
        character.movementAbilityEntry,
        character.grenadeAbilityEntry,
        character.superAbilityEntry,
        character.meleeAbilityEntry,
        character.classAbilityEntry,
    };
    std::uint8_t* laneFields[5] = {
        &character.movementAbilityEntry,
        &character.grenadeAbilityEntry,
        &character.superAbilityEntry,
        &character.meleeAbilityEntry,
        &character.classAbilityEntry,
    };
    for (std::size_t index = 0; index < 5; ++index) {
        if (lanes[index] < list.entryCount
            && entries.entries[lanes[index]].group == targetGroup) {
            lane = laneFields[index];
            break;
        }
    }
    if (lane == nullptr || *lane == targetEntry) {
        ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
        return false;
    }
    *lane = targetEntry;
    if (!account::valid(candidate)) {
        ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
        return false;
    }
    // Publish only after the whole account still meets its identity rules.
    runtime::storage::g_state.account = candidate;
    ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
    return true;
}

namespace {

namespace socket_lists = state::build_data::socket_entry_lists;
namespace socket_buckets = state::build_data::socket_entry_buckets;
namespace inventory = account::inventory;

/** Bucket the grenade publishes into (the subclass_socket_selection's fixed lanes). */
constexpr std::uint8_t kGrenadeBucket = 0;
/** Bucket the super publishes into. */
constexpr std::uint8_t kSuperBucket = 1;
/** Bucket the melee publishes into. */
constexpr std::uint8_t kMeleeBucket = 2;
/** Bucket the movement ability publishes into. */
constexpr std::uint8_t kMovementBucket = 3;
/** A wide group is at most this many same-bundle members (the Attunement diamond). */
constexpr std::uint8_t kMaxAttunementBundleSize = 4;

/** @param characterClass Authored class. @return The bucket its class ability publishes into. */
[[nodiscard]] std::uint8_t class_ability_bucket(CharacterClass characterClass) noexcept {
    switch (characterClass) {
    case CharacterClass::hunter:
        return 9;
    case CharacterClass::warlock:
        return 11;
    case CharacterClass::titan:
    default:
        return 6;
    }
}

/** One ability lane's destination bucket + the field it fills. */
struct AbilityRoute {
    std::uint8_t bucket;
    std::uint8_t* field;
    std::uint8_t defaultEntry;
};

/**
 * Stages a subclass ability-entry transition without publishing account State. The requested
 * entry's resolved destination bucket names the one ability field it updates; a wide group
 * (an Attunement bundle) resets the reachable lanes to their defaults first.
 */
[[nodiscard]] bool stage_subclass_selection(const AccountState& snapshot,
                                            std::size_t characterIndex,
                                            std::uint64_t subclassInstanceSoid,
                                            std::uint8_t requestedEntry,
                                            PendingSubclassSelection& mutation) noexcept {
    mutation = {};
    if (!account::valid(snapshot) || characterIndex >= snapshot.characterCount
        || subclassInstanceSoid == 0 || requestedEntry >= socket_lists::kEntryCapacity) {
        return false;
    }
    const CharacterState& before = snapshot.characters[characterIndex];
    if (!before.selected || before.soid == 0) {
        return false;
    }
    constexpr std::size_t kSubclassSlot =
        static_cast<std::size_t>(inventory::EquipmentSlot::subclass);
    const auto& subclass = before.equipment.slots[kSubclassSlot];
    state::build_data::items::Definition subclassDefinition{};
    state::build_data::items::details::Definition detail{};
    socket_lists::EntryTable entries{};
    if (!subclass.has_value() || subclass->instanceSoid != subclassInstanceSoid
        || !state::build_data::find_item_definition_hash(subclass->definitionHash,
                                                         subclassDefinition)
        || !state::build_data::find_configured_item_detail(subclassDefinition.definitionIndex,
                                                           detail)
        || !state::build_data::find_socket_entry_table(detail.socketEntryListIndex, entries)
        || requestedEntry >= entries.entries.size()) {
        return false;
    }
    const socket_lists::Entry& requested = entries.entries[requestedEntry];
    if (requested.plugSource == socket_lists::kNoPlugSource
        || requested.group == socket_lists::kNoEntryGroup) {
        return false;
    }
    socket_buckets::Definition buckets{};
    if (!state::build_data::find_socket_entry_buckets(detail.socketEntryListIndex, buckets)) {
        return false;
    }

    CharacterState after = before;
    std::array<AbilityRoute, 5> routes{{
        {kMovementBucket, &after.movementAbilityEntry, kDefaultMovementAbilityEntry},
        {kGrenadeBucket, &after.grenadeAbilityEntry, kDefaultGrenadeAbilityEntry},
        {kSuperBucket, &after.superAbilityEntry, kDefaultSuperAbilityEntry},
        {kMeleeBucket, &after.meleeAbilityEntry, kDefaultMeleeAbilityEntry},
        {class_ability_bucket(after.characterClass), &after.classAbilityEntry,
         kDefaultClassAbilityEntry},
    }};
    const auto bucket_of = [&](std::uint8_t entryIndex) noexcept {
        return entryIndex < buckets.buckets.size() ? buckets.buckets[entryIndex]
                                                   : socket_buckets::kNoDestinationBucket;
    };
    const auto route_entry = [&](std::uint8_t entryIndex) noexcept {
        const std::uint8_t bucket = bucket_of(entryIndex);
        for (const AbilityRoute& route : routes) {
            if (route.bucket == bucket) {
                *route.field = entryIndex;
                return;
            }
        }
    };
    std::size_t groupPopulation = 0;
    for (const socket_lists::Entry& entry : entries.entries) {
        if (entry.group == requested.group) {
            ++groupPopulation;
        }
    }
    if (groupPopulation <= kMaxAttunementBundleSize) {
        route_entry(requestedEntry);
    } else {
        // A wide group is several same-sized bundles competing for one pick; reset every
        // reachable lane to its default first, then route the picked bundle's members.
        for (std::size_t index = 0; index < entries.entries.size(); ++index) {
            if (entries.entries[index].group != requested.group) {
                continue;
            }
            const std::uint8_t bucket = bucket_of(static_cast<std::uint8_t>(index));
            for (const AbilityRoute& route : routes) {
                if (route.bucket == bucket) {
                    *route.field = route.defaultEntry;
                }
            }
        }
        std::uint8_t blockStart = requestedEntry;
        while (blockStart > 0 && requestedEntry - blockStart < kMaxAttunementBundleSize - 1
               && entries.entries[blockStart - 1].group == requested.group) {
            --blockStart;
        }
        for (std::size_t offset = 0; offset < kMaxAttunementBundleSize
             && blockStart + offset < entries.entries.size()
             && entries.entries[blockStart + offset].group == requested.group;
             ++offset) {
            route_entry(static_cast<std::uint8_t>(blockStart + offset));
        }
    }
    if (after.movementAbilityEntry == before.movementAbilityEntry
        && after.grenadeAbilityEntry == before.grenadeAbilityEntry
        && after.superAbilityEntry == before.superAbilityEntry
        && after.meleeAbilityEntry == before.meleeAbilityEntry
        && after.classAbilityEntry == before.classAbilityEntry) {
        return false;
    }
    mutation.beforeCharacter = before;
    mutation.afterCharacter = after;
    mutation.accountSoid = snapshot.primarySoid;
    mutation.characterSoid = before.soid;
    mutation.subclassInstanceSoid = subclassInstanceSoid;
    mutation.requestedEntry = requestedEntry;
    mutation.socketEntryListIndex = detail.socketEntryListIndex;
    mutation.characterIndex = characterIndex;
    mutation.prepared = true;
    return true;
}

/** @return True when both characters carry the same ability picks. */
[[nodiscard]] bool same_ability_picks(const CharacterState& left,
                                      const CharacterState& right) noexcept {
    return left.movementAbilityEntry == right.movementAbilityEntry
           && left.grenadeAbilityEntry == right.grenadeAbilityEntry
           && left.superAbilityEntry == right.superAbilityEntry
           && left.meleeAbilityEntry == right.meleeAbilityEntry
           && left.classAbilityEntry == right.classAbilityEntry;
}

} // namespace

/** Prepares one checked subclass socket-entry selection without publishing account State. */
bool prepare_subclass_selection(std::uint64_t subclassInstanceSoid,
                                std::uint8_t requestedEntry,
                                PendingSubclassSelection& mutation) noexcept {
    mutation = {};
    const AccountState snapshot = account_snapshot();
    std::size_t characterIndex = snapshot.characterCount;
    if (account::valid(snapshot)) {
        for (std::size_t index = 0; index < snapshot.characterCount; ++index) {
            if (snapshot.characters[index].selected) {
                characterIndex = index;
                break;
            }
        }
    }
    if (characterIndex >= snapshot.characterCount
        || !stage_subclass_selection(
            snapshot, characterIndex, subclassInstanceSoid, requestedEntry, mutation)) {
        mutation = {};
        return false;
    }
    return true;
}

/** Commits one prepared subclass selection behind an exact staleness guard. */
bool commit_subclass_selection(PendingSubclassSelection& mutation) noexcept {
    const PendingSubclassSelection prepared = mutation;
    mutation = {};
    if (!prepared.prepared || prepared.characterSoid == 0 || prepared.subclassInstanceSoid == 0
        || prepared.characterIndex >= kCharacterCapacity
        || prepared.beforeCharacter.soid != prepared.characterSoid
        || prepared.afterCharacter.soid != prepared.characterSoid
        || same_ability_picks(prepared.beforeCharacter, prepared.afterCharacter)) {
        return false;
    }
    AcquireSRWLockExclusive(&runtime::storage::g_stateLock);
    AccountState candidate = runtime::storage::g_state.account;
    if (prepared.characterIndex >= candidate.characterCount
        || candidate.characters[prepared.characterIndex].soid != prepared.characterSoid
        || !same_ability_picks(candidate.characters[prepared.characterIndex],
                               prepared.beforeCharacter)) {
        ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
        return false;
    }
    PendingSubclassSelection canonical{};
    if (!stage_subclass_selection(candidate,
                                  prepared.characterIndex,
                                  prepared.subclassInstanceSoid,
                                  prepared.requestedEntry,
                                  canonical)
        || canonical.characterSoid != prepared.characterSoid
        || !same_ability_picks(canonical.afterCharacter, prepared.afterCharacter)) {
        ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
        return false;
    }
    candidate.characters[prepared.characterIndex] = prepared.afterCharacter;
    if (!account::valid(candidate)) {
        ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
        return false;
    }
    runtime::storage::g_state.account = candidate;
    ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
    return true;
}

} // namespace sunrise::state
