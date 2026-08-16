#include <Windows.h>

#include <cstddef>
#include <cstdint>

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
bool equip_subclass_item(std::uint64_t itemSoid, std::uint64_t& displacedSoid) noexcept {
    displacedSoid = 0;
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
    const std::optional<account::inventory::Item>& previous =
        character.equipment.slots[static_cast<std::size_t>(
            account::inventory::EquipmentSlot::subclass)];
    if (previous.has_value()) {
        if (character.storageItemCount >= character.storageItems.size()) {
            ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
            return false;
        }
        displacedSoid = previous->instanceSoid;
        character.storageItems[character.storageItemCount++] = *previous;
    }
    character.equipment.slots[static_cast<std::size_t>(
        account::inventory::EquipmentSlot::subclass)] = picked;
    if (!account::valid(candidate)) {
        ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
        return false;
    }
    // Publish only after the whole account still meets its identity rules.
    runtime::storage::g_state.account = candidate;
    ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
    return true;
}

} // namespace sunrise::state
