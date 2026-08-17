#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "../../../../state/account/inventory/inventory_state.h"
#include "../instance/instance_encoder.h"

namespace sunrise::middleware::datagen::family4::loadout {

/**
 * One selected item can occupy each of the 16 authored semantic equipment slots, and one
 * character may additionally carry its non-equipped storage items.
 */
inline constexpr std::size_t kItemCapacity = state::account::inventory::kEquipmentSlotCount
                                             + state::account::inventory::kCharacterStorageCapacity;

/** One installed-build-resolved item ready for character and instance encoding. */
struct ResolvedItem {
    std::uint16_t inventoryRow{};
    std::uint8_t equipmentSlot{};
    std::int32_t quantity{};
    /** False for non-equipped storage rows: they publish no equippedInstanceSoids entry. */
    bool equipped{true};
    instance::ResolvedInstance instance{};
    /** Authored runtime generation copied into the native inventory row. */
    std::int32_t mutationSerial{};
    /** Accumulated native item-state bits copied into the native inventory row. */
    std::uint32_t flags{};
};

/** One item instance together with the native equipment slot that owns it. */
struct SlottedInstance {
    std::uint8_t equipmentSlot{};
    instance::ResolvedInstance instance{};
};

/** Every item instance one character owns, whether or not that character is selected. */
struct ResolvedInstances {
    std::array<SlottedInstance, kItemCapacity> items{};
    std::size_t itemCount{};
};

/** Complete selected-character loadout committed only after every mapping resolves. */
struct ResolvedLoadout {
    std::array<ResolvedItem, kItemCapacity> items{};
    std::size_t itemCount{};
    std::uint32_t nextInventorySerial{};
};

} // namespace sunrise::middleware::datagen::family4::loadout
