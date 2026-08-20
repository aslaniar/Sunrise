#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "../../../../state/account/account_state.h"
#include "../../../../state/build_data/socket_entry_lists/definition.h"
#include "../instance/instance_encoder.h"

namespace sunrise::middleware::datagen::family4::loadout {

/** Selector lanes one item instance publishes, one per semantic ability bucket. */
inline constexpr std::size_t kSelectorBucketCount = 12;
/** Selected socket entries per subclass: sprint, class, movement, grenade, super and melee. */
inline constexpr std::size_t kSelectedEntryCount = 6;

/** One selected socket entry and the semantic bucket it publishes into. */
struct SelectedEntry {
    std::uint8_t entry{};
    std::uint8_t bucket{};
};

/** The 6 entries one character has selected on its subclass. */
struct SubclassSelection {
    std::array<SelectedEntry, kSelectedEntryCount> selected{};
};

/**
 * Builds the selection for one character. Only sprint is fixed; the grenade, super, melee,
 * movement and class entries are the character's own authored choices, and the bucket the class
 * ability publishes into follows its class.
 * @param character Authored character carrying its class and every ability choice.
 * @param output Receives the 6 selected entries.
 */
void subclass_selection(const state::CharacterState& character, SubclassSelection& output) noexcept;

/**
 * Resolves one item's socket-entry states and selector lanes.
 * Only a list that carries a super lane belongs to a subclass, so every other item keeps its
 * absent and ready states and publishes no selector.
 * @param definition Installed socket-entry-list mapping.
 * @param acquiredSubclassAbilityMask Per-entry bit mask of entries the player has selected at
 *        least once (the character's runtime field, all-set by default). A readyMask entry whose
 *        bit is set resolves to acquired (0x11) instead of ready (0x10) — the upstream contract:
 *        a fully unlocked tree ships acquired/active, never the purple ready state.
 * @param character Authored character carrying its class and every ability choice.
 * @param output Receives the state of every fixed lane.
 * @param selectors Receives the selector lane of every semantic bucket.
 */
void resolve_socket_states(
    const state::build_data::socket_entry_lists::Definition& definition,
    std::uint64_t acquiredSubclassAbilityMask,
    const state::CharacterState& character,
    std::array<instance::SocketEntryState, instance::layout::kSocketEntryStateCapacity>& output,
    std::array<instance::SocketSelector, kSelectorBucketCount>& selectors) noexcept;

/**
 * Resolves ONLY the baseline states (absent/ready per the ready mask, no active picks, no
 * selectors). The synthetic-reset frame's source: the equip publishes the item cleared to this
 * baseline first so the following select frame's multi-entry ready→active transitions form the
 * merge-class socket diff the client's notify keys on.
 */
void resolve_socket_states_baseline(
    const state::build_data::socket_entry_lists::Definition& definition,
    std::array<instance::SocketEntryState, instance::layout::kSocketEntryStateCapacity>& output,
    std::array<instance::SocketSelector, kSelectorBucketCount>& selectors) noexcept;

} // namespace sunrise::middleware::datagen::family4::loadout
