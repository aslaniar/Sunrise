/**
 * Subclass socket selection. An item's socket entries start absent or ready; the entries the
 * character has selected make their whole group active, and the super lane is active although it
 * carries no plug source.
 */

#include "subclass_socket_selection.h"

#include "../../../../state/build_data/runtime.h"

namespace sunrise::middleware::datagen::family4::loadout {
namespace {

namespace build_socket_lists = state::build_data::socket_entry_lists;

/** Bucket the grenade publishes into. Entry order is sprint, class, movement, grenade, super,
 * melee, so the entries themselves are the character's own choices. */
constexpr std::uint8_t kGrenadeBucket = 0;
/** Bucket the super publishes into. */
constexpr std::uint8_t kSuperBucket = 1;
/** Bucket the melee publishes into. */
constexpr std::uint8_t kMeleeBucket = 2;
/** Bucket the movement ability publishes into. */
constexpr std::uint8_t kMovementBucket = 3;
/** Bucket the sprint publishes into. Sprint is not selectable, so its entry is fixed. */
constexpr std::uint8_t kSprintBucket = 4;
/** Socket entry of the sprint ability. */
constexpr std::uint8_t kSprintEntry = 1;

/** @param characterClass Authored class. @return The bucket its class ability publishes into. */
[[nodiscard]] std::uint8_t class_ability_bucket(state::CharacterClass characterClass) noexcept {
    switch (characterClass) {
    case state::CharacterClass::hunter:
        return 9;
    case state::CharacterClass::warlock:
        return 11;
    case state::CharacterClass::titan:
    default:
        return 6;
    }
}

} // namespace

/** Builds the selection for one character. */
void subclass_selection(const state::CharacterState& character,
                        SubclassSelection& output) noexcept {
    output = {};
    output.selected[0] = {character.grenadeAbilityEntry, kGrenadeBucket};
    output.selected[1] = {character.superAbilityEntry, kSuperBucket};
    output.selected[2] = {character.meleeAbilityEntry, kMeleeBucket};
    output.selected[3] = {character.movementAbilityEntry, kMovementBucket};
    output.selected[4] = {kSprintEntry, kSprintBucket};
    output.selected[5] = {character.classAbilityEntry,
                          class_ability_bucket(character.characterClass)};
}

/** Resolves ONLY the baseline states — the synthetic-reset frame's source. */
void resolve_socket_states_baseline(
    const build_socket_lists::Definition& definition,
    std::array<instance::SocketEntryState, instance::layout::kSocketEntryStateCapacity>& output,
    std::array<instance::SocketSelector, kSelectorBucketCount>& selectors) noexcept {
    output.fill(instance::SocketEntryState::absent);
    selectors.fill(instance::SocketSelector{});
    for (std::size_t index = 0; index < definition.entryCount; ++index) {
        const std::uint64_t bit = std::uint64_t{1} << index;
        if ((definition.readyMask & bit) != 0) {
            output[index] = instance::SocketEntryState::ready;
        }
    }
}

/** Resolves one item's socket-entry states and selector lanes. */
void resolve_socket_states(
    const build_socket_lists::Definition& definition,
    std::uint64_t acquiredSubclassAbilityMask,
    const state::CharacterState& character,
    std::array<instance::SocketEntryState, instance::layout::kSocketEntryStateCapacity>& output,
    std::array<instance::SocketSelector, kSelectorBucketCount>& selectors) noexcept {
    // The upstream's baseline (subclass_socket_selection.cpp ll. 42-51): every readyMask
    // entry starts acquired when its bit is set in the character's runtime mask, ready
    // otherwise — never a ready-only baseline, so a fully unlocked tree ships
    // {acquired, active} only and the Client's ready tier (the purple diamond) stays
    // quiet.
    output.fill(instance::SocketEntryState::absent);
    selectors.fill(instance::SocketSelector{});
    for (std::size_t index = 0; index < definition.entryCount; ++index) {
        const std::uint64_t bit = std::uint64_t{1} << index;
        if ((definition.readyMask & bit) != 0) {
            output[index] = (acquiredSubclassAbilityMask & bit) != 0
                                ? instance::SocketEntryState::acquired
                                : instance::SocketEntryState::ready;
        }
    }
    // Only a subclass keeps an entry table, so this lookup is what identifies one.
    build_socket_lists::EntryTable entries{};
    if (!state::build_data::find_socket_entry_table(definition.definitionIndex, entries)) {
        return;
    }
    SubclassSelection selection{};
    subclass_selection(character, selection);

    // A group of 2 or 3 entries is mutually exclusive alternatives: exactly one lights up. An
    // Attunement's group packs several 4-node options into one group id, so a population past the
    // widest single bundle means its members activate in same-sized runs.
    std::array<std::uint16_t, build_socket_lists::kEntryCapacity> groupPopulation{};
    for (std::size_t index = 0; index < definition.entryCount; ++index) {
        const std::uint8_t group = entries.entries[index].group;
        if (group < groupPopulation.size()) {
            ++groupPopulation[group];
        }
    }
    // Each selected entry claims its group. Every entry sharing that group and plug source is
    // active too, which is why a run of duplicate lanes flips together.
    std::array<std::uint32_t, build_socket_lists::kEntryCapacity> chosen{};
    std::array<bool, build_socket_lists::kEntryCapacity> claimed{};
    std::array<bool, build_socket_lists::kEntryCapacity> forcedActive{};
    for (const SelectedEntry& selected : selection.selected) {
        if (selected.entry >= definition.entryCount || selected.bucket >= selectors.size()) {
            continue;
        }
        selectors[selected.bucket] = instance::SocketSelector{selected.entry, 0, 0};
        const build_socket_lists::Entry& entry = entries.entries[selected.entry];
        if (entry.plugSource == build_socket_lists::kNoPlugSource || entry.group >= claimed.size()
            || claimed[entry.group]) {
            continue;
        }
        claimed[entry.group] = true;
        chosen[entry.group] = entry.plugSource;
        if (groupPopulation[entry.group] <= state::kMaxAttunementBundleSize) {
            continue;
        }
        // A pick can bundle several consecutive entries under the same group, all publishing
        // together. Siblings carry their own plug source, so force the whole contiguous run
        // active rather than relying on the plug-source match below.
        forcedActive[selected.entry] = true;
        for (std::size_t offset = 1;
             offset < state::kMaxAttunementBundleSize
             && selected.entry + offset < definition.entryCount
             && entries.entries[selected.entry + offset].group == entry.group;
             ++offset) {
            forcedActive[selected.entry + offset] = true;
        }
    }
    for (std::size_t index = 0; index < definition.entryCount; ++index) {
        const build_socket_lists::Entry& entry = entries.entries[index];
        const bool matchesGroup = entry.plugSource != build_socket_lists::kNoPlugSource
                                  && entry.group < claimed.size() && claimed[entry.group]
                                  && chosen[entry.group] == entry.plugSource;
        const bool superLane = entry.plugSource == build_socket_lists::kNoPlugSource
                               && entry.kind == build_socket_lists::kSuperEntryKind;
        if (matchesGroup || superLane || forcedActive[index]) {
            output[index] = instance::SocketEntryState::active;
        }
    }
}

} // namespace sunrise::middleware::datagen::family4::loadout
