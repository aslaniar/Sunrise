#pragma once

#include <cstdint>
#include <span>

#include "state.h"

namespace sunrise::state {

/**
 * Loads cached build data and generates secrets with Sunrise's authored activity defaults.
 * @param module Loaded Sunrise module, or null to disable disk persistence.
 * @param initialAccount Empty State, or a complete checked account from Core settings.
 * @return True when the cached data passes its checks and every secret is generated.
 */
[[nodiscard]] bool initialize(void* module = nullptr,
                              const AccountState& initialAccount = {}) noexcept;

/**
 * Loads cached build data and publishes fixed activity defaults in one step.
 * @param module Loaded Sunrise module, or null to disable disk persistence.
 * @param initialAccount Empty State, or a complete checked account from Core settings.
 * @param activityDefaults Complete local fallback policy from immutable Core settings.
 * @return True when account, defaults, cached data, and generated secrets are valid.
 */
[[nodiscard]] bool
initialize(void* module,
           const AccountState& initialAccount,
           const activity::defaults::ActivityDefaults& activityDefaults) noexcept;

/** Securely clears State, including activity destinations and matchmaking descriptors. */
void shutdown() noexcept;

/** @return Immutable generated SignOn session fields. */
[[nodiscard]] const SignOnState& sign_on() noexcept;

[[nodiscard]] bool publish_bootstrap_token(std::span<const std::byte> token) noexcept;

/** @return Immutable generated BAP session fields. */
[[nodiscard]] const BapState& bap() noexcept;

/**
 * Stores the active nonzero account key when the account remains complete.
 * @param primarySoid Account key selected by the local Client.
 * @return False when the key or resulting account State is invalid.
 */
[[nodiscard]] bool set_primary_soid(std::uint64_t primarySoid) noexcept;

/**
 * Moves the selection to one authored character.
 * The Client names its pick only in the select-character request, so this is where a player's
 * choice enters State.
 * @param characterSoid Picked character key, which must name an authored character.
 * @param changed Receives whether the selection moved to a different character.
 * @return False when no authored character carries that key.
 */
[[nodiscard]] bool set_selected_character(std::uint64_t characterSoid, bool& changed) noexcept;

/** @return A copy of the active account state, read under the lock. */
[[nodiscard]] AccountState account_snapshot() noexcept;
/** @return A copy of the evaluated content state, read under the lock. */
[[nodiscard]] InvestmentState investment_snapshot() noexcept;

/**
 * Applies one opcode-2100 ability change to the selected character. The definition
 * hash names a socket entry of the equipped subclass's entry list; the entry's
 * competition group names the lane (movement/grenade/super/melee/class), and that
 * lane's pick moves to the named entry.
 * @param definitionHash The ability definition hash the Client's 2100 carried.
 * @return True when a selected character equips a subclass that offers the entry
 *         and the whole account stayed valid after the move.
 */
[[nodiscard]] bool apply_ability_change(std::uint32_t definitionHash) noexcept;

/** One prepared opcode-801 subclass socket-entry selection, ready to commit. */
struct PendingSubclassSelection {
    state::CharacterState beforeCharacter{};
    state::CharacterState afterCharacter{};
    std::uint64_t accountSoid{};
    std::uint64_t characterSoid{};
    std::uint64_t subclassInstanceSoid{};
    std::uint8_t requestedEntry{};
    std::uint16_t socketEntryListIndex{};
    std::size_t characterIndex{};
    bool prepared{};
};

/**
 * Prepares one checked subclass socket-entry selection without publishing account State.
 * @param subclassInstanceSoid Instance key of the equipped subclass the selection names.
 * @param requestedEntry Zero-based socket-entry index the Client picked.
 * @param mutation Receives the before/after character pair when the entry routes.
 * @return True when the entry's resolved bucket names one ability field it changes.
 */
[[nodiscard]] bool prepare_subclass_selection(std::uint64_t subclassInstanceSoid,
                                              std::uint8_t requestedEntry,
                                              PendingSubclassSelection& mutation) noexcept;

/**
 * Commits one prepared subclass selection behind an exact character staleness guard.
 * @param mutation The prepared selection; cleared on failure.
 * @return True when the whole account stayed valid and the selection published.
 */
[[nodiscard]] bool commit_subclass_selection(PendingSubclassSelection& mutation) noexcept;

/**
 * Equips one storage item onto the selected character's subclass slot, returning the
 * displaced subclass to storage. The request must name a bucket-16 storage item the
 * selected character owns; the policy check and the mutation share the same data so the
 * staging step cannot fail after a request passed.
 * @param itemSoid Instance key of the storage item to equip.
 * @param displacedSoid Receives the previously equipped subclass instance key, or zero.
 * @return True when the swap left the whole account valid and was published.
 */
[[nodiscard]] bool equip_subclass_item(std::uint64_t itemSoid,
                                       std::uint64_t& displacedSoid) noexcept;

/**
 * Checks the subclass-equip request policy without touching State.
 * @param itemSoid Instance key the Client asked to equip.
 * @return True when a selected character owns that key in storage and the definition is a
 *         bucket-16 (subclass) item.
 */
[[nodiscard]] bool subclass_equip_request_valid(std::uint64_t itemSoid) noexcept;

/**
 * Replaces the published family-5 override lists with the persisted rows.
 * Object identity (objectSoid) and the content-gate arm stay owned by State.
 * @param family Bounded override lists read back from the state database.
 * @return False when the counts exceed the fixed capacities.
 */
[[nodiscard]] bool publish_family5(const Family5State& family) noexcept;

} // namespace sunrise::state
