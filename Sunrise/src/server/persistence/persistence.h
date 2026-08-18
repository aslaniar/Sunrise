#pragma once

#include <cstddef>
#include <cstdint>

#include "../../state/account/account_state.h"
#include "../../state/entitlements/definition.h"
#include "../../state/investment/investment.h"
#include "../../state/unlocks/definition.h"

namespace sunrise::server::persistence {

/** The state database file name under the shared generated-artifact directory. */
inline constexpr wchar_t kDatabaseFileName[] = L"state.db";

/**
 * Opens and migrates the state database, seeding it from the authored settings when it is
 * empty. The seed is the captured default state (the settings `state` block), so the first
 * boot creates a database that is byte-faithful to the working capture. Later boots load the
 * persisted rows instead of re-seeding.
 * @param module Loaded module used to resolve the artifact directory.
 * @return True when the database is open, migrated, and seeded or loaded.
 */
[[nodiscard]] bool initialize(void* module) noexcept;

/** Closes the state database and releases its lock. */
void shutdown() noexcept;

/** @return True when a state database is open and usable. */
[[nodiscard]] bool ready() noexcept;

/**
 * Reads the persisted account back into native State.
 * @param account Receives the account identity, characters, and profile items.
 * @param unlocks Receives the six expanded unlock banks.
 * @param family5 Receives the persisted family-5 override lists.
 * @return True when every table reads back into the fixed native shapes.
 */
[[nodiscard]] bool load_account(state::AccountState& account,
                                state::unlocks::Table& unlocks,
                                state::Family5State& family5) noexcept;

/**
 * Reads the persisted entitlement policy back into native State.
 * @param output Receives the ownership table.
 * @return True when the entitlement rows fit the native table.
 */
[[nodiscard]] bool load_entitlements(state::entitlements::Table& output) noexcept;

/**
 * Writes the current published State back into the state database (spec §4 Stage 5).
 * Replaces the account-owned rows (characters, items, plugs, flags, objectives, family-5
 * overrides, entitlements) in one transaction from the published State. The content mirror
 * (vendors/vendor_sale_items) and the encode-derived tables (instance_state/progression)
 * are left untouched.
 * @return True when every row is replaced and committed.
 */
[[nodiscard]] bool write_back() noexcept;

/**
 * Persists one subclass equip in a single transaction: the picked storage row becomes the
 * character's equipped subclass (slot 11) and the displaced row returns to storage. The
 * scope is the seed account's two affected rows only; every other row is untouched.
 * @param newlyEquippedSoid Instance key now equipped.
 * @param displacedSoid Instance key returned to storage, or zero when the slot was empty.
 * @return True when both updates commit.
 */
[[nodiscard]] bool persist_subclass_equip(std::uint64_t newlyEquippedSoid,
                                          std::uint64_t displacedSoid) noexcept;

/**
 * Persists the selected character's five ability-entry picks in one transaction, reading
 * them from the published State (the opcode-2100 mutation already landed there). The scope
 * is the selected character's row only.
 * @return True when the update commits.
 */
[[nodiscard]] bool persist_ability_change() noexcept;

} // namespace sunrise::server::persistence
