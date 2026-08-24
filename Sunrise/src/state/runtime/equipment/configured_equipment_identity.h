#pragma once

#include <cstdint>

#include "../../account/account_state.h"

namespace sunrise::state::runtime::equipment {

/**
 * Builds a nonsecret cache identity from ordered authored equipment.
 * @param accountState Checked account with canonical character and semantic-slot order.
 * @return Stable presence, base-hash, and authored-level fingerprint.
 */
[[nodiscard]] std::uint64_t configured_hash(const AccountState& accountState) noexcept;

/**
 * Folds every settings-provisioned account's configured hash in slot order.
 * Single-slot hosts reduce EXACTLY to configured_hash(slot0), preserving
 * historical cache identities byte for byte; multi-slot hosts get one stable
 * identity that never oscillates with database reload state.
 * @return The provisioned-union equipment fingerprint.
 */
[[nodiscard]] std::uint64_t configured_hash_provisioned() noexcept;

} // namespace sunrise::state::runtime::equipment
