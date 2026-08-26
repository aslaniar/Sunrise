#pragma once

/** Shared P2 provisioning constants: the per-peer account key vocabulary. */

#include <cstddef>
#include <cstdint>

namespace sunrise::core::settings {

/** Fixed upper bound on simultaneously provisioned accounts (== BAP peer slots). */
inline constexpr std::size_t kAccountCapacity = 4;

/** Index into the provisioned account set. Slot 0 is the historical sole account. */
using AccountKey = std::uint8_t;

/** The first slot: existing settings.json and state.db rows map here unchanged. */
inline constexpr AccountKey kLegacyAccount = 0;

/** Sentinel for an authenticated peer whose token matches no provisioned account. */
inline constexpr AccountKey kUnprovisionedAccount = 0xFF;

/**
 * @return The provisioned account THIS INSTALL plays as (`state.local_account_key`).
 *
 * Client-side code must use this and never `kLegacyAccount`. The server is different: it
 * serves many peers in one process and keys each session off the sign-on token it matched,
 * so `session.accountKey` is its answer. This is the answer for the one identity the local
 * install owns, and getting it wrong is silent - both machines published the same account
 * and the client refused its own roster with `tried-to-join-self` (FINDINGS 20.64).
 */
[[nodiscard]] AccountKey local_account() noexcept;

} // namespace sunrise::core::settings
