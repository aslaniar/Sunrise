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

} // namespace sunrise::core::settings
