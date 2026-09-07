#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "../../../../core/settings/provisioning.h"

namespace sunrise::server::bap::encrypted::activity_message::activity_identity {

/** The identity blob: "steamid:<id>#<token>" + zero pad + the 0x06 version byte. */
inline constexpr std::size_t kIdentityBytes = 0x56;

/**
 * Stores the 0x56-byte SteamNetworkingIdentity form one client published in its
 * matchmaking advertisement, keyed by that client's account slot. The type-51
 * bubble-startup push echoes the RECIPIENT's own identity byte-exact (the
 * client's validator memcmps it against the client's own row), so the capture
 * must run before the push and the token is per-session (it changes every
 * boot — never cache across boots, never derive).
 * @param account The account slot the advertisement arrived on.
 * @param identity The 0x56-byte form ([0x55] = the 0x06 version byte).
 * @return True when stored.
 */
[[nodiscard]] bool store(core::settings::AccountKey account,
                         std::span<const std::byte, kIdentityBytes> identity) noexcept;

/**
 * Loads the stored identity for one account.
 * @param account The account slot.
 * @param output Receives the 0x56-byte form.
 * @return True when a captured identity exists for this account.
 */
[[nodiscard]] bool load(core::settings::AccountKey account,
                        std::span<std::byte, kIdentityBytes> output) noexcept;

} // namespace sunrise::server::bap::encrypted::activity_message::activity_identity
