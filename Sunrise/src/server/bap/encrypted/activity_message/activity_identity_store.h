#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "../../../../core/settings/provisioning.h"

namespace sunrise::server::bap::encrypted::activity_message::activity_identity {

/** The identity blob: "steamid:<id>#<token>" + zero pad + the 0x06 version byte. */
inline constexpr std::size_t kIdentityBytes = 0x56;

/**
 * Stores one 0x56-byte SteamNetworkingIdentity form under an explicit 64-bit
 * key. The type-51 bubble-startup push echoes the RECIPIENT's own identity
 * byte-exact (the client's validator memcmps it against the client's own row),
 * so the capture must be attributable to the recipient THE PUSH CAN NAME.
 *
 * The capture side (matchmaking advertisement) can only name the advertiser by
 * its "steamid:<digits>" member id; the push side (join burst) can only name
 * the joiner by the wire memberKey its join request carried. Those two
 * namespaces have NO proven formula (FINDINGS 20.329 + the p2-203 matrix), so
 * the store is keyed by whichever u64 the caller has, and BOTH call sites log
 * their keys - the boot readout resolves the pairing. The previous account-slot
 * keying was provably cross-attributing (both machines' early advertisements
 * landed on one slot; p2-203's rig push echoed the mac's token).
 *
 * The token is per-session (it changes every boot - never cache across boots,
 * never derive).
 * @param key The key namespace of the caller (steamid digits at capture,
 *            wire memberKey at push).
 * @param identity The 0x56-byte form ([0x55] = the 0x06 version byte).
 * @return True when stored.
 */
[[nodiscard]] bool store(std::uint64_t key,
                         std::span<const std::byte, kIdentityBytes> identity) noexcept;

/**
 * Loads the stored identity for one key.
 * @param key The key the capture stored under.
 * @param output Receives the 0x56-byte form.
 * @return True when a captured identity exists for this key.
 */
[[nodiscard]] bool load(std::uint64_t key,
                        std::span<std::byte, kIdentityBytes> output) noexcept;

} // namespace sunrise::server::bap::encrypted::activity_message::activity_identity