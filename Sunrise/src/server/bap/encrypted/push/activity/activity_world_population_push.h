#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "../../../internal.h"

namespace sunrise::server::bap::encrypted::push::activity {

/**
 * Appends the S2-0 world-population notifications: one entity-baseline push on the
 * configured carrier type, then the patch-epoch bump (type 52). Emits nothing unless
 * server.worldPopulation is enabled in settings; the carrier type and the archetype
 * schema tag hash come from server.worldPopulationCarrier / .worldPopulationSchemaHash.
 * @param scratch Lock-owned transform buffers.
 * @param sessionId Nonzero activity id echoed in the svc9 envelope.
 * @param key Active AES-GCM session key.
 * @param nonce Local send nonce advanced once per staged notification.
 * @param response Lock-owned complete-frame staging storage.
 * @param written Existing staged byte count, updated only after every notification exists.
 * @return True when the whole sequence encodes atomically, or when the feature is off.
 */
[[nodiscard]] bool append_world_population_notifications(
    Scratch& scratch,
    std::uint64_t sessionId,
    std::span<const std::byte, state::kAesKeySize> key,
    std::array<std::byte, state::kBapNonceSize>& nonce,
    std::span<std::byte> response,
    std::size_t& written) noexcept;

} // namespace sunrise::server::bap::encrypted::push::activity
