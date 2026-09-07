#pragma once

#include <cstddef>
#include <span>

#include "../../../../core/settings/provisioning.h"
#include "../../../../state/matchmaking/matchmaking_state.h"

namespace sunrise::server::bap::encrypted::matchmaking {

/**
 * Prepares and encodes one kind-specific svc-43 response transaction.
 * @param context State-owned logical matchmaking context for this BAP session.
 * @param accountKey The account slot the request arrived on (the advertisement
 *        update carries the client's SteamNetworkingIdentity - captured here for
 *        the type-51 bubble-startup echo).
 * @param requestBody Whole decrypted svc-42 protobuf body.
 * @param output Caller-owned svc-43 body storage.
 * @param written Receives the encoded body size, or zero on failure.
 * @param mutation Receives a State mutation that stays pending until the outer frame exists.
 * @param hasMutation Receives true only when the successful response needs a later commit.
 * @return True when a kind-specific or empty fallback body is fully encoded.
 */
[[nodiscard]] bool encode_response(state::matchmaking::ContextHandle context,
                                   core::settings::AccountKey accountKey,
                                   std::span<const std::byte> requestBody,
                                   std::span<std::byte> output,
                                   std::size_t& written,
                                   state::matchmaking::PendingMutation& mutation,
                                   bool& hasMutation) noexcept;

} // namespace sunrise::server::bap::encrypted::matchmaking
