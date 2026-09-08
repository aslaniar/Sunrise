#pragma once

#include <cstddef>
#include <span>

#include "../../../../core/settings/provisioning.h"
#include "../../../../state/matchmaking/matchmaking_state.h"

namespace sunrise::server::bap::encrypted::matchmaking {

/**
 * Prepares and encodes one kind-specific svc-43 response transaction.
 * @param identityEcho The 8-byte session-token prefix this connection echoed
 *        at server hello (session.identityEcho) - the identity-store key for
 *        the type-51 bubble-startup echo. It survives reconnects (per-client
 *        stable, measured: mac CF0A98397F164482, rig 945602D41E66AC20 over
 *        every connection of p2-204 v2), unlike account slots (shared across
 *        machines, p2-203) and BAP session ids (every join spawns a fresh one
 *        while ads stick to the first, p2-204).
 * @param context State-owned logical matchmaking context for this BAP session.
 * @param accountKey The account slot the request arrived on (logged only).
 * @param requestBody Whole decrypted svc-42 protobuf body.
 * @param output Caller-owned svc-43 body storage.
 * @param written Receives the encoded body size, or zero on failure.
 * @param mutation Receives a State mutation that stays pending until the outer frame exists.
 * @param hasMutation Receives true only when the successful response needs a later commit.
 * @return True when a kind-specific or empty fallback body is fully encoded.
 */
[[nodiscard]] bool encode_response(std::uint64_t identityEcho,
                                   state::matchmaking::ContextHandle context,
                                   core::settings::AccountKey accountKey,
                                   std::span<const std::byte> requestBody,
                                   std::span<std::byte> output,
                                   std::size_t& written,
                                   state::matchmaking::PendingMutation& mutation,
                                   bool& hasMutation) noexcept;

} // namespace sunrise::server::bap::encrypted::matchmaking
