#include "matchmaking_route.h"

#include <Windows.h>
#include "../../../../middleware/gameplay/descriptor/join_descriptor.h"
#include "../../../gameplay/endpoint/gameplay_endpoint.h"
#include "../../../../core/logging/log.h"
#include <cstdio>
#include <array>

#include "../../../../middleware/bap/matchmaking/request/matchmaking_request_parser.h"
#include "../../../../middleware/bap/matchmaking/response/matchmaking_response_encoder.h"

namespace sunrise::server::bap::encrypted::matchmaking {
namespace {

namespace service = middleware::bap::matchmaking;

/** Middleware parsing and State storage must accept the same runtime descriptor size. */
static_assert(service::kJoinDescriptorSize == state::matchmaking::kDescriptorSize);

/**
 * Finds the State-backed fields for the request kinds that are not static.
 * @param context Active logical matchmaking context.
 * @param request Fully validated request fields with a borrowed descriptor.
 * @param response Receives the response shape and any id State picked.
 * @param mutation Receives a prepared update without committing persistent State.
 * @return True when the request is static or all required State fields are available.
 */
[[nodiscard]] bool prepare_fields(state::matchmaking::ContextHandle context,
                                  const service::Request& request,
                                  service::Response& response,
                                  state::matchmaking::PendingMutation& mutation) noexcept {
    response.kind = request.kind;
    switch (request.kind) {
    case service::RequestKind::advertisementUpdate:
        return state::matchmaking::prepare_variant_update(context,
                                                          request.advertisement.existingId,
                                                          request.advertisement.variantKey,
                                                          request.advertisement.hasDescriptor,
                                                          request.advertisement.descriptor,
                                                          response.advertisementId,
                                                          mutation);
    case service::RequestKind::rejoinAdvertisementUpdate:
        return state::matchmaking::prepare_initial_latest(
            context, response.advertisementId, mutation);
    case service::RequestKind::none:
    case service::RequestKind::sessionSearch:
    case service::RequestKind::advertisementDelete:
    case service::RequestKind::configuration:
    case service::RequestKind::rejoinAdvertisementDelete:
    case service::RequestKind::locateSession:
    case service::RequestKind::liveStats:
        return true;
    }
    return false;
}


/**
 * Builds the join descriptor a searcher is handed.
 *
 * It points at THIS server's gameplay endpoint, which is the host of every instance here -
 * so there is nothing to reverse-engineer: `descriptor::build` is the same constructor the
 * citizen advertisement already uses, and p2(24) proved its output builds and ships.
 *
 * @param output Receives the 128-byte descriptor only when the channel can be advertised.
 * @return True when the gameplay endpoint is bound and carries a usable identity.
 */
[[nodiscard]] bool build_search_descriptor(
    std::array<std::byte, middleware::gameplay::descriptor::kDescriptorSize>& output) noexcept {
    output = {};
    if (!server::gameplay::endpoint::ready()) {
        return false;
    }
    const server::gameplay::endpoint::Identity identity = server::gameplay::endpoint::identity();
    const state::gameplay::Endpoint advertised = server::gameplay::endpoint::advertised();
    if (identity.machineId == 0 || advertised.port == 0) {
        return false;
    }
    middleware::gameplay::descriptor::JoinEndpoint join{};
    join.address = advertised.address;
    join.port = advertised.port;
    join.machineId = identity.machineId;
    join.onlineSessionId = identity.onlineSessionId;
    return middleware::gameplay::descriptor::build(join, output);
}

} // namespace

/** Prepares and encodes one kind-specific svc-43 response transaction. */
bool encode_response(state::matchmaking::ContextHandle context,
                     std::span<const std::byte> requestBody,
                     std::span<std::byte> output,
                     std::size_t& written,
                     state::matchmaking::PendingMutation& mutation,
                     bool& hasMutation) noexcept {
    written = 0;
    hasMutation = false;
    SecureZeroMemory(&mutation, sizeof mutation);
    const service::Request request = service::request::parse(requestBody);
    service::Response response{};
    if (!prepare_fields(context, request, response, mutation)) {
        // A correlated empty fallback clears the pending client task without publishing State.
        SecureZeroMemory(&mutation, sizeof mutation);
        response = {};
    }

    // FINDINGS 20.34/20.35: an empty search result is what kept every client alone. Answer with
    // ANOTHER context's advertisement - the session some other client actually published - not a
    // synthetic self-descriptor. A client handed its own session back has nothing to join, which
    // is why the solo boot could never have succeeded whatever we encoded.
    state::matchmaking::LatestSnapshot foreign{};
    if (response.kind == service::RequestKind::sessionSearch
        && state::matchmaking::foreign_advertisement(context, foreign) && foreign.hasDescriptor) {
        response.advertisementId = foreign.advertisementId;
        response.descriptor = std::span<const std::byte>(foreign.descriptor);
    }

    state::matchmaking::LatestSnapshot latest{};
    if (response.kind == service::RequestKind::locateSession
        && state::matchmaking::latest_snapshot(context, latest)) {
        response.advertisementId = latest.advertisementId;
        if (latest.hasDescriptor) {
            response.descriptor = std::span(latest.descriptor);
        }
    }
    const bool encoded = service::response::encode(response, output, written);
    // INSTRUMENT (architecture-review-2026-08-25): nine svc-42 calls were made last boot and
    // nothing recorded WHAT they asked for. Placement lives here - sessionSearch and
    // locateSession are how a client finds a session to join - so the request kind is the one
    // fact that confirms or kills the "we are one layer too deep" model. Strip once settled.
    {
        static constexpr const char* kKinds[] = {"none",
                                                 "session_search",
                                                 "advertisement_update",
                                                 "advertisement_delete",
                                                 "configuration",
                                                 "rejoin_advertisement_update",
                                                 "rejoin_advertisement_delete",
                                                 "locate_session",
                                                 "live_stats"};
        const auto index = static_cast<std::size_t>(request.kind);
        std::array<char, 160> line{};
        const int count = std::snprintf(
            line.data(),
            line.size(),
            "ev=matchmaking stage=request kind=%s served_descriptor=%u advertisement=0x%llX "
            "encoded=%u bytes=%zu",
            index < (sizeof kKinds / sizeof kKinds[0]) ? kKinds[index] : "unknown",
            response.descriptor.empty() ? 0U : 1U,
            static_cast<unsigned long long>(response.advertisementId),
            encoded ? 1U : 0U,
            written);
        if (count > 0) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(count)});
        }
    }

    state::matchmaking::erase_snapshot(latest);
    if (!encoded) {
        written = 0;
        SecureZeroMemory(&mutation, sizeof mutation);
        return false;
    }
    hasMutation = mutation.kind != state::matchmaking::MutationKind::none;
    return true;
}

} // namespace sunrise::server::bap::encrypted::matchmaking
