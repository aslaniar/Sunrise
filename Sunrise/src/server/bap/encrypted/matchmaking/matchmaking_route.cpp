#include "matchmaking_route.h"

#include <Windows.h>
#include "../../../../middleware/gameplay/descriptor/join_descriptor.h"
#include "../../../gameplay/endpoint/gameplay_endpoint.h"
#include "../../../../core/logging/log.h"
#include <cstdio>
#include <array>
#include <cstring>
#include <span>

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
/**
 * INSTRUMENT (FINDINGS 20.38): decodes one descriptor and logs the endpoint it names.
 *
 * We have built descriptors since the plane was wired and never read one back, so what a peer
 * actually publishes - and therefore what we forward to a searcher - has never been observed.
 * If the advertised endpoint is not a routable host, a searcher is correct to ignore it and
 * every field added to the search result is wasted. Strip once the peer link forms.
 *
 * @param stage Label naming where in the route the descriptor was seen.
 * @param descriptor Borrowed bytes, of any length: a wrong length is itself the finding.
 */
void log_descriptor(const char* stage, std::span<const std::byte> descriptor) noexcept {
    namespace join = middleware::gameplay::descriptor;
    if (descriptor.size() != join::kDescriptorSize) {
        core::log::write(core::log::Channel::server, core::log::Level::warn,
                         "ev=matchmaking stage=descriptor result=size_mismatch");
        return;
    }
    std::array<std::byte, join::kDescriptorSize> bytes{};
    std::memcpy(bytes.data(), descriptor.data(), bytes.size());
    join::JoinReading reading{};
    const bool routable = join::read(bytes, reading);

    std::array<char, 256> line{};
    const int count = std::snprintf(
        line.data(), line.size(),
        "ev=matchmaking stage=descriptor where=%s routable=%d machine=0x%016llX "
        "local=%u.%u.%u.%u:%u public=%u.%u.%u.%u:%u nat=%u method=%u session=0x%016llX",
        stage, routable ? 1 : 0,
        static_cast<unsigned long long>(reading.endpoint.machineId),
        reading.endpoint.address >> 24, (reading.endpoint.address >> 16) & 0xFF,
        (reading.endpoint.address >> 8) & 0xFF, reading.endpoint.address & 0xFF,
        reading.endpoint.port,
        reading.publicAddress >> 24, (reading.publicAddress >> 16) & 0xFF,
        (reading.publicAddress >> 8) & 0xFF, reading.publicAddress & 0xFF,
        reading.publicPort, reading.natType, reading.method,
        static_cast<unsigned long long>(reading.endpoint.onlineSessionId));
    if (count > 0) {
        core::log::write(core::log::Channel::server, core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(count)});
    }

    // FINDINGS 20.40: the decoded fields came back as PRINTABLE TEXT - "steami" where an IPv4
    // belongs, "957860" where the public one does - while the tail at offset 110 decoded to a
    // sensible Steam chat-lobby id. So the layout is partly right and partly wrong, and only
    // the raw bytes say which parts. Dumped in halves because one 128-byte hex line plus its
    // ASCII rendering does not fit a single log record.
    for (std::size_t half = 0; half < 2; ++half) {
        const std::size_t start = half * (join::kDescriptorSize / 2);
        std::array<char, 160> hex{};
        std::array<char, 80> text{};
        for (std::size_t index = 0; index < join::kDescriptorSize / 2; ++index) {
            static constexpr char kDigits[] = "0123456789ABCDEF";
            const auto value = static_cast<unsigned char>(bytes[start + index]);
            hex[index * 2] = kDigits[value >> 4];
            hex[(index * 2) + 1] = kDigits[value & 0x0F];
            text[index] = (value >= 0x20 && value < 0x7F) ? static_cast<char>(value) : '.';
        }
        std::array<char, 320> dump{};
        const int written = std::snprintf(dump.data(), dump.size(),
                                          "ev=matchmaking stage=descriptor where=raw off=%zu "
                                          "hex=%s ascii=%s",
                                          start, hex.data(), text.data());
        if (written > 0) {
            core::log::write(core::log::Channel::server, core::log::Level::info,
                             {dump.data(), static_cast<std::size_t>(written)});
        }
    }
}

/**
 * INSTRUMENT (FINDINGS 20.39): dumps one request body the parser found no descriptor in.
 *
 * The first boot with log_descriptor produced ZERO lines against a stream of
 * advertisement_update calls, which says every one of them parsed as descriptor-absent. That
 * has two readings - the client publishes no descriptor, or it publishes one under a field
 * shape we do not read - and the positive-only instrument cannot tell them apart. The raw body
 * can: it is small, and the 128-byte blob either appears in it or does not.
 *
 * @param body Borrowed request body, dumped up to the cap.
 */
void log_request_body(std::span<const std::byte> body) noexcept {
    // Two hex digits per byte, so the cap keeps one line inside the buffer below.
    constexpr std::size_t kDumpCap = 96;
    const std::size_t shown = body.size() < kDumpCap ? body.size() : kDumpCap;

    std::array<char, 256> hex{};
    for (std::size_t index = 0; index < shown; ++index) {
        static constexpr char kDigits[] = "0123456789ABCDEF";
        const auto value = static_cast<unsigned char>(body[index]);
        hex[index * 2] = kDigits[value >> 4];
        hex[(index * 2) + 1] = kDigits[value & 0x0F];
    }

    std::array<char, 384> line{};
    const int count = std::snprintf(line.data(), line.size(),
                                    "ev=matchmaking stage=descriptor where=absent len=%zu "
                                    "shown=%zu body=%s",
                                    body.size(), shown, hex.data());
    if (count > 0) {
        core::log::write(core::log::Channel::server, core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(count)});
    }

}

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
    // Both readings of a descriptor-absent advertisement get recorded, so the next boot
    // distinguishes "client sends none" from "we parse the wrong shape" (FINDINGS 20.39).
    if (request.kind == service::RequestKind::advertisementUpdate) {
        if (request.advertisement.hasDescriptor) {
            log_descriptor("publish", request.advertisement.descriptor);
        } else {
            log_request_body(requestBody);
        }
    }
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
        log_descriptor("serve", response.descriptor);
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
