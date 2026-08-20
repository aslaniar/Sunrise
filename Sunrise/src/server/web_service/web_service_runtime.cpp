#include "web_service_runtime.h"

#include <array>
#include <cstdio>

#include "../../core/logging/log.h"
#include "../../middleware/web_service/messages/opcode205.h"
#include "../../middleware/web_service/messages/opcode206.h"
#include "../../middleware/web_service/messages/opcode501_codec.h"
#include "../../middleware/web_service/messages/opcode503.h"
#include "../../middleware/web_service/messages/opcode504.h"
#include "../../middleware/web_service/messages/opcode801.h"
#include "../../middleware/web_service/messages/opcode601/opcode601_codec.h"
#include "../../middleware/web_service/web_service_envelope.h"
#include "../../state/account/account_state.h"
#include "../../state/runtime/runtime.h"
#include "opcode_routes.h"

namespace sunrise::server::web_service {

/** One log line carries the opcode and its fixed prefix. */
constexpr std::size_t kOpcodeLineCapacity = 64;

/**
 * Logs which Web Service opcode arrived. One svc-10 frame looks like any other in the log, and
 * the opcodes the Client sends are what drive its queuez state machine.
 * @param opcode Parsed wire opcode.
 */
void report_opcode(std::uint32_t opcode) noexcept {
    std::array<char, kOpcodeLineCapacity> line{};
    const int written =
        std::snprintf(line.data(), line.size(), "ev=ws stage=request opcode=%u", opcode);
    if (written > 0) {
        core::log::write(core::log::Channel::server,
                         core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(written)});
    }
}

/** One line carries the picked id and whether the selection moved. */
constexpr std::size_t kSelectLineCapacity = 96;

/**
 * Records the player's character pick, which arrives nowhere else.
 * A bad or unknown id leaves the selection alone. The reply is the status pair either way. The
 * Family-4 object move follows this call, and the family-zero pair after it.
 * @param message Parsed select-character request.
 * @param outcome Gets the picked key once the selection has moved in State.
 */
void select_character(const middleware::web_service::Message& message, Outcome& outcome) noexcept {
    middleware::web_service::messages::opcode504::Request picked;
    if (!middleware::web_service::messages::opcode504::parse_request(message, picked)) {
        core::log::write(
            core::log::Channel::server, core::log::Level::warn, "ev=ws504 stage=parse result=fail");
        return;
    }
    bool changed = false;
    if (!state::set_selected_character(picked.characterSoid, changed)) {
        core::log::write(core::log::Channel::server,
                         core::log::Level::warn,
                         "ev=ws504 stage=select result=unknown");
        return;
    }
    outcome.hasSelectedCharacter = true;
    outcome.selectedCharacterSoid = picked.characterSoid;

    std::array<char, kSelectLineCapacity> line{};
    const int written = std::snprintf(line.data(),
                                      line.size(),
                                      "ev=ws504 stage=select result=ok soid=0x%llX changed=%u",
                                      static_cast<unsigned long long>(picked.characterSoid),
                                      static_cast<unsigned>(changed));
    if (written > 0) {
        core::log::write(core::log::Channel::server,
                         core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(written)});
    }
}

/**
 * Answers a request whose own codec refused with the bare correlated echo.
 * The Client matches on the echoed transaction id. A missing body is worse than a thin one. It
 * under-runs the decoder and takes the BAP connection down.
 * @param message Parsed request whose correlation fields are echoed.
 * @param response Svc-11 response-body storage owned by the caller.
 * @param written Gets the encoded response-body size in bytes.
 * @return True when the echo fits.
 */
bool encode_echo(const middleware::web_service::Message& message,
                 std::span<std::byte> response,
                 std::size_t& written) noexcept {
    std::array<char, kOpcodeLineCapacity> line{};
    const int count = std::snprintf(
        line.data(), line.size(), "ev=ws stage=body result=echo opcode=%u", message.opcode);
    if (count > 0) {
        core::log::write(core::log::Channel::server,
                         core::log::Level::warn,
                         {line.data(), static_cast<std::size_t>(count)});
    }
    namespace ws = middleware::web_service;
    return ws::encode_response(
        message, ws::ResponseShape::generic, ws::StatusResponse{}, response, written);
}

/**
 * Parses and answers one Web Service request with its whole descriptor layout.
 * @param request Whole decrypted svc-10 body.
 * @param response Svc-11 response-body storage owned by the caller.
 * @param written Gets the encoded response-body size, or zero when the header does not parse.
 * @return False only when the envelope header does not parse.
 */
bool consume(std::span<const std::byte> request,
             std::span<std::byte> response,
             std::size_t& written) noexcept {
    Outcome outcome;
    return consume(request, response, written, outcome);
}

/**
 * Parses one request, encodes its response, and publishes checked side effects last.
 * @param request Whole decrypted svc-10 body.
 * @param response Svc-11 response-body storage owned by the caller.
 * @param written Gets the encoded response-body size, or zero when the header does not parse.
 * @param outcome Gets a valid family selector only after the response is encoded.
 * @return False only when the envelope header does not parse.
 */
bool consume(std::span<const std::byte> request,
             std::span<std::byte> response,
             std::size_t& written,
             Outcome& outcome) noexcept {
    written = 0;
    outcome = {};
    middleware::web_service::Message message;
    if (!middleware::web_service::parse_request(request, message)) {
        core::log::write(
            core::log::Channel::server, core::log::Level::warn, "ev=ws stage=parse result=fail");
        return false;
    }
    report_opcode(message.opcode);

    // Inventory verb capture (temporary diagnostic; removed after the grammar is read):
    // dump the unmapped opcodes' transaction id, payload size, and first bytes so the
    // 701/702 subclass-swap and 2100 ability-change request shapes can be read live.
    if (message.opcode != middleware::web_service::messages::opcode205::kOpcode
        && message.opcode != middleware::web_service::messages::opcode206::kOpcode
        && message.opcode != middleware::web_service::messages::opcode501::kOpcode
        && message.opcode != middleware::web_service::messages::opcode503::kOpcode
        && message.opcode != middleware::web_service::messages::opcode504::kOpcode
        && message.opcode != middleware::web_service::messages::opcode601::kOpcode) {
        std::array<char, 512> line{};
        const std::size_t dumpBytes = (std::min)(message.payload.size(), std::size_t{64});
        int dumpWritten = std::snprintf(line.data(),
                                        line.size(),
                                        "ev=ws_capture stage=request opcode=%u tx=0x%08X "
                                        "payload=%zu bytes=",
                                        static_cast<unsigned>(message.opcode),
                                        message.transactionId,
                                        message.payload.size());
        for (std::size_t index = 0;
             dumpWritten > 0 && index < dumpBytes
             && static_cast<std::size_t>(dumpWritten) < line.size() - 4;
             ++index) {
            dumpWritten += std::snprintf(line.data() + dumpWritten,
                                         line.size() - static_cast<std::size_t>(dumpWritten),
                                         "%02X",
                                         static_cast<unsigned>(message.payload[index]));
        }
        if (dumpWritten > 0) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(dumpWritten)});
        }
    }

    if (message.opcode == middleware::web_service::messages::opcode205::kOpcode) {
        const auto investment = state::investment_snapshot();
        return middleware::web_service::messages::opcode205::encode_response(
                   message, investment, response, written)
               || encode_echo(message, response, written);
    }

    if (message.opcode == middleware::web_service::messages::opcode503::kOpcode) {
        middleware::web_service::messages::opcode503::Request bootstrap;
        const bool parsed =
            middleware::web_service::messages::opcode503::parse_request(message, bootstrap);
        // The request's own key is echoed and adopted. An authored id here costs the ship and the
        // banner.
        if (!bootstrap.hasPrimarySoid) {
            bootstrap.primarySoid = state::account_snapshot().primarySoid;
        }
        const auto investment = state::investment_snapshot();
        if (!parsed
            || !middleware::web_service::messages::opcode503::encode_response(
                message, bootstrap, investment, response, written)) {
            return encode_echo(message, response, written);
        }
        if (bootstrap.hasPrimarySoid && !state::set_primary_soid(bootstrap.primarySoid)) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::warn,
                             "ev=ws503 stage=adopt result=fail");
        }
        return true;
    }

    if (message.opcode == middleware::web_service::messages::opcode501::kOpcode) {
        // Returns a SOID family three already publishes. The request body is not parsed.
        const std::uint64_t characterSoid =
            state::account::selected_character_soid(state::account_snapshot());
        return middleware::web_service::messages::opcode501::encode_response(
                   message, characterSoid, response, written)
               || encode_echo(message, response, written);
    }

    if (message.opcode == middleware::web_service::messages::opcode601::kOpcode) {
        return middleware::web_service::messages::opcode601::encode_response(
                   message, response, written)
               || encode_echo(message, response, written);
    }

    // The opcode-403 subclass equip: {u64 BE item soid, u8 flag}. The policy check is
    // read-only here; the mutation, the persistence, and the Family-4 delta run in the
    // queuez outcome staging (the opcode-504 pattern). The reply itself is NOT encoded
    // here: the BAP body layer stages the Family-4 revision first and encodes the
    // statusPair with its promised value (the upstream contract — "Stage that revision
    // before encoding the reply, or the Client completes against the old store").
    if (message.opcode == 403) {
        std::uint64_t itemSoid = 0;
        if (message.payload.size() >= sizeof itemSoid) {
            for (std::size_t byte = 0; byte < sizeof itemSoid; ++byte) {
                itemSoid = (itemSoid << 8)
                           | static_cast<std::uint64_t>(message.payload[byte]);
            }
        }
        if (state::subclass_equip_request_valid(itemSoid)) {
            outcome.hasSubclassEquip = true;
            outcome.subclassEquipSoid = itemSoid;
        }
    }

    // The opcode-2100 ability change: {u32 BE definition hash, u8 flag}. The policy check is
    // read-only here; the mutation, the persistence, and the banner refresh run in the queuez
    // outcome staging after this reply encodes (the opcode-403 pattern).
    if (message.opcode == 2100) {
        std::uint32_t definitionHash = 0;
        if (message.payload.size() >= sizeof definitionHash) {
            for (std::size_t byte = 0; byte < sizeof definitionHash; ++byte) {
                definitionHash = (definitionHash << 8)
                                 | static_cast<std::uint32_t>(message.payload[byte]);
            }
        }
        if (definitionHash != 0) {
            outcome.hasAbilityChange = true;
            outcome.abilityChangeHash = definitionHash;
        }
    }

    // The opcode-801 subclass socket-entry selection: {u64 subclass SOID, u8 biased entry}.
    // The entry's resolved bucket names the ability field the selection updates; the mutation
    // commits in the queuez outcome staging after this reply encodes.
    if (message.opcode == middleware::web_service::messages::opcode801::kOpcode) {
        middleware::web_service::messages::opcode801::Request selectionRequest{};
        if (middleware::web_service::messages::opcode801::parse_request(
                message, selectionRequest)
            && state::prepare_subclass_selection(selectionRequest.subclassInstanceSoid,
                                                 selectionRequest.socketEntry,
                                                 outcome.subclassSelection)) {
            outcome.hasSubclassSelection = true;
        }
    }

    // A subscribe whose body does not parse is still answered; only the subscription is dropped.
    middleware::queuez::Subscription subscription;
    const bool subscribes =
        message.opcode == middleware::web_service::messages::opcode206::kOpcode
        && middleware::web_service::messages::opcode206::parse_request(message, subscription);

    middleware::web_service::ResponseShape shape{};
    resolve_response_shape(message.opcode, shape);
    // The opcode-403 reply encodes in the BAP body layer AFTER the queuez stage, so its
    // status-pair value can promise the staged Family-4 revision. Every other opcode's
    // reply encodes here with the plain status.
    if (message.opcode != 403
        && !middleware::web_service::encode_response(
            message, shape, middleware::web_service::StatusResponse{}, response, written)) {
        return encode_echo(message, response, written);
    }
    if (subscribes) {
        // Publish the subscription only after its correlated response is complete.
        outcome.hasSubscription = true;
        outcome.subscription = subscription;
        return true;
    }
    if (message.opcode == middleware::web_service::messages::opcode504::kOpcode) {
        // The selection is State, not a response field, so it publishes after the reply encodes.
        select_character(message, outcome);
    }
    return true;
}

} // namespace sunrise::server::web_service
