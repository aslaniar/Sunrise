#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string_view>

#include "../../../state/entitlements/validation.h"
#include "../parser.h"

namespace sunrise::core::settings::parser {
namespace {

namespace server = sunrise::core::settings::server;

/** Space is the first printable ASCII value accepted by standalone text settings. */
constexpr unsigned int kMinimumPrintableAscii = 0x20;
/** Tilde is the last printable ASCII value accepted by standalone text settings. */
constexpr unsigned int kMaximumPrintableAscii = 0x7E;

/**
 * Copies printable ASCII into fixed narrow storage.
 * JSON escapes are refused, not decoded: no supported value needs one.
 * @param encoded Borrowed JSON string.
 * @param output Receives the text and a trailing null only on success.
 * @return True for 1 to Capacity-1 printable ASCII bytes.
 */
template <std::size_t Capacity>
[[nodiscard]] bool decode_text(std::string_view encoded,
                               std::array<char, Capacity>& output) noexcept {
    if (encoded.empty() || encoded.size() >= Capacity) {
        return false;
    }
    std::array<char, Capacity> candidate{};
    for (std::size_t index = 0; index < encoded.size(); ++index) {
        const auto byte = static_cast<unsigned char>(encoded[index]);
        if (byte < kMinimumPrintableAscii || byte > kMaximumPrintableAscii || byte == '\\') {
            return false;
        }
        candidate[index] = encoded[index];
    }
    output = candidate;
    return true;
}

/**
 * Copies printable ASCII into fixed wide storage, like the external host setting.
 * Path settings use forward slashes: the JSON parser passes escapes through raw and Windows
 * accepts both separators.
 * @param encoded Borrowed JSON string.
 * @param output Receives the text and a trailing null only on success.
 * @return True for 1 to Capacity-1 printable ASCII bytes.
 */
template <std::size_t Capacity>
[[nodiscard]] bool decode_wide_text(std::string_view encoded,
                                    std::array<wchar_t, Capacity>& output) noexcept {
    if (encoded.empty() || encoded.size() >= Capacity) {
        return false;
    }
    std::array<wchar_t, Capacity> candidate{};
    for (std::size_t index = 0; index < encoded.size(); ++index) {
        const auto byte = static_cast<unsigned char>(encoded[index]);
        if (byte < kMinimumPrintableAscii || byte > kMaximumPrintableAscii || byte == '\\') {
            return false;
        }
        candidate[index] = static_cast<wchar_t>(encoded[index]);
    }
    output = candidate;
    return true;
}

} // namespace

/** Checks the standalone Server settings object. */
bool Parser::server_settings(server::Settings& output) noexcept {
    output = {};
    output.entitlements = state::entitlements::authored();
    if (!consume('{')) {
        return false;
    }
    if (consume('}')) {
        return true;
    }
    bool hasEntitlements = false;
    bool hasBapPort = false;
    bool hasHttpsPort = false;
    bool hasBootstrapToken = false;
    bool hasConfigGuid = false;
    bool hasPackagesDir = false;
    bool hasBuildDataPath = false;
    bool hasContentDir = false;
    bool hasWorldPopulation = false;
    bool hasWorldPopulationCarrier = false;
    bool hasWorldPopulationSchemaHash = false;
    for (;;) {
        std::string_view key;
        if (!string(key) || !consume(':')) {
            return false;
        }
        if (key == "entitlements") {
            if (hasEntitlements || !entitlements(output.entitlements)) {
                return false;
            }
            hasEntitlements = true;
        } else if (key == "bap_port") {
            std::uint64_t value = 0;
            if (hasBapPort || !unsigned_integer(value) || value == 0
                || value > (std::numeric_limits<std::uint16_t>::max)()) {
                return false;
            }
            output.bapPort = static_cast<std::uint16_t>(value);
            hasBapPort = true;
        } else if (key == "https_port") {
            std::uint64_t value = 0;
            if (hasHttpsPort || !unsigned_integer(value) || value == 0
                || value > (std::numeric_limits<std::uint16_t>::max)()) {
                return false;
            }
            output.httpsPort = static_cast<std::uint16_t>(value);
            hasHttpsPort = true;
        } else if (key == "bootstrap_token") {
            std::string_view value;
            if (hasBootstrapToken || !string(value)
                || value.size() >= server::kBootstrapTokenCapacity) {
                return false;
            }
            if (value.empty()) {
                output.bootstrapToken = {};
            } else if (!decode_text(value, output.bootstrapToken)) {
                return false;
            }
            hasBootstrapToken = true;
        } else if (key == "config_guid") {
            std::string_view value;
            if (hasConfigGuid || !string(value)
                || value.size() >= server::kConfigGuidCapacity) {
                return false;
            }
            if (value.empty()) {
                output.configGuid = {};
            } else if (!decode_text(value, output.configGuid)) {
                return false;
            }
            hasConfigGuid = true;
        } else if (key == "packages_dir") {
            std::string_view value;
            if (hasPackagesDir || !string(value)
                || value.size() >= server::kPathCapacity) {
                return false;
            }
            if (value.empty()) {
                output.packagesDir = {};
            } else if (!decode_wide_text(value, output.packagesDir)) {
                return false;
            }
            hasPackagesDir = true;
        } else if (key == "build_data_path") {
            std::string_view value;
            if (hasBuildDataPath || !string(value)
                || value.size() >= server::kPathCapacity) {
                return false;
            }
            if (value.empty()) {
                output.buildDataPath = {};
            } else if (!decode_wide_text(value, output.buildDataPath)) {
                return false;
            }
            hasBuildDataPath = true;
        } else if (key == "content_dir") {
            std::string_view value;
            if (hasContentDir || !string(value)
                || value.size() >= server::kPathCapacity) {
                return false;
            }
            if (value.empty()) {
                output.contentDir = {};
            } else if (!decode_wide_text(value, output.contentDir)) {
                return false;
            }
            hasContentDir = true;
        } else if (key == "world_population") {
            if (hasWorldPopulation || !boolean(output.worldPopulation)) {
                return false;
            }
            hasWorldPopulation = true;
        } else if (key == "world_population_carrier") {
            std::uint64_t value = 0;
            // The client's activity-message enum is 0..58 (entity-combatants FINAL).
            if (hasWorldPopulationCarrier || !unsigned_integer(value) || value > 58) {
                return false;
            }
            output.worldPopulationCarrier = static_cast<std::uint32_t>(value);
            hasWorldPopulationCarrier = true;
        } else if (key == "world_population_schema_hash") {
            std::uint64_t value = 0;
            if (hasWorldPopulationSchemaHash || !unsigned_integer(value)
                || value > 0xFFFFFFFFULL) {
                return false;
            }
            output.worldPopulationSchemaHash = static_cast<std::uint32_t>(value);
            hasWorldPopulationSchemaHash = true;
        } else if (!skip_value(0)) {
            return false;
        }
        if (consume('}')) {
            return state::entitlements::valid(output.entitlements);
        }
        if (!consume(',')) {
            return false;
        }
    }
}

} // namespace sunrise::core::settings::parser
