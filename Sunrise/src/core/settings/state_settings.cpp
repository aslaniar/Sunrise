#include "../../state/activity/defaults/activity_defaults_validation.h"
#include "parser.h"

namespace sunrise::core::settings::parser {

/**
 * Fills one flag bank from [start, length] runs. A run outside the bank is refused.
 * @param bank Expanded destination bank.
 * @return True when every run fits.
 */
bool Parser::flag_runs(std::span<std::uint8_t> bank) noexcept {
    if (!consume('[')) {
        return false;
    }
    if (consume(']')) {
        return true;
    }
    for (;;) {
        std::uint64_t start = 0;
        std::uint64_t length = 0;
        if (!consume('[') || !unsigned_integer(start) || !consume(',') || !unsigned_integer(length)
            || !consume(']') || length == 0 || start > bank.size()
            || length > bank.size() - start) {
            return false;
        }
        for (std::uint64_t offset = 0; offset < length; ++offset) {
            bank[static_cast<std::size_t>(start + offset)] = state::unlocks::kFlagSet;
        }
        if (consume(']')) {
            return true;
        }
        if (!consume(',')) {
            return false;
        }
    }
}

/**
 * Fills one flag bank from plain indices.
 * @param bank Expanded destination bank.
 * @return True when every index fits.
 */
bool Parser::flag_indices(std::span<std::uint8_t> bank) noexcept {
    if (!consume('[')) {
        return false;
    }
    if (consume(']')) {
        return true;
    }
    for (;;) {
        std::uint64_t index = 0;
        if (!unsigned_integer(index) || index >= bank.size()) {
            return false;
        }
        bank[static_cast<std::size_t>(index)] = state::unlocks::kFlagSet;
        if (consume(']')) {
            return true;
        }
        if (!consume(',')) {
            return false;
        }
    }
}

/**
 * Fills one objective bank from [index, value] pairs.
 * @param bank Expanded destination bank.
 * @return True when every index fits.
 */
bool Parser::objective_values(std::span<std::int32_t> bank) noexcept {
    if (!consume('[')) {
        return false;
    }
    if (consume(']')) {
        return true;
    }
    for (;;) {
        std::uint64_t index = 0;
        std::int32_t value = 0;
        if (!consume('[') || !unsigned_integer(index) || !consume(',') || !signed_32(value)
            || !consume(']') || index >= bank.size()) {
            return false;
        }
        bank[static_cast<std::size_t>(index)] = value;
        if (consume(']')) {
            return true;
        }
        if (!consume(',')) {
            return false;
        }
    }
}

/**
 * Parses the four authored unlock banks.
 * @param output Receives every expanded bank.
 * @return True when the object is valid JSON and every entry fits its bank.
 */
bool Parser::unlocks(state::unlocks::Table& output) noexcept {
    output = {};
    if (!consume('{')) {
        return false;
    }
    if (consume('}')) {
        return true;
    }
    for (;;) {
        std::string_view key;
        if (!string(key) || !consume(':')) {
            return false;
        }
        bool parsed = false;
        if (key == "account_flag_runs") {
            parsed = flag_runs(output.accountFlags);
        } else if (key == "profile_flag_runs") {
            parsed = flag_runs(output.profileFlags);
        } else if (key == "character_flags") {
            parsed = flag_indices(output.characterFlags);
        } else if (key == "objective_values") {
            parsed = objective_values(output.objectiveValues);
        } else if (key == "character_flag_runs") {
            parsed = flag_runs(output.characterObjectFlags);
        } else if (key == "character_objective_values") {
            parsed = objective_values(output.characterObjectValues);
        } else {
            parsed = skip_value(0);
        }
        if (!parsed) {
            return false;
        }
        if (consume('}')) {
            return true;
        }
        if (!consume(',')) {
            return false;
        }
    }
}

/**
 * Parses authored State ids. Native mapping data is refused.
 * @param output Receives the initial account, unlock policy and activity defaults.
 * @return True when activity appears once and the cross-field rules hold.
 */
bool Parser::state_settings(Settings& output) noexcept {
    output.initialAccount = {};
    output.initialUnlocks = {};
    output.initialFamily5 = {};
    output.initialActivityDefaults = state::activity::defaults::authored();
    if (!consume('{')) {
        return false;
    }
    if (consume('}')) {
        return true;
    }
    bool hasActivity = false;
    bool hasInvestment = false;
    for (;;) {
        std::string_view key;
        if (!string(key) || !consume(':')) {
            return false;
        }
        if (key == "account") {
            if (!account(output.initialAccount)) {
                return false;
            }
        } else if (key == "accounts") {
            // P2 provisioned accounts. An explicit array replaces the legacy block entirely.
            if (output.provisionedAccountCount != 0 || !consume('[')) {
                return false;
            }
            if (!consume(']')) {
                for (;;) {
                    if (output.provisionedAccountCount >= kAccountCapacity) {
                        return false;
                    }
                    ProvisionedAccount& entry = output.accounts[output.provisionedAccountCount];
                    if (!provisioned_account_entry(entry)) {
                        return false;
                    }
                    ++output.provisionedAccountCount;
                    if (consume(']')) {
                        break;
                    }
                    if (!consume(',')) {
                        return false;
                    }
                }
            }
        } else if (key == "accounts") {
            // P2 provisioned accounts. An explicit array replaces the legacy block entirely.
            if (output.provisionedAccountCount != 0 || !consume('[')) {
                return false;
            }
            if (!consume(']')) {
                for (;;) {
                    if (output.provisionedAccountCount >= kAccountCapacity) {
                        return false;
                    }
                    ProvisionedAccount& entry = output.accounts[output.provisionedAccountCount];
                    if (!provisioned_account_entry(entry)) {
                        return false;
                    }
                    ++output.provisionedAccountCount;
                    if (consume(']')) {
                        break;
                    }
                    if (!consume(',')) {
                        return false;
                    }
                }
            }
        } else if (key == "characters") {
            if (!characters(output.initialAccount)) {
                return false;
            }
        } else if (key == "unlocks") {
            if (!unlocks(output.initialUnlocks)) {
                return false;
            }
        } else if (key == "investment") {
            if (hasInvestment || !investment(output.initialFamily5)) {
                return false;
            }
            hasInvestment = true;
        } else if (key == "activity") {
            if (hasActivity || !activity_settings(output.initialActivityDefaults)) {
                return false;
            }
            hasActivity = true;
        } else if (!skip_value(0)) {
            return false;
        }
        if (consume('}')) {
            return normalize_accounts(output)
                   && state::account::valid(output.initialAccount)
                   && state::activity::defaults::valid(output.initialActivityDefaults);
        }
        if (!consume(',')) {
            return false;
        }
    }
}

/**
 * Fills the legacy single account into slot 0 when no explicit array was authored, so every
 * downstream consumer reads one normalized list. Legacy mode keeps today's behavior exactly:
 * the settings initialAccount plus server.bootstrap_token become provisioned entry 0.
 * @param output Parsed settings, updated in place.
 * @return True when every provisioned entry carries a nonzero account and a 32-hex token.
 */
bool Parser::normalize_accounts(Settings& output) noexcept {
    if (output.provisionedAccountCount == 0) {
        const std::string_view token(output.server.bootstrapToken.data(), 32);
        if (token.size() != output.accounts[0].bootstrapToken.size() - 1) {
            return false;
        }
        output.accounts[0].account = output.initialAccount;
        token.copy(output.accounts[0].bootstrapToken.data(), token.size());
        output.provisionedAccountCount = 1;
    }
    for (std::size_t index = 0; index < output.provisionedAccountCount; ++index) {
        const ProvisionedAccount& entry = output.accounts[index];
        if (entry.account.primarySoid == 0) {
            return false;
        }
        const std::string_view token(entry.bootstrapToken.data(), 32);
        for (const char digit : token) {
            const bool hex = (digit >= '0' && digit <= '9') || (digit >= 'a' && digit <= 'f')
                             || (digit >= 'A' && digit <= 'F');
            if (!hex) {
                return false;
            }
        }
    }
    return true;
}

/**
 * Parses one provisioned-account array element: the legacy account block keys plus the
 * bootstrap token that names the account on the wire.
 * @param output Receives the account and its bootstrap token.
 * @return True when the object parses and carries a valid account and token.
 */
bool Parser::provisioned_account_entry(ProvisionedAccount& output) noexcept {
    output = {};
    if (!consume('{')) {
        return false;
    }
    bool hasToken = false;
    if (consume('}')) {
        return false;
    }
    for (;;) {
        std::string_view key;
        if (!string(key) || !consume(':')) {
            return false;
        }
        if (key == "account") {
            if (!account(output.account)) {
                return false;
            }
        } else if (key == "characters") {
            if (!characters(output.account)) {
                return false;
            }
        } else if (key == "bootstrap_token") {
            std::string_view value;
            if (hasToken || !string(value)
                || value.size() != output.bootstrapToken.size() - 1) {
                return false;
            }
            value.copy(output.bootstrapToken.data(), value.size());
            hasToken = true;
        } else if (!skip_value(0)) {
            return false;
        }
        if (consume('}')) {
            return hasToken && state::account::valid(output.account);
        }
        if (!consume(',')) {
            return false;
        }
    }
}

/**
 * Parses an optional account id object.
 * @param output Receives the authored primary account SOID.
 * @return True for null or an object with one nonzero SOID and complete settings.
 */
bool Parser::account(state::AccountState& output) noexcept {
    if (literal("null")) {
        output = {};
        return true;
    }
    if (!consume('{')) {
        return false;
    }
    bool hasPrimarySoid = false;
    bool hasSettings = false;
    if (consume('}')) {
        return false;
    }
    for (;;) {
        std::string_view key;
        if (!string(key) || !consume(':')) {
            return false;
        }
        if (key == "primary_soid") {
            if (hasPrimarySoid || !unsigned_value(output.primarySoid) || output.primarySoid == 0) {
                return false;
            }
            hasPrimarySoid = true;
        } else if (key == "settings") {
            if (hasSettings || !account_settings(output.settings)) {
                return false;
            }
            hasSettings = true;
        } else if (key == "profile_items") {
            if (!profile_items(output)) {
                return false;
            }
        } else if (!skip_value(0)) {
            return false;
        }
        if (consume('}')) {
            return hasPrimarySoid && hasSettings;
        }
        if (!consume(',')) {
            return false;
        }
    }
}

} // namespace sunrise::core::settings::parser
