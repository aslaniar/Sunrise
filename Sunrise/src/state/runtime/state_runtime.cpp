#include <Windows.h>

#include <algorithm>
#include <array>
#include <bcrypt.h>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <span>
#include <string_view>

#include "../../core/logging/log.h"
#include "../../core/settings/provisioning.h"
#include "../../core/settings/settings.h"
#include "../../middleware/crypto/hmac.h"
#include "../activity/defaults/activity_defaults_validation.h"
#include "../build_data/runtime.h"
#include "equipment/configured_equipment_identity.h"
#include "runtime.h"
#include "state.h"
#include "storage/internal.h"

namespace sunrise::state {
namespace runtime::storage {

/** One State per provisioned account; slot 0 is the historical sole account. */
std::array<State, kAccountCapacity> g_states{};
/** How many slots are live (>=1 after any successful initialize). */
std::size_t g_accountCount = 1;
SRWLOCK g_stateLock{SRWLOCK_INIT};

} // namespace runtime::storage

namespace hmac = middleware::crypto::hmac;

namespace {

/** Network-order IPv4 loopback returned by the in-process SignOn route. */
/** Default one-hour lifetime for generated SignOn session tokens. */
constexpr std::uint32_t kDefaultTokenLifetimeSeconds = 3600;
/** Family 5 uses the largest signed 64-bit value as its process-global object key. */
constexpr std::uint64_t kGlobalFamily5Soid =
    static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)());
/** The configured bootstrap token is 32 hex characters wrapping 16 raw bytes. */
constexpr std::size_t kBootstrapTokenBytes = 16;

/**
 * Converts one ASCII hex digit to its 4-bit value.
 * @param digit Input character.
 * @param value Receives the decoded nibble.
 * @return True for a valid hex digit.
 */
[[nodiscard]] bool hex_nibble(char digit, unsigned int& value) noexcept {
    if (digit >= '0' && digit <= '9') {
        value = static_cast<unsigned int>(digit - '0');
        return true;
    }
    if (digit >= 'A' && digit <= 'F') {
        value = static_cast<unsigned int>(digit - 'A') + 10;
        return true;
    }
    if (digit >= 'a' && digit <= 'f') {
        value = static_cast<unsigned int>(digit - 'a') + 10;
        return true;
    }
    return false;
}

/**
 * Derives the SignOn envelope-wrap keys from the configured bootstrap token, so every process
 * that shares the setting derives the identical pair. The Standalone server and the Client's
 * own in-process SignOn responder are separate processes with no live handshake of their own -
 * these two keys are what lets either one's server-hello envelope decrypt correctly for the
 * other. The nonce and session key the envelope wraps stay independently random per boot (the
 * Client learns them by decrypting it); only the wrap keys themselves need to match.
 * @param signOn Receives the derived encryptionKey and authenticationKey.
 * @return True when the token is configured as valid hex and both derivations succeed.
 */
[[nodiscard]] bool derive_signon_secrets(const std::array<std::byte, kBootstrapTokenBytes>& token,
                                         SignOnState& signOn) noexcept {
    constexpr std::string_view kEncryptionLabel = "sunrise-signon-encryption-key";
    constexpr std::string_view kAuthenticationLabel = "sunrise-signon-authentication-key";
    // P2: the session token derives from the same bootstrap token instead of being randomized.
    // Both sides of the hybrid architecture (a client DLL answering its own SignOn and the
    // external BAP server) derive identical tokens from one authored setting, which turns the
    // service-25 hello echo into a real identity proof. Same pattern as b84f8de's wrap keys.
    constexpr std::string_view kSessionTokenLabel = "sunrise-signon-session-token";
    const auto label_bytes = [](const std::string_view text) {
        return std::as_bytes(std::span<const char>(text.data(), text.size()));
    };
    hmac::Digest encryptionDigest{};
    hmac::Digest authenticationDigest{};
    hmac::Digest sessionDigest{};
    const bool derived =
        hmac::authenticate(hmac::Algorithm::sha256, token, label_bytes(kEncryptionLabel), {}, encryptionDigest)
        && hmac::authenticate(
            hmac::Algorithm::sha256, token, label_bytes(kAuthenticationLabel), {}, authenticationDigest)
        && hmac::authenticate(
            hmac::Algorithm::sha256, token, label_bytes(kSessionTokenLabel), {}, sessionDigest);
    if (!derived) {
        return false;
    }
    std::copy_n(
        encryptionDigest.bytes.begin(), signOn.encryptionKey.size(), signOn.encryptionKey.begin());
    std::copy_n(authenticationDigest.bytes.begin(),
               signOn.authenticationKey.size(),
               signOn.authenticationKey.begin());
    static_assert(kSessionTokenSize <= hmac::kMaximumDigestSize);
    std::copy_n(sessionDigest.bytes.begin(), signOn.sessionToken.size(), signOn.sessionToken.begin());
    return true;
}

/**
 * Fills fixed secret storage with Windows system randomness.
 * @tparam Size Required secret byte count.
 * @param output Secret storage to overwrite.
 * @return True when Windows generates every byte.
 */
template <std::size_t Size>
[[nodiscard]] bool randomize(std::array<std::byte, Size>& output) noexcept {
    return BCryptGenRandom(nullptr,
                           reinterpret_cast<PUCHAR>(output.data()),
                           static_cast<ULONG>(output.size()),
                           BCRYPT_USE_SYSTEM_PREFERRED_RNG)
           >= 0;
}

/**
 * Seeds canonical character row generations before installed build data is needed. The stamp
 * only runs while the whole account's serial space is still zero: a fresh settings-authored
 * account gets ascending serials (equipment in semantic slot order, then storage in authored
 * order) and a counter equal to the item count — the same assignment the database migration
 * seeds for legacy rows — while a database-loaded or already-equipped account keeps its
 * persisted serials untouched.
 */
[[nodiscard]] bool seed_inventory_runtime_fields(AccountState& accountState) noexcept {
    if (!account::valid(accountState)) {
        return false;
    }
    bool serialSpaceUsed = false;
    for (const CharacterState& character : accountState.characters) {
        serialSpaceUsed = serialSpaceUsed || character.nextInventorySerial != 0;
        for (const std::optional<account::inventory::Item>& item : character.equipment.slots) {
            serialSpaceUsed = serialSpaceUsed || (item.has_value() && item->mutationSerial != 0);
        }
        for (std::size_t index = 0; index < character.storageItemCount; ++index) {
            serialSpaceUsed = serialSpaceUsed || character.storageItems[index].mutationSerial != 0;
        }
    }
    if (serialSpaceUsed) {
        return account::valid(accountState);
    }
    for (std::size_t characterIndex = 0; characterIndex < accountState.characterCount;
         ++characterIndex) {
        CharacterState& character = accountState.characters[characterIndex];
        std::uint32_t next = 0;
        for (std::optional<account::inventory::Item>& item : character.equipment.slots) {
            if (item.has_value()) {
                item->mutationSerial = static_cast<std::int32_t>(next++);
            }
        }
        for (std::size_t index = 0; index < character.storageItemCount; ++index) {
            character.storageItems[index].mutationSerial = static_cast<std::int32_t>(next++);
        }
        character.nextInventorySerial = next;
    }
    return account::valid(accountState);
}

} // namespace

/** One provisioned account's boot inputs: authored State plus the token that names it. */
struct ProvisionedAccountInput {
    const AccountState* account{};
    std::string_view bootstrapTokenHex;
};

/**
 * Decodes 32 hex characters into the 16 raw token bytes.
 * @param text Authored hex text. @param output Receives the raw bytes.
 * @return True when every character is valid hex and the length matches exactly.
 */
[[nodiscard]] bool
decode_hex_token(std::string_view text,
                 std::array<std::byte, kBootstrapTokenBytes>& output) noexcept {
    if (text.size() != output.size() * 2) {
        return false;
    }
    for (std::size_t index = 0; index < output.size(); ++index) {
        unsigned int high = 0;
        unsigned int low = 0;
        if (!hex_nibble(text[index * 2], high) || !hex_nibble(text[index * 2 + 1], low)) {
            return false;
        }
        output[index] = static_cast<std::byte>((high << 4) | low);
    }
    return true;
}

/**
 * Builds one complete account State: derived secrets, relay fields, authored content policy.
 * @param input Authored account plus its bootstrap token.
 * @param activityDefaults Complete local fallback policy from immutable Core settings.
 * @param initialized Receives the built State on success.
 * @return True when every secret derives and the account passes its checks.
 */
[[nodiscard]] bool
build_account_state(const ProvisionedAccountInput& input,
                    const activity::defaults::ActivityDefaults& activityDefaults,
                    State& initialized) noexcept {
    initialized = {};
    if (input.account == nullptr) {
        return false;
    }
    AccountState runtimeAccount = *input.account;
    if (!seed_inventory_runtime_fields(runtimeAccount)) {
        return false;
    }
    std::array<std::byte, kBootstrapTokenBytes> token{};
    if (!decode_hex_token(input.bootstrapTokenHex, token)
        || !derive_signon_secrets(token, initialized.signOn)
        || !randomize(initialized.bap.nonce) || !randomize(initialized.bap.sessionKey)
        || !randomize(initialized.bap.envelopeIv)) {
        SecureZeroMemory(token.data(), token.size());
        return false;
    }
    SecureZeroMemory(token.data(), token.size());
    const auto& relayOctets = core::settings::get().server.relayAddress;
    initialized.signOn.relayAddress = (std::uint32_t(relayOctets[0]) << 24)
                                    | (std::uint32_t(relayOctets[1]) << 16)
                                    | (std::uint32_t(relayOctets[2]) << 8)
                                    | std::uint32_t(relayOctets[3]);
    // The published relay port is the one the listener binds, so both move with one setting.
    initialized.signOn.relayPort = core::settings::get().server.bapPort;
    initialized.signOn.tokenLifetimeSeconds = kDefaultTokenLifetimeSeconds;
    initialized.account = runtimeAccount;
    initialized.activity.defaults = activityDefaults;
    initialized.investment.family5.objectSoid = kGlobalFamily5Soid;
    // Only the override lists come from settings. Identity and gate stay owned by State.
    const Family5State& authored = core::settings::get().initialFamily5;
    initialized.investment.family5.flags = authored.flags;
    initialized.investment.family5.flagCount = authored.flagCount;
    initialized.investment.family5.values = authored.values;
    initialized.investment.family5.valueCount = authored.valueCount;
    // The arm is account-wide and rides the first ws-503, which goes out before any pick. Nothing
    // is selected at boot, so it is armed when any authored character carries the bypass. The
    // per-character objB byte is the other half, and it still decides which character it opens.
    for (std::size_t index = 0; index < input.account->characterCount; ++index) {
        if (input.account->characters[index].contentBypass) {
            initialized.investment.family5.contentGateArm = true;
            break;
        }
    }
    return true;
}

/**
 * Provisions every authored account into its own State slot in one pass.
 * Slot 0 keeps full legacy responsibility: its equipment hash drives build-data identity.
 * @param module Loaded Sunrise module, or null to disable disk persistence.
 * @param accounts One input per provisioned account, slot order = key order.
 * @param activityDefaults Complete local fallback policy from immutable Core settings.
 * @return True when every account built and the whole array published under the lock.
 */
bool initialize_accounts(void* module,
                         std::span<const ProvisionedAccountInput> accounts,
                         const activity::defaults::ActivityDefaults& activityDefaults) noexcept {
    if (accounts.empty() || accounts.size() > kAccountCapacity
        || !activity::defaults::valid(activityDefaults)) {
        return false;
    }
    for (const ProvisionedAccountInput& input : accounts) {
        if (input.account == nullptr || !account::valid(*input.account)) {
            return false;
        }
    }
    {
        // Slot 0 drives build-data identity exactly as the single-account pass always did.
        AccountState probe = *accounts[0].account;
        if (!seed_inventory_runtime_fields(probe)
            || !build_data::initialize(module, runtime::equipment::configured_hash(probe))) {
            return false;
        }
    }
    std::array<State, kAccountCapacity> built{};
    for (std::size_t index = 0; index < accounts.size(); ++index) {
        if (!build_account_state(accounts[index], activityDefaults, built[index])) {
            SecureZeroMemory(built.data(), sizeof built);
            build_data::shutdown();
            return false;
        }
        std::array<char, 128> line{};
        const int written =
            std::snprintf(line.data(),
                          line.size(),
                          "ev=account stage=identity key=%zu primary=0x%016llX characters=%zu",
                          index,
                          static_cast<unsigned long long>(built[index].account.primarySoid),
                          built[index].account.characterCount);
        if (written > 0) {
            core::log::write(core::log::Channel::state,
                             core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(written)});
        }
    }

    // Publish the whole provisioned set only after every secret is valid.
    AcquireSRWLockExclusive(&runtime::storage::g_stateLock);
    for (std::size_t index = 0; index < accounts.size(); ++index) {
        runtime::storage::g_states[index] = built[index];
    }
    runtime::storage::g_accountCount = accounts.size();
    ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
    SecureZeroMemory(built.data(), sizeof built);
    return true;
}

/**
 * Legacy single-account entry point: provisions exactly one account from the caller's block
 * and the settings bootstrap token. Multi-account hosts call initialize_provisioned instead.
 * @param module Loaded Sunrise module, or null to disable disk persistence.
 * @param initialAccount Empty State, or a complete checked account from Core settings.
 * @param activityDefaults Complete local fallback policy from immutable Core settings.
 * @return True when account, defaults, cached data, and generated secrets are valid.
 */
bool initialize(void* module,
                const AccountState& initialAccount,
                const activity::defaults::ActivityDefaults& activityDefaults) noexcept {
    const std::array<ProvisionedAccountInput, 1> accounts{
        ProvisionedAccountInput{
            &initialAccount,
            std::string_view(core::settings::get().server.bootstrapToken.data())}};
    return initialize_accounts(module, accounts, activityDefaults);
}

/**
 * Provisions every settings-authored account: state.accounts[] entries, legacy-normalized to
 * exactly one entry when no array was authored.
 * @param module Loaded Sunrise module, or null to disable disk persistence.
 * @param activityDefaults Complete local fallback policy from immutable Core settings.
 * @return True when every provisioned account built and published.
 */
bool initialize_provisioned(
    void* module,
    const activity::defaults::ActivityDefaults& activityDefaults) noexcept {
    const core::settings::Settings& settings = core::settings::get();
    std::array<ProvisionedAccountInput, kAccountCapacity> inputs{};
    for (std::size_t index = 0; index < settings.provisionedAccountCount; ++index) {
        inputs[index] =
            ProvisionedAccountInput{&settings.accounts[index].account,
                                    std::string_view(settings.accounts[index]
                                                         .bootstrapToken.data())};
    }
    return initialize_accounts(
        module,
        std::span<const ProvisionedAccountInput>(inputs.begin(),
                                                 settings.provisionedAccountCount),
        activityDefaults);
}

/**
 * Loads build data and generates secrets with Sunrise's authored activity defaults.
 * @param module Loaded Sunrise module, or null to disable disk persistence.
 * @param initialAccount Empty State, or a complete checked account from Core settings.
 * @return True when the cached data passes its checks and every secret gets random bytes.
 */
bool initialize(void* module, const AccountState& initialAccount) noexcept {
    return initialize(module, initialAccount, activity::defaults::authored());
}

/**
 * Replaces one provisioned slot's State with a persisted account (the boot's database pass).
 * Slot 0 keeps build-data ownership exactly like the historical two-pass flow; other slots
 * rebuild without touching the shared cache identity.
 */
bool reload_account_from_database(
    void* module,
    const AccountState& account,
    const activity::defaults::ActivityDefaults& activityDefaults,
    const AccountKey key) noexcept {
    if (account.primarySoid == 0 || !account::valid(account)
        || !activity::defaults::valid(activityDefaults)) {
        return false;
    }
    const core::settings::Settings& settings = core::settings::get();
    const std::size_t index =
        key < settings.provisionedAccountCount ? key : kLegacyAccount;
    if (key == kLegacyAccount) {
        // Slot 0 keeps the historical responsibility for the shared cache identity.
        AccountState probe = account;
        if (!seed_inventory_runtime_fields(probe)
            || !build_data::initialize(module, runtime::equipment::configured_hash(probe))) {
            return false;
        }
    }
    State built{};
    if (!build_account_state(ProvisionedAccountInput{
                                 &account,
                                 std::string_view(settings.accounts[index]
                                                      .bootstrapToken.data())},
                             activityDefaults,
                             built)) {
        return false;
    }
    AcquireSRWLockExclusive(&runtime::storage::g_stateLock);
    runtime::storage::g_states[key] = built;
    if (static_cast<std::size_t>(key) >= runtime::storage::g_accountCount) {
        runtime::storage::g_accountCount = static_cast<std::size_t>(key) + 1;
    }
    ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
    SecureZeroMemory(&built, sizeof built);
    return true;
}

/** Securely erases State, including activity destinations and matchmaking descriptors. */
void shutdown() noexcept {
    AcquireSRWLockExclusive(&runtime::storage::g_stateLock);
    SecureZeroMemory(runtime::storage::g_states.data(), sizeof runtime::storage::g_states);
    runtime::storage::g_accountCount = 1;
    ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
    build_data::shutdown();
}

/** Clamps a caller key into the live provisioned range; slot 0 always exists. */
[[nodiscard]] AccountKey clamp_key(const AccountKey key) noexcept {
    return key < runtime::storage::g_accountCount ? key : kLegacyAccount;
}

/** @return Immutable generated SignOn session fields for one account slot. */
const SignOnState& sign_on(const AccountKey key) noexcept {
    return runtime::storage::g_states[clamp_key(key)].signOn;
}

/** @return How many accounts this process serves. */
std::size_t account_count() noexcept {
    return runtime::storage::g_accountCount;
}

AccountKey match_session_token(std::span<const std::byte, kSessionTokenSize> echoed) noexcept {
    for (std::size_t index = 0; index < runtime::storage::g_accountCount; ++index) {
        const SignOnState& candidate = runtime::storage::g_states[index].signOn;
        if (std::equal(echoed.begin(), echoed.end(), candidate.sessionToken.begin())) {
            return static_cast<AccountKey>(index);
        }
    }
    return kUnprovisionedAccount;
}

/**
 * Publishes the bootstrap content-id token read from the installed client.
 * @param token Exactly 16 native bytes.
 * @return True when the complete token is kept for this process.
 */
bool publish_bootstrap_token(std::span<const std::byte> token) noexcept {
    SignOnState& signOn = runtime::storage::g_states[kLegacyAccount].signOn;
    if (token.size() != signOn.bootstrapToken.size()) {
        return false;
    }
    std::copy(token.begin(), token.end(), signOn.bootstrapToken.begin());
    signOn.bootstrapTokenPresent = true;
    return true;
}

/** @return Immutable generated BAP session fields for one account slot. */
const BapState& bap(const AccountKey key) noexcept {
    return runtime::storage::g_states[clamp_key(key)].bap;
}

/** @return A copy of the evaluated content state, read under the lock. */
InvestmentState investment_snapshot(const AccountKey key) noexcept {
    AcquireSRWLockShared(&runtime::storage::g_stateLock);
    const InvestmentState snapshot =
        runtime::storage::g_states[clamp_key(key)].investment;
    ReleaseSRWLockShared(&runtime::storage::g_stateLock);
    return snapshot;
}

/** Replaces the published family-5 override lists, keeping object identity and gate. */
bool publish_family5(const Family5State& family, const AccountKey key) noexcept {
    if (family.flagCount > family.flags.size() || family.valueCount > family.values.size()) {
        return false;
    }
    AcquireSRWLockExclusive(&runtime::storage::g_stateLock);
    InvestmentState& investment = runtime::storage::g_states[clamp_key(key)].investment;
    investment.family5.flags = family.flags;
    investment.family5.flagCount = family.flagCount;
    investment.family5.values = family.values;
    investment.family5.valueCount = family.valueCount;
    ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
    return true;
}

} // namespace sunrise::state
