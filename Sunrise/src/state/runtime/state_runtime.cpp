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

State g_state;
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
 * Decodes the configured 32-hex-character bootstrap token into 16 raw bytes.
 * @param output Receives the decoded token.
 * @return True when the configured text is exactly 32 valid hex characters.
 */
[[nodiscard]] bool decode_bootstrap_token(std::array<std::byte, kBootstrapTokenBytes>& output) noexcept {
    const std::string_view text(core::settings::get().server.bootstrapToken.data());
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
 * Derives the SignOn envelope-wrap keys from the configured bootstrap token, so every process
 * that shares the setting derives the identical pair. The Standalone server and the Client's
 * own in-process SignOn responder are separate processes with no live handshake of their own -
 * these two keys are what lets either one's server-hello envelope decrypt correctly for the
 * other. The nonce and session key the envelope wraps stay independently random per boot (the
 * Client learns them by decrypting it); only the wrap keys themselves need to match.
 * @param signOn Receives the derived encryptionKey and authenticationKey.
 * @return True when the token is configured as valid hex and both derivations succeed.
 */
[[nodiscard]] bool derive_envelope_wrap_keys(SignOnState& signOn) noexcept {
    std::array<std::byte, kBootstrapTokenBytes> token{};
    if (!decode_bootstrap_token(token)) {
        return false;
    }
    constexpr std::string_view kEncryptionLabel = "sunrise-signon-encryption-key";
    constexpr std::string_view kAuthenticationLabel = "sunrise-signon-authentication-key";
    const auto encryptionLabel =
        std::as_bytes(std::span<const char>(kEncryptionLabel.data(), kEncryptionLabel.size()));
    const auto authenticationLabel =
        std::as_bytes(std::span<const char>(kAuthenticationLabel.data(), kAuthenticationLabel.size()));
    hmac::Digest encryptionDigest{};
    hmac::Digest authenticationDigest{};
    const bool derived =
        hmac::authenticate(
            hmac::Algorithm::sha256, token, encryptionLabel, {}, encryptionDigest)
        && hmac::authenticate(
            hmac::Algorithm::sha256, token, authenticationLabel, {}, authenticationDigest);
    SecureZeroMemory(token.data(), token.size());
    if (!derived) {
        return false;
    }
    std::copy_n(
        encryptionDigest.bytes.begin(), signOn.encryptionKey.size(), signOn.encryptionKey.begin());
    std::copy_n(authenticationDigest.bytes.begin(),
               signOn.authenticationKey.size(),
               signOn.authenticationKey.begin());
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
 * Loads build data and publishes fixed activity defaults in one step.
 * @param module Loaded Sunrise module, or null to disable disk persistence.
 * @param initialAccount Empty State, or a complete checked account from Core settings.
 * @param activityDefaults Complete local fallback policy from immutable Core settings.
 * @return True when account, defaults, cached data, and generated secrets are valid.
 */
bool initialize(void* module,
                const AccountState& initialAccount,
                const activity::defaults::ActivityDefaults& activityDefaults) noexcept {
    AccountState runtimeAccount = initialAccount;
    if (!seed_inventory_runtime_fields(runtimeAccount)
        || !activity::defaults::valid(activityDefaults)) {
        return false;
    }
    if (!build_data::initialize(module, runtime::equipment::configured_hash(runtimeAccount))) {
        return false;
    }
    {
        // The account key is authored, and a truncated one is consistent enough to go unnoticed.
        std::array<char, 96> line{};
        const int written =
            std::snprintf(line.data(),
                          line.size(),
                          "ev=account stage=identity primary=0x%016llX characters=%zu",
                          static_cast<unsigned long long>(runtimeAccount.primarySoid),
                          runtimeAccount.characterCount);
        if (written > 0) {
            core::log::write(core::log::Channel::state,
                             core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(written)});
        }
    }
    State initialized{};
    if (!derive_envelope_wrap_keys(initialized.signOn)
        || !randomize(initialized.signOn.sessionToken) || !randomize(initialized.bap.nonce)
        || !randomize(initialized.bap.sessionKey) || !randomize(initialized.bap.envelopeIv)) {
        SecureZeroMemory(&initialized, sizeof initialized);
        build_data::shutdown();
        return false;
    }
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
    for (std::size_t index = 0; index < initialAccount.characterCount; ++index) {
        if (initialAccount.characters[index].contentBypass) {
            initialized.investment.family5.contentGateArm = true;
            break;
        }
    }

    // Publish one complete State only after every generated secret is valid.
    AcquireSRWLockExclusive(&runtime::storage::g_stateLock);
    runtime::storage::g_state = initialized;
    ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
    SecureZeroMemory(&initialized, sizeof initialized);
    return true;
}

/** Securely erases State, including activity destinations and matchmaking descriptors. */
void shutdown() noexcept {
    AcquireSRWLockExclusive(&runtime::storage::g_stateLock);
    SecureZeroMemory(&runtime::storage::g_state, sizeof runtime::storage::g_state);
    ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
    build_data::shutdown();
}

/** @return Immutable generated SignOn session fields. */
const SignOnState& sign_on() noexcept {
    return runtime::storage::g_state.signOn;
}

/**
 * Publishes the bootstrap content-id token read from the installed client.
 * @param token Exactly 16 native bytes.
 * @return True when the complete token is kept for this process.
 */
bool publish_bootstrap_token(std::span<const std::byte> token) noexcept {
    SignOnState& signOn = runtime::storage::g_state.signOn;
    if (token.size() != signOn.bootstrapToken.size()) {
        return false;
    }
    std::copy(token.begin(), token.end(), signOn.bootstrapToken.begin());
    signOn.bootstrapTokenPresent = true;
    return true;
}

/** @return Immutable generated BAP session fields. */
const BapState& bap() noexcept {
    return runtime::storage::g_state.bap;
}

/** @return A copy of the evaluated content state, read under the lock. */
InvestmentState investment_snapshot() noexcept {
    AcquireSRWLockShared(&runtime::storage::g_stateLock);
    const InvestmentState snapshot = runtime::storage::g_state.investment;
    ReleaseSRWLockShared(&runtime::storage::g_stateLock);
    return snapshot;
}

/** Replaces the published family-5 override lists, keeping object identity and gate. */
bool publish_family5(const Family5State& family) noexcept {
    if (family.flagCount > family.flags.size() || family.valueCount > family.values.size()) {
        return false;
    }
    AcquireSRWLockExclusive(&runtime::storage::g_stateLock);
    runtime::storage::g_state.investment.family5.flags = family.flags;
    runtime::storage::g_state.investment.family5.flagCount = family.flagCount;
    runtime::storage::g_state.investment.family5.values = family.values;
    runtime::storage::g_state.investment.family5.valueCount = family.valueCount;
    ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
    return true;
}

} // namespace sunrise::state
