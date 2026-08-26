#include <Windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string_view>

#include "../../core/filesystem/path.h"
#include "../../core/logging/log.h"
#include "../../core/settings/settings.h"
#include "../../middleware/compression/oodle/runtime.h"
#include "../../middleware/runtime/middleware_runtime.h"
#include "../../state/runtime/equipment/configured_equipment_identity.h"
#include "../../state/account/account_state.h"
#include "../../state/content_manifest/content_manifest_state_runtime.h"
#include "../../state/entitlements/definition.h"
#include "../../state/entitlements/entitlement_runtime.h"
#include "../../state/runtime/runtime.h"
#include "../../state/unlocks/definition.h"
#include "../../state/unlocks/unlocks_runtime.h"
#include "../http/https_listener.h"
#include "../admin/admin_http.h"
#include "../content/content_loader.h"
#include "../persistence/account_memcmp_test.h"
#include "../persistence/cache_check.h"
#include "../persistence/equip_diff_test.h"
#include "../persistence/persistence.h"
#include "../persistence/selection_version_test.h"
#include "../transport/discovery_listener.h"
#include "server_runtime.h"
#include "../bap/encrypted/push/activity/membership_sweep.h"

namespace sunrise::server {
namespace {

std::atomic_bool g_running{true};

/** One bounded sleep between server service slices. The transport poll interval is 50 ms. */
constexpr DWORD kServiceIntervalMilliseconds = 10;

/** The installed public package headers live beside the main executable by default. */
constexpr std::wstring_view kInstalledPackagesDirectory = L"packages";
/** The build-data cache file under the owned artifact directory. */
constexpr std::wstring_view kBuildDataCacheFile = L"\\Sunrise\\cache\\build_data.bin";
/** Oodle codec the queuez encoder borrows; the game loads it, the server must load it too. */
constexpr wchar_t kOodleModuleName[] = L"oo2core_3_win64.dll";
/** Self-test plaintext size, small enough for the fixed round-trip buffers. */
constexpr std::size_t kOodleSelfTestSize = 64;

/**
 * Stops the service loop on a console shutdown signal.
 * @param signal Control event kind.
 * @return True when the event is a shutdown request this handler owns.
 */
BOOL WINAPI on_console_signal(DWORD signal) noexcept {
    if (signal == CTRL_C_EVENT || signal == CTRL_BREAK_EVENT || signal == CTRL_CLOSE_EVENT) {
        g_running.store(false, std::memory_order_release);
        return TRUE;
    }
    return FALSE;
}

/**
 * Names the initialization stage that failed.
 * The logging sinks are the first stage, so their own failure has only the debugger.
 * @param stage Short key naming the stage.
 */
void report_stage_failure(const char* stage) noexcept {
    std::array<char, 96> line{};
    const int written = std::snprintf(line.data(), line.size(), "ev=initialize stage=%s result=fail", stage);
    if (written <= 0) {
        return;
    }
    const std::string_view event{line.data(), static_cast<std::size_t>(written)};
    core::log::early(event);
    core::log::write(core::log::Channel::core, core::log::Level::error, event);
}

/**
 * Resolves the installed packages directory: the setting when one is configured, else the
 * directory beside the executable.
 * @param output Receives the complete null-terminated directory.
 * @return True when the configured setting or the default resolution is usable.
 */
[[nodiscard]] bool resolve_packages_directory(core::path::Buffer& output) noexcept {
    const std::wstring_view configured(core::settings::get().server.packagesDir.data());
    if (!configured.empty()) {
        return core::path::assign(output, configured);
    }
    const HMODULE process = GetModuleHandleW(nullptr);
    return process != nullptr && core::path::module_directory(process, output)
           && core::path::append(output, kInstalledPackagesDirectory);
}

/**
 * Builds the local content manifest when an installed packages directory is present.
 * A standalone host without installed packages leaves the manifest pending, matching the
 * in-process host classification that skips the manifest for non-production hosts.
 * @param module Loaded module used for generated cache placement.
 * @return True when no packages directory exists or one complete catalog is ready.
 */
[[nodiscard]] bool initialize_content_manifest(void* module) noexcept {
    core::path::Buffer packages;
    if (!resolve_packages_directory(packages)) {
        core::log::write(core::log::Channel::core,
                         core::log::Level::error,
                         "ev=initialize stage=content_manifest result=fail");
        return false;
    }
    const DWORD attributes = GetFileAttributesW(packages.chars.data());
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
        core::log::write(core::log::Channel::core,
                         core::log::Level::warn,
                         "ev=initialize stage=content_manifest result=skipped reason=no_packages");
        return true;
    }
    const bool initialized = state::content_manifest::initialize(
        module, std::wstring_view(packages.chars.data(), packages.length));
    if (!initialized) {
        core::log::write(core::log::Channel::core,
                         core::log::Level::error,
                         "ev=initialize stage=content_manifest result=fail");
    }
    return initialized;
}

/** @param digit ASCII hex digit. @return Nibble value, or -1 when the digit is not hex. */
[[nodiscard]] int hex_value(char digit) noexcept {
    if (digit >= '0' && digit <= '9') {
        return digit - '0';
    }
    if (digit >= 'a' && digit <= 'f') {
        return digit - 'a' + 10;
    }
    if (digit >= 'A' && digit <= 'F') {
        return digit - 'A' + 10;
    }
    return -1;
}

/**
 * Publishes the configured bootstrap token into the State the SignOn blob reads.
 * The token is 16 bytes configured as 32 hex characters. An empty or malformed value must fail
 * the boot: a missing config blob is a silent client-side package-validation failure.
 * @return True when the complete token is published.
 */
[[nodiscard]] bool publish_configured_token() noexcept {
    const std::string_view token(core::settings::get().server.bootstrapToken.data());
    if (token.size() != 32) {
        core::log::write(core::log::Channel::core,
                         core::log::Level::error,
                         "ev=bootstrap stage=token result=fail reason=config");
        return false;
    }
    std::array<std::byte, 16> bytes{};
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        const int high = hex_value(token[index * 2]);
        const int low = hex_value(token[index * 2 + 1]);
        if (high < 0 || low < 0) {
            core::log::write(core::log::Channel::core,
                             core::log::Level::error,
                             "ev=bootstrap stage=token result=fail reason=config");
            return false;
        }
        bytes[index] = static_cast<std::byte>((high << 4) | low);
    }
    const bool published = state::publish_bootstrap_token(bytes);
    SecureZeroMemory(bytes.data(), bytes.size());
    if (!published) {
        core::log::write(core::log::Channel::core,
                         core::log::Level::error,
                         "ev=bootstrap stage=token result=fail reason=size");
        return false;
    }
    core::log::write(core::log::Channel::core,
                     core::log::Level::info,
                     "ev=bootstrap stage=token result=ok");
    return true;
}

/**
 * Loads the Oodle codec and proves one full compress round trip works.
 * Risk 5 mitigation: a missing codec silently empties family-4 snapshots.
 */
void initialize_oodle() noexcept {
    const HMODULE module = LoadLibraryW(kOodleModuleName);
    if (module == nullptr) {
        core::log::write(core::log::Channel::core,
                         core::log::Level::warn,
                         "ev=oodle stage=load result=fail");
        return;
    }
    std::array<std::byte, kOodleSelfTestSize> plain{};
    for (std::size_t index = 0; index < plain.size(); ++index) {
        plain[index] = static_cast<std::byte>(index);
    }
    std::size_t capacity = 0;
    std::array<std::byte, 4096> compressed{};
    std::size_t compressedSize = 0;
    std::array<std::byte, kOodleSelfTestSize> restored{};
    const bool ready =
        middleware::compression::oodle::required_capacity(module, plain.size(), capacity)
        && capacity <= compressed.size()
        && middleware::compression::oodle::compress(
            module, plain, std::span(compressed).first(capacity), compressedSize)
        && compressedSize != 0
        && middleware::compression::oodle::decompress(
            module, std::span(compressed).first(compressedSize), restored);
    core::log::write(core::log::Channel::core,
                     core::log::Level::info,
                     ready ? "ev=oodle stage=load result=ok"
                           : "ev=oodle stage=load result=fail reason=roundtrip");
}

/**
 * Reports the resolved build-data cache state without failing the boot.
 * LoadStatus::missing is success in State, so a missing file only warns.
 */
void report_build_data() noexcept {
    core::path::Buffer path;
    const std::wstring_view configured(core::settings::get().server.buildDataPath.data());
    bool resolved = !configured.empty() && core::path::assign(path, configured);
    if (!resolved) {
        const HMODULE process = GetModuleHandleW(nullptr);
        resolved = process != nullptr && core::path::module_directory(process, path)
                   && core::path::append(path, kBuildDataCacheFile);
    }
    if (!resolved) {
        core::log::write(core::log::Channel::core,
                         core::log::Level::warn,
                         "ev=build_data stage=cache result=fail reason=path");
        return;
    }
    const DWORD attributes = GetFileAttributesW(path.chars.data());
    const bool present =
        attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
    core::log::write(core::log::Channel::core,
                     present ? core::log::Level::info : core::log::Level::warn,
                     present ? "ev=build_data stage=cache result=ok"
                             : "ev=build_data stage=cache result=missing");
}

/** Caller-owned GUID storage filled by the State snapshot visitor. */
struct GuidContext {
    std::array<char, 37> text{};
    std::size_t length{};
};

/** @param context GuidContext. @param view Borrowed manifest. @return True always. */
[[nodiscard]] bool copy_guid(void* context, const state::content_manifest::View& view) noexcept {
    auto& guid = *static_cast<GuidContext*>(context);
    guid.length = view.guid.size();
    std::copy(view.guid.begin(), view.guid.end(), guid.text.begin());
    return true;
}

/**
 * Validates an optional configured ContentConfig id and logs the exact id the config route
 * serves. The operator copies that id into the Client's external config_guid (risk 2).
 * @return False only when a configured override is not a canonical id, which the Client would
 *         reject silently.
 */
[[nodiscard]] bool validate_served_guid() noexcept {
    const std::string_view override(core::settings::get().server.configGuid.data());
    if (!override.empty() && !https::valid_config_guid(override)) {
        core::log::write(core::log::Channel::core,
                         core::log::Level::error,
                         "ev=content_manifest stage=guid result=fail reason=invalid_override");
        return false;
    }
    if (!override.empty()) {
        std::array<char, 128> line{};
        const int written = std::snprintf(line.data(),
                                          line.size(),
                                          "ev=content_manifest stage=guid guid=%.*s "
                                          "source=override",
                                          static_cast<int>(override.size()),
                                          override.data());
        if (written > 0) {
            core::log::write(core::log::Channel::core,
                             core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(written)});
        }
        return true;
    }
    GuidContext context{};
    if (state::content_manifest::visit_snapshot(&copy_guid, &context)) {
        std::array<char, 128> line{};
        const int written = std::snprintf(line.data(),
                                          line.size(),
                                          "ev=content_manifest stage=guid guid=%.*s",
                                          static_cast<int>(context.length),
                                          context.text.data());
        if (written > 0) {
            core::log::write(core::log::Channel::core,
                             core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(written)});
        }
        return true;
    }
    core::log::write(core::log::Channel::core,
                     core::log::Level::warn,
                     "ev=content_manifest stage=guid result=skipped");
    return true;
}

} // namespace
} // namespace sunrise::server

/**
 * Standalone server entry point: core_runtime's boot order minus the Client and UI layers,
 * plus the data-handoff steps (bootstrap token, Oodle, build-data report) and the HTTPS
 * listener, then a bounded service loop driving the BAP transport. No Detours, no hooks, no
 * UI, no egress. The `--s1-test` argument runs the S1-1 account-object memcmp acceptance test
 * after the shared boot chain and exits with its verdict.
 * @return Zero after a clean shutdown signal, or nonzero when a boot stage fails.
 */
int main(int argc, char** argv) {
    const bool s1Test = argc > 1 && std::strcmp(argv[1], "--s1-test") == 0;
    const bool equipDiff = argc > 1 && std::strcmp(argv[1], "--equip-diff") == 0;
    const bool cacheCheck = argc > 1 && std::strcmp(argv[1], "--cache-check") == 0;
    const bool selectionVersionTest =
        argc > 1 && std::strcmp(argv[1], "--selection-version-test") == 0;
    // P2: prints the provisioned-union equipment hash so the cache's eqHash
    // field can be stamped OFFLINE whenever the provisioned set changes -
    // otherwise every post-change pass loads stale (the standalone server
    // cannot regenerate details) and the catalog boots empty.
    const bool printProvisionedHash =
        argc > 1 && std::strcmp(argv[1], "--print-provisioned-hash") == 0;
    // The sweep's first live run tested ONE shape while its boot record looked like two. That
    // failure was invisible in a log and trivial to see here, so the sweep's own invariants
    // gate a deploy now (AGENTS.md lesson 13: instrument the boring path).
    const bool membershipSweepTest =
        argc > 1 && std::strcmp(argv[1], "--membership-sweep-test") == 0;
    const HMODULE module = GetModuleHandleW(nullptr);
    if (!sunrise::core::settings::initialize(module)) {
        // Settings name their own failure; the sinks do not exist yet to carry a second line.
        return 1;
    }
    if (membershipSweepTest) {
        return sunrise::server::bap::encrypted::push::activity::run_membership_sweep_test();
    }
    if (printProvisionedHash) {
        const auto hash = sunrise::state::runtime::equipment::
            configured_hash_provisioned();
        std::printf("PROVISIONED_HASH=0x%016llX\n",
                    static_cast<unsigned long long>(hash));
        sunrise::core::settings::shutdown();
        return 0;
    }
    (void)SetConsoleCtrlHandler(&sunrise::server::on_console_signal, TRUE);
    // One stage per step, so a boot failure names the step instead of the whole expression.
    const char* stage = nullptr;
    if (!sunrise::core::log::initialize(module, sunrise::core::settings::get().logging)) {
        stage = "logging";
    } else if (!sunrise::state::entitlements::publish(
                   sunrise::core::settings::get().server.entitlements)) {
        stage = "entitlements";
    } else if (!sunrise::state::initialize_provisioned(
                   module,
                   sunrise::core::settings::get().initialActivityDefaults)) {
        stage = "state";
    } else if (!sunrise::server::persistence::initialize(module)) {
        stage = "persistence";
    }
    if (stage != nullptr) {
        sunrise::server::report_stage_failure(stage);
        // Reverse every stage because the failing expression may have completed earlier stages.
        sunrise::server::https::shutdown();
        sunrise::server::admin::shutdown();
        sunrise::server::transport::discovery::shutdown();
        sunrise::server::shutdown();
        sunrise::middleware::shutdown();
        sunrise::state::content_manifest::shutdown();
        sunrise::server::persistence::shutdown();
        sunrise::state::shutdown();
        sunrise::state::entitlements::clear();
        sunrise::state::unlocks::clear();
        sunrise::core::log::shutdown();
        sunrise::core::settings::shutdown();
        return 1;
    }
    // S1-2/P2: each provisioned slot reloads its own persisted account when the database holds
    // one; the settings blocks remain the fresh-database fallback. Unlocks and entitlements
    // stay process-global policy for now (owner call D3 scope): they publish once from slot 0.
    sunrise::state::unlocks::Table bootUnlocks = sunrise::core::settings::get().initialUnlocks;
    sunrise::state::entitlements::Table bootEntitlements =
        sunrise::core::settings::get().server.entitlements;
    bool family5FromDatabase = false;
    bool globalPolicyFromDatabase = false;
    const std::size_t provisionedCount =
        sunrise::core::settings::get().provisionedAccountCount;
    for (std::size_t key = 0; key < provisionedCount && !stage; ++key) {
        if (!sunrise::server::persistence::ready()) {
            break;
        }
        const auto accountKey = static_cast<sunrise::core::settings::AccountKey>(key);
        sunrise::state::AccountState databaseAccount{};
        sunrise::state::unlocks::Table databaseUnlocks{};
        sunrise::state::Family5State databaseFamily5{};
        if (!sunrise::server::persistence::load_account(
                databaseAccount, databaseUnlocks, databaseFamily5, accountKey)
            || databaseAccount.primarySoid == 0) {
            continue;
        }
        // The first State pass above loaded build data and seeded the database; publish each
        // persisted account into its own slot as the source of truth. Slot 0 also refreshes
        // the shared cache identity exactly like the historical second pass did.
        if (key == 0) {
            bootUnlocks = databaseUnlocks;
            globalPolicyFromDatabase = true;
            family5FromDatabase = true;
            sunrise::state::entitlements::Table databaseEntitlements{};
            if (sunrise::server::persistence::load_entitlements(databaseEntitlements, accountKey)) {
                bootEntitlements = databaseEntitlements;
            }
        }
        if (!sunrise::state::reload_account_from_database(
                module,
                databaseAccount,
                sunrise::core::settings::get().initialActivityDefaults,
                accountKey)
            || (family5FromDatabase
                && !sunrise::state::publish_family5(databaseFamily5, accountKey))) {
            stage = "persistence_account";
        }
    }
    if (!stage) {
        sunrise::state::unlocks::publish(bootUnlocks);
        if (!globalPolicyFromDatabase
            || !sunrise::state::entitlements::publish(bootEntitlements)) {
            // A fresh database keeps the authored entitlement policy; a failed DB read of an
            // existing policy is fatal, matching the historical single-account behavior.
            if (globalPolicyFromDatabase) {
                stage = "persistence_account";
            }
        }
    }
    // S1-3 Option-B: the five decoded content domains replace the cache-driven runtime rows
    // after the last cache::load (every State pass above runs one). A missing content file or
    // a contradictory ability-bucket domain stops the boot with a named stage.
    if (cacheCheck) {
        // The cache verification: the reader's exact model applied to the deployed cache,
        // with every check printed. Runs BEFORE the content swap (which aborts the boot
        // when the cache is refused), right after the persistence stage.
        const int verdict = sunrise::server::persistence::run_cache_check(module);
        sunrise::server::https::shutdown();
        sunrise::server::admin::shutdown();
        sunrise::server::transport::discovery::shutdown();
        sunrise::server::shutdown();
        sunrise::middleware::shutdown();
        sunrise::state::content_manifest::shutdown();
        sunrise::server::persistence::shutdown();
        sunrise::state::shutdown();
        sunrise::state::entitlements::clear();
        sunrise::state::unlocks::clear();
        sunrise::core::log::shutdown();
        sunrise::core::settings::shutdown();
        return verdict;
    }
    if (!sunrise::server::content::apply_oracle_swap(module)) {
        stage = "content_swap";
    }
    if (stage != nullptr) {
        sunrise::server::report_stage_failure(stage);
        // Reverse every stage because the failing expression may have completed earlier stages.
        sunrise::server::https::shutdown();
        sunrise::server::admin::shutdown();
        sunrise::server::transport::discovery::shutdown();
        sunrise::server::shutdown();
        sunrise::middleware::shutdown();
        sunrise::state::content_manifest::shutdown();
        sunrise::server::persistence::shutdown();
        sunrise::state::shutdown();
        sunrise::state::entitlements::clear();
        sunrise::state::unlocks::clear();
        sunrise::core::log::shutdown();
        sunrise::core::settings::shutdown();
        return 1;
    }
    // The S1-1 acceptance test needs only settings, unlocks, build data, and the state
    // database, so it runs before the network stages bind any port.
    if (s1Test) {
        const int verdict = sunrise::server::persistence::run_account_memcmp_test(module);
        sunrise::server::https::shutdown();
        sunrise::server::admin::shutdown();
        sunrise::server::transport::discovery::shutdown();
        sunrise::server::shutdown();
        sunrise::middleware::shutdown();
        sunrise::state::content_manifest::shutdown();
        sunrise::server::persistence::shutdown();
        sunrise::state::shutdown();
        sunrise::state::entitlements::clear();
        sunrise::state::unlocks::clear();
        sunrise::core::log::shutdown();
        sunrise::core::settings::shutdown();
        return verdict;
    }
    if (equipDiff) {
        // The subclass-equip diff test: the character object pre-equip vs post-equip
        // through the exact mutation + re-encode the live server's queuez path uses.
        const int verdict = sunrise::server::persistence::run_equip_diff_test(module);
        sunrise::server::https::shutdown();
        sunrise::server::admin::shutdown();
        sunrise::server::transport::discovery::shutdown();
        sunrise::server::shutdown();
        sunrise::middleware::shutdown();
        sunrise::state::content_manifest::shutdown();
        sunrise::server::persistence::shutdown();
        sunrise::state::shutdown();
        sunrise::state::entitlements::clear();
        sunrise::state::unlocks::clear();
        sunrise::core::log::shutdown();
        sunrise::core::settings::shutdown();
        return verdict;
    }
    if (selectionVersionTest) {
        // The family-4 version-discipline test: the replay + 801x2 + 403 ladder with the
        // delivered versions asserted strictly consecutive, plus the deferred-repush cases.
        const int verdict = sunrise::server::persistence::run_selection_version_test(module);
        sunrise::server::https::shutdown();
        sunrise::server::admin::shutdown();
        sunrise::server::transport::discovery::shutdown();
        sunrise::server::shutdown();
        sunrise::middleware::shutdown();
        sunrise::state::content_manifest::shutdown();
        sunrise::server::persistence::shutdown();
        sunrise::state::shutdown();
        sunrise::state::entitlements::clear();
        sunrise::state::unlocks::clear();
        sunrise::core::log::shutdown();
        sunrise::core::settings::shutdown();
        return verdict;
    }
    if (!sunrise::server::publish_configured_token()) {
        stage = "bootstrap";
    } else if (!sunrise::server::initialize_content_manifest(module)) {
        stage = "content_manifest";
    } else if (!sunrise::server::validate_served_guid()) {
        stage = "guid";
    } else if (!sunrise::middleware::initialize()) {
        stage = "middleware";
    } else if (!sunrise::server::initialize()) {
        stage = "server";
    } else if (!sunrise::server::transport::discovery::initialize()) {
        stage = "discovery";
    } else if (!sunrise::server::https::initialize()) {
        stage = "https";
    } else if (!sunrise::server::admin::initialize()) {
        stage = "admin";
    }
    if (stage != nullptr) {
        sunrise::server::report_stage_failure(stage);
        // Reverse every stage because the failing expression may have completed earlier stages.
        sunrise::server::https::shutdown();
        sunrise::server::admin::shutdown();
        sunrise::server::transport::discovery::shutdown();
        sunrise::server::shutdown();
        sunrise::middleware::shutdown();
        sunrise::state::content_manifest::shutdown();
        sunrise::server::persistence::shutdown();
        sunrise::state::shutdown();
        sunrise::state::entitlements::clear();
        sunrise::state::unlocks::clear();
        sunrise::core::log::shutdown();
        sunrise::core::settings::shutdown();
        return 1;
    }
    // Data-handoff self-tests run after the boot chain, before the first service tick.
    sunrise::server::initialize_oodle();
    sunrise::server::report_build_data();
    sunrise::core::log::write(sunrise::core::log::Channel::core,
                              sunrise::core::log::Level::info,
                              "ev=initialize result=ok");
    while (sunrise::server::g_running.load(std::memory_order_acquire)) {
        sunrise::server::service(GetTickCount64());
        Sleep(sunrise::server::kServiceIntervalMilliseconds);
    }
    sunrise::core::log::write(sunrise::core::log::Channel::core,
                              sunrise::core::log::Level::info,
                              "ev=shutdown stage=console_signal result=ok");
    sunrise::server::https::shutdown();
    sunrise::server::admin::shutdown();
    sunrise::server::transport::discovery::shutdown();
    sunrise::server::shutdown();
    sunrise::middleware::shutdown();
    sunrise::state::content_manifest::shutdown();
    sunrise::server::persistence::shutdown();
    sunrise::state::shutdown();
    sunrise::state::entitlements::clear();
    sunrise::state::unlocks::clear();
    sunrise::core::log::write(sunrise::core::log::Channel::core,
                              sunrise::core::log::Level::info,
                              "ev=shutdown result=ok");
    sunrise::core::log::shutdown();
    sunrise::core::settings::shutdown();
    return 0;
}
