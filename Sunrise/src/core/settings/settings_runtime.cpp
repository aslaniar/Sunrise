#include <Windows.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <string_view>

#include "../../../resources/resource.h"
#include "../filesystem/path.h"
#include "../logging/log.h"
#include "settings.h"
#include "settings_upgrade.h"

namespace sunrise::core::settings {
namespace {

/** The JSON settings file is the only file stored directly in the owned folder. */
constexpr std::wstring_view kSettingsFileSuffix = L"\\settings.json";
/** An upgraded document is staged under this suffix before it replaces the settings file. */
constexpr std::wstring_view kUpgradeStageSuffix = L".new";
/** Largest settings file accepted into fixed storage. */
constexpr std::size_t kConfigCapacity = 1024 * 1024;

Settings g_settings = defaults();

/**
 * Names the step that ended the load. Settings are read before the log sinks exist, so this line
 * is the only way to report a boot failure here.
 * @param reason Short key naming the step.
 * @param stage "load" at boot, "reload" for a hot-reload pass - a refused reload
 *              must never read as a boot failure in the logs.
 * @return Always false, so callers can return it directly.
 */
[[nodiscard]] bool fail(std::string_view reason, std::string_view stage = "load") noexcept {
    std::array<char, 96> line{};
    const int written = std::snprintf(line.data(),
                                      line.size(),
                                      "ev=settings stage=%.*s result=fail reason=%.*s",
                                      static_cast<int>(stage.size()),
                                      stage.data(),
                                      static_cast<int>(reason.size()),
                                      reason.data());
    if (written > 0) {
        log::early({line.data(), static_cast<std::size_t>(written)});
    }
    // ALSO to stderr: the sandbox/gate runs' console visibility (the silent
    // rc=1 class - the p2-224 deploy arc's unidentified early abort).
    std::fputs(line.data(), stderr);
    std::fputc('\n', stderr);
    return false;
}

/**
 * Reports a file this build did not upgrade, which means a newer build wrote it.
 * @param fileVersion Version read from the file, or zero when the key was missing.
 */
void report_version(std::uint32_t fileVersion) noexcept {
    if (fileVersion == kSettingsVersion) {
        return;
    }
    std::array<char, 96> line{};
    const int written = std::snprintf(line.data(),
                                      line.size(),
                                      "ev=settings stage=version result=mismatch file=%u build=%u",
                                      static_cast<unsigned>(fileVersion),
                                      static_cast<unsigned>(kSettingsVersion));
    if (written > 0) {
        log::early({line.data(), static_cast<std::size_t>(written)});
    }
}

/**
 * Borrows the default settings document out of the module resources.
 * @param module Loaded DLL holding the default JSON resource.
 * @param output Receives the resource bytes, owned by the module.
 * @return True when the resource is present and not empty.
 */
[[nodiscard]] bool bundled_document(void* module, std::string_view& output) noexcept {
    const HMODULE loadedModule = static_cast<HMODULE>(module);
    const HRSRC resource =
        FindResourceW(loadedModule, MAKEINTRESOURCEW(IDR_DEFAULT_SETTINGS), MAKEINTRESOURCEW(10));
    if (resource == nullptr) {
        return false;
    }
    const DWORD size = SizeofResource(loadedModule, resource);
    const HGLOBAL loaded = LoadResource(loadedModule, resource);
    const auto* bytes =
        loaded != nullptr ? static_cast<const char*>(LockResource(loaded)) : nullptr;
    if (size == 0 || bytes == nullptr) {
        return false;
    }
    output = std::string_view(bytes, size);
    return true;
}

/**
 * Copies the bundled default settings. An existing file is never overwritten.
 * @param module Loaded DLL holding the default JSON resource.
 * @param configPath Null-terminated destination path.
 * @return True when every bundled byte is written and the file closes cleanly.
 */
[[nodiscard]] bool write_default(void* module, const path::Buffer& configPath) noexcept {
    std::string_view document;
    if (!bundled_document(module, document)) {
        return false;
    }
    const HANDLE file = CreateFileW(configPath.chars.data(),
                                    GENERIC_WRITE,
                                    0,
                                    nullptr,
                                    CREATE_NEW,
                                    FILE_ATTRIBUTE_NORMAL,
                                    nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }
    DWORD written = 0;
    const auto size = static_cast<DWORD>(document.size());
    bool complete =
        WriteFile(file, document.data(), size, &written, nullptr) != FALSE && written == size;
    complete = CloseHandle(file) != FALSE && complete;
    if (!complete) {
        // A half-written default must not become the next boot's settings.
        (void)DeleteFileW(configPath.chars.data());
    }
    return complete;
}

/**
 * Replaces the settings file with an upgraded document.
 * The text is staged beside the file and moved over it, so a failed write cannot leave half a file.
 * @param configPath Null-terminated settings path.
 * @param document Complete upgraded document.
 * @return True when the file now holds the upgraded document.
 */
[[nodiscard]] bool store_upgraded(const path::Buffer& configPath,
                                  std::string_view document) noexcept {
    path::Buffer stagePath = configPath;
    if (!path::append(stagePath, kUpgradeStageSuffix)) {
        return false;
    }
    const HANDLE file = CreateFileW(stagePath.chars.data(),
                                    GENERIC_WRITE,
                                    0,
                                    nullptr,
                                    CREATE_ALWAYS,
                                    FILE_ATTRIBUTE_NORMAL,
                                    nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }
    DWORD written = 0;
    const auto size = static_cast<DWORD>(document.size());
    bool complete =
        WriteFile(file, document.data(), size, &written, nullptr) != FALSE && written == size;
    complete = CloseHandle(file) != FALSE && complete;
    complete =
        complete
        && MoveFileExW(stagePath.chars.data(), configPath.chars.data(), MOVEFILE_REPLACE_EXISTING)
               != FALSE;
    if (!complete) {
        (void)DeleteFileW(stagePath.chars.data());
    }
    return complete;
}

/**
 * Reports the outcome of an in-place upgrade of the settings file.
 * @param stored True when the upgraded document replaced the file on disk.
 */
void report_upgrade(bool stored) noexcept {
    std::array<char, 96> line{};
    const int written = std::snprintf(line.data(),
                                      line.size(),
                                      "ev=settings stage=upgrade version=%u stored=%u",
                                      static_cast<unsigned>(kSettingsVersion),
                                      stored ? 1U : 0U);
    if (written > 0) {
        log::early({line.data(), static_cast<std::size_t>(written)});
    }
}

/** The module handle, captured at initialize - the reload's read path needs it. */
void* g_module{};

/**
 * One read of the settings file. The text banks below are function-local
 * statics, so a returned document stays valid until the NEXT call re-reads -
 * which is exactly the sharing contract between initialize and reload.
 */
struct Document {
    /** The settings file's resolved path; store_upgraded needs it after a parse. */
    path::Buffer configPath;
    /** The document to parse (the file's bytes, or the upgraded rewrite of them). */
    std::string_view text;
    /** True when the text is an in-memory upgrade that must be stored once it parses. */
    bool upgraded{};
};

/**
 * Reads (and upgrades, when needed) the settings document. Shared by
 * initialize and reload - the weasel/marionberry arc's FIX B.
 * @param module Loaded module naming the owned folder.
 * @param loaded Receives the path, the text, and the upgrade flag.
 * @param stage The failing reader's stage name ("load" or "reload").
 * @return True when the file was read (the caller owns the parse decision).
 */
[[nodiscard]] bool read_settings_document(void* module,
                                          Document& loaded,
                                          std::string_view stage = "load") noexcept {

    loaded = {};
    path::Buffer configPath;
    if (!path::artifact_directory(module, configPath)
        || !path::append(configPath, kSettingsFileSuffix)) {
        return fail("path", stage);
    }

    const HANDLE file = CreateFileW(configPath.chars.data(),
                                    GENERIC_READ,
                                    FILE_SHARE_READ,
                                    nullptr,
                                    OPEN_EXISTING,
                                    FILE_ATTRIBUTE_NORMAL,
                                    nullptr);
    HANDLE readableFile = file;
    if (readableFile == INVALID_HANDLE_VALUE) {
        // A missing file is created once; other open failures remain fatal.
        if (GetLastError() != ERROR_FILE_NOT_FOUND) {
            return fail("open", stage);
        }
        if (!write_default(module, configPath)) {
            return fail("write_default", stage);
        }
        readableFile = CreateFileW(configPath.chars.data(),
                                   GENERIC_READ,
                                   FILE_SHARE_READ,
                                   nullptr,
                                   OPEN_EXISTING,
                                   FILE_ATTRIBUTE_NORMAL,
                                   nullptr);
        if (readableFile == INVALID_HANDLE_VALUE) {
            return fail("reopen", stage);
        }
    }

    LARGE_INTEGER size{};
    if (!GetFileSizeEx(readableFile, &size) || size.QuadPart <= 0) {
        CloseHandle(readableFile);
        return fail("empty", stage);
    }
    if (static_cast<std::uint64_t>(size.QuadPart) > kConfigCapacity) {
        // Silence here reads exactly like a crash, and the cap is the usual cause.
        CloseHandle(readableFile);
        return fail("too_large", stage);
    }

    // Static because two 1 MiB banks overflow the stack. Settings load once, on one thread.
    static std::array<char, kConfigCapacity> buffer{};
    DWORD read = 0;
    const bool readOk =
        ReadFile(readableFile, buffer.data(), static_cast<DWORD>(size.QuadPart), &read, nullptr)
            != FALSE
        && read == size.QuadPart;
    const bool closed = CloseHandle(readableFile) != FALSE;
    if (!readOk || !closed) {
        return fail("read", stage);
    }
    std::string_view document(buffer.data(), read);
    static std::array<char, kConfigCapacity> upgradedBuffer{};
    bool upgraded = false;
    if (upgrade::needed(document)) {
        std::string_view bundled;
        std::size_t upgradedSize = 0;
        if (!bundled_document(module, bundled)
            || !upgrade::apply(document, bundled, upgradedBuffer, upgradedSize)) {
            return fail("upgrade", stage);
        }
        document = std::string_view(upgradedBuffer.data(), upgradedSize);
        upgraded = true;
    }
    loaded.configPath = configPath;
    loaded.text = document;
    loaded.upgraded = upgraded;
    return true;
}

/**
 * Stores an upgraded document once it is known to parse. The upgrade side
 * effect the extraction initially dropped: without this store, every boot
 * re-upgrades in memory while the file on disk stays one version behind.
 * @param loaded One completed read whose text already parsed.
 */
void store_parsed_upgrade(const Document& loaded) noexcept {
    if (loaded.upgraded) {
        report_upgrade(store_upgraded(loaded.configPath, loaded.text));
    }
}

} // namespace

/** Loads the settings file from the owned folder, or creates the default one. */
bool initialize(void* module) noexcept {
    g_module = module;
    Document loaded;
    if (!read_settings_document(module, loaded)) {
        return false;
    }
    Settings parsed;
    if (!parse(loaded.text, parsed)) {
        return fail("parse");
    }
    // The file is replaced only once the upgraded document is known to parse.
    store_parsed_upgrade(loaded);
    report_version(parsed.version);
    g_settings = parsed;
    return true;
}

bool reload() noexcept {
    Document loaded;
    if (!read_settings_document(g_module, loaded, "reload")) {
        return fail("reload-read", "reload");
    }
    Settings parsed;
    if (!parse(loaded.text, parsed)) {
        return fail("reload-parse", "reload");
    }
    store_parsed_upgrade(loaded);
    // THE BOOT-TIME CLASS: preserved from the running object. Everything here
    // seeded state a mid-flight swap cannot re-derive - the bootstrap token is
    // the signon identity, and every bind field below names a listener that
    // bound ONCE at boot (a new value would never be observed; silently
    // adopting it would only hide why nothing moved).
    parsed.server.bootstrapToken = g_settings.server.bootstrapToken;
    parsed.server.bindAddress = g_settings.server.bindAddress;
    parsed.server.relayAddress = g_settings.server.relayAddress;
    parsed.server.bapPort = g_settings.server.bapPort;
    parsed.server.httpsPort = g_settings.server.httpsPort;
    parsed.server.adminPort = g_settings.server.adminPort;
    parsed.server.discoveryPort = g_settings.server.discoveryPort;
    parsed.server.gameplay.port = g_settings.server.gameplay.port;
    parsed.client.externalServer = g_settings.client.externalServer;
    g_settings = parsed;
    return true;
}

/** Resets active settings to the fixed defaults. */
void shutdown() noexcept {
    g_module = nullptr;
    g_settings = defaults();
}

/** @return Active read-only Core settings. */
const Settings& get() noexcept {
    return g_settings;
}

/** @return The provisioned account this install plays as. */
AccountKey local_account() noexcept {
    const Settings& settings = get();
    // A key naming a slot this file does not provision would silently mean slot 0, which is
    // the failure this accessor exists to end. The parser already refuses out-of-range keys;
    // this clamps against a file that names a slot inside the capacity but beyond the array
    // it actually authored.
    if (settings.provisionedAccountCount != 0
        && settings.localAccountKey >= settings.provisionedAccountCount) {
        return kLegacyAccount;
    }
    return settings.localAccountKey;
}

} // namespace sunrise::core::settings
