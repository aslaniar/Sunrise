/**
 * Log-only observer on the schema-decode entry point.
 *
 * FUN_1404C74D0 (destiny2 + 0x4C74D0) is the archetype schema resolver every quantized
 * property decode funnels through (entity-archetypes.md FINAL F1 layer 2; full body in
 * phase3/decompiles.txt lines 5251-5304). It is a 5-argument fastcall:
 *   RCX = u32 schemaHash (param_1), RDX = dest, R8 = arg3, R9 = arg4,
 *   stack = int codec (1 = table A walker FUN_1404B9200, else table B FUN_1404BF920)
 * The hash's bucket = (hash >> 13) & 0x3FF and row = hash & 0x1FFF select the schema
 * group/row in *DAT_142439C70 (schema-hash-mine.md section 1.2). The client's own
 * player-baseline decode at destination load passes the EXACT schemaTagHash as RCX, so
 * one boot prints the real hash the world_population_schema_hash knob must carry.
 * The hook runs the original untouched and then logs each DISTINCT hash it sees (a
 * last-seen dedupe keeps the load-time flood to one line per hash). It changes nothing.
 * Attaches only while client.externalServer.enabled is true (same gate as the
 * package-validator hook).
 */

#include "schema_capture_observer.h"

#include <Windows.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>

#include "../../../core/logging/log.h"
#include "../../../core/settings/settings.h"
#include "../../diagnostics/module_range.h"
#include "../../hooking/detour.h"

namespace sunrise::client::hooks::schema_capture {
namespace {

/** Image RVA of FUN_1404C74D0, the schema-decode entry point. */
constexpr std::uintptr_t kSchemaDecodeRva = 0x4C74D0;
/** Bucket width of the runtime schema table (bit31 = 0 form, schema-hash-mine 1.2). */
constexpr std::uint32_t kBucketMask = 0x3FFU;
/** Row width of the runtime schema table. */
constexpr std::uint32_t kRowMask = 0x1FFFU;

/** Exact schema-decode ABI from the phase3 decompile of FUN_1404C74D0. */
using Decode = std::uint64_t(__fastcall*)(std::uint32_t,
                                          std::uint64_t,
                                          std::uint64_t,
                                          std::uint64_t,
                                          std::int32_t) noexcept;

hooking::detour::Handle g_handle{};
/** Trampoline published by the detour transaction; read on the decode path. */
std::atomic<Decode> g_original{nullptr};
/** Last logged hash; only distinct hashes print (load floods one line per hash). */
std::atomic<std::uint32_t> g_lastLoggedHash{0xFFFFFFFFU};

/**
 * Runs the original schema decode, then logs the hash when it differs from the last
 * logged one.
 * @return The original decode result, or 0 (resolve rejected) when no trampoline is
 *         reachable -- never fabricates an accept.
 */
__declspec(noinline) std::uint64_t __fastcall observer(std::uint32_t schemaHash,
                                                        std::uint64_t dest,
                                                        std::uint64_t arg3,
                                                        std::uint64_t arg4,
                                                        std::int32_t codec) noexcept {
    const Decode original = g_original.load(std::memory_order_acquire);
    if (original == nullptr) {
        return 0;
    }
    const std::uint64_t result = original(schemaHash, dest, arg3, arg4, codec);
    std::uint32_t last = g_lastLoggedHash.load(std::memory_order_acquire);
    if (last == schemaHash) {
        return result;
    }
    while (!g_lastLoggedHash.compare_exchange_weak(last, schemaHash,
                                                   std::memory_order_release,
                                                   std::memory_order_acquire)) {
        if (last == schemaHash) {
            return result;
        }
    }
    std::array<char, 128> line{};
    const int written = std::snprintf(
        line.data(),
        line.size(),
        "ev=schema_capture stage=decode result=ok hash=0x%08X bucket=%u row=%u codec=%d",
        schemaHash,
        (schemaHash >> 13) & kBucketMask,
        schemaHash & kRowMask,
        static_cast<int>(codec));
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(written)});
    }
    return result;
}

/** @param reason Key naming the step that failed. @return False, for a direct return. */
[[nodiscard]] bool fail_install(const char* reason) noexcept {
    std::array<char, 96> line{};
    const int written = std::snprintf(line.data(),
                                      line.size(),
                                      "ev=schema_capture stage=install result=fail reason=%s",
                                      reason);
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::warn,
                         {line.data(), static_cast<std::size_t>(written)});
    }
    return false;
}

} // namespace

/** Attaches the observer detour when the external-server switch is on. */
bool install() noexcept {
    if (!core::settings::get().client.externalServer.enabled || g_handle.attached) {
        return true;
    }
    std::byte* const base = reinterpret_cast<std::byte*>(GetModuleHandleW(nullptr));
    if (base == nullptr) {
        return fail_install("base");
    }
    const std::uintptr_t baseValue = reinterpret_cast<std::uintptr_t>(base);
    diagnostics::ModuleRange range{};
    if (!diagnostics::module_range(reinterpret_cast<HMODULE>(base), range)
        || !diagnostics::contains(range, baseValue + kSchemaDecodeRva)) {
        return fail_install("target");
    }
    const hooking::detour::Spec spec{base + kSchemaDecodeRva, reinterpret_cast<void*>(&observer)};
    if (!hooking::detour::install(spec, g_handle)) {
        return fail_install("attach");
    }
    g_original.store(reinterpret_cast<Decode>(g_handle.original), std::memory_order_release);
    core::log::write(core::log::Channel::client,
                     core::log::Level::info,
                     "ev=schema_capture stage=install result=ok");
    return true;
}

/** Detaches the observer detour and drops its trampoline. */
bool uninstall() noexcept {
    if (g_handle.attached) {
        (void)hooking::detour::uninstall(g_handle);
    }
    g_original.store(nullptr, std::memory_order_release);
    return true;
}

/** @return True while the observer detour is attached. */
bool is_installed() noexcept {
    return g_handle.attached;
}

} // namespace sunrise::client::hooks::schema_capture
