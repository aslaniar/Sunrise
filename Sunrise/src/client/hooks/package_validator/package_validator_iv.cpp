/**
 * Re-asserts the healthy kind0 IV before the package-registration validator runs.
 *
 * The external-mode black screen ends in the package-registration validator
 * FUN_140381dd0 (destiny2 + 0x381DD0). The game's own registration path writes a wrong
 * ("hybrid") 16-byte value into the kind0 IV buffer (image RVA 0x1F44CE0) microseconds
 * before the validator reads it. The validator's hash chain (thunk_FUN_14480a10f) mixes
 * only those 16 IV bytes, so the computed hash no longer matches the expected hash at the
 * record + 0x168 and the validator returns -87 (0xffffffa9): "Patchable package
 * registration failed" -> black screen. This detour writes the healthy 16 bytes at every
 * validator entry and passes every argument through to the original untouched. The write
 * is an in-process .data write only; no code pages and no other game buffer are touched.
 * Attaches only while client.externalServer.enabled is true.
 */

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

namespace sunrise::client::hooks::package_validator {
namespace {

/** Image RVA of the package-registration validator FUN_140381dd0 (destiny2 + 0x381DD0). */
constexpr std::uintptr_t kValidatorRva = 0x381DD0;
/** Image RVA of the kind0 IV buffer the hash chain reads (destiny2 + 0x1F44CE0). */
constexpr std::uintptr_t kKind0IvRva = 0x1F44CE0;
/** The healthy 16 kind0 IV bytes that make the validator pass. */
constexpr std::array<std::byte, 16> kHealthyIv{
    std::byte{0xD6}, std::byte{0x2A}, std::byte{0xB2}, std::byte{0xC1},
    std::byte{0x0C}, std::byte{0xC0}, std::byte{0x1B}, std::byte{0xC5},
    std::byte{0x35}, std::byte{0xDB}, std::byte{0x7B}, std::byte{0x86},
    std::byte{0x55}, std::byte{0xC7}, std::byte{0xDC}, std::byte{0x3B},
};

/**
 * Exact validator ABI from the phase_registration3 decompile:
 * undefined8 FUN_140381dd0(uint *param_1, ushort param_2, longlong param_3, int param_4,
 *                          ushort param_5, char param_6, longlong param_7)
 */
using Validator = std::uint64_t(__fastcall*)(std::uint32_t*,
                                             std::uint16_t,
                                             std::int64_t,
                                             std::int32_t,
                                             std::uint16_t,
                                             std::int8_t,
                                             std::int64_t) noexcept;

hooking::detour::Handle g_handle{};
/** Trampoline published by the detour transaction; read on the validator's hot path. */
std::atomic<Validator> g_original{nullptr};
/** Runtime address of the kind0 IV buffer, fixed once at install. */
std::atomic<std::byte*> g_ivAddress{nullptr};
/** One warn per process when the IV write fails, so the log ring is not flooded. */
std::atomic<bool> g_writeFailureLogged{false};

/** Reports one IV write failure, once. */
void report_write_failure() noexcept {
    bool expected = false;
    if (g_writeFailureLogged.compare_exchange_strong(expected, true)) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::warn,
                         "ev=package_validator_iv stage=write result=fail reason=memory");
    }
}

/**
 * Re-asserts the healthy kind0 IV, then runs the validator with every argument unchanged.
 * @return The original validator result, or -87 when no trampoline is reachable.
 */
__declspec(noinline) std::uint64_t __fastcall validator_iv_body(std::uint32_t* param1,
                                                                std::uint16_t param2,
                                                                std::int64_t param3,
                                                                std::int32_t param4,
                                                                std::uint16_t param5,
                                                                std::int8_t param6,
                                                                std::int64_t param7) noexcept {
    const Validator original = g_original.load(std::memory_order_acquire);
    if (original != nullptr) {
        std::byte* const iv = g_ivAddress.load(std::memory_order_acquire);
        if (iv != nullptr) {
            SIZE_T written = 0;
            if (WriteProcessMemory(GetCurrentProcess(),
                                   iv,
                                   kHealthyIv.data(),
                                   kHealthyIv.size(),
                                   &written) == FALSE
                || written != kHealthyIv.size()) {
                report_write_failure();
            }
        }
        return original(param1, param2, param3, param4, param5, param6, param7);
    }
    // No trampoline: reproduce the validator's own failure result instead of faking a pass.
    return 0xFFFFFFA9ULL;
}

/** @param reason Key naming the step that failed. @return False, for a direct return. */
[[nodiscard]] bool fail_install(const char* reason) noexcept {
    std::array<char, 96> line{};
    const int written = std::snprintf(line.data(),
                                      line.size(),
                                      "ev=package_validator_iv stage=install result=fail "
                                      "reason=%s",
                                      reason);
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::warn,
                         {line.data(), static_cast<std::size_t>(written)});
    }
    return false;
}

} // namespace

/** Attaches the IV re-assertion detour when the external-server switch is on. */
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
        || !diagnostics::contains(range, baseValue + kValidatorRva)
        || !diagnostics::contains(range, baseValue + kKind0IvRva)) {
        return fail_install("target");
    }
    const hooking::detour::Spec spec{base + kValidatorRva, reinterpret_cast<void*>(&validator_iv_body)};
    if (!hooking::detour::install(spec, g_handle)) {
        return fail_install("attach");
    }
    g_ivAddress.store(base + kKind0IvRva, std::memory_order_release);
    g_original.store(reinterpret_cast<Validator>(g_handle.original), std::memory_order_release);
    core::log::write(core::log::Channel::client,
                     core::log::Level::info,
                     "ev=package_validator_iv stage=install result=ok");
    return true;
}

/** Detaches the IV re-assertion detour and drops its trampoline. */
bool uninstall() noexcept {
    if (g_handle.attached) {
        (void)hooking::detour::uninstall(g_handle);
    }
    g_original.store(nullptr, std::memory_order_release);
    g_ivAddress.store(nullptr, std::memory_order_release);
    return true;
}

/** @return True while the IV re-assertion detour is attached. */
bool is_installed() noexcept {
    return g_handle.attached;
}

} // namespace sunrise::client::hooks::package_validator
