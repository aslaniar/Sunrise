/**
 * Log-only observers on the gate-side primitives (see the header). Both detours call the
 * original first, then log one line. Nothing is changed, so the hooks are safe on every
 * path. The caller capture = the return address the detour saw, which resolves to the
 * un-analyzed CUI-region caller via (caller - base) in Ghidra.
 */

#include "ability_gate_observer.h"

#include <Windows.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>

#include "../../../core/logging/log.h"
#include "../../../core/settings/settings.h"
#include "../../diagnostics/module_range.h"
#include "../../hooking/detour.h"

namespace sunrise::client::hooks::ability_gate {
namespace {

/** Image RVA of FUN_140E06070, the acquiredFlags byte test. */
constexpr std::uintptr_t kFlagTestRva = 0xE06070;
/** Image RVA of FUN_140F2B690, the opcode-2100 ability-change emitter. */
constexpr std::uintptr_t kAbilityEmitRva = 0xF2B690;
/** The definition-hash default the offline build never resolves away from. */
constexpr std::uint32_t kNoDefinitionHash = 0x811C9DC5U;
/** One log line's capacity. */
constexpr std::size_t kLineCapacity = 192;

/** Exact ABI from the L3 decompile: the byte test takes the account-ish pointer + the
 *  index (the first observed arg = a heap pointer, so the index rides the second
 *  register). Two-register signature is safe for the fastcall either way. */
using FlagTest = bool(__fastcall*)(void*, std::uintptr_t) noexcept;
/** Exact ABI from the L1 decompile: payload source + output, return unused. */
using AbilityEmit = void(__fastcall*)(void*, void*) noexcept;

hooking::detour::Handle g_testHandle{};
hooking::detour::Handle g_emitHandle{};
std::atomic<FlagTest> g_originalTest{nullptr};
std::atomic<AbilityEmit> g_originalEmit{nullptr};

/** @return The module base, for the caller-RVA line. */
std::uintptr_t module_base() noexcept {
    return reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
}

/** @return The return address one frame above the detoured call. */
void* caller_address() noexcept {
    return _ReturnAddress();
}

/** Runs the original flag test, then logs the raw registers and the caller. No
 *  dereference happens here — pass 2's byte read (base + 0x742C + idx) crashed the
 *  boot when the args were not the expected (pointer, index) pair. The raw dump is
 *  safe on every shape and still names the caller. */
__declspec(noinline) bool __fastcall test_observer(void* rcx, std::uintptr_t rdx) noexcept {
    const FlagTest original = g_originalTest.load(std::memory_order_acquire);
    const bool result = original != nullptr ? original(rcx, rdx) : false;
    const std::uintptr_t caller = reinterpret_cast<std::uintptr_t>(caller_address());
    const std::uintptr_t moduleBase = module_base();
    const std::uintptr_t callerRva = caller >= moduleBase ? caller - moduleBase : 0;
    std::array<char, kLineCapacity> line{};
    const int written = std::snprintf(
        line.data(),
        line.size(),
        "ev=ability_gate stage=flag_test rcx=0x%llX rdx=0x%llX result=%u caller=+0x%llX",
        static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(rcx)),
        static_cast<unsigned long long>(rdx),
        static_cast<unsigned>(result),
        static_cast<unsigned long long>(callerRva));
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(written)});
    }
    return result;
}

/** Runs the original emitter, then logs the payload hash it carried. */
__declspec(noinline) void __fastcall emit_observer(void* payloadSource, void* out) noexcept {
    const AbilityEmit original = g_originalEmit.load(std::memory_order_acquire);
    if (original != nullptr) {
        original(payloadSource, out);
    }
    const std::uintptr_t caller = reinterpret_cast<std::uintptr_t>(caller_address());
    const std::uintptr_t base = module_base();
    const std::uintptr_t callerRva = caller >= base ? caller - base : 0;
    std::uint32_t hash = kNoDefinitionHash;
    if (payloadSource != nullptr) {
        hash = *static_cast<std::uint32_t*>(payloadSource);
    }
    std::array<char, kLineCapacity> line{};
    const int written = std::snprintf(line.data(),
                                      line.size(),
                                      "ev=ability_gate stage=emit_2100 hash=0x%08X caller=+0x%llX",
                                      static_cast<unsigned>(hash),
                                      static_cast<unsigned long long>(callerRva));
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(written)});
    }
}

/** @param reason Key naming the step that failed. @return False, for a direct return. */
[[nodiscard]] bool fail_install(const char* reason) noexcept {
    std::array<char, 96> line{};
    const int written = std::snprintf(line.data(),
                                      line.size(),
                                      "ev=ability_gate stage=install result=fail reason=%s",
                                      reason);
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::warn,
                         {line.data(), static_cast<std::size_t>(written)});
    }
    return false;
}

} // namespace

/** Attaches both observers when the external-server switch is on. */
bool install() noexcept {
    if (!core::settings::get().client.externalServer.enabled) {
        return true;
    }
    if (g_testHandle.attached && g_emitHandle.attached) {
        return true;
    }
    std::byte* const base = reinterpret_cast<std::byte*>(GetModuleHandleW(nullptr));
    if (base == nullptr) {
        return fail_install("base");
    }
    const std::uintptr_t baseValue = reinterpret_cast<std::uintptr_t>(base);
    diagnostics::ModuleRange range{};
    if (!diagnostics::module_range(reinterpret_cast<HMODULE>(base), range)
        || !diagnostics::contains(range, baseValue + kFlagTestRva)
        || !diagnostics::contains(range, baseValue + kAbilityEmitRva)) {
        return fail_install("target");
    }
    const hooking::detour::Spec testSpec{base + kFlagTestRva,
                                         reinterpret_cast<void*>(&test_observer)};
    const hooking::detour::Spec emitSpec{base + kAbilityEmitRva,
                                         reinterpret_cast<void*>(&emit_observer)};
    const std::array<hooking::detour::Spec, 2> specs{testSpec, emitSpec};
    std::array<hooking::detour::Handle, 2> handles{};
    if (!hooking::detour::install(specs, handles)) {
        return fail_install("attach");
    }
    g_testHandle = handles[0];
    g_emitHandle = handles[1];
    g_originalTest.store(reinterpret_cast<FlagTest>(g_testHandle.original),
                         std::memory_order_release);
    g_originalEmit.store(reinterpret_cast<AbilityEmit>(g_emitHandle.original),
                         std::memory_order_release);
    core::log::write(core::log::Channel::client,
                     core::log::Level::info,
                     "ev=ability_gate stage=install result=ok");
    return true;
}

/** Detaches both observers and drops their trampolines. */
bool uninstall() noexcept {
    (void)hooking::detour::uninstall(g_testHandle);
    (void)hooking::detour::uninstall(g_emitHandle);
    g_testHandle = {};
    g_emitHandle = {};
    g_originalTest.store(nullptr, std::memory_order_release);
    g_originalEmit.store(nullptr, std::memory_order_release);
    return true;
}

/** @return True while either observer is attached. */
bool is_installed() noexcept {
    return g_testHandle.attached || g_emitHandle.attached;
}

} // namespace sunrise::client::hooks::ability_gate
