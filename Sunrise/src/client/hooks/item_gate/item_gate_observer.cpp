#include "item_gate_observer.h"

#include <Windows.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <intrin.h>

#include "../../../core/logging/log.h"
#include "../../diagnostics/module_range.h"
#include "../../hooking/detour.h"

namespace sunrise::client::hooks::item_gate {
namespace {

/** Image RVA of FUN_140547800, the weapon/armor validator A (char(instance)). */
constexpr std::uintptr_t kValidatorARva = 0x547800;
/** Image RVA of FUN_140555280, the weapon/armor validator B (char(store, instance)). */
constexpr std::uintptr_t kValidatorBRva = 0x555280;
/** Image RVA of FUN_140BFA030, the investment lookup whose result's +0xa32 byte
 *  decides the gate (the caller reads it right after the call, so may we). */
constexpr std::uintptr_t kInvestRva = 0xBFA030;
/**
 * The volume gate (the boot of 2026-08-21 ~21:4x: unfiltered logging hit 145k lines
 * in one load and took the game down - these functions run in huge store-walk sweeps
 * from dozens of callers, NOT just the family-4 handler). Only calls returning into
 * FUN_140E06380's own body - the weapon/armor instance-event handler, 3323 bytes -
 * are logged; every other caller passes through silently.
 */
constexpr std::uintptr_t kHandlerStartRva = 0xE06380;
constexpr std::uintptr_t kHandlerEndRva = kHandlerStartRva + 3323;
/** One log line's capacity. */
constexpr std::size_t kLineCapacity = 256;

/** @return True when a caller RVA sits inside the family-4 instance-event handler. */
bool from_handler(std::uintptr_t callerRva) noexcept {
    return callerRva >= kHandlerStartRva && callerRva < kHandlerEndRva;
}

/**
 * The equipment-region window (the PC map's acquire/equipment logic, where the two
 * equipped-region failures of 2026-08-21 ~21:4x were asked) and the pass-side capture
 * window: a passing instance asked from here names its first qword, so address<->soid
 * correlation for the working set rides the same boot.
 */
constexpr std::uintptr_t kEquipRegionStart = 0xFAD000;
constexpr std::uintptr_t kEquipRegionEnd = 0xFAF000;

/** @return True when a caller RVA sits in the equipment-region window. */
bool from_equip_region(std::uintptr_t callerRva) noexcept {
    return callerRva >= kEquipRegionStart && callerRva < kEquipRegionEnd;
}

/**
 * Dedupe set for failure lines (fixed, no allocation): the 21:4x boot showed ~3k
 * distinct failing pointers overall but only THREE inside the equipped region - the
 * cap exists purely as a runaway guard.
 */
constexpr std::size_t kSeenCapacity = 256;
std::uintptr_t g_seen[kSeenCapacity]{};
std::size_t g_seenCount{};

bool seen_and_record(std::uintptr_t address) noexcept {
    for (std::size_t i = 0; i < g_seenCount; ++i) {
        if (g_seen[i] == address) {
            return true;
        }
    }
    if (g_seenCount < kSeenCapacity) {
        g_seen[g_seenCount++] = address;
    }
    return false;
}

/** Decompile-verified ABI: `char FUN_140547800(void* instance)`. */
using ValidatorA = char(__fastcall*)(void*) noexcept;
/** Decompile-verified ABI: `char FUN_140555280(void* store, void* instance)`. */
using ValidatorB = char(__fastcall*)(void*, void*) noexcept;
/** Decompile-verified ABI: `void* FUN_140bfa030(int index)`; caller tests null and
 *  reads the flag byte at +0xa32. */
using InvestLookup = void*(__fastcall*)(std::int32_t) noexcept;

hooking::detour::Handle g_validatorAHandle{};
hooking::detour::Handle g_validatorBHandle{};
hooking::detour::Handle g_investHandle{};
std::atomic<ValidatorA> g_originalA{nullptr};
std::atomic<ValidatorB> g_originalB{nullptr};
std::atomic<InvestLookup> g_originalInvest{nullptr};

/** @return The module base, for the caller-RVA line. */
std::uintptr_t module_base() noexcept {
    return reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
}

/** @return The return address one frame above the detoured call. */
void* caller_address() noexcept {
    return _ReturnAddress();
}

/** Logs one line to the client channel. */
void write_line(const char* text, std::size_t length) noexcept {
    core::log::write(core::log::Channel::client, core::log::Level::info,
                     {text, length});
}

__declspec(noinline) char __fastcall validator_a_observer(void* instance) noexcept {
    const ValidatorA original = g_originalA.load(std::memory_order_acquire);
    const char result = original != nullptr ? original(instance) : 0;
    const std::uintptr_t caller = reinterpret_cast<std::uintptr_t>(caller_address());
    const std::uintptr_t base = module_base();
    const std::uintptr_t callerRva = caller >= base ? caller - base : 0;
    // Failure lines: deduped per pointer (the 14.24 redesign - name WHICH items fail).
    // Pass lines: only from the equipment-region window, to map address -> first qword
    // for the working set on the same boot.
    const bool fail = result == 0;
    if (!fail && !(from_equip_region(callerRva))) {
        return result;
    }
    if (fail && seen_and_record(reinterpret_cast<std::uintptr_t>(instance))) {
        return result;
    }
    // Raw identification fields: the candidate soid (first qword), the next qword,
    // and the u16 at +0x10. No assumed structure - logged raw so the shape itself
    // is what the dump side reads.
    std::uint64_t field0 = 0;
    std::uint64_t field8 = 0;
    std::uint16_t field10 = 0;
    if (instance != nullptr) {
        std::memcpy(&field0, instance, sizeof field0);
        std::memcpy(&field8, reinterpret_cast<const std::byte*>(instance) + 8,
                    sizeof field8);
        std::memcpy(&field10, reinterpret_cast<const std::byte*>(instance) + 0x10,
                    sizeof field10);
    }
    std::array<char, kLineCapacity> line{};
    const int written = std::snprintf(
        line.data(),
        line.size(),
        "ev=item_gate stage=validator_a res=%u inst=0x%llX f0=0x%llX f8=0x%llX "
        "f10=0x%04X caller=+0x%llX",
        static_cast<unsigned>(static_cast<unsigned char>(result)),
        static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(instance)),
        static_cast<unsigned long long>(field0),
        static_cast<unsigned long long>(field8),
        static_cast<unsigned>(field10),
        static_cast<unsigned long long>(callerRva));
    if (written > 0) {
        write_line(line.data(), static_cast<std::size_t>(written));
    }
    return result;
}

__declspec(noinline) char __fastcall validator_b_observer(void* store,
                                                          void* instance) noexcept {
    const ValidatorB original = g_originalB.load(std::memory_order_acquire);
    const char result = original != nullptr ? original(store, instance) : 0;
    const std::uintptr_t caller = reinterpret_cast<std::uintptr_t>(caller_address());
    const std::uintptr_t base = module_base();
    const std::uintptr_t callerRva = caller >= base ? caller - base : 0;
    if (!from_handler(callerRva)) {
        return result;
    }
    std::array<char, kLineCapacity> line{};
    const int written = std::snprintf(
        line.data(),
        line.size(),
        "ev=item_gate stage=validator_b store=0x%llX inst=0x%llX result=%u caller=+0x%llX",
        static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(store)),
        static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(instance)),
        static_cast<unsigned>(static_cast<unsigned char>(result)),
        static_cast<unsigned long long>(callerRva));
    if (written > 0) {
        write_line(line.data(), static_cast<std::size_t>(written));
    }
    return result;
}

__declspec(noinline) void* __fastcall invest_observer(std::int32_t index) noexcept {
    const InvestLookup original = g_originalInvest.load(std::memory_order_acquire);
    void* result = original != nullptr ? original(index) : nullptr;
    const std::uintptr_t caller = reinterpret_cast<std::uintptr_t>(caller_address());
    const std::uintptr_t base = module_base();
    const std::uintptr_t callerRva = caller >= base ? caller - base : 0;
    if (!from_handler(callerRva)) {
        return result;
    }
    const unsigned char flag =
        result != nullptr ? *reinterpret_cast<const unsigned char*>(
                                reinterpret_cast<std::uintptr_t>(result) + 0xA32)
                          : 0;
    std::array<char, kLineCapacity> line{};
    const int written = std::snprintf(
        line.data(),
        line.size(),
        "ev=item_gate stage=invest_lookup idx=%d out=0x%llX flagA32=%u caller=+0x%llX",
        index,
        static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(result)),
        static_cast<unsigned>(flag),
        static_cast<unsigned long long>(callerRva));
    if (written > 0) {
        write_line(line.data(), static_cast<std::size_t>(written));
    }
    return result;
}

[[nodiscard]] bool fail_install(const char* reason) noexcept {
    std::array<char, 128> line{};
    const int written = std::snprintf(
        line.data(), line.size(), "ev=item_gate stage=install result=fail reason=%s", reason);
    if (written > 0) {
        write_line(line.data(), static_cast<std::size_t>(written));
    }
    return false;
}

} // namespace

bool install() noexcept {
    if (g_validatorAHandle.attached && g_validatorBHandle.attached
        && g_investHandle.attached) {
        return true;
    }
    g_seenCount = 0;
    std::byte* const base = reinterpret_cast<std::byte*>(GetModuleHandleW(nullptr));
    if (base == nullptr) {
        return fail_install("base");
    }
    diagnostics::ModuleRange range{};
    const std::uintptr_t baseValue = reinterpret_cast<std::uintptr_t>(base);
    if (!diagnostics::module_range(reinterpret_cast<HMODULE>(base), range)
        || !diagnostics::contains(range, baseValue + kValidatorARva)
        || !diagnostics::contains(range, baseValue + kValidatorBRva)
        || !diagnostics::contains(range, baseValue + kInvestRva)) {
        return fail_install("target");
    }
    const hooking::detour::Spec aSpec{base + kValidatorARva,
                                      reinterpret_cast<void*>(&validator_a_observer)};
    const hooking::detour::Spec bSpec{base + kValidatorBRva,
                                      reinterpret_cast<void*>(&validator_b_observer)};
    const hooking::detour::Spec investSpec{base + kInvestRva,
                                           reinterpret_cast<void*>(&invest_observer)};
    const std::array<hooking::detour::Spec, 3> specs{aSpec, bSpec, investSpec};
    std::array<hooking::detour::Handle, 3> handles{};
    if (!hooking::detour::install(specs, handles)) {
        return fail_install("attach");
    }
    g_validatorAHandle = handles[0];
    g_validatorBHandle = handles[1];
    g_investHandle = handles[2];
    g_originalA.store(reinterpret_cast<ValidatorA>(g_validatorAHandle.original),
                      std::memory_order_release);
    g_originalB.store(reinterpret_cast<ValidatorB>(g_validatorBHandle.original),
                      std::memory_order_release);
    g_originalInvest.store(reinterpret_cast<InvestLookup>(g_investHandle.original),
                           std::memory_order_release);
    constexpr char ok[] = "ev=item_gate stage=install result=ok count=3";
    write_line(ok, sizeof(ok) - 1);
    return true;
}

bool uninstall() noexcept {
    std::array<hooking::detour::Handle, 3> handles{g_validatorAHandle, g_validatorBHandle,
                                                   g_investHandle};
    const bool detached = hooking::detour::uninstall(handles);
    g_validatorAHandle = {};
    g_validatorBHandle = {};
    g_investHandle = {};
    g_originalA.store(nullptr, std::memory_order_release);
    g_originalB.store(nullptr, std::memory_order_release);
    g_originalInvest.store(nullptr, std::memory_order_release);
    return detached;
}

bool is_installed() noexcept {
    return g_validatorAHandle.attached;
}

} // namespace sunrise::client::hooks::item_gate
