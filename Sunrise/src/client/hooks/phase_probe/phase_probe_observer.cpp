#include "phase_probe_observer.h"

#include <Windows.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>

#include "../../../core/logging/log.h"
#include "../../diagnostics/module_range.h"
#include "../../hooking/detour.h"

namespace sunrise::client::hooks::phase_probe {
namespace {

/** Image RVA of the slice-set transition phase query (FINDINGS 20.154). */
constexpr std::uintptr_t kPhaseQueryRva = 0xE22C70;

/** Public/shared-region flag the phase query gates on; wants exactly 1. */
constexpr std::uintptr_t kPublicFlagOffset = 0x2bc;
/** The second gate byte; wants exactly 2. Never written by any disp32 store in .text. */
constexpr std::uintptr_t kGateByteOffset = 0x2c1;
/** Region index the constructor stored alongside the flag (bounded by 0x1ff there). */
constexpr std::uintptr_t kRegionOffset = 0x2b0;

/**
 * Hard line cap. The distinct-answer filter below should hold this to a handful per
 * boot; the cap is the backstop for the case where the tuple oscillates per frame,
 * which is exactly how the stripped ws_wire observer stalled the tower.
 */
constexpr unsigned kLineCap = 64;
/** One log line's capacity. */
constexpr std::size_t kLineCapacity = 224;

/**
 * Verified ABI. rcx carries the object (its `mov rbx,[rcx+0x4d8]` at 0x140e22cb8 reads
 * the field the constructor writes at 0x140e2b425), and the query takes two floats in
 * xmm1/xmm2 - the fall-through compares one of them (`comiss xmm9,xmm7`) to pick 2 or 3.
 * The detour mirrors the signature exactly so the original's arguments pass through.
 */
using PhaseQuery = std::int32_t(__fastcall*)(void*, float, float) noexcept;

hooking::detour::Handle g_handle{};
/** Packed (phase, publicFlag, gateByte, region) of the last line written. */
std::atomic<std::uint64_t> g_lastKey{~0ULL};
std::atomic<unsigned> g_lines{};
std::uintptr_t g_base{};

/** @return False when the object could not be read. Never dereferences blindly. */
[[nodiscard]] bool read_fields(const void* object,
                               std::uint8_t& publicFlag,
                               std::uint8_t& gateByte,
                               std::int32_t& region) noexcept {
    if (object == nullptr) {
        return false;
    }
    const auto* const bytes = static_cast<const std::uint8_t*>(object);
    __try {
        publicFlag = bytes[kPublicFlagOffset];
        gateByte = bytes[kGateByteOffset];
        region = *reinterpret_cast<const std::int32_t*>(bytes + kRegionOffset);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return true;
}

/** The observer. Runs the original first and returns its answer untouched. */
std::int32_t __fastcall observe(void* object, float first, float second) noexcept {
    const auto original = reinterpret_cast<PhaseQuery>(g_handle.original);
    const std::int32_t phase = original(object, first, second);
    if (g_lines.load(std::memory_order_relaxed) >= kLineCap) {
        return phase;
    }
    std::uint8_t publicFlag = 0;
    std::uint8_t gateByte = 0;
    std::int32_t region = 0;
    if (!read_fields(object, publicFlag, gateByte, region)) {
        return phase;
    }
    // Distinct-answer filter. This is the whole hot-path budget: one compare, one branch.
    const std::uint64_t key = (static_cast<std::uint64_t>(static_cast<std::uint32_t>(phase)) << 48)
                              | (static_cast<std::uint64_t>(publicFlag) << 40)
                              | (static_cast<std::uint64_t>(gateByte) << 32)
                              | static_cast<std::uint32_t>(region);
    if (g_lastKey.exchange(key, std::memory_order_relaxed) == key) {
        return phase;
    }
    const unsigned line = g_lines.fetch_add(1, std::memory_order_relaxed) + 1;
    const std::uintptr_t objectRva =
        g_base != 0 ? reinterpret_cast<std::uintptr_t>(object) - g_base : 0;
    std::array<char, kLineCapacity> text{};
    const int written = std::snprintf(text.data(),
                                      text.size(),
                                      "ev=phase stage=query phase=%d public=%u gate=%u "
                                      "region=%d want=public:1,gate:2 obj=0x%llX n=%u",
                                      phase,
                                      static_cast<unsigned>(publicFlag),
                                      static_cast<unsigned>(gateByte),
                                      region,
                                      static_cast<unsigned long long>(objectRva),
                                      line);
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         {text.data(), static_cast<std::size_t>(written)});
    }
    return phase;
}

/** @return False, after reporting why the install could not proceed. */
bool fail_install(const char* reason) noexcept {
    std::array<char, 96> text{};
    const int written =
        std::snprintf(text.data(), text.size(), "ev=phase stage=install result=fail why=%s", reason);
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::warn,
                         {text.data(), static_cast<std::size_t>(written)});
    }
    return false;
}

} // namespace

bool install() noexcept {
    if (g_handle.attached) {
        return true;
    }
    std::byte* const base = reinterpret_cast<std::byte*>(GetModuleHandleW(nullptr));
    if (base == nullptr) {
        return fail_install("base");
    }
    const std::uintptr_t baseValue = reinterpret_cast<std::uintptr_t>(base);
    diagnostics::ModuleRange range{};
    if (!diagnostics::module_range(reinterpret_cast<HMODULE>(base), range)
        || !diagnostics::contains(range, baseValue + kPhaseQueryRva)) {
        return fail_install("range");
    }
    g_base = baseValue;
    const hooking::detour::Spec spec{reinterpret_cast<void*>(baseValue + kPhaseQueryRva),
                            reinterpret_cast<void*>(&observe)};
    if (!hooking::detour::install(spec, g_handle)) {
        return fail_install("attach");
    }
    // L13: a silent instrument is indistinguishable from one that never ran, so the
    // attach announces itself and carries the RVA the next lane will correlate against.
    std::array<char, 96> text{};
    const int written = std::snprintf(text.data(),
                                      text.size(),
                                      "ev=phase stage=install result=ok rva=0x%llX cap=%u",
                                      static_cast<unsigned long long>(kPhaseQueryRva),
                                      kLineCap);
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         {text.data(), static_cast<std::size_t>(written)});
    }
    return true;
}

bool uninstall() noexcept {
    if (!g_handle.attached) {
        return true;
    }
    return hooking::detour::uninstall(g_handle);
}

bool is_installed() noexcept {
    return g_handle.attached;
}

} // namespace sunrise::client::hooks::phase_probe
