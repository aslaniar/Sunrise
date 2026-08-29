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
 * The two POLLERS that accept transition type 3 (FINDINGS 20.156). The constructor calls
 * the phase query only for types {2,4,5,6,7}; normal_z_leg is 3, so a public transition's
 * phase must be driven from one of these instead - and neither ran for region 56 in
 * p2(95). These observers answer whether they are entered at all for a z-leg and, if they
 * are, which guard turns them back.
 */
constexpr std::uintptr_t kPollerARva = 0xE244C0;   // guard: type <= 5
constexpr std::uintptr_t kPollerBRva = 0xE25A30;   // guard: type <= 7, and [obj+0x200] == 0

/** Transition type, written by the constructor at 0x140e2b382. 3 = normal_z_leg. */
constexpr std::uintptr_t kTypeOffset = 0x209;
/** Both pollers bail when this is non-zero (0x140e24a42 / 0x140e25a48). Prime suspect. */
constexpr std::uintptr_t kPollGateOffset = 0x200;
/** The region field poller A range-checks against 0x1ff (0x140e24a5e). */
constexpr std::uintptr_t kRegionAltOffset = 0x210;
/** The region field poller B range-checks against 0x1ff (0x140e25a5f). */
constexpr std::uintptr_t kRegionAltBOffset = 0x524;

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

/** Verified ABI for both pollers: the object arrives in rcx (poller A does `mov rsi,rcx`;
 *  poller B reads `[rcx+0x209]` directly). The remaining integer registers are declared and
 *  passed through untouched so nothing is lost if a poller takes more than one argument. */
using Poller = std::uint64_t(__fastcall*)(void*, void*, void*, void*) noexcept;

hooking::detour::Handle g_pollerA{};
hooking::detour::Handle g_pollerB{};
std::atomic<std::uint64_t> g_lastPollA{~0ULL};
std::atomic<std::uint64_t> g_lastPollB{~0ULL};
std::atomic<unsigned> g_pollLines{};

/** Reads the guard inputs both pollers test at entry. @return False when unreadable. */
[[nodiscard]] bool read_poll_fields(const void* object,
                                    std::uint8_t& type,
                                    std::uint8_t& gate,
                                    std::int32_t& region,
                                    std::int32_t& regionAltA,
                                    std::int32_t& regionAltB) noexcept {
    if (object == nullptr) {
        return false;
    }
    const auto* const bytes = static_cast<const std::uint8_t*>(object);
    __try {
        type = bytes[kTypeOffset];
        gate = bytes[kPollGateOffset];
        region = *reinterpret_cast<const std::int32_t*>(bytes + kRegionOffset);
        regionAltA = *reinterpret_cast<const std::int32_t*>(bytes + kRegionAltOffset);
        regionAltB = *reinterpret_cast<const std::int32_t*>(bytes + kRegionAltBOffset);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return true;
}

/** Shared body. Reads the entry state, runs the original, logs only on a changed tuple. */
std::uint64_t poll_observe(const char* which,
                           hooking::detour::Handle& handle,
                           std::atomic<std::uint64_t>& last,
                           void* object,
                           void* second,
                           void* third,
                           void* fourth) noexcept {
    std::uint8_t type = 0;
    std::uint8_t gate = 0;
    std::int32_t region = 0;
    std::int32_t regionAltA = 0;
    std::int32_t regionAltB = 0;
    const bool readable = read_poll_fields(object, type, gate, region, regionAltA, regionAltB);
    const auto original = reinterpret_cast<Poller>(handle.original);
    const std::uint64_t result = original(object, second, third, fourth);
    if (!readable || g_pollLines.load(std::memory_order_relaxed) >= kLineCap) {
        return result;
    }
    const std::uint64_t key = (static_cast<std::uint64_t>(type) << 56)
                              | (static_cast<std::uint64_t>(gate) << 48)
                              | (static_cast<std::uint64_t>(static_cast<std::uint32_t>(region))
                                 << 16)
                              | static_cast<std::uint16_t>(regionAltA);
    if (last.exchange(key, std::memory_order_relaxed) == key) {
        return result;
    }
    const unsigned line = g_pollLines.fetch_add(1, std::memory_order_relaxed) + 1;
    std::array<char, kLineCapacity> text{};
    const int written = std::snprintf(text.data(),
                                      text.size(),
                                      "ev=phase stage=poll which=%s type=%u gate=%u region=%d "
                                      "regionA=%d regionB=%d want=type:3,gate:0 n=%u",
                                      which,
                                      static_cast<unsigned>(type),
                                      static_cast<unsigned>(gate),
                                      region,
                                      regionAltA,
                                      regionAltB,
                                      line);
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         {text.data(), static_cast<std::size_t>(written)});
    }
    return result;
}

std::uint64_t __fastcall observe_poller_a(void* o, void* b, void* c, void* d) noexcept {
    return poll_observe("A", g_pollerA, g_lastPollA, o, b, c, d);
}

std::uint64_t __fastcall observe_poller_b(void* o, void* b, void* c, void* d) noexcept {
    return poll_observe("B", g_pollerB, g_lastPollB, o, b, c, d);
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
    if (!diagnostics::contains(range, baseValue + kPollerARva)
        || !diagnostics::contains(range, baseValue + kPollerBRva)) {
        return fail_install("range_poll");
    }
    g_base = baseValue;
    const hooking::detour::Spec spec{reinterpret_cast<void*>(baseValue + kPhaseQueryRva),
                                     reinterpret_cast<void*>(&observe)};
    if (!hooking::detour::install(spec, g_handle)) {
        return fail_install("attach");
    }
    const hooking::detour::Spec specA{reinterpret_cast<void*>(baseValue + kPollerARva),
                                      reinterpret_cast<void*>(&observe_poller_a)};
    if (!hooking::detour::install(specA, g_pollerA)) {
        return fail_install("attach_poll_a");
    }
    const hooking::detour::Spec specB{reinterpret_cast<void*>(baseValue + kPollerBRva),
                                      reinterpret_cast<void*>(&observe_poller_b)};
    if (!hooking::detour::install(specB, g_pollerB)) {
        return fail_install("attach_poll_b");
    }
    // L13: a silent instrument is indistinguishable from one that never ran, so the
    // attach announces itself and carries the RVA the next lane will correlate against.
    std::array<char, 96> text{};
    const int written = std::snprintf(text.data(),
                                      text.size(),
                                      "ev=phase stage=install result=ok rva=0x%llX "
                                      "pollA=0x%llX pollB=0x%llX cap=%u",
                                      static_cast<unsigned long long>(kPhaseQueryRva),
                                      static_cast<unsigned long long>(kPollerARva),
                                      static_cast<unsigned long long>(kPollerBRva),
                                      kLineCap);
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         {text.data(), static_cast<std::size_t>(written)});
    }
    return true;
}

bool uninstall() noexcept {
    bool ok = true;
    if (g_pollerB.attached) {
        ok = hooking::detour::uninstall(g_pollerB) && ok;
    }
    if (g_pollerA.attached) {
        ok = hooking::detour::uninstall(g_pollerA) && ok;
    }
    if (g_handle.attached) {
        ok = hooking::detour::uninstall(g_handle) && ok;
    }
    return ok;
}

bool is_installed() noexcept {
    return g_handle.attached || g_pollerA.attached || g_pollerB.attached;
}

} // namespace sunrise::client::hooks::phase_probe
