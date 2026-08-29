#include "profile_ingress_observer.h"

#include <Windows.h>
#include <intrin.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>

#include "../../../core/logging/log.h"
#include "../../../core/settings/settings.h"
#include "../../diagnostics/module_range.h"
#include "../../hooking/detour.h"

namespace sunrise::client::hooks::profile_ingress {
namespace {

/**
 * Image RVA of the region-A/header/tail apply helper 0x1417AF360.
 *   0x1417AF360 - 0x140000000 = 0x17AF360
 * CONFIRMED by `RE_scripts/verify_hook_rvas.py` / `pdata_bounds.py`: entry
 * 0x1417AF360..0x1417AFB2B, offset=0x0 - a genuine function START.
 */
constexpr std::uintptr_t kHelperARva = 0x17AF360;

/** Region A width (the 9-bit-masked 8-sub-chunk blob). */
constexpr std::size_t kRegionABytes = 232;
/** Region B width (0x1417AF2D0's 8 x movups + 1 movsd, counted from its disassembly). */
constexpr std::size_t kRegionBBytes = 136;
/** Tail width (helper A's qword + qword + dword). */
constexpr std::size_t kTailBytes = 20;
/** delta+0x118 (region B) - delta+0x30 (region A). Wire-caller arithmetic ONLY. */
constexpr std::size_t kRegionBFromA = 0xE8;
/** Bytes per emitted line; keeps every line well under core::log::kLineCapacity. */
constexpr std::size_t kChunkBytes = 64;
/** Distinct applies worth dumping in full. The counter keeps reporting past this. */
constexpr unsigned kDumpCap = 8;

/** Verified pass-through depth: 4 registers + 16 stack slots, forwarded bit-exact. */
using HelperFn = std::uint64_t(__fastcall*)(void*, void*, void*, void*,
                                            void*, void*, void*, void*, void*, void*,
                                            void*, void*, void*, void*, void*, void*,
                                            void*, void*, void*, void*) noexcept;

hooking::detour::Handle g_handle{};
std::atomic<unsigned> g_calls{};
std::atomic<unsigned> g_dumped{};
std::atomic<bool> g_installed{};
std::uintptr_t g_base{};

/** Copies borrowed memory under SEH and emits it as 64-byte tagged chunks. */
void dump_region(const char* tag,
                 unsigned call,
                 const void* address,
                 std::size_t bytes) noexcept {
    if (address == nullptr || bytes == 0) {
        return;
    }
    std::array<std::uint8_t, kRegionABytes> copy{};
    const std::size_t span = bytes > copy.size() ? copy.size() : bytes;
    bool ok = true;
    __try {
        const auto* const source = static_cast<const std::uint8_t*>(address);
        for (std::size_t i = 0; i < span; ++i) {
            copy[i] = source[i];
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ok = false;
    }
    if (!ok) {
        std::array<char, 160> bad{};
        const int n = std::snprintf(bad.data(),
                                    bad.size(),
                                    "ev=ingress stage=dump call=%u tag=%s ptr=0x%llX ok=0 why=seh",
                                    call, tag,
                                    static_cast<unsigned long long>(
                                        reinterpret_cast<std::uintptr_t>(address)));
        if (n > 0) {
            core::log::write(core::log::Channel::client, core::log::Level::warn,
                             {bad.data(), static_cast<std::size_t>(n)});
        }
        return;
    }
    for (std::size_t offset = 0; offset < span; offset += kChunkBytes) {
        const std::size_t width =
            (span - offset) < kChunkBytes ? (span - offset) : kChunkBytes;
        std::array<char, core::log::kLineCapacity> text{};
        int written = std::snprintf(text.data(), text.size(),
                                    "ev=ingress stage=dump call=%u tag=%s off=%zu len=%zu ok=1 hex=",
                                    call, tag, offset, width);
        if (written <= 0) {
            return;
        }
        for (std::size_t i = 0; i < width && written + 2 < static_cast<int>(text.size()); ++i) {
            written += std::snprintf(text.data() + written,
                                     text.size() - static_cast<std::size_t>(written),
                                     "%02X", copy[offset + i]);
        }
        core::log::write(core::log::Channel::client, core::log::Level::info,
                         {text.data(), static_cast<std::size_t>(written)});
    }
}

/**
 * The pass-through observer. Reads arguments and the return address only.
 * The caller RVA (LESSONS 18c) separates the WIRE apply (returns into 0x141782xxx)
 * from the local registry commit (returns into 0x1417a6xxx) - region B's
 * regionA+0xE8 arithmetic is valid for the wire caller ONLY, so the label matters.
 */
std::uint64_t __fastcall observe_helper(void* rcx, void* rdx, void* r8, void* r9,
                                        void* a5, void* a6, void* a7, void* a8,
                                        void* a9, void* s5, void* s6, void* s7,
                                        void* s8, void* s9, void* s10, void* s11,
                                        void* s12, void* s13, void* s14,
                                        void* s15) noexcept {
    const unsigned call = g_calls.fetch_add(1, std::memory_order_relaxed) + 1U;
    if (g_dumped.load(std::memory_order_relaxed) < kDumpCap) {
        g_dumped.fetch_add(1, std::memory_order_relaxed);
        const auto ret = reinterpret_cast<std::uintptr_t>(_ReturnAddress());
        const unsigned long long callerRva =
            g_base != 0 && ret > g_base ? static_cast<unsigned long long>(ret - g_base) : 0ULL;
        std::array<char, 448> text{};
        const int written = std::snprintf(
            text.data(), text.size(),
            "ev=ingress stage=apply call=%u caller_rva=0x%llX index=%u header1=0x%08X "
            "header2=0x%08X mask=0x%llX verify=0x%llX hash=0x%08X regionA=0x%llX tail=0x%llX",
            call, callerRva,
            static_cast<unsigned>(reinterpret_cast<std::uintptr_t>(rdx) & 0xFFFFFFFFULL),
            static_cast<unsigned>(reinterpret_cast<std::uintptr_t>(r8) & 0xFFFFFFFFULL),
            static_cast<unsigned>(reinterpret_cast<std::uintptr_t>(r9) & 0xFFFFFFFFULL),
            static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(a5)),
            static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(a7)),
            static_cast<unsigned>(reinterpret_cast<std::uintptr_t>(a8) & 0xFFFFFFFFULL),
            static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(a6)),
            static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(a9)));
        if (written > 0) {
            core::log::write(core::log::Channel::client, core::log::Level::info,
                             {text.data(), static_cast<std::size_t>(written)});
        }
        dump_region("regionA", call, a6, kRegionABytes);
        dump_region("tail", call, a9, kTailBytes);
        // Valid ONLY for the wire caller; the line above carries the RVA that says which.
        if (a6 != nullptr) {
            dump_region("regionB_ifwire", call,
                        reinterpret_cast<const std::uint8_t*>(a6) + kRegionBFromA,
                        kRegionBBytes);
        }
    }
    const auto original = reinterpret_cast<HelperFn>(g_handle.original);
    return original(rcx, rdx, r8, r9, a5, a6, a7, a8, a9, s5, s6, s7, s8, s9, s10,
                    s11, s12, s13, s14, s15);
}

bool fail_install(const char* reason) noexcept {
    std::array<char, 112> text{};
    const int written = std::snprintf(
        text.data(), text.size(), "ev=ingress stage=install result=fail why=%s", reason);
    if (written > 0) {
        core::log::write(core::log::Channel::client, core::log::Level::warn,
                         {text.data(), static_cast<std::size_t>(written)});
    }
    return false;
}

} // namespace

bool install() noexcept {
    if (!core::settings::get().client.profileIngress) {
        core::log::write(core::log::Channel::client, core::log::Level::info,
                         "ev=ingress stage=install result=skipped why=disarmed");
        return true;
    }
    if (g_installed.exchange(true, std::memory_order_relaxed)) {
        return true;
    }
    std::byte* const base = reinterpret_cast<std::byte*>(GetModuleHandleW(nullptr));
    if (base == nullptr) {
        return fail_install("base");
    }
    g_base = reinterpret_cast<std::uintptr_t>(base);
    diagnostics::ModuleRange range{};
    if (!diagnostics::module_range(reinterpret_cast<HMODULE>(base), range)
        || !diagnostics::contains(range, g_base + kHelperARva)) {
        return fail_install("range");
    }
    const hooking::detour::Spec spec{reinterpret_cast<void*>(g_base + kHelperARva),
                                     reinterpret_cast<void*>(&observe_helper)};
    if (!hooking::detour::install(spec, g_handle)) {
        return fail_install("attach");
    }
    std::array<char, 112> text{};
    const int written = std::snprintf(text.data(), text.size(),
                                      "ev=ingress stage=install result=ok rva=0x%llX",
                                      static_cast<unsigned long long>(kHelperARva));
    if (written > 0) {
        core::log::write(core::log::Channel::client, core::log::Level::info,
                         {text.data(), static_cast<std::size_t>(written)});
    }
    return true;
}

bool uninstall() noexcept {
    if (!g_handle.attached) {
        return true;
    }
    const bool ok = hooking::detour::uninstall(g_handle);
    g_installed.store(false, std::memory_order_relaxed);
    return ok;
}

bool is_installed() noexcept {
    return g_handle.attached;
}

} // namespace sunrise::client::hooks::profile_ingress
