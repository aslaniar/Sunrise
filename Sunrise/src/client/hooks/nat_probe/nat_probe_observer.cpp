#include "nat_probe_observer.h"

#include <Windows.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>

#include "../../../core/logging/log.h"
#include "../../diagnostics/module_range.h"
#include "../../hooking/detour.h"

namespace sunrise::client::hooks::nat_probe {
namespace {

/** Image RVA of the bdNAT logging shim (p2(107) caller capture, all three targets). */
constexpr std::uintptr_t kShimRva = 0x9E3230;

/** Verified pass-through depth: 4 registers + 16 stack slots, forwarded bit-exact. */
using ShimFn = std::uint64_t(__fastcall*)(void*, void*, void*, void*,
                                          void*, void*, void*, void*, void*, void*,
                                          void*, void*, void*, void*, void*, void*,
                                          void*, void*, void*, void*) noexcept;

/** Bytes per hexdump line. */
constexpr std::size_t kDumpBytes = 0x80;
constexpr std::size_t kLineCapacity = 512;
/** The retry loop re-fires; the first 8 calls are the whole story. */
constexpr unsigned kDumpCap = 8;

hooking::detour::Handle g_handle{};
std::atomic<unsigned> g_calls{};
std::atomic<bool> g_installed{};

/**
 * Hex-dumps borrowed memory into one log line, or reports it unreadable.
 * Same shape as the admission observer's dumper: SEH-guarded copy, values only.
 */
void dump_hex(const char* tag, const void* address) noexcept {
    if (address == nullptr) {
        return;
    }
    std::array<std::uint8_t, kDumpBytes> copy{};
    bool ok = true;
    __try {
        const auto* const source = static_cast<const std::uint8_t*>(address);
        for (std::size_t i = 0; i < kDumpBytes; ++i) {
            copy[i] = source[i];
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ok = false;
    }
    std::array<char, kLineCapacity> text{};
    int written = std::snprintf(text.data(),
                                text.size(),
                                "ev=nat stage=dump tag=%s ptr=0x%llX ok=%u hex=",
                                tag,
                                static_cast<unsigned long long>(
                                    reinterpret_cast<std::uintptr_t>(address)),
                                ok ? 1U : 0U);
    if (written <= 0) {
        return;
    }
    if (ok) {
        for (std::size_t i = 0; i < kDumpBytes
                                  && written + 2 < static_cast<int>(text.size());
             ++i) {
            written += std::snprintf(text.data() + written,
                                     text.size() - static_cast<std::size_t>(written),
                                     "%02X",
                                     copy[i]);
        }
    }
    core::log::write(core::log::Channel::client,
                     core::log::Level::info,
                     {text.data(), static_cast<std::size_t>(written)});
}

/** The pass-through probe: count, dump the first calls, forward bit-exact. */
std::uint64_t __fastcall observe_shim(void* rcx, void* rdx, void* r8, void* r9,
                                      void* s0, void* s1, void* s2, void* s3,
                                      void* s4, void* s5, void* s6, void* s7,
                                      void* s8, void* s9, void* s10, void* s11,
                                      void* s12, void* s13, void* s14, void* s15) noexcept {
    if (g_calls.fetch_add(1, std::memory_order_relaxed) < kDumpCap) {
        std::array<char, 192> text{};
        const int written = std::snprintf(text.data(),
                                          text.size(),
                                          "ev=nat stage=dial call=%u rcx=0x%llX rdx=0x%llX "
                                          "r8=0x%llX r9=0x%llX",
                                          g_calls.load(std::memory_order_relaxed),
                                          static_cast<unsigned long long>(
                                              reinterpret_cast<std::uintptr_t>(rcx)),
                                          static_cast<unsigned long long>(
                                              reinterpret_cast<std::uintptr_t>(rdx)),
                                          static_cast<unsigned long long>(
                                              reinterpret_cast<std::uintptr_t>(r8)),
                                          static_cast<unsigned long long>(
                                              reinterpret_cast<std::uintptr_t>(r9)));
        if (written > 0) {
            core::log::write(core::log::Channel::client,
                             core::log::Level::info,
                             {text.data(), static_cast<std::size_t>(written)});
        }
        dump_hex("obj_rcx", rcx);
        dump_hex("payload_r9", r9);
        dump_hex("arg_r8", r8);
    }
    const auto original = reinterpret_cast<ShimFn>(g_handle.original);
    return original(rcx, rdx, r8, r9, s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10,
                    s11, s12, s13, s14, s15);
}

bool fail_install(const char* reason) noexcept {
    std::array<char, 96> text{};
    const int written = std::snprintf(
        text.data(), text.size(), "ev=nat stage=install result=fail why=%s", reason);
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::warn,
                         {text.data(), static_cast<std::size_t>(written)});
    }
    return false;
}

} // namespace

bool install() noexcept {
    if (g_installed.exchange(true, std::memory_order_relaxed)) {
        return true;
    }
    std::byte* const base = reinterpret_cast<std::byte*>(GetModuleHandleW(nullptr));
    if (base == nullptr) {
        return fail_install("base");
    }
    diagnostics::ModuleRange range{};
    if (!diagnostics::module_range(reinterpret_cast<HMODULE>(base), range)
        || !diagnostics::contains(range, reinterpret_cast<std::uintptr_t>(base) + kShimRva)) {
        return fail_install("range");
    }
    const hooking::detour::Spec spec{
        reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(base) + kShimRva),
        reinterpret_cast<void*>(&observe_shim)};
    if (!hooking::detour::install(spec, g_handle)) {
        return fail_install("attach");
    }
    std::array<char, 96> text{};
    const int written = std::snprintf(text.data(),
                                      text.size(),
                                      "ev=nat stage=install result=ok rva=0x%llX",
                                      static_cast<unsigned long long>(kShimRva));
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
    const bool ok = hooking::detour::uninstall(g_handle);
    g_installed.store(false, std::memory_order_relaxed);
    return ok;
}

bool is_installed() noexcept {
    return g_handle.attached;
}

} // namespace sunrise::client::hooks::nat_probe
