#include "profile_harvest_observer.h"

#include <Windows.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>

#include "../../../core/logging/log.h"
#include "../../../core/settings/settings.h"
#include "../../diagnostics/module_range.h"
#include "../../hooking/detour.h"

namespace sunrise::client::hooks::profile_harvest {
namespace {

/**
 * Image RVA of the decision/apply wrapper 0x1417a6040 (base 0x140000000):
 *   0x1417A6040 - 0x140000000 = 0x17A6040
 * CONFIRMED against .pdata by `RE_scripts/pdata_bounds.py 0x1417a6040`, which resolves
 * it to entry 0x1417A6040..0x1417A643B at RVA 0x17A6040, offset=0x0 - a genuine
 * function START, not a chained fragment (the 20.112 trap).
 * p2(112) shipped 0x1A6040 here - a dropped digit. It sat inside the module, so the
 * range check PASSED and the detour attached to an unrelated function: `install
 * result=ok` with zero commits, through a Tower dwell, a subclass swap AND a full
 * character switch. LESSON: a range check proves an address is in the image, never
 * that it is the RIGHT address. Resolve every hook RVA through pdata_bounds first.
 */
constexpr std::uintptr_t kWrapperRva = 0x17A6040;

/** Region A width, verified as the 14x-movups + 1-qword 232-byte unroll. */
constexpr std::size_t kRegionABytes = 232;
/** Tail width, verified as movups(16) + mov(4) at 0x1417668b1/0x1417668c0. */
constexpr std::size_t kTailBytes = 20;
/** Bytes per emitted line; keeps every line far under core::log::kLineCapacity. */
constexpr std::size_t kChunkBytes = 64;
/** Distinct commits worth dumping. The loop re-commits per character on version change. */
constexpr unsigned kDumpCap = 6;

/** Verified pass-through depth: 4 registers + 16 stack slots, forwarded bit-exact. */
using WrapperFn = std::uint64_t(__fastcall*)(void*, void*, void*, void*,
                                             void*, void*, void*, void*, void*, void*,
                                             void*, void*, void*, void*, void*, void*,
                                             void*, void*, void*, void*) noexcept;

hooking::detour::Handle g_handle{};
std::atomic<unsigned> g_calls{};
std::atomic<unsigned> g_dumped{};
std::atomic<bool> g_installed{};

/**
 * Copies borrowed memory under SEH and emits it as 64-byte tagged chunks.
 * Values only; nothing is written back and the source is never held past the copy.
 */
void dump_region(const char* tag,
                 unsigned call,
                 const void* address,
                 std::size_t bytes) noexcept {
    if (address == nullptr || bytes == 0) {
        std::array<char, 128> empty{};
        const int n = std::snprintf(empty.data(),
                                    empty.size(),
                                    "ev=profile stage=dump call=%u tag=%s ok=0 why=null",
                                    call,
                                    tag);
        if (n > 0) {
            core::log::write(core::log::Channel::client,
                             core::log::Level::warn,
                             {empty.data(), static_cast<std::size_t>(n)});
        }
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
                                    "ev=profile stage=dump call=%u tag=%s ptr=0x%llX ok=0 why=seh",
                                    call,
                                    tag,
                                    static_cast<unsigned long long>(
                                        reinterpret_cast<std::uintptr_t>(address)));
        if (n > 0) {
            core::log::write(core::log::Channel::client,
                             core::log::Level::warn,
                             {bad.data(), static_cast<std::size_t>(n)});
        }
        return;
    }
    for (std::size_t offset = 0; offset < span; offset += kChunkBytes) {
        const std::size_t width =
            (span - offset) < kChunkBytes ? (span - offset) : kChunkBytes;
        std::array<char, core::log::kLineCapacity> text{};
        int written = std::snprintf(text.data(),
                                    text.size(),
                                    "ev=profile stage=dump call=%u tag=%s off=%zu len=%zu "
                                    "ptr=0x%llX ok=1 hex=",
                                    call,
                                    tag,
                                    offset,
                                    width,
                                    static_cast<unsigned long long>(
                                        reinterpret_cast<std::uintptr_t>(address)));
        if (written <= 0) {
            return;
        }
        for (std::size_t i = 0; i < width
                                && written + 2 < static_cast<int>(text.size());
             ++i) {
            written += std::snprintf(text.data() + written,
                                     text.size() - static_cast<std::size_t>(written),
                                     "%02X",
                                     copy[offset + i]);
        }
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         {text.data(), static_cast<std::size_t>(written)});
    }
}

/**
 * The pass-through harvest. Reads arguments only, forwards every slot bit-exact.
 * Argument map verified from the call site 0x14176681a (claims/profile-builder-raw.md
 * PHASE 2): a5=mask, a6=region A ptr, a7=valid flag, a8=expected hash, a9=tail ptr.
 */
std::uint64_t __fastcall observe_wrapper(void* rcx, void* rdx, void* r8, void* r9,
                                         void* a5, void* a6, void* a7, void* a8,
                                         void* a9, void* s5, void* s6, void* s7,
                                         void* s8, void* s9, void* s10, void* s11,
                                         void* s12, void* s13, void* s14,
                                         void* s15) noexcept {
    const unsigned call = g_calls.fetch_add(1, std::memory_order_relaxed) + 1U;
    if (g_dumped.load(std::memory_order_relaxed) < kDumpCap) {
        g_dumped.fetch_add(1, std::memory_order_relaxed);
        std::array<char, 384> text{};
        const int written =
            std::snprintf(text.data(),
                          text.size(),
                          "ev=profile stage=commit call=%u index=%u header=0x%08X "
                          "marker=0x%08X mask=0x%llX valid=0x%llX hash=0x%08X "
                          "regionA=0x%llX tail=0x%llX",
                          call,
                          static_cast<unsigned>(reinterpret_cast<std::uintptr_t>(rdx)
                                                & 0xFFFFFFFFULL),
                          static_cast<unsigned>(reinterpret_cast<std::uintptr_t>(r8)
                                                & 0xFFFFFFFFULL),
                          static_cast<unsigned>(reinterpret_cast<std::uintptr_t>(r9)
                                                & 0xFFFFFFFFULL),
                          static_cast<unsigned long long>(
                              reinterpret_cast<std::uintptr_t>(a5)),
                          static_cast<unsigned long long>(
                              reinterpret_cast<std::uintptr_t>(a7)),
                          static_cast<unsigned>(reinterpret_cast<std::uintptr_t>(a8)
                                                & 0xFFFFFFFFULL),
                          static_cast<unsigned long long>(
                              reinterpret_cast<std::uintptr_t>(a6)),
                          static_cast<unsigned long long>(
                              reinterpret_cast<std::uintptr_t>(a9)));
        if (written > 0) {
            core::log::write(core::log::Channel::client,
                             core::log::Level::info,
                             {text.data(), static_cast<std::size_t>(written)});
        }
        dump_region("regionA", call, a6, kRegionABytes);
        dump_region("tail", call, a9, kTailBytes);
    }
    const auto original = reinterpret_cast<WrapperFn>(g_handle.original);
    return original(rcx, rdx, r8, r9, a5, a6, a7, a8, a9, s5, s6, s7, s8, s9, s10,
                    s11, s12, s13, s14, s15);
}

bool fail_install(const char* reason) noexcept {
    std::array<char, 112> text{};
    const int written = std::snprintf(
        text.data(), text.size(), "ev=profile stage=install result=fail why=%s", reason);
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::warn,
                         {text.data(), static_cast<std::size_t>(written)});
    }
    return false;
}

} // namespace

bool install() noexcept {
    if (!core::settings::get().client.profileHarvest) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         "ev=profile stage=install result=skipped why=disarmed");
        return true;
    }
    if (g_installed.exchange(true, std::memory_order_relaxed)) {
        return true;
    }
    std::byte* const base = reinterpret_cast<std::byte*>(GetModuleHandleW(nullptr));
    if (base == nullptr) {
        return fail_install("base");
    }
    diagnostics::ModuleRange range{};
    if (!diagnostics::module_range(reinterpret_cast<HMODULE>(base), range)
        || !diagnostics::contains(range,
                                  reinterpret_cast<std::uintptr_t>(base) + kWrapperRva)) {
        return fail_install("range");
    }
    const hooking::detour::Spec spec{
        reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(base) + kWrapperRva),
        reinterpret_cast<void*>(&observe_wrapper)};
    if (!hooking::detour::install(spec, g_handle)) {
        return fail_install("attach");
    }
    std::array<char, 112> text{};
    const int written = std::snprintf(text.data(),
                                      text.size(),
                                      "ev=profile stage=install result=ok rva=0x%llX",
                                      static_cast<unsigned long long>(kWrapperRva));
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

} // namespace sunrise::client::hooks::profile_harvest
