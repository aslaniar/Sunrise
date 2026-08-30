#include "decoder_trace_observer.h"

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

namespace sunrise::client::hooks::decoder_trace {
namespace {

/**
 * Image RVAs.
 *   decoder 0x14173BFC0 - 0x140000000 = 0x173BFC0  (id-30 handler +0x28, 20.176 R2)
 *   apply   0x141781800 - 0x140000000 = 0x1781800  (l9-profile-layout CLAIM 1)
 * Both must be .pdata function STARTs; verify_hook_rvas.py gates every boot on this.
 */
constexpr std::uintptr_t kDecoderRva = 0x173BFC0;
constexpr std::uintptr_t kApplyRva = 0x1781800;

/** Distinct reports per hook worth emitting; counters keep the rate visible past this. */
constexpr unsigned kReportCap = 16;

/** Verified pass-through shapes: 4 register args + 6 stack slots, forwarded bit-exact. */
using DecoderFn = std::uint64_t(__fastcall*)(void*, void*, void*, void*,
                                             void*, void*, void*, void*, void*, void*) noexcept;
using ApplyFn = std::uint64_t(__fastcall*)(void*, void*, void*, void*,
                                           void*, void*, void*, void*, void*, void*) noexcept;

hooking::detour::Handle g_decoder{};
hooking::detour::Handle g_apply{};
std::atomic<unsigned> g_decoderCalls{};
std::atomic<unsigned> g_applyCalls{};
std::atomic<unsigned> g_decoderReported{};
std::atomic<unsigned> g_applyReported{};
std::atomic<bool> g_installed{};
std::uintptr_t g_base{};

/** Reads the session STAGE field (session+0x1aef8) from the apply's rcx (session+0x860). */
int read_stage(const void* rcx) noexcept;

/** Logs one entry with the caller RVA and the struct pointer, under the report cap. */
void report(const char* stage,
            unsigned call,
            std::atomic<unsigned>& reported,
            const void* rcx,
            const void* rdx,
            const void* r8) noexcept {
    if (reported.load(std::memory_order_relaxed) >= kReportCap) {
        return;
    }
    reported.fetch_add(1, std::memory_order_relaxed);
    const auto ret = reinterpret_cast<std::uintptr_t>(_ReturnAddress());
    const unsigned long long callerRva =
        g_base != 0 && ret > g_base ? static_cast<unsigned long long>(ret - g_base) : 0ULL;
    std::array<char, 224> text{};
    const int written = std::snprintf(
        text.data(), text.size(),
        "ev=dtrace stage=%s call=%u caller_rva=0x%llX reader=0x%llX arg2=0x%llX struct=0x%llX "
        "stage=%d",
        stage, call, callerRva,
        static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(rcx)),
        static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(rdx)),
        static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(r8)),
        read_stage(rcx));
    if (written > 0) {
        core::log::write(core::log::Channel::client, core::log::Level::info,
                         {text.data(), static_cast<std::size_t>(written)});
    }
}

std::uint64_t __fastcall observe_decoder(void* rcx, void* rdx, void* r8, void* r9,
                                         void* a5, void* a6, void* a7, void* a8,
                                         void* a9, void* a10) noexcept {
    const unsigned call = g_decoderCalls.fetch_add(1, std::memory_order_relaxed) + 1U;
    report("decoder", call, g_decoderReported, rcx, rdx, r8);
    const auto original = reinterpret_cast<DecoderFn>(g_decoder.original);
    return original(rcx, rdx, r8, r9, a5, a6, a7, a8, a9, a10);
}

/** Dumps the decoded update's counts + first rows (defined below observe_apply). */
void dump_update(unsigned call, const void* structure) noexcept;

/**
 * Reads the session STAGE field off the object the apply was invoked with.
 * The apply's rcx = session+0x860 (the selector: `lea rcx,[rbx+0x860]`), and the stage
 * the selector itself read lives at session+0x1aef8 - i.e. rcx+0x1a698 from here.
 * SEH-guarded; -1 when unreadable.
 */
int read_stage(const void* rcx) noexcept {
    if (rcx == nullptr) {
        return -1;
    }
    __try {
        const auto* const base = static_cast<const std::uint8_t*>(rcx);
        std::uint32_t stage = 0;
        stage |= static_cast<std::uint32_t>(base[0x1a698]);
        stage |= static_cast<std::uint32_t>(base[0x1a699]) << 8;
        stage |= static_cast<std::uint32_t>(base[0x1a69a]) << 16;
        stage |= static_cast<std::uint32_t>(base[0x1a69b]) << 24;
        return static_cast<int>(stage);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return -2;
    }
}

std::uint64_t __fastcall observe_apply(void* rcx, void* rdx, void* r8, void* r9,
                                       void* a5, void* a6, void* a7, void* a8,
                                       void* a9, void* a10) noexcept {
    const unsigned call = g_applyCalls.fetch_add(1, std::memory_order_relaxed) + 1U;
    report("apply", call, g_applyReported, rcx, rdx, r8);
    dump_update(call, rdx);
    const auto original = reinterpret_cast<ApplyFn>(g_apply.original);
    return original(rcx, rdx, r8, r9, a5, a6, a7, a8, a9, a10);
}

bool fail_install(const char* reason) noexcept {
    std::array<char, 112> text{};
    const int written = std::snprintf(
        text.data(), text.size(), "ev=dtrace stage=install result=fail why=%s", reason);
    if (written > 0) {
        core::log::write(core::log::Channel::client, core::log::Level::warn,
                         {text.data(), static_cast<std::size_t>(written)});
    }
    return false;
}

/**
 * Dumps the DECODED update struct's decision fields (post-decode, pre-apply):
 *   +0x1748 word  member count   +0x174a word  player count   (FINDINGS 20.176 R2)
 * then a NONZERO MAP of the whole struct: every 64-byte block containing any nonzero
 * byte, emitted as offsets/ranges. First probe showed counts correct but zeros at the
 * assumed delta base +0x4280 - the map locates where the decoded rows actually live.
 */
void dump_update(unsigned call, const void* structure) noexcept {
    if (structure == nullptr
        || g_applyReported.load(std::memory_order_relaxed) > kReportCap + 4U) {
        return;
    }
    bool ok = true;
    std::uint16_t memberCount = 0;
    std::uint16_t playerCount = 0;
    std::array<std::uint8_t, 0x7980> copy{};
    __try {
        const auto* const base = static_cast<const std::uint8_t*>(structure);
        memberCount = static_cast<std::uint16_t>(base[0x1748])
                      | static_cast<std::uint16_t>(base[0x1749] << 8);
        playerCount = static_cast<std::uint16_t>(base[0x174a])
                      | static_cast<std::uint16_t>(base[0x174b] << 8);
        for (std::size_t i = 0; i < copy.size(); ++i) {
            copy[i] = base[i];
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ok = false;
    }
    if (!ok) {
        return;
    }
    std::array<char, core::log::kLineCapacity> text{};
    int written = std::snprintf(text.data(), text.size(),
                                "ev=dtrace stage=update call=%u members=%u players=%u nz=",
                                call, memberCount, playerCount);
    std::size_t runStart = 0;
    bool inRun = false;
    for (std::size_t block = 0; block <= copy.size() / 64; ++block) {
        const std::size_t offset = block * 64;
        bool nonzero = false;
        if (offset < copy.size()) {
            for (std::size_t i = 0; i < 64; ++i) {
                if (copy[offset + i] != 0) {
                    nonzero = true;
                    break;
                }
            }
        }
        if (nonzero && !inRun) {
            runStart = offset;
            inRun = true;
        } else if (!nonzero && inRun) {
            written += std::snprintf(text.data() + written,
                                     text.size() - static_cast<std::size_t>(written),
                                     "%zx-%zx,", runStart, offset);
            inRun = false;
            if (written > static_cast<int>(text.size()) - 32) {
                written += std::snprintf(text.data() + written,
                                         text.size() - static_cast<std::size_t>(written),
                                         "...");
                break;
            }
        }
    }
    // The row head at +0x4240: slot/present/playerId at +0x09, gate byte at +0x21,
    // hdr1 at +0x24, hdr2 at +0x28 (all offsets within the row base - 20.176 R3 via
    // the corrected row base from the nonzero map). This is the apply's own input.
    written += std::snprintf(text.data() + written,
                             text.size() - static_cast<std::size_t>(written),
                             " row0=");
    for (std::size_t i = 0; i < 48 && written + 2 < static_cast<int>(text.size()); ++i) {
        written += std::snprintf(text.data() + written,
                                 text.size() - static_cast<std::size_t>(written),
                                 "%02X", copy[0x4240 + i]);
    }
    if (written > 0) {
        core::log::write(core::log::Channel::client, core::log::Level::info,
                         {text.data(), static_cast<std::size_t>(written)});
    }
}

} // namespace

bool install() noexcept {
    if (!core::settings::get().client.decoderTrace) {
        core::log::write(core::log::Channel::client, core::log::Level::info,
                         "ev=dtrace stage=install result=skipped why=disarmed");
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
        || !diagnostics::contains(range, g_base + kDecoderRva)
        || !diagnostics::contains(range, g_base + kApplyRva)) {
        return fail_install("range");
    }
    const hooking::detour::Spec decoderSpec{reinterpret_cast<void*>(g_base + kDecoderRva),
                                            reinterpret_cast<void*>(&observe_decoder)};
    if (!hooking::detour::install(decoderSpec, g_decoder)) {
        return fail_install("decoder");
    }
    const hooking::detour::Spec applySpec{reinterpret_cast<void*>(g_base + kApplyRva),
                                          reinterpret_cast<void*>(&observe_apply)};
    if (!hooking::detour::install(applySpec, g_apply)) {
        hooking::detour::uninstall(g_decoder);
        return fail_install("apply");
    }
    std::array<char, 128> text{};
    const int written = std::snprintf(text.data(), text.size(),
                                      "ev=dtrace stage=install result=ok decoder=0x%llX apply=0x%llX",
                                      static_cast<unsigned long long>(kDecoderRva),
                                      static_cast<unsigned long long>(kApplyRva));
    if (written > 0) {
        core::log::write(core::log::Channel::client, core::log::Level::info,
                         {text.data(), static_cast<std::size_t>(written)});
    }
    return true;
}

bool uninstall() noexcept {
    if (!g_decoder.attached && !g_apply.attached) {
        return true;
    }
    const bool ok = hooking::detour::uninstall(g_decoder)
                    && hooking::detour::uninstall(g_apply);
    g_installed.store(false, std::memory_order_relaxed);
    return ok;
}

bool is_installed() noexcept {
    return g_decoder.attached && g_apply.attached;
}

} // namespace sunrise::client::hooks::decoder_trace
