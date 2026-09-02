#include "state_diff_observer.h"

#include <Windows.h>
#include <intrin.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "../../../core/logging/log.h"
#include "../../../core/settings/settings.h"
#include "../../../middleware/crypto/lookup3.h"
#include "../../diagnostics/module_range.h"
#include "../../hooking/detour.h"

namespace sunrise::client::hooks::state_diff {
namespace {

/**
 * Image RVA of the membership APPLY 0x141781800 (.pdata START). p2(130) hooked the
 * checksum verifier 0x141772100 instead and logged ZERO calls across a full paired run
 * (20.204 R2) - that function does not run in this flow. The apply is where the profile
 * lands: it writes the two 0xFFFFFFFF absent markers at entry+0x1c/+0x108 (0x141782408 /
 * 0x141782410) and calls the region-A/tail and region-B helpers under the profile gate.
 * decoder_trace also owns this address and MUST stay disarmed (it already is).
 */
constexpr std::uintptr_t kChecksumFnRva = 0x1781800;
/**
 * Player table base in the apply's OWN coordinates. Helper B writes player entry +0x108
 * to state+0x3c68 (0x1417af2de), so the table sits at 0x3c68-0x108 = 0x3b60 relative to
 * the apply's base pointer. (The hashed buffer starts 8 bytes above that base, which is
 * why the fork's replica model correctly uses 15192 - FINDINGS 20.206.)
 */
constexpr std::uintptr_t kPlayerTableOffset = 0x3b60;
/** Bytes one player entry occupies. */
constexpr std::size_t kPlayerStride = 424;
/** Player slots captured. Two players is the whole paired case. */
constexpr std::size_t kCapturedSlots = 2;
/** Bytes captured per call: the two entries, back to back. */
constexpr std::size_t kReplicaBytes = kPlayerStride * kCapturedSlots;
/** The session-state hash initial (the immediate at offset 0x76). */
constexpr std::uint32_t kHashInitial = 0xDEAE2F4EU;
/** Bytes per hexdump line (kLineCapacity is 1024: 512 hex chars + prefix fits). */
constexpr std::size_t kDumpLineBytes = 0x100;
/** Full-replica dumps before falling back to hash-only lines. */
constexpr unsigned kDumpCap = 2;
/** Hash-only reports after the dumps are spent. */
constexpr unsigned kHashCap = 32;

using ChecksumFn = std::uint64_t(__fastcall*)(void*, void*, void*, void*,
                                              void*, void*, void*, void*,
                                              void*, void*) noexcept;

hooking::detour::Handle g_handle{};
std::atomic<unsigned> g_calls{};
std::atomic<unsigned> g_dumped{};
std::atomic<unsigned> g_hashed{};
std::atomic<bool> g_installed{};
std::uintptr_t g_base{};

/** Reads `bytes` from `address` into `out`; false on any fault. */
bool copy_state(std::uintptr_t address, std::array<std::byte, kReplicaBytes>& out) noexcept {
    const auto* const src = reinterpret_cast<const std::uint8_t*>(address);
    __try {
        std::memcpy(out.data(), src, out.size());
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

/** Hexdump line: 0x100 bytes with a tagged prefix. */
void dump_line(unsigned call, std::size_t slot, std::size_t offset,
               const std::byte* bytes, std::size_t span) noexcept {
    std::array<char, core::log::kLineCapacity> text{};
    int written = std::snprintf(text.data(), text.size(),
                                "ev=sdiff stage=entry call=%u slot=%zu off=0x%zx hex=",
                                call, slot, offset);
    for (std::size_t i = 0; i < span && written > 0; ++i) {
        written += std::snprintf(text.data() + written,
                                 text.size() - static_cast<std::size_t>(written),
                                 "%02X", static_cast<unsigned>(*reinterpret_cast<const std::uint8_t*>(
                                             bytes + i)));
    }
    if (written > 0) {
        core::log::write(core::log::Channel::client, core::log::Level::info,
                         {text.data(), static_cast<std::size_t>(written)});
    }
}

std::uint64_t __fastcall observe_checksum(void* rcx, void* rdx, void* r8, void* r9,
                                          void* a5, void* a6, void* a7, void* a8,
                                          void* a9, void* a10) noexcept {
    const unsigned call = g_calls.fetch_add(1, std::memory_order_relaxed) + 1U;
    // POST-APPLY. The profile lands inside the player entry during the original, so a
    // capture taken before it would show the pre-update bytes - which is the whole point
    // of the diff and the easiest thing to get wrong.
    const auto original = reinterpret_cast<ChecksumFn>(g_handle.original);
    const std::uint64_t result = original(rcx, rdx, r8, r9, a5, a6, a7, a8, a9, a10);

    const std::uintptr_t base = reinterpret_cast<std::uintptr_t>(rcx);
    std::array<std::byte, kReplicaBytes> replica{};
    const bool ok = base != 0 && copy_state(base + kPlayerTableOffset, replica);
    if (!ok) {
        if (g_hashed.fetch_add(1, std::memory_order_relaxed) < kHashCap) {
            std::array<char, 128> text{};
            const int written = std::snprintf(text.data(), text.size(),
                                              "ev=sdiff stage=entry call=%u base=0x%llX "
                                              "result=unreadable",
                                              call,
                                              static_cast<unsigned long long>(base));
            if (written > 0) {
                core::log::write(core::log::Channel::client, core::log::Level::info,
                                 {text.data(), static_cast<std::size_t>(written)});
            }
        }
        return result;
    }
    // Only dump an entry that actually carries something: an all-zero entry is an unused
    // slot and spending the budget on it is the p2(133) mistake (budget per event class).
    for (std::size_t slot = 0; slot < kCapturedSlots; ++slot) {
        const std::byte* const entry = replica.data() + slot * kPlayerStride;
        bool empty = true;
        for (std::size_t i = 0; i < kPlayerStride && empty; ++i) {
            empty = entry[i] == std::byte{0};
        }
        if (empty || g_dumped.fetch_add(1, std::memory_order_relaxed) >= kDumpCap) {
            continue;
        }
        for (std::size_t offset = 0; offset < kPlayerStride; offset += kDumpLineBytes) {
            const std::size_t span = kPlayerStride - offset < kDumpLineBytes
                                         ? kPlayerStride - offset
                                         : kDumpLineBytes;
            dump_line(call, slot, offset, entry + offset, span);
        }
    }
    return result;
}

bool fail_install(const char* reason) noexcept {
    std::array<char, 112> text{};
    const int written = std::snprintf(
        text.data(), text.size(), "ev=sdiff stage=install result=fail why=%s", reason);
    if (written > 0) {
        core::log::write(core::log::Channel::client, core::log::Level::warn,
                         {text.data(), static_cast<std::size_t>(written)});
    }
    return false;
}

} // namespace

bool install() noexcept {
    if (!core::settings::get().client.stateDiff) {
        core::log::write(core::log::Channel::client, core::log::Level::info,
                         "ev=sdiff stage=install result=skipped why=disarmed");
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
        || !diagnostics::contains(range, g_base + kChecksumFnRva)) {
        return fail_install("range");
    }
    const hooking::detour::Spec spec{reinterpret_cast<void*>(g_base + kChecksumFnRva),
                                     reinterpret_cast<void*>(&observe_checksum)};
    if (!hooking::detour::install(spec, g_handle)) {
        return fail_install("attach");
    }
    std::array<char, 160> text{};
    const int written = std::snprintf(text.data(), text.size(),
                                      "ev=sdiff stage=install result=ok fn=0x%llX "
                                      "replica=holder+8 bytes=%zu init=0x%08X",
                                      static_cast<unsigned long long>(kChecksumFnRva),
                                      kReplicaBytes, static_cast<unsigned>(kHashInitial));
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

} // namespace sunrise::client::hooks::state_diff
