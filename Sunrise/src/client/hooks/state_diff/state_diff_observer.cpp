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
 * Image RVA of the checksum verifier 0x141772100 (0x141772100..0x1417722F8, .pdata
 * START; verify_hook_rvas.py gates this). The state hash immediate 0xDEAE2F4E sits
 * inside it at offset 0x76.
 */
constexpr std::uintptr_t kChecksumFnRva = 0x1772100;
/** The replica lives at holder+8 (the function copies from there). */
constexpr std::uintptr_t kReplicaOffset = 8;
/** The session-state replica size, byte-exact (the copy loop moves 0x7060). */
constexpr std::size_t kReplicaBytes = 28768;
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
void dump_line(unsigned call, std::size_t offset, const std::byte* bytes) noexcept {
    std::array<char, core::log::kLineCapacity> text{};
    int written = std::snprintf(text.data(), text.size(),
                                "ev=sdiff stage=dump call=%u off=0x%zx hex=",
                                call, offset);
    for (std::size_t i = 0; i < kDumpLineBytes && written > 0; ++i) {
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
    const std::uintptr_t holder = reinterpret_cast<std::uintptr_t>(rcx);
    std::array<std::byte, kReplicaBytes> replica{};
    const bool ok = holder != 0 && copy_state(holder + kReplicaOffset, replica);
    std::uint32_t hash = 0;
    if (ok) {
        hash = middleware::crypto::lookup3::hash_bytes(replica, kHashInitial);
    }
    const bool dump = ok && g_dumped.load(std::memory_order_relaxed) < kDumpCap;
    if (ok) {
        const unsigned hashed = g_hashed.fetch_add(1, std::memory_order_relaxed) + 1U;
        if (hashed <= kHashCap || dump) {
            std::array<char, 160> text{};
            const int written = std::snprintf(
                text.data(), text.size(),
                "ev=sdiff stage=verify call=%u holder=0x%llX hash=0x%08X%s",
                call, static_cast<unsigned long long>(holder),
                static_cast<unsigned>(hash), dump ? " dump=1" : "");
            if (written > 0) {
                core::log::write(core::log::Channel::client, core::log::Level::info,
                                 {text.data(), static_cast<std::size_t>(written)});
            }
        }
    } else {
        std::array<char, 128> text{};
        const int written = std::snprintf(text.data(), text.size(),
                                          "ev=sdiff stage=verify call=%u holder=0x%llX "
                                          "result=unreadable",
                                          call, static_cast<unsigned long long>(holder));
        if (written > 0) {
            core::log::write(core::log::Channel::client, core::log::Level::info,
                             {text.data(), static_cast<std::size_t>(written)});
        }
    }
    if (dump) {
        g_dumped.fetch_add(1, std::memory_order_relaxed);
        for (std::size_t offset = 0; offset < kReplicaBytes; offset += kDumpLineBytes) {
            dump_line(call, offset, replica.data() + offset);
        }
    }
    const auto original = reinterpret_cast<ChecksumFn>(g_handle.original);
    const std::uint64_t result = original(rcx, rdx, r8, r9, a5, a6, a7, a8, a9, a10);
    if (ok && g_hashed.load(std::memory_order_relaxed) <= kHashCap + 2U) {
        std::array<char, 128> text{};
        const int written = std::snprintf(text.data(), text.size(),
                                          "ev=sdiff stage=verify_done call=%u ret=%llu",
                                          call, static_cast<unsigned long long>(result));
        if (written > 0) {
            core::log::write(core::log::Channel::client, core::log::Level::info,
                             {text.data(), static_cast<std::size_t>(written)});
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
