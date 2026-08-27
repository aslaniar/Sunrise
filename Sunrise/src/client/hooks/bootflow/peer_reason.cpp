#include <Windows.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <intrin.h>
#include <string_view>

#include "../../../core/logging/log.h"
#include "../../hooking/detour.h"
#include "internal.h"

namespace sunrise::client::hooks::bootflow {
namespace {

/**
 * `reason_name(int)` - the peer-link failure-reason name accessor at static 0x1416E1620.
 *
 * FINDINGS 20.85: the five printer sites that format a reason all take it as a PARAMETER, and
 * the static walk above them ends in a 27-arm observer fan-out with .vmp0 beyond it. This
 * accessor is the one place every reason lookup converges, and its argument IS the reason byte,
 * so hooking it names the DECIDING call site directly instead of searching for it.
 *
 *   83 F9 23        cmp ecx, 0x23        <- 35 entries; the sibling 11-entry accessor at
 *   77 0F           ja  fallback            0x1416E1600 is byte-identical except for 0x0A here,
 *   48 63 C1        movsxd rax, ecx         which is what makes this pattern unambiguous
 *   48 8D 0D ? ? ? ? lea rcx, [table]
 *   48 8B 04 C1     mov rax, [rcx + rax*8]
 *   C3              ret
 *
 * Verified UNIQUE in .text (one match, at 0x1416E1620) before this shipped.
 */
constexpr std::string_view kReasonNameSignatureText =
    "83 F9 23 77 0F 48 63 C1 48 8D 0D ? ? ? ? 48 8B 04 C1 C3";
/** Compiled pattern bytes of the signature text above. */
constexpr auto kReasonNameSignature =
    signature<signature_length(kReasonNameSignatureText)>(kReasonNameSignatureText);

/**
 * Distinct (reason, call-site) pairs reported per run.
 *
 * A plain line budget would be spent by whichever reason fires most and hide the rare one, which
 * is exactly the reason we care about. Deduplicating on the PAIR reports every distinct decision
 * site once and then goes quiet, so a long boot cannot bury a late first-of-its-kind lookup.
 */
constexpr std::size_t kMaxPairs = 48;
/** Size of one report line. */
constexpr std::size_t kLineCapacity = 160;

using ReasonName = const char*(__fastcall*)(int);

hooking::detour::Handle g_handle{};
std::atomic<ReasonName> g_original{nullptr};

struct Pair {
    std::uint32_t site;   // return-site RVA, so it reads straight against the static image
    std::int32_t reason;
};

std::array<Pair, kMaxPairs> g_seen{};
std::atomic<std::size_t> g_count{0};

/** @return Main-image base, for turning a runtime return address into a static-image RVA. */
[[nodiscard]] std::uintptr_t image_base() noexcept {
    return reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
}

/**
 * Records one (reason, site) pair the first time it is seen.
 * @param site Return-site RVA.
 * @param reason Reason value the caller asked to name.
 * @return True when this pair is new and should be reported.
 */
[[nodiscard]] bool claim(std::uint32_t site, std::int32_t reason) noexcept {
    const std::size_t used = g_count.load(std::memory_order_acquire);
    for (std::size_t index = 0; index < used && index < g_seen.size(); ++index) {
        if (g_seen[index].site == site && g_seen[index].reason == reason) {
            return false;
        }
    }
    const std::size_t slot = g_count.fetch_add(1, std::memory_order_acq_rel);
    if (slot >= g_seen.size()) {
        return false;
    }
    g_seen[slot] = Pair{site, reason};
    return true;
}

/**
 * Names a peer-link failure reason and reports who asked.
 *
 * LIVENESS (pre-boot checklist item 2): this fires on EVERY reason lookup, including the boring
 * ones we already understand, so silence means the hook never ran rather than "no interesting
 * reason occurred". An instrument that can only speak on the interesting case makes silence
 * unreadable - AGENTS.md lesson 13.
 *
 * @param reason Peer-link failure reason index, 0..35.
 * @return Whatever the original returns, unchanged.
 */
__declspec(noinline) const char* __fastcall reason_name(int reason) noexcept {
    const ReasonName original = g_original.load(std::memory_order_acquire);
    // The detour is live for a few instructions before install publishes its trampoline.
    if (original == nullptr) {
        return nullptr;
    }
    const char* const name = original(reason);
    const auto caller = reinterpret_cast<std::uintptr_t>(_ReturnAddress());
    const std::uintptr_t base = image_base();
    const auto site =
        static_cast<std::uint32_t>(caller >= base ? caller - base : 0);
    if (!claim(site, reason)) {
        return name;
    }
    std::array<char, kLineCapacity> line{};
    const int written = std::snprintf(line.data(),
                                      line.size(),
                                      "ev=peerlink stage=reason value=%d name=%s site_rva=0x%08X "
                                      "static=0x%llX",
                                      reason,
                                      name == nullptr ? "<null>" : name,
                                      site,
                                      // The dump's static image base, so the address can be fed
                                      // straight to disasm_fn.py with no arithmetic at the desk.
                                      static_cast<unsigned long long>(0x140000000ULL + site));
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(written)});
    }
    return name;
}

/** @param reason Key naming the step that failed. @return False, for a direct return. */
[[nodiscard]] bool fail(const char* reason) noexcept {
    std::array<char, kLineCapacity> line{};
    const int written = std::snprintf(
        line.data(), line.size(), "ev=peerlink stage=reason result=fail reason=%s", reason);
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::warn,
                         {line.data(), static_cast<std::size_t>(written)});
    }
    return false;
}

} // namespace

/** Attaches the peer-link reason observer. */
bool install_peer_reason() noexcept {
    if (g_handle.attached) {
        return true;
    }
    std::byte* const target =
        scan_main_image_unique(kReasonNameSignature, "peerlink_reason_name");
    if (target == nullptr) {
        return fail("target");
    }
    const hooking::detour::Spec spec{target, reinterpret_cast<void*>(&reason_name)};
    if (!hooking::detour::install(spec, g_handle)) {
        return fail("attach");
    }
    g_original.store(reinterpret_cast<ReasonName>(g_handle.original), std::memory_order_release);
    core::log::write(core::log::Channel::client,
                     core::log::Level::info,
                     "ev=peerlink stage=reason result=ok");
    return true;
}

/** Detaches the peer-link reason observer. */
void uninstall_peer_reason() noexcept {
    if (g_handle.attached) {
        (void)hooking::detour::uninstall(g_handle);
    }
    g_original.store(nullptr, std::memory_order_release);
    g_count.store(0, std::memory_order_release);
}

} // namespace sunrise::client::hooks::bootflow
