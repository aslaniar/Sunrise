#include "join_roster_observer.h"

#include <Windows.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>

#include "../../../core/logging/log.h"
#include "../../../core/settings/settings.h"
#include "../../hooking/detour.h"

namespace sunrise::client::hooks::join_roster {
namespace {

/** Image RVA and expected prologue bytes for one observed checkpoint. */
struct SiteSpec {
    std::uintptr_t rva;
    std::array<std::uint8_t, 24> prologue;
    const char* name;
};

/**
 * The five checkpoints, in pipeline order. Prologues transcribed from
 * destiny2_unpacked_full.exe at base 0x140000000 (FINDINGS 20.108/20.109);
 * the installer compares them before attaching, so a wrong RVA fails loud
 * instead of trampolining into unrelated code.
 */
constexpr std::array<SiteSpec, 5> kSites{{
    {0x16E0460,
     {0x48, 0x89, 0x5C, 0x24, 0x20, 0x55, 0x56, 0x57, 0x41, 0x56,
      0x41, 0x57, 0x48, 0x8D, 0xAC, 0x24, 0x90, 0xFD, 0xFF, 0xFF,
      0x48, 0x81, 0xEC, 0x70},
     "join_request"},
    {0x17806C0,
     {0x40, 0x55, 0x53, 0x56, 0x41, 0x54, 0x41, 0x56, 0x41, 0x57,
      0x48, 0x8D, 0xAC, 0x24, 0x88, 0xFD, 0xFF, 0xFF, 0x48, 0x81,
      0xEC, 0x78, 0x03, 0x00},
     "join_process"},
    {0x17692E0,
     {0x48, 0x89, 0x5C, 0x24, 0x18, 0x55, 0x56, 0x57, 0x41, 0x54,
      0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0xAC, 0x24,
      0x40, 0xFD, 0xFF, 0xFF},
     "reserve"},
    {0x1777EC0,
     {0x40, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41,
      0x56, 0x41, 0x57, 0x48, 0x8D, 0xAC, 0x24, 0x78, 0xFD, 0xFF,
      0xFF, 0x48, 0x81, 0xEC},
     "admit"},
    {0x1792080,
     {0x40, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41,
      0x56, 0x41, 0x57, 0x48, 0x8D, 0xAC, 0x24, 0x88, 0xFD, 0xFF,
      0xFF, 0x48, 0x81, 0xEC},
     "add_candidates"}},
};

/** Per-call log budget before suppression: hot paths must not flood the log. */
constexpr std::uint32_t kCallsLoggedPerSite = 16;
/** Image RVA of the join-candidate table count dword (20.109). */
constexpr std::uintptr_t kCandidateCountRva = 0x431E1118;
/** Site indices, matching kSites order. */
constexpr std::size_t kJoinRequest = 0;
constexpr std::size_t kJoinProcess = 1;
constexpr std::size_t kReserve = 2;
constexpr std::size_t kAdmit = 3;
constexpr std::size_t kAddCandidates = 4;

using Orig = std::uint64_t(__fastcall*)(
    std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t, std::uint32_t) noexcept;

std::atomic<std::uint64_t> g_original[kSites.size()]{};
std::atomic<std::uint32_t> g_calls[kSites.size()]{};
std::atomic<std::uint32_t> g_lastCandidateCount{0xFFFFFFFFU};
std::atomic<std::uint64_t> g_gameBase{0};
/** One trampoline per site, indexed like kSites. */
hooking::detour::Handle g_handles[kSites.size()]{};

/**
 * Reads one qword through a guarded access, so a stale or wild pointer costs
 * a zero instead of a crash.
 * @param address Any address.
 * @return The qword there, or zero when unreadable.
 */
std::uint64_t safe_read(std::uintptr_t address) noexcept {
    if (address == 0) {
        return 0;
    }
    __try {
        return *reinterpret_cast<const volatile std::uint64_t*>(address);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

/** @overload dword variant for the session-state and packet fields. */
std::uint32_t safe_read32(std::uintptr_t address) noexcept {
    if (address == 0) {
        return 0;
    }
    __try {
        return *reinterpret_cast<const volatile std::uint32_t*>(address);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

/** Emits one ev=jr line. */
void write_line(const char* text) noexcept {
    core::log::write(core::log::Channel::client, core::log::Level::info, text);
}

/**
 * Shared per-call logger: the first kCallsLoggedPerSite calls of each site
 * print, then the site goes silent for the rest of the boot (the counters in
 * the summary tell the story; a flood would bury the retail narration).
 * @param site Index into kSites.
 * @param a1..a4 Raw register arguments captured at the detour boundary.
 * @param a5 Raw fifth (stack) argument.
 * @param detail Site-specific formatted fields, already bounded.
 */
void log_call(std::size_t site,
              std::uint64_t a1,
              std::uint64_t a2,
              std::uint64_t a3,
              std::uint64_t a4,
              std::uint32_t a5,
              const char* detail) noexcept {
    if (!core::log::accepts(core::log::Channel::client, core::log::Level::info)) {
        return;
    }
    const std::uint32_t calls = g_calls[site].fetch_add(1, std::memory_order_relaxed);
    if (calls == 0) {
        std::array<char, 96> first{};
        const int firstWritten = std::snprintf(first.data(),
                                               first.size(),
                                               "ev=jr stage=first fn=%s",
                                               kSites[site].name);
        if (firstWritten > 0) {
            write_line(first.data());
        }
    }
    if (calls >= kCallsLoggedPerSite) {
        return;
    }
    std::array<char, 320> line{};
    const int written = std::snprintf(line.data(),
                                      line.size(),
                                      "ev=jr fn=%s n=%u a1=0x%llX a2=0x%llX a3=0x%llX "
                                      "a4=0x%llX a5=%u %s",
                                      kSites[site].name,
                                      static_cast<unsigned>(calls + 1),
                                      static_cast<unsigned long long>(a1),
                                      static_cast<unsigned long long>(a2),
                                      static_cast<unsigned long long>(a3),
                                      static_cast<unsigned long long>(a4),
                                      static_cast<unsigned>(a5),
                                      detail);
    if (written > 0) {
        write_line(line.data());
    }
}

/**
 * Calls the original body through the trampoline and returns its result
 * unchanged. Reads the trampoline once; a missing trampoline answers zero,
 * which every caller of these functions treats as a failure code.
 * @param site Index into kSites.
 */
std::uint64_t run_original(std::size_t site,
                           std::uint64_t a1,
                           std::uint64_t a2,
                           std::uint64_t a3,
                           std::uint64_t a4,
                           std::uint32_t a5) noexcept {
    const Orig original = reinterpret_cast<Orig>(
        g_original[site].load(std::memory_order_acquire));
    if (original == nullptr) {
        return 0;
    }
    return original(a1, a2, a3, a4, a5);
}

/**
 * Body for the inbound type-0x0A join-request handler. rcx = connection
 * context, rdx = connection, r8 = packet record (word[+0] nonce, dword[+4]
 * flags/version, dword[+8] member count, qword[+0x10]/[+0x18] ids).
 */
std::uint64_t __fastcall site_join_request(std::uint64_t a1,
                                           std::uint64_t a2,
                                           std::uint64_t a3,
                                           std::uint64_t a4,
                                           std::uint32_t a5) noexcept {
    std::array<char, 160> detail{};
    const std::uint64_t pkt = a3;
    const int written = std::snprintf(detail.data(),
                                      detail.size(),
                                      "pkt_n=0x%X f=0x%X cnt=%u id0=0x%llX id1=0x%llX",
                                      static_cast<unsigned>(safe_read32(pkt)),
                                      static_cast<unsigned>(safe_read32(pkt + 4)),
                                      static_cast<unsigned>(safe_read32(pkt + 8)),
                                      static_cast<unsigned long long>(safe_read(pkt + 0x10)),
                                      static_cast<unsigned long long>(safe_read(pkt + 0x18)));
    log_call(kJoinRequest, a1, a2, a3, a4, a5, written > 0 ? detail.data() : "");
    return run_original(kJoinRequest, a1, a2, a3, a4, a5);
}

/**
 * Body for the join-request processor. rcx = session object (state dword at
 * +0x1AEF8), rdx = connection, r8 = packet record (dword[+4], dword[+8]
 * member count, qword[+0x18]).
 */
std::uint64_t __fastcall site_join_process(std::uint64_t a1,
                                           std::uint64_t a2,
                                           std::uint64_t a3,
                                           std::uint64_t a4,
                                           std::uint32_t a5) noexcept {
    std::array<char, 160> detail{};
    const int written = std::snprintf(detail.data(),
                                      detail.size(),
                                      "sess_state=%u f=0x%X cnt=%u id1=0x%llX",
                                      static_cast<unsigned>(safe_read32(a1 + 0x1AEF8)),
                                      static_cast<unsigned>(safe_read32(a3 + 4)),
                                      static_cast<unsigned>(safe_read32(a3 + 8)),
                                      static_cast<unsigned long long>(safe_read(a3 + 0x18)));
    log_call(kJoinProcess, a1, a2, a3, a4, a5, written > 0 ? detail.data() : "");
    return run_original(kJoinProcess, a1, a2, a3, a4, a5);
}

/**
 * Body for the reserve (machine registration) gate. rcx = context, edx/r8d =
 * machine and member indices, r9 = record whose first qword names the joiner.
 */
std::uint64_t __fastcall site_reserve(std::uint64_t a1,
                                      std::uint64_t a2,
                                      std::uint64_t a3,
                                      std::uint64_t a4,
                                      std::uint32_t a5) noexcept {
    std::array<char, 128> detail{};
    const int written = std::snprintf(detail.data(),
                                      detail.size(),
                                      "mach=%u memb=%u id=0x%llX",
                                      static_cast<unsigned>(a2 & 0xFFFFFFFFU),
                                      static_cast<unsigned>(a3 & 0xFFFFFFFFU),
                                      static_cast<unsigned long long>(safe_read(a4)));
    log_call(kReserve, a1, a2, a3, a4, a5, written > 0 ? detail.data() : "");
    return run_original(kReserve, a1, a2, a3, a4, a5);
}

/**
 * Body for the admit (member record fill). rcx = context, edx = machine
 * index, r8d = member index, r9 = record whose first qword is the xuid.
 */
std::uint64_t __fastcall site_admit(std::uint64_t a1,
                                    std::uint64_t a2,
                                    std::uint64_t a3,
                                    std::uint64_t a4,
                                    std::uint32_t a5) noexcept {
    std::array<char, 128> detail{};
    const int written = std::snprintf(detail.data(),
                                      detail.size(),
                                      "mach=%u memb=%u xuid=0x%llX",
                                      static_cast<unsigned>(a2 & 0xFFFFFFFFU),
                                      static_cast<unsigned>(a3 & 0xFFFFFFFFU),
                                      static_cast<unsigned long long>(safe_read(a4)));
    log_call(kAdmit, a1, a2, a3, a4, a5, written > 0 ? detail.data() : "");
    return run_original(kAdmit, a1, a2, a3, a4, a5);
}

/**
 * Body for add-candidates, the sustained writer of session candidates +0xC8.
 * ecx = session id, rdx = xuid array, r8/r9 = flag arrays, a5 = count.
 */
std::uint64_t __fastcall site_add_candidates(std::uint64_t a1,
                                             std::uint64_t a2,
                                             std::uint64_t a3,
                                             std::uint64_t a4,
                                             std::uint32_t a5) noexcept {
    std::array<char, 224> detail{};
    const unsigned count = a5 > 4 ? 4 : a5;
    int written = std::snprintf(detail.data(),
                                detail.size(),
                                "xuid0=0x%llX xuid1=0x%llX xuid2=0x%llX xuid3=0x%llX",
                                static_cast<unsigned long long>(count > 0 ? safe_read(a2) : 0),
                                static_cast<unsigned long long>(count > 1 ? safe_read(a2 + 8) : 0),
                                static_cast<unsigned long long>(count > 2 ? safe_read(a2 + 16) : 0),
                                static_cast<unsigned long long>(count > 3 ? safe_read(a2 + 24) : 0));
    log_call(kAddCandidates, a1, a2, a3, a4, a5, written > 0 ? detail.data() : "");
    return run_original(kAddCandidates, a1, a2, a3, a4, a5);
}

/** @return True when the prologue at @p address matches the expected bytes. */
bool prologue_matches(std::uintptr_t address, const SiteSpec& site) noexcept {
    __try {
        const auto* bytes = reinterpret_cast<const std::uint8_t*>(address);
        for (std::size_t i = 0; i < site.prologue.size(); ++i) {
            if (bytes[i] != site.prologue[i]) {
                return false;
            }
        }
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

/** @param reason Key naming the step that failed. @return False, for a direct return. */
bool fail_install(const char* reason) noexcept {
    std::array<char, 96> line{};
    const int written = std::snprintf(line.data(),
                                      line.size(),
                                      "ev=jr stage=install result=fail reason=%s",
                                      reason);
    if (written > 0) {
        write_line(line.data());
    }
    return false;
}

} // namespace

/** Attaches all five observers when the settings switch allows it. */
bool install() noexcept {
    if (!core::settings::get().client.joinRosterObserver) {
        write_line("ev=jr stage=install result=skip reason=disabled");
        return true;
    }
    if (g_gameBase.load(std::memory_order_acquire) != 0) {
        return true;
    }
    const HMODULE game = GetModuleHandleW(nullptr);
    if (game == nullptr) {
        return fail_install("base");
    }
    const std::uintptr_t base = reinterpret_cast<std::uintptr_t>(game);
    g_gameBase.store(base, std::memory_order_release);

    bool allAttached = true;
    for (std::size_t i = 0; i < kSites.size(); ++i) {
        const std::uintptr_t target = base + kSites[i].rva;
        if (!prologue_matches(target, kSites[i])) {
            std::array<char, 128> line{};
            std::snprintf(line.data(),
                          line.size(),
                          "ev=jr stage=install fn=%s result=fail reason=prologue",
                          kSites[i].name);
            write_line(line.data());
            allAttached = false;
            continue;
        }
        void* bodies[kSites.size()] = {
            reinterpret_cast<void*>(&site_join_request),
            reinterpret_cast<void*>(&site_join_process),
            reinterpret_cast<void*>(&site_reserve),
            reinterpret_cast<void*>(&site_admit),
            reinterpret_cast<void*>(&site_add_candidates),
        };
        const hooking::detour::Spec spec{reinterpret_cast<void*>(target), bodies[i]};
        const bool attached = hooking::detour::install(spec, g_handles[i]);
        g_original[i].store(reinterpret_cast<std::uint64_t>(g_handles[i].original),
                            std::memory_order_release);
        std::array<char, 128> line{};
        std::snprintf(line.data(),
                      line.size(),
                      "ev=jr stage=install fn=%s result=%s",
                      kSites[i].name,
                      attached ? "ok" : "fail reason=detour");
        write_line(line.data());
        allAttached &= attached;
    }
    return allAttached;
}

/** Detaches every observer and drops the trampolines. */
bool uninstall() noexcept {
    bool allRemoved = true;
    for (std::size_t i = 0; i < kSites.size(); ++i) {
        g_original[i].store(0, std::memory_order_release);
        if (g_handles[i].attached) {
            const bool removed = hooking::detour::uninstall(g_handles[i]);
            allRemoved = allRemoved && removed;
        }
    }
    write_line(allRemoved ? "ev=jr stage=uninstall result=ok" : "ev=jr stage=uninstall result=fail");
    if (allRemoved) {
        g_gameBase.store(0, std::memory_order_release);
    }
    return allRemoved;
}

/** @return True while the observers are attached. */
bool is_installed() noexcept {
    return g_gameBase.load(std::memory_order_acquire) != 0;
}

/**
 * Read-only poll of the join-candidate table count. Emits on change only, so
 * a silent poll means the waiting list never grew (the pre-named negative).
 * Called from the retail-log observer's 2 s re-assert block, which runs on a
 * game thread after the funnel is live.
 */
void poll_candidate_table() noexcept {
    const std::uint64_t base = g_gameBase.load(std::memory_order_acquire);
    if (base == 0) {
        return;
    }
    const std::uint32_t count = safe_read32(base + kCandidateCountRva);
    std::uint32_t last = g_lastCandidateCount.load(std::memory_order_acquire);
    if (last == count) {
        return;
    }
    while (!g_lastCandidateCount.compare_exchange_weak(last,
                                                       count,
                                                       std::memory_order_release,
                                                       std::memory_order_acquire)) {
        if (last == count) {
            return;
        }
    }
    std::array<char, 64> line{};
    const int written = std::snprintf(line.data(),
                                      line.size(),
                                      "ev=jr stage=poll cand=%u",
                                      static_cast<unsigned>(count));
    if (written > 0) {
        write_line(line.data());
    }
}

} // namespace sunrise::client::hooks::join_roster
