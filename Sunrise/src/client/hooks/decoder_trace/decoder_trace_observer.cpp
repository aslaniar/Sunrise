#include "decoder_trace_observer.h"

#include <Windows.h>
#include <intrin.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>

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

/**
 * Post-decode dumps get their own, larger cap. The server builds THREE bodies per ~15.85 s
 * cycle (players=0, then two players=1) and in the 22:11 run of 20.187 the apply only ever
 * ran on the players=0 one, so the interesting decode is the SECOND of each cycle. At 16 the
 * old cap covered ~8 cycles; 40 covers the whole dwell without the cap deciding what we see.
 */
constexpr unsigned kDecodedCap = 40;

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
std::atomic<unsigned> g_decodedReported{};

/**
 * THE STAGING SUBSTITUTION (p2(116), settings-gated by client.staging_populate).
 * Offsets the apply 0x141781800 reads its profile content from, per the helper call sites
 * 0x14178241b / 0x141782458 (20.183 R2, disassembly - that part of 20.183 is static and
 * stands regardless of 20.187's run-to-run variance).
 */
constexpr std::size_t kStageGate = 0x19;      // byte: 1 = this row carries a profile
constexpr std::size_t kStageHeader1 = 0x1c;   // u32: the region-A self-hash, unverified on
                                              //      the wire path (verify=0, 20.181 R2)
constexpr std::size_t kStageMask = 0x20;      // u32: the 9-bit region-A chunk mask
constexpr std::size_t kStageRegionA = 0x28;   // pointer to the region-A body
constexpr std::size_t kStageTail = 0x198;     // pointer to the tail
constexpr std::size_t kStagingBytes = 0x400;  // > kStageTail + 8, rounded well past it

/** What write_minimal_profile publishes: chunks 0x001 | 0x008 | 0x100 (20.178). */
constexpr std::uint32_t kMinimalMask = 0x109;
/** Region A is 232 bytes - the span the 0xdeadbfd6 self-hash covers (20.181 R1). */
constexpr std::size_t kRegionABytes = 232;
/** The tail span profile_ingress dumps beside region A. */
constexpr std::size_t kTailBytes = 20;
/** Substitutions per run. Small: this is a write detour, not an observation. */
constexpr unsigned kSubstituteCap = 8;

/**
 * Buffers WE own. The whole safety argument of this detour is that it never writes through
 * a client pointer: the incoming r8 is logged and discarded, never dereferenced. Static
 * storage (not stack) because the callee may retain the pointer past the call.
 * Zero-filled content is faithful to what the server actually publishes - the minimal
 * block's name word, dec-bytes and tail are all zero (write_minimal_profile).
 */
alignas(16) std::uint8_t g_staging[kStagingBytes]{};
alignas(16) std::uint8_t g_regionA[kRegionABytes]{};
alignas(16) std::uint8_t g_tail[kTailBytes]{};
std::atomic<unsigned> g_substituted{};
bool g_stagingArmed = false;
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

/** Dumps a decoded update's counts + nonzero map + row candidates (defined below). */
void dump_update(const char* stageName, unsigned call, const void* structure) noexcept;

/**
 * The decoder's destination struct is its THIRD argument (r8): the p2(115) lines read
 * `reader=<rcx> arg2=0x7980 struct=0x3BE1300`, i.e. rdx is the 0x7980 BYTE SIZE and r8 is
 * the same buffer the apply later receives in rdx. We dump r8 AFTER the original returns,
 * which is the whole point of this build: 20.187 showed a whole run in which the apply
 * never ran for a player-bearing body, so the decoder's own verdict is the only thing that
 * can say whether our block decoded at all.
 */
std::uint64_t __fastcall observe_decoder(void* rcx, void* rdx, void* r8, void* r9,
                                         void* a5, void* a6, void* a7, void* a8,
                                         void* a9, void* a10) noexcept {
    const unsigned call = g_decoderCalls.fetch_add(1, std::memory_order_relaxed) + 1U;
    report("decoder", call, g_decoderReported, rcx, rdx, r8);
    const auto original = reinterpret_cast<DecoderFn>(g_decoder.original);
    const std::uint64_t result = original(rcx, rdx, r8, r9, a5, a6, a7, a8, a9, a10);
    if (g_decodedReported.load(std::memory_order_relaxed) < kDecodedCap) {
        g_decodedReported.fetch_add(1, std::memory_order_relaxed);
        std::array<char, 160> text{};
        // The caller at 0x1416E33AC tests AL and treats zero as failure (`je` to the
        // `[rbx+9] = 1` abort store), so the low byte is the decode verdict.
        const int written = std::snprintf(
            text.data(), text.size(),
            "ev=dtrace stage=decoded call=%u ret=0x%llX ok=%u struct=0x%llX",
            call, static_cast<unsigned long long>(result),
            static_cast<unsigned>(result & 0xFFU),
            static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(r8)));
        if (written > 0) {
            core::log::write(core::log::Channel::client, core::log::Level::info,
                             {text.data(), static_cast<std::size_t>(written)});
        }
        dump_update("decoded", call, r8);
    }
    return result;
}

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

/** Player count from a decoded update struct (+0x174a, 20.176 R2). SEH-guarded; 0 on fault. */
std::uint16_t read_player_count(const void* structure) noexcept {
    if (structure == nullptr) {
        return 0;
    }
    __try {
        const auto* const base = static_cast<const std::uint8_t*>(structure);
        return static_cast<std::uint16_t>(base[0x174a])
               | static_cast<std::uint16_t>(base[0x174b] << 8);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

/** Fills our own staging object with the fields the apply reads. Returns it; never fails. */
void* build_staging() noexcept {
    std::memset(g_staging, 0, sizeof g_staging);
    std::memset(g_regionA, 0, sizeof g_regionA);
    std::memset(g_tail, 0, sizeof g_tail);
    g_staging[kStageGate] = 1U;
    const std::uint32_t header1 = 0U;
    const std::uint32_t mask = kMinimalMask;
    std::memcpy(g_staging + kStageHeader1, &header1, sizeof header1);
    std::memcpy(g_staging + kStageMask, &mask, sizeof mask);
    void* const regionA = g_regionA;
    void* const tail = g_tail;
    std::memcpy(g_staging + kStageRegionA, &regionA, sizeof regionA);
    std::memcpy(g_staging + kStageTail, &tail, sizeof tail);
    return g_staging;
}

std::uint64_t __fastcall observe_apply(void* rcx, void* rdx, void* r8, void* r9,
                                       void* a5, void* a6, void* a7, void* a8,
                                       void* a9, void* a10) noexcept {
    const unsigned call = g_applyCalls.fetch_add(1, std::memory_order_relaxed) + 1U;
    report("apply", call, g_applyReported, rcx, rdx, r8);
    dump_update("update", call, rdx);
    void* staging = r8;
    const std::uint16_t players = read_player_count(rdx);
    /**
     * p2(117) measured the arming condition exactly, so it is now stated exactly: with the
     * region-B fix in, every players>0 apply arrives with a NULL third argument and the
     * session stage reading 4 - the selector's "else" branch, which 0x14058C5A0 nulls (8/8
     * calls; the players=0 applies keep stage=2 and a nonzero tick value). Substituting for
     * a NULL displaces nothing: there is no client object there to lose. If a run ever
     * hands us players>0 with a NON-null pointer, we do NOT substitute - we log the skip and
     * pass it through, because that pointer might be real and this detour has no business
     * guessing.
     */
    const bool nullStaging = (r8 == nullptr);
    if (g_stagingArmed && players > 0 && !nullStaging) {
        std::array<char, 176> text{};
        const int written = std::snprintf(
            text.data(), text.size(),
            "ev=dtrace stage=staging call=%u result=skipped why=non_null_r8 players=%u r8=0x%llX",
            call, static_cast<unsigned>(players),
            static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(r8)));
        if (written > 0) {
            core::log::write(core::log::Channel::client, core::log::Level::warn,
                             {text.data(), static_cast<std::size_t>(written)});
        }
    }
    if (g_stagingArmed && players > 0 && nullStaging
        && g_substituted.load(std::memory_order_relaxed) < kSubstituteCap) {
        const unsigned nth = g_substituted.fetch_add(1, std::memory_order_relaxed) + 1U;
        staging = build_staging();
        std::array<char, 208> text{};
        const int written = std::snprintf(
            text.data(), text.size(),
            "ev=dtrace stage=staging call=%u nth=%u players=%u discarded_r8=0x%llX "
            "staging=0x%llX regionA=0x%llX tail=0x%llX mask=0x%X",
            call, nth, static_cast<unsigned>(players),
            static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(r8)),
            static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(staging)),
            static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(g_regionA)),
            static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(g_tail)),
            static_cast<unsigned>(kMinimalMask));
        if (written > 0) {
            core::log::write(core::log::Channel::client, core::log::Level::warn,
                             {text.data(), static_cast<std::size_t>(written)});
        }
    }
    const auto original = reinterpret_cast<ApplyFn>(g_apply.original);
    return original(rcx, rdx, staging, r9, a5, a6, a7, a8, a9, a10);
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
void dump_update(const char* stageName, unsigned call, const void* structure) noexcept {
    if (structure == nullptr) {
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
                                "ev=dtrace stage=%s call=%u members=%u players=%u nz=",
                                stageName, call, memberCount, playerCount);
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
    if (written > 0) {
        core::log::write(core::log::Channel::client, core::log::Level::info,
                         {text.data(), static_cast<std::size_t>(written)});
    }
    if (playerCount == 0) {
        return;
    }
    /**
     * The row base is UNRESOLVED between +0x4240 and +0x4280 (20.184 R1: the member-delta
     * stride 0xb8 x2 ends near 0x4280, so 0x4240 may be the member tail rather than player
     * row 0). Dumping BOTH candidates on the same body settles it without another boot, and
     * these lines only ever emit when a player row is actually present - which, per 20.187,
     * was true in the earlier flag-on run and never in the 22:11 one.
     */
    static constexpr std::size_t kRowCandidates[] = {0x4240, 0x4280, 0x43c0};
    for (const std::size_t rowBase : kRowCandidates) {
        std::array<char, core::log::kLineCapacity> row{};
        int rw = std::snprintf(row.data(), row.size(),
                               "ev=dtrace stage=%s_row call=%u players=%u base=0x%zx hex=",
                               stageName, call, playerCount, rowBase);
        for (std::size_t i = 0; i < 64 && rw + 2 < static_cast<int>(row.size()); ++i) {
            rw += std::snprintf(row.data() + rw, row.size() - static_cast<std::size_t>(rw),
                                "%02X", copy[rowBase + i]);
        }
        if (rw > 0) {
            core::log::write(core::log::Channel::client, core::log::Level::info,
                             {row.data(), static_cast<std::size_t>(rw)});
        }
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
    g_stagingArmed = core::settings::get().client.stagingPopulate;
    std::array<char, 160> text{};
    const int written = std::snprintf(text.data(), text.size(),
                                      "ev=dtrace stage=install result=ok staging_populate=%u "
                                      "decoder=0x%llX apply=0x%llX",
                                      g_stagingArmed ? 1U : 0U,
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
