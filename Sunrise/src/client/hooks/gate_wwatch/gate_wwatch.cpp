#include "gate_wwatch.h"

#include <Windows.h>
#include <tlhelp32.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>

#include "../../../core/logging/log.h"

/**
 * Design rules honoured here (POSTMORTEM_2026-09-01_INSTRUMENTATION):
 * - DEFECT 1: every hit logs the KEY (table, record index, record identity, which byte),
 *   not just "a byte changed". The record index is captured INTO the hit at hit time,
 *   so a re-arm between the hit and the drain cannot mis-attribute it.
 * - DEFECT 2: no detail budgets - capture is bounded only by the flood guard, and every
 *   census prints captured, drained AND dropped counts. Nothing can be silently starved.
 * - DEFECT 3: the positive control (self-test) fires BY CONSTRUCTION - we watch our own
 *   byte and write it from a fresh thread. A boot with `selftest ok` proves the whole
 *   DR->VEC->ring->log pipeline end to end; a FAIL indicts the instrument, not the world.
 * - DEFECT 5: every census prints its denominator (threads covered / total, per-slot
 *   hits, dropped, refused tables).
 * - DEFECT 6: guards precede every dereference; every game-memory read is SEH-guarded;
 *   plausibility failures log refusals instead of faulting.
 * - DEFECT 7: the only alarm is the self-test, which can actually fire by construction;
 *   a FAIL there means the instrument is broken and is MEANT to stop the boot.
 * - DEFECT 8: post-boot analysis goes through log_archive/logindex/logq, never grep chains.
 *
 * Adversarial-review fixes baked in (verify session, pre-boot):
 * - The capture ring WRAPS with per-entry sequence numbers: a burst can no longer
 *   permanently kill the capture channel after N lifetime hits; overwrites of undrained
 *   entries are counted per entry as dropped and are visible in every census.
 * - The thread fast-path verifies Dr0-3 ADDRESSES as well as Dr7, so a re-arm that moves
 *   a watch address cannot leave threads silently watching a stale address.
 * - A spurious fast-path mismatch re-verifies once before suspending, so a stale
 *   GetThreadContext on a running thread cannot cause a suspend storm.
 *
 * Crash safety (the instrument must not change the game's behaviour):
 * - NO detours, NO game-memory writes. The only byte the instrument ever writes is its
 *   own self-test byte.
 * - The VEC handler consumes ONLY EXCEPTION_SINGLE_STEP whose DR6 bits name a slot we
 *   armed; everything else is EXCEPTION_CONTINUE_SEARCH (the game never sees us).
 *   It takes no locks, allocates nothing, and calls no logging function - it only fills
 *   one preallocated ring slot. Logging happens on the watchdog thread.
 * - Thread contexts are only modified through the documented
 *   GetThreadContext -> SuspendThread -> SetThreadContext -> ResumeThread sequence; no
 *   locks are taken between suspend and resume, and a failed operation is counted by
 *   the census and skipped, never retried in a loop.
 */

namespace sunrise::client::hooks::gate_wwatch {
namespace {

constexpr std::uintptr_t kRecStride = 0x2AC0;   ///< participant record stride (20.229)
constexpr std::uintptr_t kRecGateByte = 0x38;   ///< cond 5's byte inside the record

/**
 * Fixed DR-slot allocation (a CPU has exactly four):
 *   slot 0: FIRST table's peer record gate byte (+0x38, 4-byte window, write-only)
 *   slot 1: SECOND table's peer record gate byte (two tables run concurrently, 20.230 R2)
 *   slot 2: first table's SELF record gate byte - a global writer touching every record
 *           fires here even when the peer's slot somehow does not
 *   slot 3: our own self-test byte - the by-construction positive control
 */
struct Slot {
    std::atomic<std::uint64_t> addr{0};   ///< linear address watched (0 = unused)
    std::atomic<std::uint32_t> len{1};    ///< 1 or 4 (4 only when the address is 4-aligned)
    std::atomic<std::uint32_t> recIndex{0xFFFFFFFFU};
    std::atomic<std::uint64_t> table{0};  ///< owning table (0 for the self-test slot)
    std::atomic<std::uint64_t> shadow{0}; ///< last observed byte (the no-hit safety net)
    std::atomic<std::uint32_t> hits{0};   ///< total hits since arm (census)
};
std::array<Slot, 4> g_slots{};
std::atomic<unsigned> g_enabledMask{0};     ///< bits = DR slots we armed
std::atomic<unsigned> g_version{0};         ///< bumped on (re)arm; forces a DR re-apply
std::atomic<bool> g_installed{false};
std::atomic<std::uint64_t> g_tableBits{0};  ///< bit per allocated table slot (0..1)
std::atomic<unsigned> g_refusedTables{0};
std::atomic<std::uint64_t> g_dropped{0};    ///< overwrites of undrained hits (census)
std::atomic<std::uint64_t> g_drainedSeq{0}; ///< watermark: every claim <= this is drained
std::atomic<bool> g_selfTestSeen{false};
std::atomic<unsigned> g_lastTotal{0};
std::atomic<unsigned> g_lastCovered{0};
std::atomic<unsigned> g_lastFailed{0};
std::uintptr_t g_base{0};  ///< main module base, for RIP -> RVA conversion in the handler

alignas(8) volatile std::uint8_t g_selfTestByte{0};

constexpr unsigned kRingCapacity = 1024;

/** One captured write. Fixed layout, no pointers into game code. */
struct Hit {
    std::uint64_t seq;        ///< monotonic claim number (0 = empty slot)
    std::uint64_t when;
    std::uint64_t ripRva;     ///< module-relative RIP - a DATA breakpoint TRAPS after the
                              ///< writing instruction completes, so this is the address
                              ///< AFTER it; the instruction bytes below END at it
    std::uint64_t rec8;       ///< the record's identity qword (the KEY)
    std::uint64_t table;
    std::uint32_t tid;
    std::uint32_t slot;
    std::uint32_t recIndex;   ///< captured at hit time - a re-arm cannot mis-attribute
    std::uint32_t oldByte;    ///< shadow value before the write was seen
    std::uint32_t newByte;    ///< byte re-read in the handler (post-write); 0xFF=unreadable
    std::uint32_t dr6;
    std::uint32_t instrOk;    ///< 1 when the instruction window was readable
    std::uint8_t instr[16];   ///< 16 bytes ending at RIP - decodes to the writing instruction
};
std::array<Hit, kRingCapacity> g_ring{};
std::atomic<std::uint64_t> g_ringClaim{0};  ///< monotonic; slot = claim % capacity

/** SEH-guarded byte copy. Kept object-free so any compiler accepts __try here. */
bool safe_copy(void* dst, const void* src, std::size_t n) noexcept {
    __try {
        const volatile std::uint8_t* s = static_cast<const volatile std::uint8_t*>(src);
        std::uint8_t* d = static_cast<std::uint8_t*>(dst);
        for (std::size_t i = 0; i < n; ++i) {
            d[i] = s[i];
        }
        return true;
    } __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION
                    ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        return false;
    }
}

void emit_line(const char* text, std::size_t length) noexcept {
    core::log::write(core::log::Channel::client, core::log::Level::info, {text, length});
}

/** DR7 field for one slot: R/W=01 (write), LEN bits 2-3 (00=1 byte, 11=4 bytes). */
[[nodiscard]] std::uint64_t dr7_field(unsigned slot, std::uint32_t len) noexcept {
    const std::uint64_t lenBits = (len >= 4U) ? 3U : 0U;
    return (1ULL << (2U * slot))                // local enable for this slot
         | (0x1ULL << (16U + 4U * slot))        // R/W = write only
         | (lenBits << (16U + 4U * slot + 2U)); // LEN
}

[[nodiscard]] std::uint64_t build_dr7(unsigned mask) noexcept {
    std::uint64_t dr7 = 0;
    for (unsigned slot = 0; slot < 4; ++slot) {
        if (((mask >> slot) & 1U) == 0U) {
            continue;
        }
        dr7 |= dr7_field(slot, g_slots[slot].len.load(std::memory_order_relaxed));
    }
    return dr7;
}

/**
 * THE VECTORED EXCEPTION HANDLER. Runs first for every exception in the process; the
 * fast path is one relaxed atomic load. Consumes ONLY hardware watchpoint hits whose
 * DR6 bit names a slot we armed - everything else passes through untouched.
 */
LONG NTAPI vec_handler(PEXCEPTION_POINTERS info) noexcept {
    if (!g_installed.load(std::memory_order_relaxed)) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    if (info == nullptr || info->ExceptionRecord == nullptr
        || info->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP
        || info->ContextRecord == nullptr) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    const unsigned dr6bits = static_cast<unsigned>(info->ContextRecord->Dr6 & 0xFULL);
    const unsigned ours = dr6bits & g_enabledMask.load(std::memory_order_relaxed);
    if (ours == 0U) {
        // A single-step that is not ours (none exists in this process today) must pass
        // through so any other handler behaves exactly as before.
        return EXCEPTION_CONTINUE_SEARCH;
    }
    unsigned slot = 0U;
    while (((ours >> slot) & 1U) == 0U) {
        ++slot;
    }

    Hit hit{};
    const std::uint64_t claim = g_ringClaim.fetch_add(1U, std::memory_order_relaxed) + 1U;
    hit.seq = claim;
    hit.when = GetTickCount64();
    hit.tid = GetCurrentThreadId();
    hit.slot = slot;
    hit.dr6 = dr6bits;
    const auto addr = g_slots[slot].addr.load(std::memory_order_relaxed);
    hit.table = g_slots[slot].table.load(std::memory_order_relaxed);
    hit.recIndex = g_slots[slot].recIndex.load(std::memory_order_relaxed);
    hit.oldByte = static_cast<std::uint32_t>(
        g_slots[slot].shadow.load(std::memory_order_relaxed));
    const auto rip = info->ContextRecord->Rip;
    hit.ripRva = (g_base != 0 && rip >= g_base) ? (rip - g_base) : rip;

    std::uint8_t now = 0;
    if (addr != 0 && safe_copy(&now, reinterpret_cast<const void*>(addr), 1)) {
        hit.newByte = now;
        g_slots[slot].shadow.store(now, std::memory_order_relaxed);
    } else {
        hit.newByte = 0xFFFFFFFFU;  // "unreadable" sentinel, never a real byte value
    }
    // The record identity is the KEY (DEFECT 1): read it guarded, log it even when the
    // byte read failed - address + slot still identify the record.
    std::uint64_t rec8 = 0;
    if (addr != 0 && hit.table != 0) {
        const auto recAddr = hit.table + static_cast<std::uint64_t>(hit.recIndex)
                                 * kRecStride + 8U;
        (void)safe_copy(&rec8, reinterpret_cast<const void*>(recAddr), sizeof(rec8));
    }
    hit.rec8 = rec8;
    // Data breakpoints trap AFTER the writing instruction: capture the window ENDING at
    // RIP so the last instruction in it is the writer.
    hit.instrOk = (rip >= 16 && safe_copy(hit.instr, reinterpret_cast<const void*>(rip - 16),
                                          sizeof(hit.instr)))
                      ? 1U : 0U;

    // WRAPPING ring: slot = claim % capacity. If the previous occupant of this slot was
    // never drained (its seq is above the watermark), that entry is lost - counted per
    // entry, visible in every census.
    Hit& target = g_ring[static_cast<std::size_t>(claim % kRingCapacity)];
    const std::uint64_t previous = target.seq;
    if (previous != 0 && previous > g_drainedSeq.load(std::memory_order_relaxed)) {
        g_dropped.fetch_add(1U, std::memory_order_relaxed);
    }
    target = hit;

    g_slots[slot].hits.fetch_add(1U, std::memory_order_relaxed);
    if (slot == 3U) {
        g_selfTestSeen.store(true, std::memory_order_relaxed);
    }

    // Consume the hit (clear our DR6 status bits so the watchpoint can fire again) and
    // resume. The writing instruction has already completed (trap semantics).
    info->ContextRecord->Dr6 &= ~0xFULL;
    return EXCEPTION_CONTINUE_EXECUTION;
}

/**
 * The self-test: a FRESH short-lived thread writes our own watched byte after a delay
 * longer than two sweeps, so a sweep has already armed its debug registers. The
 * self-test therefore exercises the whole pipeline AND the new-thread arming path -
 * the exact path a real writer on a freshly spawned thread would take.
 */
DWORD WINAPI selftest_main(LPVOID) noexcept {
    Sleep(1200);
    g_selfTestByte = static_cast<std::uint8_t>(g_selfTestByte + 1U);
    return 0U;
}

/** The full expected debug-register state for one thread, from the slot table. */
struct ExpectedContext {
    std::uint64_t dr0;
    std::uint64_t dr1;
    std::uint64_t dr2;
    std::uint64_t dr3;
    std::uint64_t dr7;
};

[[nodiscard]] ExpectedContext expected_context() noexcept {
    return {
        g_slots[0].addr.load(std::memory_order_relaxed),
        g_slots[1].addr.load(std::memory_order_relaxed),
        g_slots[2].addr.load(std::memory_order_relaxed),
        g_slots[3].addr.load(std::memory_order_relaxed),
        build_dr7(g_enabledMask.load(std::memory_order_relaxed)),
    };
}

/** True when a thread's debug registers already match the expected state exactly. */
bool context_matches(const CONTEXT& ctx, const ExpectedContext& e) noexcept {
    return ctx.Dr0 == e.dr0 && ctx.Dr1 == e.dr1 && ctx.Dr2 == e.dr2 && ctx.Dr3 == e.dr3
        && ctx.Dr7 == e.dr7;
}

/** Applies our DR0-3/DR7 to one thread. Returns 1 verified-armed, 0 failed. */
int apply_context(HANDLE thread, const ExpectedContext& e) noexcept {
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(thread, &ctx) == FALSE) {
        return 0;
    }
    if (context_matches(ctx, e)) {
        return 1;  // already armed - the cheap verify path, no suspend
    }
    // Re-verify once: GetThreadContext on a RUNNING thread may hand back stale values,
    // and a suspend storm over phantom mismatches is the p2-156 deadlock class.
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(thread, &ctx) != FALSE && context_matches(ctx, e)) {
        return 1;
    }
    if (SuspendThread(thread) == static_cast<DWORD>(-1)) {
        return 0;
    }
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    const BOOL got = GetThreadContext(thread, &ctx);
    BOOL set = FALSE;
    if (got == FALSE || !context_matches(ctx, e)) {
        ctx = {};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        ctx.Dr0 = e.dr0;
        ctx.Dr1 = e.dr1;
        ctx.Dr2 = e.dr2;
        ctx.Dr3 = e.dr3;
        ctx.Dr6 = 0;
        ctx.Dr7 = e.dr7;
        set = SetThreadContext(thread, &ctx);
    }
    ResumeThread(thread);
    return (set == TRUE) ? 1 : 0;
}

struct SweepCounters {
    unsigned total{0};
    unsigned covered{0};
    unsigned failed{0};
};

/** One sweep: verify (and only where wrong, correct) every thread's debug registers. */
void sweep_threads(const ExpectedContext& e) noexcept {
    const std::uint32_t pid = GetCurrentProcessId();
    const std::uint32_t self = GetCurrentThreadId();
    SweepCounters counters;
    const HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        return;
    }
    THREADENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    if (Thread32First(snap, &entry)) {
        do {
            if (entry.th32OwnerProcessID != pid) {
                continue;
            }
            ++counters.total;
            if (entry.th32ThreadID == self) {
                // Never suspend ourselves. The self-test thread covers the "fresh
                // thread" case by being armed by a sweep like any other thread.
                continue;
            }
            const HANDLE thread = OpenThread(
                THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME
                    | THREAD_QUERY_INFORMATION,
                FALSE, entry.th32ThreadID);
            if (thread == nullptr) {
                ++counters.failed;
                continue;
            }
            const int ok = apply_context(thread, e);
            CloseHandle(thread);
            if (ok > 0) {
                ++counters.covered;
            } else {
                ++counters.failed;
            }
        } while (Thread32Next(snap, &entry));
    }
    CloseHandle(snap);
    g_lastTotal.store(counters.total, std::memory_order_relaxed);
    g_lastCovered.store(counters.covered, std::memory_order_relaxed);
    g_lastFailed.store(counters.failed, std::memory_order_relaxed);
}

/** The watchdog: drains the ring into the log, keeps DR coverage complete, runs the
 *  self-test, and diffs the watched bytes against the shadow (the safety net for any
 *  thread a sweep could not arm). Everything it emits carries its denominator. */
DWORD WINAPI watchdog_main(LPVOID) noexcept {
    constexpr DWORD kSweepMs = 250;
    constexpr DWORD kCensusMs = 60000;
    constexpr DWORD kSelfTestMs = 30000;
    constexpr unsigned kFloodDisarmPerSweep = 200;
    std::uint64_t lastCensus = GetTickCount64();
    std::uint64_t lastSelfTest = 0;
    std::uint64_t selfTestLaunchedAt = 0;
    bool selfTestPending = false;
    unsigned selfTestSeq = 0;
    std::uint64_t drainedSeq = 0;
    std::uint32_t prevHits[4] = {0, 0, 0, 0};

    for (;;) {
        Sleep(kSweepMs);
        const auto now = GetTickCount64();

        // 1. Drain the capture ring (the ONLY place hits reach the log). Walk claims in
        //    strict seq order; a slot whose seq does not match was overwritten before we
        //    could drain it - the handler already counted that overwrite as dropped.
        //    Bounded to one ring capacity of history: anything older was necessarily
        //    overwritten (and counted) long ago.
        const std::uint64_t claimed = g_ringClaim.load(std::memory_order_relaxed);
        const std::uint64_t from = drainedSeq;
        const std::uint64_t begin =
            (claimed - from > kRingCapacity) ? (claimed - kRingCapacity) : from;
        for (std::uint64_t s = begin + 1; s <= claimed; ++s) {
            Hit& h = g_ring[static_cast<std::size_t>(s % kRingCapacity)];
            if (h.seq != s) {
                continue;  // overwritten pre-drain; the drop was counted at overwrite
            }
            std::array<char, 420> t{};
            int w;
            if (h.slot == 3U) {
                w = std::snprintf(t.data(), t.size(),
                    "ev=mtrace stage=wwatch fn=wwatch result=selftest-hit slot=3 "
                    "tid=%u rip_rva=0x%llX",
                    h.tid, static_cast<unsigned long long>(h.ripRva));
            } else {
                w = std::snprintf(t.data(), t.size(),
                    "ev=mtrace stage=wwatch fn=wwatch result=hit slot=%u "
                    "table=0x%llX i=%u rec8=0x%llX byte=0x%02X->0x%02X tid=%u "
                    "rip_rva=0x%llX dr6=%u instr_ok=%u instr=",
                    h.slot, static_cast<unsigned long long>(h.table), h.recIndex,
                    static_cast<unsigned long long>(h.rec8),
                    h.oldByte & 0xFFU,
                    (h.newByte == 0xFFFFFFFFU) ? 0xFFU : (h.newByte & 0xFFU),
                    h.tid, static_cast<unsigned long long>(h.ripRva), h.dr6,
                    h.instrOk);
                for (std::size_t b = 0; w > 0 && b < sizeof(h.instr); ++b) {
                    w += std::snprintf(t.data() + w,
                                       t.size() - static_cast<std::size_t>(w),
                                       "%02x", h.instr[b]);
                }
            }
            if (w > 0) {
                emit_line(t.data(), static_cast<std::size_t>(w));
            }
        }
        drainedSeq = claimed;
        g_drainedSeq.store(claimed, std::memory_order_relaxed);

        // 2. Flood guard: a watched window written hundreds of times per sweep is either
        //    a hot neighbour byte or a misunderstanding - disarm THAT slot and say so
        //    (the census keeps its hit count; the instrument never silently starves).
        unsigned mask = g_enabledMask.load(std::memory_order_relaxed);
        for (unsigned s = 0; s < 3; ++s) {
            const auto total = g_slots[s].hits.load(std::memory_order_relaxed);
            const auto delta = total - prevHits[s];
            prevHits[s] = total;
            if (delta > kFloodDisarmPerSweep && ((mask >> s) & 1U) != 0U) {
                mask &= ~(1U << s);
                g_enabledMask.store(mask, std::memory_order_relaxed);
                g_version.fetch_add(1U, std::memory_order_relaxed);
                std::array<char, 192> t{};
                const int w = std::snprintf(t.data(), t.size(),
                    "ev=mtrace stage=wwatch fn=wwatch result=disarm slot=%u "
                    "why=flood hits_this_sweep=%u",
                    s, static_cast<unsigned>(delta));
                if (w > 0) {
                    emit_line(t.data(), static_cast<std::size_t>(w));
                }
            }
        }

        // 3. Re-apply DRs EVERY sweep. The fast path is a no-suspend context compare,
        //    so the per-thread cost is one GetThreadContext - and this is what arms
        //    freshly spawned threads (the self-test thread and any real writer thread
        //    created after boot). Sweeping only on re-arm was the p2-158 solo-canary
        //    selftest FAIL: threads born after the first sweep were never watched.
        sweep_threads(expected_context());

        // 4. Shadow diff: a watched byte that moved WITHOUT a captured hit is a thread
        //    coverage gap and must never read as "no writer" (the ABSENCE NEGATIVE).
        for (unsigned slot = 0; slot < 3; ++slot) {
            if (((g_enabledMask.load(std::memory_order_relaxed) >> slot) & 1U) == 0U) {
                continue;
            }
            const auto addr = g_slots[slot].addr.load(std::memory_order_relaxed);
            if (addr == 0) {
                continue;
            }
            std::uint8_t nowByte = 0;
            if (!safe_copy(&nowByte, reinterpret_cast<const void*>(addr), 1)) {
                continue;
            }
            const auto shadow = g_slots[slot].shadow.load(std::memory_order_relaxed);
            if (static_cast<std::uint64_t>(nowByte) != shadow) {
                std::array<char, 256> t{};
                const int w = std::snprintf(t.data(), t.size(),
                    "ev=mtrace stage=wwatch fn=wwatch result=shadow-hit slot=%u "
                    "addr=0x%llX old=0x%02X new=0x%02X why=no-dr-captured",
                    slot, static_cast<unsigned long long>(addr),
                    static_cast<unsigned>(shadow), static_cast<unsigned>(nowByte));
                if (w > 0) {
                    emit_line(t.data(), static_cast<std::size_t>(w));
                }
                g_slots[slot].shadow.store(nowByte, std::memory_order_relaxed);
            }
        }

        // 5. Self-test verdict (DEFECT 3): the control fires by construction, so a FAIL
        //    indicts the instrument, not the world.
        if (selfTestPending) {
            if (g_selfTestSeen.exchange(false, std::memory_order_relaxed)) {
                std::array<char, 128> t{};
                const int w = std::snprintf(t.data(), t.size(),
                    "ev=mtrace stage=wwatch fn=wwatch result=selftest ok seq=%u",
                    selfTestSeq);
                if (w > 0) {
                    emit_line(t.data(), static_cast<std::size_t>(w));
                }
                selfTestPending = false;
            } else if (now - selfTestLaunchedAt > 6000) {
                std::array<char, 160> t{};
                const int w = std::snprintf(t.data(), t.size(),
                    "ev=mtrace stage=wwatch fn=wwatch result=selftest FAIL seq=%u "
                    "why=no-slot3-hit (instrument broke: all wwatch silence is void)",
                    selfTestSeq);
                if (w > 0) {
                    emit_line(t.data(), static_cast<std::size_t>(w));
                }
                selfTestPending = false;
            }
        }
        if (now - lastSelfTest >= kSelfTestMs) {
            lastSelfTest = now;
            selfTestSeq = static_cast<unsigned>(g_selfTestByte) + 1U;
            const HANDLE t = CreateThread(nullptr, 0, &selftest_main, nullptr, 0, nullptr);
            if (t != nullptr) {
                CloseHandle(t);
                selfTestPending = true;
                selfTestLaunchedAt = now;
            }
        }

        // 6. Census with denominators (DEFECT 5).
        if (now - lastCensus >= kCensusMs) {
            lastCensus = now;
            std::array<char, 448> t{};
            const int w = std::snprintf(t.data(), t.size(),
                "ev=mtrace stage=wwatch fn=wwatch result=census threads=%u/%u "
                "unopenable=%u enabled=0x%X hits=%llu/%llu/%llu/%llu "
                "drained=%llu dropped=%llu refused_tables=%u",
                g_lastCovered.load(std::memory_order_relaxed),
                g_lastTotal.load(std::memory_order_relaxed),
                g_lastFailed.load(std::memory_order_relaxed),
                g_enabledMask.load(std::memory_order_relaxed),
                static_cast<unsigned long long>(
                    g_slots[0].hits.load(std::memory_order_relaxed)),
                static_cast<unsigned long long>(
                    g_slots[1].hits.load(std::memory_order_relaxed)),
                static_cast<unsigned long long>(
                    g_slots[2].hits.load(std::memory_order_relaxed)),
                static_cast<unsigned long long>(
                    g_slots[3].hits.load(std::memory_order_relaxed)),
                static_cast<unsigned long long>(g_drainedSeq.load(
                    std::memory_order_relaxed)),
                static_cast<unsigned long long>(g_dropped.load(std::memory_order_relaxed)),
                g_refusedTables.load(std::memory_order_relaxed));
            if (w > 0) {
                emit_line(t.data(), static_cast<std::size_t>(w));
            }
        }
    }
}

} // namespace

bool install() noexcept {
    if (g_installed.exchange(true, std::memory_order_relaxed)) {
        return true;
    }
    // The self-test slot is armed FIRST: it is the pipeline's liveness proof.
    g_slots[3].addr.store(reinterpret_cast<std::uintptr_t>(&g_selfTestByte),
                          std::memory_order_relaxed);
    g_slots[3].len.store(1, std::memory_order_relaxed);
    g_enabledMask.store(0x8U, std::memory_order_relaxed);  // slot 3 only, for now
    g_version.fetch_add(1U, std::memory_order_relaxed);

    const HANDLE module = GetModuleHandleW(nullptr);
    if (module != nullptr) {
        g_base = reinterpret_cast<std::uintptr_t>(module);
    }
    if (AddVectoredExceptionHandler(1U, &vec_handler) == nullptr) {
        std::array<char, 128> t{};
        const int w = std::snprintf(t.data(), t.size(),
            "ev=mtrace stage=wwatch fn=wwatch result=install FAIL why=vec");
        if (w > 0) {
            emit_line(t.data(), static_cast<std::size_t>(w));
        }
        g_installed.store(false, std::memory_order_relaxed);
        return false;
    }
    const HANDLE thread = CreateThread(nullptr, 0, &watchdog_main, nullptr, 0, nullptr);
    const bool ok = (thread != nullptr);
    if (ok) {
        CloseHandle(thread);
    }
    std::array<char, 160> t{};
    const int w = std::snprintf(t.data(), t.size(),
        "ev=mtrace stage=wwatch fn=wwatch result=install %s vec=1 watchdog=%d",
        ok ? "ok" : "FAIL", ok ? 1 : 0);
    if (w > 0) {
        emit_line(t.data(), static_cast<std::size_t>(w));
    }
    return ok;
}

void arm_table(std::uintptr_t table, int selfIdx, int peerIdx) noexcept {
    if (!g_installed.load(std::memory_order_relaxed) || table == 0) {
        return;
    }
    // Fast path when this table already owns a slot and nothing moved.
    const std::uint64_t tableKey = static_cast<std::uint64_t>(table);
    const std::uint64_t bits = g_tableBits.load(std::memory_order_relaxed);

    int slot = -1;
    for (unsigned s = 0; s < 2; ++s) {
        if (((bits >> s) & 1U) != 0U
            && g_slots[s].table.load(std::memory_order_relaxed) == tableKey) {
            slot = static_cast<int>(s);
            break;
        }
    }
    if (slot < 0) {
        unsigned freeSlot = 99U;
        for (unsigned s = 0; s < 2; ++s) {
            if (((bits >> s) & 1U) == 0U) {
                freeSlot = s;
                break;
            }
        }
        if (freeSlot > 1U) {
            // A THIRD table: DR registers are exhausted. Say so once - the watch then
            // covers the two tables it has, and the census carries the refusal count.
            if (g_refusedTables.fetch_add(1U, std::memory_order_relaxed) == 0U) {
                std::array<char, 192> t{};
                const int w = std::snprintf(t.data(), t.size(),
                    "ev=mtrace stage=wwatch fn=wwatch result=refused "
                    "why=too-many-tables table=0x%llX (two DR table slots exist)",
                    static_cast<unsigned long long>(table));
                if (w > 0) {
                    emit_line(t.data(), static_cast<std::size_t>(w));
                }
            }
            return;
        }
        slot = static_cast<int>(freeSlot);
        g_slots[freeSlot].table.store(tableKey, std::memory_order_relaxed);
        g_tableBits.fetch_or((1ULL << freeSlot), std::memory_order_relaxed);
    }

    bool changed = false;
    const unsigned peerSlot = static_cast<unsigned>(slot);
    if (peerIdx >= 0) {
        // A 4-byte window when alignment allows: a wider write touching +0x38 still
        // fires. Degrade to 1 byte when it does not (recorded in the arm line).
        const auto addr = table + static_cast<std::uint64_t>(peerIdx) * kRecStride
                              + kRecGateByte;
        const std::uint32_t len = ((addr & 3ULL) == 0ULL) ? 4U : 1U;
        if (g_slots[peerSlot].addr.load(std::memory_order_relaxed) != addr
            || g_slots[peerSlot].len.load(std::memory_order_relaxed) != len) {
            std::uint8_t now = 0;
            (void)safe_copy(&now, reinterpret_cast<const void*>(addr), 1);
            g_slots[peerSlot].shadow.store(now, std::memory_order_relaxed);
            g_slots[peerSlot].addr.store(addr, std::memory_order_relaxed);
            g_slots[peerSlot].len.store(len, std::memory_order_relaxed);
            g_slots[peerSlot].recIndex.store(static_cast<std::uint32_t>(peerIdx),
                                             std::memory_order_relaxed);
            changed = true;
            std::array<char, 224> t{};
            const int w = std::snprintf(t.data(), t.size(),
                "ev=mtrace stage=wwatch fn=wwatch result=arm slot=%u table=0x%llX "
                "i=%d role=peer addr=0x%llX len=%u shadow=0x%02X",
                peerSlot, static_cast<unsigned long long>(table), peerIdx,
                static_cast<unsigned long long>(addr), len,
                static_cast<unsigned>(now));
            if (w > 0) {
                emit_line(t.data(), static_cast<std::size_t>(w));
            }
        }
    }
    if (slot == 0 && selfIdx >= 0) {
        const auto addr = table + static_cast<std::uint64_t>(selfIdx) * kRecStride
                              + kRecGateByte;
        const std::uint32_t len = ((addr & 3ULL) == 0ULL) ? 4U : 1U;
        if (g_slots[2].addr.load(std::memory_order_relaxed) != addr
            || g_slots[2].len.load(std::memory_order_relaxed) != len) {
            std::uint8_t now = 0;
            (void)safe_copy(&now, reinterpret_cast<const void*>(addr), 1);
            g_slots[2].shadow.store(now, std::memory_order_relaxed);
            g_slots[2].addr.store(addr, std::memory_order_relaxed);
            g_slots[2].len.store(len, std::memory_order_relaxed);
            g_slots[2].recIndex.store(static_cast<std::uint32_t>(selfIdx),
                                      std::memory_order_relaxed);
            changed = true;
            std::array<char, 224> t{};
            const int w = std::snprintf(t.data(), t.size(),
                "ev=mtrace stage=wwatch fn=wwatch result=arm slot=2 table=0x%llX "
                "i=%d role=self addr=0x%llX len=%u shadow=0x%02X",
                static_cast<unsigned long long>(table), selfIdx,
                static_cast<unsigned long long>(addr), len,
                static_cast<unsigned>(now));
            if (w > 0) {
                emit_line(t.data(), static_cast<std::size_t>(w));
            }
        }
    }
    if (changed) {
        unsigned mask = 0x8U;  // the self-test slot is always on
        for (unsigned s = 0; s < 3; ++s) {
            if (g_slots[s].addr.load(std::memory_order_relaxed) != 0) {
                mask |= (1U << s);
            }
        }
        g_enabledMask.store(mask, std::memory_order_relaxed);
        g_version.fetch_add(1U, std::memory_order_relaxed);
    }
}

} // namespace sunrise::client::hooks::gate_wwatch
