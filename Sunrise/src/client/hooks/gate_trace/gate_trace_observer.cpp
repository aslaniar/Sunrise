/**
 * Log-only observers on the round-2 gate-trace surface (see the header). Each detour
 * runs the original untouched, then logs the raw registers + the caller RVA. The caller
 * address is the prize: it names the un-analyzed CUI-region functions that drive the
 * character-bank gates and the rollback apply.
 */

#include "gate_trace_observer.h"

#include <Windows.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>

#include "../../../core/logging/log.h"
#include "../../diagnostics/module_range.h"
#include "../../hooking/detour.h"

namespace sunrise::client::hooks::gate_trace {
namespace {

/** Image RVA of FUN_140E06090, the character-object acquiredFlags byte test. */
constexpr std::uintptr_t kCharTestRva = 0xE06090;
/** Image RVA of FUN_140E078F0, the family-4 kind-0 diff-apply (the rollback executor). */
constexpr std::uintptr_t kRollbackRva = 0xE078F0;
/** Image RVA of FUN_140FA8FD0, the acquire-flag writer. */
constexpr std::uintptr_t kAcquireRva = 0xFA8FD0;
/** Image RVA of FUN_140BA3E70, the per-item marker-bit poll. */
constexpr std::uintptr_t kPollRva = 0xBA3E70;
/** Image RVA of FUN_1405084C0, the character-level requirement session (the evaluator's
 *  cold caller — the session entry names WHEN a requirement evaluation runs). */
constexpr std::uintptr_t kSessionRva = 0x5084C0;
/** Image RVA of FUN_140548D80, the session wrapper (the evaluator's other caller). */
constexpr std::uintptr_t kSessionWrapRva = 0x548D80;
/** Image RVA of FUN_140C8F1C0, the shared per-index marker-bit poll primitive — every
 *  informative bit read funnels through it, the index in RDX (a register read, no deref). */
constexpr std::uintptr_t kBitPrimRva = 0xC8F1C0;
/** Image RVA of FUN_14050F4C0, the item-service vtable+0x6F8 hash->index resolver — THE
 *  correspondence instrument: every requirement expression resolves through it. */
constexpr std::uintptr_t kResolveRva = 0x50F4C0;
/** Image RVA of FUN_140548E00, the requirement-expression evaluator (7 args, the last 3
 *  on the stack; the completion marker sits at outEval+0x14dfc). */
constexpr std::uintptr_t kExprEvalRva = 0x548E00;
/** Image RVA of FUN_140A42FD0, the stamp-table flag consume (no register args). */
constexpr std::uintptr_t kStampConsumeRva = 0xA42FD0;
/** Image RVA of FUN_140E82AB0, the stamp-chain consume gate (the record key in RDX). */
constexpr std::uintptr_t kStampGateRva = 0xE82AB0;
/** Image RVA of FUN_140E80FC0, the 5-byte UI-refresh thunk (the record key in RDX, the
 *  0x100-B out buffer in R8 — both logged raw, never dereferenced). */
constexpr std::uintptr_t kUiRefreshRva = 0xE80FC0;
/** One log line's capacity. */
constexpr std::size_t kLineCapacity = 256;

/** Decompile-verified ABI: `bool FUN_140e06090(undefined8 param_1, int param_2)`. */
using CharTest = bool(__fastcall*)(void*, std::uintptr_t) noexcept;
/** Decompile-verified ABI: `void FUN_140e078f0(longlong desired, longlong store)`. */
using RollbackApply = void(__fastcall*)(void*, void*) noexcept;
/** Decompile-verified ABI: `void FUN_140fa8fd0(char* record, short itemIndex, uint32 value)`. */
using AcquireCheck = void(__fastcall*)(void*, std::uintptr_t, std::uint32_t) noexcept;
/** Decompile-verified ABI: `ulonglong FUN_140ba3e70(int* itemHashRecord)`. */
using PollGate = std::uint64_t(__fastcall*)(void*) noexcept;
/** Decompile-verified ABI: `void FUN_1405084c0(longlong* a, undefined8 b, undefined1* c)`. */
using RequirementSession = void(__fastcall*)(void*, void*, void*) noexcept;
/** Decompile-verified ABI: `void FUN_140548d80(undefined8 a, undefined8 b)`. */
using SessionWrap = void(__fastcall*)(void*, void*) noexcept;
/** Decompile-verified ABI: `ulonglong FUN_140c8f1c0(undefined8* ctx, u16 index)`. */
using BitPrim = std::uint64_t(__fastcall*)(void*, std::uintptr_t) noexcept;
/** Decompile-verified ABI: `uint16_t* FUN_14050f4c0(void* this, uint16_t* idxOut,
 *  const uint32_t* hashIn)` — the resolver walks the runtime registry and writes the
 *  found index into idxOut (0xFFFF pre-filled = miss). Returns idxOut. */
using Resolve = std::uint16_t*(__fastcall*)(void*, std::uint16_t*, const std::uint32_t*) noexcept;
/** Decompile-verified ABI: `void FUN_140548e00(rcx, rdx, r8, r9, outEval, version,
 *  outD)` — 7 args, the last three on the stack (the x64 fastcall ABI; the observer
 *  mirrors the signature exactly). The compiler's own copy loop writes the completion
 *  marker byte 1 at outEval+0x14dfc. */
using ExprEval = void(__fastcall*)(void*, void*, void*, void*, void*, void*, void*) noexcept;
/** Decompile-verified ABI: `uint8_t FUN_140a42fd0(void)` — returns AL = 1 when a slot
 *  was consumed from the stamp table. */
using StampConsume = std::uint8_t(__fastcall*)() noexcept;
/** Decompile-verified ABI: `bool FUN_140e82ab0(void* rcx, void* rdx)` — the consume gate;
 *  RDX = the record key pointer (logged raw). */
using StampGate = bool(__fastcall*)(void*, void*) noexcept;
/** Decompile-verified ABI: `void FUN_140e80fc0(void* rcx, void* rdx, void* r8)` — the
 *  UI-refresh thunk; RDX = the record key, R8 = the out buffer (raw, no post-read). */
using UiRefresh = void(__fastcall*)(void*, void*, void*) noexcept;

hooking::detour::Handle g_charHandle{};
hooking::detour::Handle g_rollbackHandle{};
hooking::detour::Handle g_acquireHandle{};
hooking::detour::Handle g_pollHandle{};
hooking::detour::Handle g_sessionHandle{};
hooking::detour::Handle g_sessionWrapHandle{};
hooking::detour::Handle g_bitPrimHandle{};
hooking::detour::Handle g_resolveHandle{};
hooking::detour::Handle g_exprEvalHandle{};
hooking::detour::Handle g_stampConsumeHandle{};
hooking::detour::Handle g_stampGateHandle{};
hooking::detour::Handle g_uiRefreshHandle{};
std::atomic<CharTest> g_originalChar{nullptr};
std::atomic<RollbackApply> g_originalRollback{nullptr};
std::atomic<AcquireCheck> g_originalAcquire{nullptr};
std::atomic<PollGate> g_originalPoll{nullptr};
std::atomic<RequirementSession> g_originalSession{nullptr};
std::atomic<SessionWrap> g_originalSessionWrap{nullptr};
std::atomic<BitPrim> g_originalBitPrim{nullptr};
std::atomic<Resolve> g_originalResolve{nullptr};
std::atomic<ExprEval> g_originalExprEval{nullptr};
std::atomic<StampConsume> g_originalStampConsume{nullptr};
std::atomic<StampGate> g_originalStampGate{nullptr};
std::atomic<UiRefresh> g_originalUiRefresh{nullptr};

/** @return The module base, for the caller-RVA line. */
std::uintptr_t module_base() noexcept {
    return reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
}

/** @return The return address one frame above the detoured call. */
void* caller_address() noexcept {
    return _ReturnAddress();
}

/** Runs the original character-bank test, then logs the raw registers + the caller. */
__declspec(noinline) bool __fastcall char_observer(void* rcx, std::uintptr_t rdx) noexcept {
    const CharTest original = g_originalChar.load(std::memory_order_acquire);
    const bool result = original != nullptr ? original(rcx, rdx) : false;
    const std::uintptr_t caller = reinterpret_cast<std::uintptr_t>(caller_address());
    const std::uintptr_t base = module_base();
    const std::uintptr_t callerRva = caller >= base ? caller - base : 0;
    std::array<char, kLineCapacity> line{};
    const int written = std::snprintf(
        line.data(),
        line.size(),
        "ev=gate_trace stage=char_test rcx=0x%llX rdx=0x%llX result=%u caller=+0x%llX",
        static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(rcx)),
        static_cast<unsigned long long>(rdx),
        static_cast<unsigned>(result),
        static_cast<unsigned long long>(callerRva));
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(written)});
    }
    return result;
}

/** Runs the original diff-apply, then logs the raw record pointers + the caller. */
__declspec(noinline) void __fastcall rollback_observer(void* rcx, void* rdx) noexcept {
    const RollbackApply original = g_originalRollback.load(std::memory_order_acquire);
    if (original != nullptr) {
        original(rcx, rdx);
    }
    const std::uintptr_t caller = reinterpret_cast<std::uintptr_t>(caller_address());
    const std::uintptr_t base = module_base();
    const std::uintptr_t callerRva = caller >= base ? caller - base : 0;
    std::array<char, kLineCapacity> line{};
    const int written = std::snprintf(
        line.data(),
        line.size(),
        "ev=gate_trace stage=rollback_apply rcx=0x%llX rdx=0x%llX caller=+0x%llX",
        static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(rcx)),
        static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(rdx)),
        static_cast<unsigned long long>(callerRva));
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(written)});
    }
}

/** Runs the original acquire-flag write, then logs the item index (RDX lo16), the value,
 *  the raw record pointer, and the caller. The lo16 read is decompile-verified (`short
 *  param_2`); the record pointer is logged raw, never dereferenced. */
__declspec(noinline) void __fastcall acquire_observer(void* rcx, std::uintptr_t rdx,
                                                      std::uint32_t r8) noexcept {
    const AcquireCheck original = g_originalAcquire.load(std::memory_order_acquire);
    if (original != nullptr) {
        original(rcx, rdx, r8);
    }
    const std::uintptr_t caller = reinterpret_cast<std::uintptr_t>(caller_address());
    const std::uintptr_t base = module_base();
    const std::uintptr_t callerRva = caller >= base ? caller - base : 0;
    std::array<char, kLineCapacity> line{};
    const int written = std::snprintf(
        line.data(),
        line.size(),
        "ev=gate_trace stage=acquire_check rcx=0x%llX item=0x%llX value=0x%08X caller=+0x%llX",
        static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(rcx)),
        static_cast<unsigned long long>(rdx & 0xFFFFULL),
        static_cast<unsigned>(r8),
        static_cast<unsigned long long>(callerRva));
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(written)});
    }
}

/** Runs the original marker-bit poll, then logs the raw record pointer + the result +
 *  the caller. NO dereference: the pass-2 lesson holds — the runtime shapes are never
 *  safe to assume; the hash is recoverable from the dump side when a pointer repeats. */
__declspec(noinline) std::uint64_t __fastcall poll_observer(void* rcx) noexcept {
    const PollGate original = g_originalPoll.load(std::memory_order_acquire);
    const std::uint64_t result = original != nullptr ? original(rcx) : 0;
    const std::uintptr_t caller = reinterpret_cast<std::uintptr_t>(caller_address());
    const std::uintptr_t base = module_base();
    const std::uintptr_t callerRva = caller >= base ? caller - base : 0;
    std::array<char, kLineCapacity> line{};
    const int written = std::snprintf(line.data(),
                                      line.size(),
                                      "ev=gate_trace stage=item_poll rcx=0x%llX result=0x%llX "
                                      "caller=+0x%llX",
                                      static_cast<unsigned long long>(
                                          reinterpret_cast<std::uintptr_t>(rcx)),
                                      static_cast<unsigned long long>(result),
                                      static_cast<unsigned long long>(callerRva));
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(written)});
    }
    return result;
}

/** Runs the original requirement session, then logs the raw register args + the caller
 *  (the session's caller names the UI context that triggered the evaluation). */
__declspec(noinline) void __fastcall session_observer(void* rcx, void* rdx,
                                                      void* r8) noexcept {
    const RequirementSession original = g_originalSession.load(std::memory_order_acquire);
    if (original != nullptr) {
        original(rcx, rdx, r8);
    }
    const std::uintptr_t caller = reinterpret_cast<std::uintptr_t>(caller_address());
    const std::uintptr_t base = module_base();
    const std::uintptr_t callerRva = caller >= base ? caller - base : 0;
    std::array<char, kLineCapacity> line{};
    const int written = std::snprintf(line.data(),
                                      line.size(),
                                      "ev=gate_trace stage=requirement_session rcx=0x%llX "
                                      "rdx=0x%llX r8=0x%llX caller=+0x%llX",
                                      static_cast<unsigned long long>(
                                          reinterpret_cast<std::uintptr_t>(rcx)),
                                      static_cast<unsigned long long>(
                                          reinterpret_cast<std::uintptr_t>(rdx)),
                                      static_cast<unsigned long long>(
                                          reinterpret_cast<std::uintptr_t>(r8)),
                                      static_cast<unsigned long long>(callerRva));
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(written)});
    }
}

/** Runs the original session wrapper, then logs the raw args + the caller. */
__declspec(noinline) void __fastcall session_wrap_observer(void* rcx, void* rdx) noexcept {
    const SessionWrap original = g_originalSessionWrap.load(std::memory_order_acquire);
    if (original != nullptr) {
        original(rcx, rdx);
    }
    const std::uintptr_t caller = reinterpret_cast<std::uintptr_t>(caller_address());
    const std::uintptr_t base = module_base();
    const std::uintptr_t callerRva = caller >= base ? caller - base : 0;
    std::array<char, kLineCapacity> line{};
    const int written = std::snprintf(line.data(),
                                      line.size(),
                                      "ev=gate_trace stage=session_wrap rcx=0x%llX "
                                      "rdx=0x%llX caller=+0x%llX",
                                      static_cast<unsigned long long>(
                                          reinterpret_cast<std::uintptr_t>(rcx)),
                                      static_cast<unsigned long long>(
                                          reinterpret_cast<std::uintptr_t>(rdx)),
                                      static_cast<unsigned long long>(callerRva));
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(written)});
    }
}

/** Runs the original bit-poll primitive, then logs the raw ctx + the INDEX (RDX, a
 *  register read — no deref) + the result bit + the caller. THIS = the census's
 *  per-index marker-poll surface (the hook spec's MARKER_POLL: every informative
 *  marker-bit read funnels through here; one detour covers both pollers). */
__declspec(noinline) std::uint64_t __fastcall bit_prim_observer(void* rcx,
                                                                std::uintptr_t rdx) noexcept {
    const BitPrim original = g_originalBitPrim.load(std::memory_order_acquire);
    const std::uint64_t result = original != nullptr ? original(rcx, rdx) : 0;
    const std::uintptr_t caller = reinterpret_cast<std::uintptr_t>(caller_address());
    const std::uintptr_t base = module_base();
    const std::uintptr_t callerRva = caller >= base ? caller - base : 0;
    std::array<char, kLineCapacity> line{};
    const int written = std::snprintf(line.data(),
                                      line.size(),
                                      "ev=gate_trace stage=marker_poll idx=0x%04X result=%u "
                                      "caller=+0x%llX",
                                      static_cast<unsigned>(rdx & 0xFFFFULL),
                                      static_cast<unsigned>(result & 0xFFULL),
                                      static_cast<unsigned long long>(callerRva));
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(written)});
    }
    return result;
}

/** Runs the original hash->index resolver, then logs the resolved hash (R8, the input
 *  pointer — read before the call, null-guarded), the index the walk wrote (RDX, read
 *  after, 0xFFFF = miss), and the caller. THE CORRESPONDENCE INSTRUMENT: every
 *  requirement-expression resolution surfaces as a hash->index pair here. */
__declspec(noinline) std::uint16_t* __fastcall resolve_observer(void* rcx,
                                                                std::uint16_t* rdx,
                                                                const std::uint32_t* r8) noexcept {
    const std::uint32_t hash = r8 != nullptr ? *r8 : 0;
    const Resolve original = g_originalResolve.load(std::memory_order_acquire);
    std::uint16_t* result = original != nullptr ? original(rcx, rdx, r8) : rdx;
    const std::uint16_t idx = rdx != nullptr ? *rdx : 0xFFFF;
    const std::uintptr_t caller = reinterpret_cast<std::uintptr_t>(caller_address());
    const std::uintptr_t base = module_base();
    const std::uintptr_t callerRva = caller >= base ? caller - base : 0;
    std::array<char, kLineCapacity> line{};
    const int written = std::snprintf(
        line.data(),
        line.size(),
        "ev=gate_trace stage=resolve hash=0x%08X idx=0x%04X caller=+0x%llX",
        static_cast<unsigned>(hash),
        static_cast<unsigned>(idx),
        static_cast<unsigned long long>(callerRva));
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(written)});
    }
    return result;
}

/** Runs the original requirement-expression evaluator (7 args, the signature mirrors
 *  the ABI exactly so the stack args pass through), then logs the raw register args,
 *  the completion marker (outEval+0x14dfc == 1, decompile-verified), and the caller —
 *  which requirement expressions the session actually evaluates. */
__declspec(noinline) void __fastcall expr_eval_observer(void* rcx,
                                                        void* rdx,
                                                        void* r8,
                                                        void* r9,
                                                        void* outEval,
                                                        void* version,
                                                        void* outD) noexcept {
    const ExprEval original = g_originalExprEval.load(std::memory_order_acquire);
    if (original != nullptr) {
        original(rcx, rdx, r8, r9, outEval, version, outD);
    }
    const bool done = outEval != nullptr
                      && *reinterpret_cast<const std::uint8_t*>(
                             reinterpret_cast<const std::uintptr_t>(outEval) + 0x14DFC)
                             == 1;
    const std::uintptr_t caller = reinterpret_cast<std::uintptr_t>(caller_address());
    const std::uintptr_t base = module_base();
    const std::uintptr_t callerRva = caller >= base ? caller - base : 0;
    std::array<char, kLineCapacity> line{};
    const int written = std::snprintf(
        line.data(),
        line.size(),
        "ev=gate_trace stage=expr_eval rcx=0x%llX rdx=0x%llX r8=0x%llX r9=0x%llX "
        "done=%u caller=+0x%llX",
        static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(rcx)),
        static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(rdx)),
        static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(r8)),
        static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(r9)),
        static_cast<unsigned>(done ? 1 : 0),
        static_cast<unsigned long long>(callerRva));
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(written)});
    }
}

/** Runs the original stamp-table consume, then logs the consumed flag + the caller —
 *  which side of the stamp chain actually fires in the tour. */
__declspec(noinline) std::uint8_t __fastcall stamp_consume_observer() noexcept {
    const StampConsume original = g_originalStampConsume.load(std::memory_order_acquire);
    const std::uint8_t result = original != nullptr ? original() : 0;
    const std::uintptr_t caller = reinterpret_cast<std::uintptr_t>(caller_address());
    const std::uintptr_t base = module_base();
    const std::uintptr_t callerRva = caller >= base ? caller - base : 0;
    std::array<char, kLineCapacity> line{};
    const int written = std::snprintf(
        line.data(),
        line.size(),
        "ev=gate_trace stage=stamp_consume result=%u caller=+0x%llX",
        static_cast<unsigned>(result),
        static_cast<unsigned long long>(callerRva));
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(written)});
    }
    return result;
}

/** Runs the original consume gate, then logs the record key (RDX, RAW — a pointer,
 *  never dereferenced, never labeled as an index), the gated flag, and the caller. */
__declspec(noinline) bool __fastcall stamp_gate_observer(void* rcx, void* rdx) noexcept {
    const StampGate original = g_originalStampGate.load(std::memory_order_acquire);
    const bool result = original != nullptr ? original(rcx, rdx) : false;
    const std::uintptr_t caller = reinterpret_cast<std::uintptr_t>(caller_address());
    const std::uintptr_t base = module_base();
    const std::uintptr_t callerRva = caller >= base ? caller - base : 0;
    std::array<char, kLineCapacity> line{};
    const int written = std::snprintf(
        line.data(),
        line.size(),
        "ev=gate_trace stage=stamp_gate rdx=0x%llX result=%u caller=+0x%llX",
        static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(rdx)),
        static_cast<unsigned>(result ? 1 : 0),
        static_cast<unsigned long long>(callerRva));
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(written)});
    }
    return result;
}

/** Runs the original UI-refresh thunk, then logs the raw register args + the caller.
 *  NO post-read (the out-buffer semantics are complex; the raw regs + the caller +
 *  the stamp_gate/stamp_consume context provide the census signal). */
__declspec(noinline) void __fastcall ui_refresh_observer(void* rcx, void* rdx,
                                                         void* r8) noexcept {
    const UiRefresh original = g_originalUiRefresh.load(std::memory_order_acquire);
    if (original != nullptr) {
        original(rcx, rdx, r8);
    }
    const std::uintptr_t caller = reinterpret_cast<std::uintptr_t>(caller_address());
    const std::uintptr_t base = module_base();
    const std::uintptr_t callerRva = caller >= base ? caller - base : 0;
    std::array<char, kLineCapacity> line{};
    const int written = std::snprintf(
        line.data(),
        line.size(),
        "ev=gate_trace stage=ui_refresh rcx=0x%llX rdx=0x%llX r8=0x%llX caller=+0x%llX",
        static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(rcx)),
        static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(rdx)),
        static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(r8)),
        static_cast<unsigned long long>(callerRva));
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(written)});
    }
}

/** @param reason Key naming the step that failed. @return False, for a direct return. */
[[nodiscard]] bool fail_install(const char* reason) noexcept {
    std::array<char, 96> line{};
    const int written = std::snprintf(line.data(),
                                      line.size(),
                                      "ev=gate_trace stage=install result=fail reason=%s",
                                      reason);
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::warn,
                         {line.data(), static_cast<std::size_t>(written)});
    }
    return false;
}

} // namespace

/** Attaches the twelve observers in either server mode. */
bool install() noexcept {
    if (g_charHandle.attached && g_rollbackHandle.attached && g_acquireHandle.attached
        && g_pollHandle.attached && g_sessionHandle.attached
        && g_sessionWrapHandle.attached && g_bitPrimHandle.attached
        && g_resolveHandle.attached && g_exprEvalHandle.attached
        && g_stampConsumeHandle.attached && g_stampGateHandle.attached
        && g_uiRefreshHandle.attached) {
        return true;
    }
    std::byte* const base = reinterpret_cast<std::byte*>(GetModuleHandleW(nullptr));
    if (base == nullptr) {
        return fail_install("base");
    }
    const std::uintptr_t baseValue = reinterpret_cast<std::uintptr_t>(base);
    diagnostics::ModuleRange range{};
    if (!diagnostics::module_range(reinterpret_cast<HMODULE>(base), range)
        || !diagnostics::contains(range, baseValue + kCharTestRva)
        || !diagnostics::contains(range, baseValue + kRollbackRva)
        || !diagnostics::contains(range, baseValue + kAcquireRva)
        || !diagnostics::contains(range, baseValue + kPollRva)
        || !diagnostics::contains(range, baseValue + kSessionRva)
        || !diagnostics::contains(range, baseValue + kSessionWrapRva)
        || !diagnostics::contains(range, baseValue + kBitPrimRva)
        || !diagnostics::contains(range, baseValue + kResolveRva)
        || !diagnostics::contains(range, baseValue + kExprEvalRva)
        || !diagnostics::contains(range, baseValue + kStampConsumeRva)
        || !diagnostics::contains(range, baseValue + kStampGateRva)
        || !diagnostics::contains(range, baseValue + kUiRefreshRva)) {
        return fail_install("target");
    }
    const hooking::detour::Spec charSpec{base + kCharTestRva,
                                         reinterpret_cast<void*>(&char_observer)};
    const hooking::detour::Spec rollbackSpec{base + kRollbackRva,
                                             reinterpret_cast<void*>(&rollback_observer)};
    const hooking::detour::Spec acquireSpec{base + kAcquireRva,
                                            reinterpret_cast<void*>(&acquire_observer)};
    const hooking::detour::Spec pollSpec{base + kPollRva,
                                         reinterpret_cast<void*>(&poll_observer)};
    const hooking::detour::Spec sessionSpec{base + kSessionRva,
                                            reinterpret_cast<void*>(&session_observer)};
    const hooking::detour::Spec sessionWrapSpec{base + kSessionWrapRva,
                                                reinterpret_cast<void*>(
                                                    &session_wrap_observer)};
    const hooking::detour::Spec bitPrimSpec{base + kBitPrimRva,
                                            reinterpret_cast<void*>(&bit_prim_observer)};
    const hooking::detour::Spec resolveSpec{base + kResolveRva,
                                            reinterpret_cast<void*>(&resolve_observer)};
    const hooking::detour::Spec exprEvalSpec{base + kExprEvalRva,
                                             reinterpret_cast<void*>(&expr_eval_observer)};
    const hooking::detour::Spec stampConsumeSpec{
        base + kStampConsumeRva, reinterpret_cast<void*>(&stamp_consume_observer)};
    const hooking::detour::Spec stampGateSpec{base + kStampGateRva,
                                              reinterpret_cast<void*>(&stamp_gate_observer)};
    const hooking::detour::Spec uiRefreshSpec{base + kUiRefreshRva,
                                              reinterpret_cast<void*>(&ui_refresh_observer)};
    const std::array<hooking::detour::Spec, 12> specs{
        charSpec,   rollbackSpec, acquireSpec,     pollSpec,
        sessionSpec, sessionWrapSpec, bitPrimSpec, resolveSpec,
        exprEvalSpec, stampConsumeSpec, stampGateSpec, uiRefreshSpec};
    std::array<hooking::detour::Handle, 12> handles{};
    if (!hooking::detour::install(specs, handles)) {
        return fail_install("attach");
    }
    g_charHandle = handles[0];
    g_rollbackHandle = handles[1];
    g_acquireHandle = handles[2];
    g_pollHandle = handles[3];
    g_sessionHandle = handles[4];
    g_sessionWrapHandle = handles[5];
    g_bitPrimHandle = handles[6];
    g_resolveHandle = handles[7];
    g_exprEvalHandle = handles[8];
    g_stampConsumeHandle = handles[9];
    g_stampGateHandle = handles[10];
    g_uiRefreshHandle = handles[11];
    g_originalChar.store(reinterpret_cast<CharTest>(g_charHandle.original),
                         std::memory_order_release);
    g_originalRollback.store(reinterpret_cast<RollbackApply>(g_rollbackHandle.original),
                             std::memory_order_release);
    g_originalAcquire.store(reinterpret_cast<AcquireCheck>(g_acquireHandle.original),
                            std::memory_order_release);
    g_originalPoll.store(reinterpret_cast<PollGate>(g_pollHandle.original),
                         std::memory_order_release);
    g_originalSession.store(reinterpret_cast<RequirementSession>(g_sessionHandle.original),
                            std::memory_order_release);
    g_originalSessionWrap.store(reinterpret_cast<SessionWrap>(g_sessionWrapHandle.original),
                                std::memory_order_release);
    g_originalBitPrim.store(reinterpret_cast<BitPrim>(g_bitPrimHandle.original),
                            std::memory_order_release);
    g_originalResolve.store(reinterpret_cast<Resolve>(g_resolveHandle.original),
                            std::memory_order_release);
    g_originalExprEval.store(reinterpret_cast<ExprEval>(g_exprEvalHandle.original),
                             std::memory_order_release);
    g_originalStampConsume.store(
        reinterpret_cast<StampConsume>(g_stampConsumeHandle.original),
        std::memory_order_release);
    g_originalStampGate.store(reinterpret_cast<StampGate>(g_stampGateHandle.original),
                              std::memory_order_release);
    g_originalUiRefresh.store(reinterpret_cast<UiRefresh>(g_uiRefreshHandle.original),
                              std::memory_order_release);
    std::array<char, kLineCapacity> line{};
    const int written = std::snprintf(
        line.data(), line.size(), "ev=gate_trace stage=install result=ok count=%u",
        static_cast<unsigned>(specs.size()));
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(written)});
    }
    return true;
}

/** Detaches all twelve observers and drops their trampolines. */
bool uninstall() noexcept {
    (void)hooking::detour::uninstall(g_charHandle);
    (void)hooking::detour::uninstall(g_rollbackHandle);
    (void)hooking::detour::uninstall(g_acquireHandle);
    (void)hooking::detour::uninstall(g_pollHandle);
    (void)hooking::detour::uninstall(g_sessionHandle);
    (void)hooking::detour::uninstall(g_sessionWrapHandle);
    (void)hooking::detour::uninstall(g_bitPrimHandle);
    (void)hooking::detour::uninstall(g_resolveHandle);
    (void)hooking::detour::uninstall(g_exprEvalHandle);
    (void)hooking::detour::uninstall(g_stampConsumeHandle);
    (void)hooking::detour::uninstall(g_stampGateHandle);
    (void)hooking::detour::uninstall(g_uiRefreshHandle);
    g_charHandle = {};
    g_rollbackHandle = {};
    g_acquireHandle = {};
    g_pollHandle = {};
    g_sessionHandle = {};
    g_sessionWrapHandle = {};
    g_bitPrimHandle = {};
    g_resolveHandle = {};
    g_exprEvalHandle = {};
    g_stampConsumeHandle = {};
    g_stampGateHandle = {};
    g_uiRefreshHandle = {};
    g_originalChar.store(nullptr, std::memory_order_release);
    g_originalRollback.store(nullptr, std::memory_order_release);
    g_originalAcquire.store(nullptr, std::memory_order_release);
    g_originalPoll.store(nullptr, std::memory_order_release);
    g_originalSession.store(nullptr, std::memory_order_release);
    g_originalSessionWrap.store(nullptr, std::memory_order_release);
    g_originalBitPrim.store(nullptr, std::memory_order_release);
    g_originalResolve.store(nullptr, std::memory_order_release);
    g_originalExprEval.store(nullptr, std::memory_order_release);
    g_originalStampConsume.store(nullptr, std::memory_order_release);
    g_originalStampGate.store(nullptr, std::memory_order_release);
    g_originalUiRefresh.store(nullptr, std::memory_order_release);
    return true;
}

/** @return True while any observer is attached. */
bool is_installed() noexcept {
    return g_charHandle.attached || g_rollbackHandle.attached || g_acquireHandle.attached
           || g_pollHandle.attached || g_sessionHandle.attached
           || g_sessionWrapHandle.attached || g_bitPrimHandle.attached
           || g_resolveHandle.attached || g_exprEvalHandle.attached
           || g_stampConsumeHandle.attached || g_stampGateHandle.attached
           || g_uiRefreshHandle.attached;
}

} // namespace sunrise::client::hooks::gate_trace
