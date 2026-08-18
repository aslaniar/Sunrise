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

hooking::detour::Handle g_charHandle{};
hooking::detour::Handle g_rollbackHandle{};
hooking::detour::Handle g_acquireHandle{};
hooking::detour::Handle g_pollHandle{};
hooking::detour::Handle g_sessionHandle{};
hooking::detour::Handle g_sessionWrapHandle{};
hooking::detour::Handle g_bitPrimHandle{};
std::atomic<CharTest> g_originalChar{nullptr};
std::atomic<RollbackApply> g_originalRollback{nullptr};
std::atomic<AcquireCheck> g_originalAcquire{nullptr};
std::atomic<PollGate> g_originalPoll{nullptr};
std::atomic<RequirementSession> g_originalSession{nullptr};
std::atomic<SessionWrap> g_originalSessionWrap{nullptr};
std::atomic<BitPrim> g_originalBitPrim{nullptr};

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
 *  register read — no deref) + the result + the caller. THIS = the census's per-index
 *  surface: every informative marker-bit read funnels through here. */
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
                                      "ev=gate_trace stage=bit_poll idx=0x%llX result=0x%llX "
                                      "caller=+0x%llX",
                                      static_cast<unsigned long long>(rdx & 0xFFFFULL),
                                      static_cast<unsigned long long>(result),
                                      static_cast<unsigned long long>(callerRva));
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(written)});
    }
    return result;
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

/** Attaches the seven observers in either server mode. */
bool install() noexcept {
    if (g_charHandle.attached && g_rollbackHandle.attached && g_acquireHandle.attached
        && g_pollHandle.attached && g_sessionHandle.attached
        && g_sessionWrapHandle.attached && g_bitPrimHandle.attached) {
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
        || !diagnostics::contains(range, baseValue + kBitPrimRva)) {
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
    const std::array<hooking::detour::Spec, 7> specs{charSpec, rollbackSpec, acquireSpec,
                                                     pollSpec, sessionSpec, sessionWrapSpec,
                                                     bitPrimSpec};
    std::array<hooking::detour::Handle, 7> handles{};
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
    core::log::write(core::log::Channel::client,
                     core::log::Level::info,
                     "ev=gate_trace stage=install result=ok");
    return true;
}

/** Detaches all seven observers and drops their trampolines. */
bool uninstall() noexcept {
    (void)hooking::detour::uninstall(g_charHandle);
    (void)hooking::detour::uninstall(g_rollbackHandle);
    (void)hooking::detour::uninstall(g_acquireHandle);
    (void)hooking::detour::uninstall(g_pollHandle);
    (void)hooking::detour::uninstall(g_sessionHandle);
    (void)hooking::detour::uninstall(g_sessionWrapHandle);
    (void)hooking::detour::uninstall(g_bitPrimHandle);
    g_charHandle = {};
    g_rollbackHandle = {};
    g_acquireHandle = {};
    g_pollHandle = {};
    g_sessionHandle = {};
    g_sessionWrapHandle = {};
    g_bitPrimHandle = {};
    g_originalChar.store(nullptr, std::memory_order_release);
    g_originalRollback.store(nullptr, std::memory_order_release);
    g_originalAcquire.store(nullptr, std::memory_order_release);
    g_originalPoll.store(nullptr, std::memory_order_release);
    g_originalSession.store(nullptr, std::memory_order_release);
    g_originalSessionWrap.store(nullptr, std::memory_order_release);
    g_originalBitPrim.store(nullptr, std::memory_order_release);
    return true;
}

/** @return True while any observer is attached. */
bool is_installed() noexcept {
    return g_charHandle.attached || g_rollbackHandle.attached || g_acquireHandle.attached
           || g_pollHandle.attached || g_sessionHandle.attached
           || g_sessionWrapHandle.attached || g_bitPrimHandle.attached;
}

} // namespace sunrise::client::hooks::gate_trace
