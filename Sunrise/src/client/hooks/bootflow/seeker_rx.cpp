#include <Windows.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string_view>

#include "../../../core/logging/log.h"
#include "../../../core/settings/settings.h"
#include "../../diagnostics/module_range.h"
#include "internal.h"

namespace sunrise::client::hooks::bootflow {
namespace {

/**
 * FINDINGS 20.88/20.90 DISCRIMINATOR INSTRUMENT - p2(60) REWRITE AFTER THE
 * p2(59) FREEZE (INCIDENT_2026-08-26_p2-59-freeze.md).
 *
 * SAME OBSERVATION, SAFER MECHANISM: p2(59) placed FIVE CODE DETOURS on the
 * BAP receive-class [0x10] payload-decode functions and froze the client at
 * bootflow:package_registration BEFORE ANY instrument row completed. This build
 * patches NO instructions: the eight class handler descriptors live in .rdata
 * at static 0x141C3C600+c*0x90, and their [0x10] slot (bap-dispatch.md line 21)
 * is a DATA POINTER. We swap the eight pointers to our observers under
 * VirtualProtect and restore them on uninstall. The observed functions are
 * never modified; callers outside these class tables are completely unaffected;
 * every call that arrives must come through exactly the path we want to watch.
 *
 * The five unique [0x10] targets across the eight classes (static dump,
 * pe_reader): 0x106EE90(c3), 0x106EF20(c0,1,4), 0x106EF80(c2,7),
 * 0x106F000(c6), 0x106F180(c5). Which class decodes inbound svc-43 stays a
 * boot observable via the logged received-object RVA.
 *
 * Call shape (phase3/decompiles.txt ~2737):
 *   verdict = (**obj+0x10)(obj, payload, &frame, &out);  '\0' means parse fail.
 * LAYOUT HONESTY: arg semantics beyond obj are partially pinned; every foreign
 * dereference goes through fault-guarded loads (safe_read*) so a wrong guess
 * degrades to "unreadable" instead of raising inside the game.
 */

/** Static image base of destiny2.exe, for logging addresses desk-side. */
constexpr std::uintptr_t kStaticBase = 0x140000000;
/** First class-descriptor method table, static. */
constexpr std::uintptr_t kDescriptorTableRva = 0x1C3C600;
/** Descriptor stride (bap-dispatch.md: 0x141C3C600 + c*0x90). */
constexpr std::size_t kDescriptorStride = 0x90;
/** Payload-decode slot inside a descriptor (byte offset == vtable qword 2). */
constexpr std::size_t kSlotOffset = 0x10;
/** Eight receive-class descriptors. */
constexpr std::size_t kClassCount = 8;

using Decode = char(__fastcall*)(void*, void*, void*, void*) noexcept;

/** One swapped slot: its address, the original value, and its observer entry. */
struct Swap {
    std::atomic<Decode>* originalOut;
    void** address;
    Decode replacement;
};
std::array<std::atomic<Decode>, kClassCount> g_originals{};
std::array<void**, kClassCount> g_slotAddresses{};

/** Distinct (object-rva, verdict, header word) triples reported per run. */
constexpr std::size_t kMaxPairs = 48;
struct Pair {
    std::uint32_t objectRva;
    std::uint32_t verdict;
    std::uint64_t head;
};
std::array<Pair, kMaxPairs> g_seen{};
std::atomic<std::size_t> g_count{0};

[[nodiscard]] bool claim(std::uint32_t objectRva,
                         std::uint32_t verdict,
                         std::uint64_t head) noexcept {
    const std::size_t used = g_count.load(std::memory_order_acquire);
    for (std::size_t index = 0; index < used && index < g_seen.size(); ++index) {
        if (g_seen[index].objectRva == objectRva && g_seen[index].verdict == verdict
            && g_seen[index].head == head) {
            return false;
        }
    }
    const std::size_t slot = g_count.fetch_add(1, std::memory_order_acq_rel);
    if (slot >= g_seen.size()) {
        return false;
    }
    g_seen[slot] = Pair{objectRva, verdict, head};
    return true;
}

/**
 * Fault-guarded memory read. Argument-buffer layouts behind these pointers are
 * not fully pinned, so every foreign dereference goes through here: a bad guess
 * returns false instead of raising inside the game process.
 */
bool safe_read(const void* address, void* output, std::size_t size) noexcept {
    __try {
        const auto* source = static_cast<const unsigned char*>(address);
        auto* destination = static_cast<unsigned char*>(output);
        for (std::size_t index = 0; index < size; ++index) {
            destination[index] = source[index];
        }
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

/** Renders up to 12 bytes at @p address as uppercase hex, or "unreadable". */
void hex_prefix(const void* address, char (&out)[25]) noexcept {
    unsigned char buffer[12]{};
    if (!safe_read(address, buffer, sizeof buffer)) {
        constexpr char kUnreadable[] = "unreadable";
        for (std::size_t index = 0; index < sizeof kUnreadable; ++index) {
            out[index] = kUnreadable[index];
        }
        return;
    }
    static constexpr char kDigits[] = "0123456789ABCDEF";
    for (std::size_t index = 0; index < sizeof buffer; ++index) {
        out[index * 2] = kDigits[buffer[index] >> 4];
        out[(index * 2) + 1] = kDigits[buffer[index] & 0x0F];
    }
    out[sizeof buffer * 2] = '\0';
}

/**
 * Shared observation body: runs the ORIGINAL function pointer first (the
 * function itself was never modified, so this is a plain call), then reports
 * one deduped row with the parse verdict and guarded raw prefixes.
 */
char observe_and_report(Decode original,
                        void* object,
                        void* payload,
                        void* frame,
                        void* decoded) noexcept {
    const char verdict = original(object, payload, frame, decoded);

    const auto baseValue = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
    const auto objectAddress = reinterpret_cast<std::uintptr_t>(object);
    const auto objectRva =
        static_cast<std::uint32_t>(objectAddress >= baseValue ? objectAddress - baseValue : 0);

    unsigned long long head = 0;
    static_cast<void>(safe_read(frame, &head, sizeof head));
    if (!claim(objectRva, verdict != 0 ? 1U : 0U, head)) {
        return verdict;
    }

    char payloadHex[25] = "unreadable";
    char frameHex[25] = "unreadable";
    hex_prefix(payload, payloadHex);
    hex_prefix(frame, frameHex);
    std::array<char, 384> line{};
    const int written =
        std::snprintf(line.data(),
                      line.size(),
                      "ev=matchmaking stage=rx_decode object_rva=0x%X result=%s "
                      "payload_ptr=0x%llX frame_ptr=0x%llX out_ptr=0x%llX h0=%016llX "
                      "p2=%s f3=%s",
                      objectRva,
                      verdict != 0 ? "ok" : "fail",
                      reinterpret_cast<unsigned long long>(payload),
                      reinterpret_cast<unsigned long long>(frame),
                      reinterpret_cast<unsigned long long>(decoded),
                      head,
                      payloadHex,
                      frameHex);
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(written)});
    }
    return verdict;
}

/** One typed observer per CLASS SLOT so every swap forwards to its own saved original. */
template <std::size_t Slot>
__declspec(noinline) char __fastcall rx_decode(void* object,
                                               void* payload,
                                               void* frame,
                                               void* decoded) noexcept {
    const Decode original = g_originals[Slot].load(std::memory_order_acquire);
    if (original == nullptr) {
        // Swapped slot whose original was not published yet cannot happen at a
        // decoded call site in practice; forwarding nothing would fabricate a
        // parse failure, so fall back to failure-free neutrality is IMPOSSIBLE -
        // instead treat this as an unreached defensive arm and fail loudly once.
        return '\0';
    }
    return observe_and_report(original, object, payload, frame, decoded);
}

/** @param reason Key naming the step that failed. @return False, for a direct return. */
bool fail_install(const char* reason) noexcept {
    std::array<char, 128> line{};
    const int written =
        std::snprintf(line.data(), line.size(),
                      "ev=matchmaking stage=rx_decode_install result=fail reason=%s", reason);
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::warn,
                         {line.data(), static_cast<std::size_t>(written)});
    }
    return false;
}

} // namespace

/**
 * Swaps the eight descriptor [0x10] pointers to the observers when the
 * external-server switch is on. No game .text bytes are touched (INCIDENT
 * 2026-08-26 p2(59): five code detours froze the client pre-bootstrap).
 */
bool install_seeker_rx() noexcept {
    if (!core::settings::get().client.externalServer.enabled || g_slotAddresses[0] != nullptr) {
        return true;
    }
    std::byte* const base = reinterpret_cast<std::byte*>(GetModuleHandleW(nullptr));
    if (base == nullptr) {
        return fail_install("base");
    }
    diagnostics::ModuleRange range{};
    const auto baseValue = reinterpret_cast<std::uintptr_t>(base);
    if (!diagnostics::module_range(reinterpret_cast<HMODULE>(base), range)
        || !diagnostics::contains(range, baseValue + kDescriptorTableRva)) {
        return fail_install("target");
    }
    /** Observer entry points, index-matched against class slots. */
    static constexpr Decode kObservers[kClassCount] = {
        &rx_decode<0>, &rx_decode<1>, &rx_decode<2>, &rx_decode<3>,
        &rx_decode<4>, &rx_decode<5>, &rx_decode<6>, &rx_decode<7>,
    };

    // Validate EVERY slot target first: each must hold a readable .text pointer
    // matching the known five-value set; anything else means the layout guess is
    // wrong TODAY on THIS client and the swap aborts cleanly instead of guessing.
    static constexpr std::uintptr_t kKnownTargets[] = {
        0x106EE90, 0x106EF20, 0x106EF80, 0x106F000, 0x106F180,
    };
    for (std::size_t slot = 0; slot < kClassCount; ++slot) {
        void** const address =
            reinterpret_cast<void**>(baseValue + kDescriptorTableRva
                                     + slot * kDescriptorStride + kSlotOffset);
        unsigned long long current = 0;
        if (!safe_read(address, &current, sizeof current)) {
            return fail_install("read");
        }
        bool known = false;
        for (const std::uintptr_t target : kKnownTargets) {
            if (current == baseValue + target) {
                known = true;
                break;
            }
        }
        if (!known || diagnostics::contains(range, current) == false) {
            return fail_install("unexpected_target");
        }
        g_slotAddresses[slot] = address;
    }

    // Commit the swaps: descriptors sit in .rdata (read-only pages), so flip
    // protections around each write and RESTORE immediately after.
    for (std::size_t slot = 0; slot < kClassCount; ++slot) {
        void** const address = g_slotAddresses[slot];
        DWORD oldProtect = 0;
        if (!VirtualProtect(address, sizeof(void*), PAGE_READWRITE, &oldProtect)) {
            return fail_install("protect");
        }
        void* const previous = *address;
        g_originals[slot].store(reinterpret_cast<Decode>(previous),
                                std::memory_order_release);
        *address = reinterpret_cast<void*>(kObservers[slot]);
        DWORD restored = 0;
        static_cast<void>(VirtualProtect(address, sizeof(void*), oldProtect, &restored));
    }
    // Unconditional liveness line: silence after this means the swap never ran,
    // never that nothing interesting happened (LESSONS.md 13).
    core::log::write(core::log::Channel::client,
                     core::log::Level::info,
                     "ev=matchmaking stage=rx_decode_install result=ok hooks=8 mode=vtableswap");
    return true;
}

/** Restores every descriptor slot pointer to its original value. */
void uninstall_seeker_rx() noexcept {
    for (std::size_t slot = 0; slot < kClassCount; ++slot) {
        void** const address = g_slotAddresses[slot];
        if (address == nullptr) {
            continue;
        }
        const Decode original = g_originals[slot].load(std::memory_order_acquire);
        if (original != nullptr) {
            DWORD oldProtect = 0;
            if (VirtualProtect(address, sizeof(void*), PAGE_READWRITE, &oldProtect)) {
                *address = reinterpret_cast<void*>(original);
                DWORD restored = 0;
                static_cast<void>(VirtualProtect(address, sizeof(void*), oldProtect, &restored));
            }
        }
        g_originals[slot].store(nullptr, std::memory_order_release);
        g_slotAddresses[slot] = nullptr;
    }
    g_count.store(0, std::memory_order_release);
}

} // namespace sunrise::client::hooks::bootflow
