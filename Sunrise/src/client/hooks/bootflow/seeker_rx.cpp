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
#include "../../hooking/detour.h"
#include "internal.h"

namespace sunrise::client::hooks::bootflow {
namespace {

/**
 * FINDINGS 20.88/20.90 DISCRIMINATOR INSTRUMENT: the inbound-frame PAYLOAD DECODE method
 * ([0x10], bap-dispatch.md line 21) of EVERY BAP receive-class handler descriptor.
 *
 * phase3/decompiles.txt line ~2737 shows the call shape:
 *   cVar3 = (**(obj+0x10))(obj, local_e8, &local_168, &local_d8);
 *   if (cVar3 == '\0') -> error 0x2a.
 * The descriptors live in clean .rdata at static 0x141C3C600+c*0x90. The class map
 * FUN_140E74F80(type)+8 was NOT walked offline, so which class carries inbound svc-43 is
 * itself a boot observable - hence ALL classes are hooked. Static dump of the eight slot[0x10]
 * entries yields exactly FIVE unique .text functions - verified clean, NOT obfuscated (unlike
 * the serializer core at 0x1407Dxxxx, svc43-response-divergence-census.md PHASE-2):
 *
 *   0x106EE90 -> class 3          0x106EF20 -> classes 0,1,4     0x106EF80 -> classes 2,7
 *   0x106F000 -> class 6          0x106F180 -> class 5
 *
 * Each hook runs its own trampoline untouched, then reports verdict + raw prefixes once per
 * distinct frame. When a matchmaking search response (svc 43) decodes through whichever class
 * owns it:
 *   result=fail  -> candidates never parse (fill omitted fields; census Risk B path)
 *   result=ok    -> candidates parse and die later (traversal/suitability path opens)
 *
 * LAYOUT HONESTY: arg2 (`local_e8`) has NO decompiled field semantics, and exact offsets of
 * the header/output structs are not pinned. Every dereference below goes through fault-guarded
 * loads (safe_read*): a wrong guess cannot crash the client and cannot fake an observation.
 * The received OBJECT's RVA is logged raw - never mapped by assumption.
 */

/** The five unique [0x10] payload-decode RVAs (static image); see comment above for classes. */
constexpr std::uintptr_t kRxDecodeRvas[] = {
    0x106EE90, 0x106EF20, 0x106EF80, 0x106F000, 0x106F180,
};
constexpr std::size_t kHookCount = sizeof kRxDecodeRvas / sizeof kRxDecodeRvas[0];

/** Distinct (class-rva, verdict, header word) triples reported per run. */
constexpr std::size_t kMaxPairs = 48;

using Decode = char(__fastcall*)(void*, void*, void*, void*) noexcept;

std::array<hooking::detour::Handle, kHookCount> g_handles{};
std::array<std::atomic<Decode>, kHookCount> g_originals{};

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
 * Fault-guarded memory read. Argument-buffer layouts behind these pointers are not fully
 * pinned, so every foreign dereference goes through here: a bad guess returns false instead of
 * raising inside the game process.
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

/** Renders up to 12 bytes at @p address as uppercase hex, or "unreadable" on fault. */
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
 * Shared observation body: runs @p original first (never changes its result), then emits one
 * deduped row naming the verdict, both pointer values, and guarded hex prefixes.
 */
char observe_and_report(Decode original,
                        void* object,
                        void* payload,
                        void* frame,
                        void* decoded) noexcept {
    const char verdict = original(object, payload, frame, decoded);

    const auto baseValue = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
    const uintptr_t objectAddress = reinterpret_cast<std::uintptr_t>(object);
    const auto objectRva =
        static_cast<std::uint32_t>(objectAddress >= baseValue ? objectAddress - baseValue : 0);

    // Dedupe key includes the first guarded qword at the frame arg: identical frames repeat;
    // anything new reports once. An unreadable frame yields head=0 like any other value.
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

/** One typed observer per hook target, so each detour calls exactly its own trampoline. */
template <std::size_t Hook>
__declspec(noinline) char __fastcall rx_decode(void* object,
                                               void* payload,
                                               void* frame,
                                               void* decoded) noexcept {
    const Decode original = g_originals[Hook].load(std::memory_order_acquire);
    if (original == nullptr) {
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
 * Attaches the receive-decode observers when the external-server switch is on. Same absolute-
 * RVA pattern as the push dispatcher observer (handle_message_observer.cpp): the game image is
 * fixed-position and these functions were verified clean statically.
 */
bool install_seeker_rx() noexcept {
    if (!core::settings::get().client.externalServer.enabled || g_handles[0].attached) {
        return true;
    }
    std::byte* const base = reinterpret_cast<std::byte*>(GetModuleHandleW(nullptr));
    if (base == nullptr) {
        return fail_install("base");
    }
    const std::uintptr_t baseValue = reinterpret_cast<std::uintptr_t>(base);
    diagnostics::ModuleRange range{};
    for (std::size_t hook = 0; hook < kHookCount; ++hook) {
        if (!diagnostics::module_range(reinterpret_cast<HMODULE>(base), range)
            || !diagnostics::contains(range, baseValue + kRxDecodeRvas[hook])) {
            return fail_install("target");
        }
    }
    /** Observer entry points, index-matched against kRxDecodeRvas. */
    static constexpr Decode kObservers[kHookCount] = {
        &rx_decode<0>, &rx_decode<1>, &rx_decode<2>, &rx_decode<3>, &rx_decode<4>,
    };
    for (std::size_t hook = 0; hook < kHookCount; ++hook) {
        const hooking::detour::Spec spec{base + kRxDecodeRvas[hook],
                                         reinterpret_cast<void*>(kObservers[hook])};
        if (!hooking::detour::install(spec, g_handles[hook])) {
            return fail_install("attach");
        }
        g_originals[hook].store(reinterpret_cast<Decode>(g_handles[hook].original),
                                std::memory_order_release);
    }
    // Unconditional liveness line: silence after this means the hooks never ran, never that
    // nothing interesting happened (LESSONS.md 13).
    core::log::write(core::log::Channel::client,
                     core::log::Level::info,
                     "ev=matchmaking stage=rx_decode_install result=ok hooks=5");
    return true;
}

/** Detaches every receive-decode observer. */
void uninstall_seeker_rx() noexcept {
    for (std::size_t hook = 0; hook < kHookCount; ++hook) {
        if (g_handles[hook].attached) {
            (void)hooking::detour::uninstall(g_handles[hook]);
        }
        g_originals[hook].store(nullptr, std::memory_order_release);
    }
    g_count.store(0, std::memory_order_release);
}

} // namespace sunrise::client::hooks::bootflow
