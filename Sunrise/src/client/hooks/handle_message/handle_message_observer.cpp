/**
 * Log-only observer on the per-type server-push apply dispatcher.
 *
 * FUN_140E0F000 ("handle_message_internal", destiny2 + 0xE0F000) is the push apply
 * every decoded server activity message reaches: the join burst (types 4, 0, 1, 54), the
 * roster/membership (5/6), and any future entity-state carrier. It is a 7-argument
 * fastcall:
 *   RCX = u32 id, RDX = u16* body (wire type at body[0]), R8 = u32 payloadLen,
 *   R9 = u8* payload, stack = u64 cb, u32 cbArg, const char* name
 * (entity-combatants.md FINAL R1, Hook B; phase5 decompile of FUN_140E0F000).
 * The hook runs the original untouched and then logs the message name and payload head.
 * It changes nothing, so it is safe on every push path. Attaches only while
 * client.externalServer.enabled is true (same gate as the package-validator hook).
 */

#include "handle_message_observer.h"

#include <Windows.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>

#include "../../../core/logging/log.h"
#include "../../../core/settings/settings.h"
#include "../../diagnostics/module_range.h"
#include "../../hooking/detour.h"

namespace sunrise::client::hooks::handle_message {
namespace {

/** Image RVA of FUN_140E0F000, the per-type push apply dispatcher. */
constexpr std::uintptr_t kHandleMessageRva = 0xE0F000;
/** How many payload head bytes one log line prints. */
constexpr std::size_t kPayloadHeadBytes = 8;
/** Payload bytes beyond the head are counted, not printed. */
constexpr std::size_t kLineCapacity = 192;

/** Exact dispatcher ABI from the phase5 decompile of FUN_140E0F000. */
using Handler = std::uint64_t(__fastcall*)(std::uint32_t,
                                           std::uint16_t*,
                                           std::uint32_t,
                                           std::uint8_t*,
                                           std::uint64_t,
                                           std::uint32_t,
                                           const char*) noexcept;

hooking::detour::Handle g_handle{};
/** Trampoline published by the detour transaction; read on the push path. */
std::atomic<Handler> g_original{nullptr};

/** Appends the first payload bytes as zero-padded hex, up to kPayloadHeadBytes. */
void append_payload_hex(std::span<char> line,
                        std::size_t& used,
                        const std::uint8_t* payload,
                        std::uint32_t payloadLen) noexcept {
    const std::size_t shown = payloadLen < kPayloadHeadBytes
                                  ? static_cast<std::size_t>(payloadLen)
                                  : kPayloadHeadBytes;
    for (std::size_t index = 0; index < shown && used + 4 <= line.size(); ++index) {
        const int written = std::snprintf(line.data() + used,
                                          line.size() - used,
                                          "%02X ",
                                          static_cast<unsigned>(payload[index]));
        if (written > 0) {
            used += static_cast<std::size_t>(written);
        }
    }
}

/**
 * Runs the original dispatcher, then logs the decoded push.
 * @return The original dispatcher result, or 1 (apply rejected) when no trampoline is
 *         reachable -- never fabricates an accept.
 */
__declspec(noinline) std::uint64_t __fastcall observer(std::uint32_t id,
                                                       std::uint16_t* body,
                                                       std::uint32_t payloadLen,
                                                       std::uint8_t* payload,
                                                       std::uint64_t cb,
                                                       std::uint32_t cbArg,
                                                       const char* name) noexcept {
    const Handler original = g_original.load(std::memory_order_acquire);
    if (original == nullptr) {
        return 1;
    }
    const std::uint64_t result = original(id, body, payloadLen, payload, cb, cbArg, name);
    const std::uint32_t type = body != nullptr ? static_cast<std::uint32_t>(*body) : 0xFFFFU;
    const char* const messageName = name != nullptr ? name : "unknown";
    std::array<char, kLineCapacity> line{};
    int written = std::snprintf(line.data(),
                                line.size(),
                                "ev=handle_message stage=push result=ok name=%s type=%u "
                                "id=%u len=%u first=",
                                messageName,
                                type,
                                id,
                                payloadLen);
    if (written <= 0) {
        return result;
    }
    std::size_t used = static_cast<std::size_t>(written);
    if (used > line.size()) {
        used = line.size();
    }
    if (payload != nullptr && payloadLen != 0) {
        append_payload_hex(line, used, payload, payloadLen);
    }
    core::log::write(core::log::Channel::client,
                     core::log::Level::info,
                     {line.data(), used});
    return result;
}

/** @param reason Key naming the step that failed. @return False, for a direct return. */
[[nodiscard]] bool fail_install(const char* reason) noexcept {
    std::array<char, 96> line{};
    const int written = std::snprintf(line.data(),
                                      line.size(),
                                      "ev=handle_message stage=install result=fail reason=%s",
                                      reason);
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::warn,
                         {line.data(), static_cast<std::size_t>(written)});
    }
    return false;
}

} // namespace

/** Attaches the observer detour when the external-server switch is on. */
bool install() noexcept {
    if (!core::settings::get().client.externalServer.enabled || g_handle.attached) {
        return true;
    }
    std::byte* const base = reinterpret_cast<std::byte*>(GetModuleHandleW(nullptr));
    if (base == nullptr) {
        return fail_install("base");
    }
    const std::uintptr_t baseValue = reinterpret_cast<std::uintptr_t>(base);
    diagnostics::ModuleRange range{};
    if (!diagnostics::module_range(reinterpret_cast<HMODULE>(base), range)
        || !diagnostics::contains(range, baseValue + kHandleMessageRva)) {
        return fail_install("target");
    }
    const hooking::detour::Spec spec{base + kHandleMessageRva, reinterpret_cast<void*>(&observer)};
    if (!hooking::detour::install(spec, g_handle)) {
        return fail_install("attach");
    }
    g_original.store(reinterpret_cast<Handler>(g_handle.original), std::memory_order_release);
    core::log::write(core::log::Channel::client,
                     core::log::Level::info,
                     "ev=handle_message stage=install result=ok");
    return true;
}

/** Detaches the observer detour and drops its trampoline. */
bool uninstall() noexcept {
    if (g_handle.attached) {
        (void)hooking::detour::uninstall(g_handle);
    }
    g_original.store(nullptr, std::memory_order_release);
    return true;
}

/** @return True while the observer detour is attached. */
bool is_installed() noexcept {
    return g_handle.attached;
}

} // namespace sunrise::client::hooks::handle_message
