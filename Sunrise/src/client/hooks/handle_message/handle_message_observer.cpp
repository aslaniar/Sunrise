/**
 * Protocol tape observer on the per-type server-push apply dispatcher.
 *
 * FUN_140E0F000 ("handle_message_internal", destiny2 + 0xE0F000) is the push apply
 * every decoded server activity message reaches: the join burst (kinds 4, 0, 1, 54), the
 * roster/membership (5/6), and any future entity-state carrier. It is a 7-argument
 * fastcall:
 *   RCX = u32 session, RDX = u16* body (BAP service number at body[0]),
 *   R8 = u32 payloadLen, R9 = u8* payload (activity-message envelope when the
 *   service is 9), stack = u64 cb, u32 cbArg, const char* name
 * (entity-combatants.md FINAL R1, Hook B; phase5 decompile of FUN_140E0F000).
 * The hook runs the original untouched and then emits ONE structured tape row
 * per applied push (the transaction): direction, named BAP service (handbook
 * registry, protocol_table.h), envelope kind when decodable, session, size,
 * result, elapsed, account handle, connection label. It changes nothing, so it
 * is safe on every push path. Attaches only while client.externalServer.enabled
 * is true (same gate as the package-validator hook).
 *
 * TAPE FORMAT (one row per transaction, key=value, tailable):
 *   ev=handle_message stage=push tape=1 dir=down svc=9 service=activity_message
 *   type=5 msg=auth_sense session=1 size=573 result=ok accepted=1 elapsed=0
 *   handle=0x019EAA3001002000 conn=BAP ID  1 desc:OUT FAH
 * Names come from RE_scripts/generate_protocol_table.py -> protocol_table.h
 * (handbook pp15-17 service registry, pp46-47 message kinds). The old row's
 * payload-head hex and hardcoded result=ok are gone: the row names the routing
 * decision (which service, which kind), not the payload bytes.
 */

#include "handle_message_observer.h"

#include <Windows.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>

#include "../../../core/logging/log.h"
#include "../../../core/settings/settings.h"
#include "../../diagnostics/module_range.h"
#include "../../hooking/detour.h"
#include "protocol_table.h"

namespace sunrise::client::hooks::handle_message {
namespace {

/** Image RVA of FUN_140E0F000, the per-type push apply dispatcher. */
constexpr std::uintptr_t kHandleMessageRva = 0xE0F000;
/** One tape row must fit every field at worst-case width. */
constexpr std::size_t kLineCapacity = 384;
/** Connection labels beyond this many characters truncate in the row. */
constexpr std::size_t kConnLabelCapacity = 96;
/** The activity-message envelope's discriminator byte value (handbook p46). */
constexpr std::uint8_t kEnvelopeDiscriminator = 1;
/** The activity session id follows the discriminator in the svc-9 DOWN envelope. */
constexpr std::size_t kAsidOffset = 1;
/** Envelope fields before the message type: handle + discriminator (p46). */
constexpr std::size_t kTypeOffset = 9;
/** The BAP notification service that carries activity-message envelopes. */
constexpr std::uint16_t kActivityMessageService = 9;

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

/** Reads one big-endian u64 (the envelope's account handle, p46). */
std::uint64_t read_u64_be(const std::uint8_t* bytes) noexcept {
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < 8; ++index) {
        value = (value << 8U) | bytes[index];
    }
    return value;
}

/** Reads one big-endian u32 (the envelope's message type, p46). */
std::uint32_t read_u32_be(const std::uint8_t* bytes) noexcept {
    return (static_cast<std::uint32_t>(bytes[0]) << 24U)
           | (static_cast<std::uint32_t>(bytes[1]) << 16U)
           | (static_cast<std::uint32_t>(bytes[2]) << 8U) | static_cast<std::uint32_t>(bytes[3]);
}

/**
 * Runs the original dispatcher, then emits one named tape row per push.
 * @return The original dispatcher result, or 1 (apply rejected) when no trampoline is
 *         reachable -- never fabricates an accept.
 */
__declspec(noinline) std::uint64_t __fastcall observer(std::uint32_t session,
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
    const unsigned long long started = GetTickCount64();
    const std::uint64_t accepted = original(session, body, payloadLen, payload, cb, cbArg, name);
    const unsigned long long elapsed = GetTickCount64() - started;
    const std::uint16_t service = body != nullptr ? *body : 0xFFFFU;
    const char* const serviceName = protocol::service_name(service);
    const char* const conn = name != nullptr ? name : "unknown";
    const char* const verdict = accepted != 0 ? "ok" : "rejected";
    std::array<char, kLineCapacity> line{};
    int written = std::snprintf(line.data(),
                                line.size(),
                                "ev=handle_message stage=push tape=1 dir=down svc=%u "
                                "service=%s session=%u size=%u result=%s accepted=%llu "
                                "elapsed=%llu",
                                service,
                                serviceName != nullptr && serviceName[0] != '\0' ? serviceName
                                                                                 : "unknown",
                                session,
                                payloadLen,
                                verdict,
                                static_cast<unsigned long long>(accepted),
                                static_cast<unsigned long long>(elapsed));
    if (written <= 0) {
        return accepted;
    }
    std::size_t used = static_cast<std::size_t>(written);
    if (used > line.size()) {
        used = line.size();
    }
    // The activity-message envelope decodes only on the svc-9 notification
    // (handle + discriminator + type, handbook p46); queuez (123) frames use a
    // different layout and stay named at the service level only.
    // LAYOUT (verified two ways 2026-08-28): the svc-9 DOWN envelope is
    // [disc=1][u64be asid][u32be type][u32be len][payload] - discriminator at
    // byte 0, type at byte 9 (NotificationLayout + the decode lane's frame map;
    // the old payload[8] test read the svc-8 REQUEST layout's offset, where an
    // 8-byte account handle precedes the discriminator, so type= never fired).
    if (service == kActivityMessageService && payload != nullptr && payloadLen >= kTypeOffset + 4
        && payload[0] == kEnvelopeDiscriminator) {
        const std::uint32_t type = read_u32_be(payload + kTypeOffset);
        const char* kind = type <= 0xFFU ? protocol::kind_name(static_cast<std::uint8_t>(type))
                                         : "";
        const int extended = std::snprintf(line.data() + used,
                                           line.size() - used,
                                           " type=%u msg=%s asid=0x%016llX "
                                           "handle=0x%016llX",
                                           type,
                                           kind != nullptr && kind[0] != '\0' ? kind : "unknown",
                                           static_cast<unsigned long long>(
                                               read_u64_be(payload + kAsidOffset)),
                                           static_cast<unsigned long long>(
                                               read_u64_be(payload)));
        if (extended > 0) {
            used += static_cast<std::size_t>(extended);
            if (used > line.size()) {
                used = line.size();
            }
        }
    }
    const int connWritten = std::snprintf(line.data() + used,
                                          line.size() - used,
                                          " conn=%.*s",
                                          static_cast<int>(kConnLabelCapacity),
                                          conn);
    if (connWritten > 0) {
        used += static_cast<std::size_t>(connWritten);
        if (used > line.size()) {
            used = line.size();
        }
    }
    core::log::write(core::log::Channel::client,
                     core::log::Level::info,
                     {line.data(), used});
    return accepted;
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