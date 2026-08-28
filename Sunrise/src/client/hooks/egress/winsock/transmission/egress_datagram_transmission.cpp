#include <limits>

#include "../../../../../core/logging/log.h"
#include "../../internal.h"
#include "../../policy/policy.h"
#include "../discovery/egress_discovery_responder.h"
#include "replacements.h"

#include "../netprobe.h"

namespace sunrise::client::hooks::egress::winsock::transmission {
namespace {

/** FINDINGS 20.125 instrument: per-stage observation counters (netprobe.h rate-limits). */
std::uint32_t g_probeSendTo = 0;
std::uint32_t g_probeWsaSendTo = 0;


/** A null destination picks the connected peer only when the address length is 0. */
constexpr int kConnectedDestinationLength = 0;

/** Clears an optional send count before a denial. */
void clear_bytes(LPDWORD bytes) noexcept {
    if (bytes != nullptr) {
        *bytes = 0;
    }
}

/**
 * Redirects an explicit IPv4 destination, or checks a connected redirect-target peer.
 * @param socket Socket used when the destination is omitted.
 * @param destination Optional destination address.
 * @param destinationLength Available destination bytes.
 * @param redirected Receives the rewritten explicit destination.
 * @param forwardedDestination Receives null or the rewritten destination.
 * @param forwardedLength Receives the destination byte count for the original.
 * @return True only when the original can target the exact IPv4 redirect target.
 */
[[nodiscard]] bool prepare_destination(SOCKET socket,
                                       const sockaddr* destination,
                                       int destinationLength,
                                       sockaddr_in& redirected,
                                       sockaddr*& forwardedDestination,
                                       int& forwardedLength) noexcept {
    if (destination != nullptr) {
        if (!policy::redirect_ipv4(destination, destinationLength, redirected)) {
            return false;
        }
        forwardedDestination = reinterpret_cast<sockaddr*>(&redirected);
        forwardedLength = static_cast<int>(sizeof(redirected));
        return true;
    }
    forwardedDestination = nullptr;
    forwardedLength = kConnectedDestinationLength;
    return destinationLength == kConnectedDestinationLength
           && policy::has_redirect_target_peer(socket);
}

/** Reports a discovery request the local responder could not answer. */
void log_discovery(bool succeeded) noexcept {
    if (succeeded) {
        return;
    }
    core::log::write(core::log::Channel::client,
                     core::log::Level::warn,
                     "ev=egress stage=discovery target=redirect action=respond result=fail");
}

/**
 * Adapts one synchronous WSA buffer to the local discovery responder.
 * @param overlapped Optional asynchronous state.
 * @param completion Optional completion callback.
 * @param sendTo The original sendto entry.
 * @return Local discovery result, or an unhandled result.
 */
[[nodiscard]] discovery::Result
handle_buffer_discovery(SOCKET socket,
                        LPWSABUF buffers,
                        DWORD bufferCount,
                        DWORD flags,
                        const sockaddr* destination,
                        int destinationLength,
                        LPWSAOVERLAPPED overlapped,
                        LPWSAOVERLAPPED_COMPLETION_ROUTINE completion,
                        discovery::SendTo sendTo) noexcept {
    if (buffers == nullptr || bufferCount != 1 || overlapped != nullptr || completion != nullptr
        || buffers[0].len > static_cast<ULONG>((std::numeric_limits<int>::max)())) {
        return {};
    }
    return discovery::handle(socket,
                             std::as_bytes(std::span(buffers[0].buf, buffers[0].len)),
                             static_cast<int>(flags),
                             destination,
                             destinationLength,
                             sendTo);
}

} // namespace

/** Handles local discovery or redirects one datagram to the redirect target. */
int WSAAPI send_bytes_to(SOCKET socket,
                         const char* buffer,
                         int length,
                         int flags,
                         const sockaddr* destination,
                         int destinationLength) noexcept {
    const void* const probeCaller = _ReturnAddress();
    netprobe::enter("sendto",
                    g_probeSendTo,
                    socket,
                    destination,
                    destinationLength,
                    length,
                    probeCaller);
    const auto call = original<decltype(&::sendto)>(HookSlot::sendTo);
    if (buffer != nullptr && length >= 0) {
        const discovery::Result discoveryResult =
            discovery::handle(socket,
                              std::as_bytes(std::span(buffer, static_cast<std::size_t>(length))),
                              flags,
                              destination,
                              destinationLength,
                              call);
        if (discoveryResult.handled) {
            log_discovery(discoveryResult.result != SOCKET_ERROR);
            netprobe::exit_call("sendto", g_probeSendTo, discoveryResult.result);
            return discoveryResult.result;
        }
    }

    sockaddr_in redirected{};
    sockaddr* forwardedDestination = nullptr;
    int forwardedLength = 0;
    const bool targetsRedirect = prepare_destination(
        socket, destination, destinationLength, redirected, forwardedDestination, forwardedLength);
    if (call == nullptr
        || !policy::allow_socket_call(policy::SocketOperation::send, targetsRedirect, true)) {
        netprobe::exit_call("sendto", g_probeSendTo, policy::deny_socket_call());
        return SOCKET_ERROR;
    }
    const int sent = call(socket, buffer, length, flags, forwardedDestination, forwardedLength);
    netprobe::exit_call("sendto", g_probeSendTo, sent);
    return sent;
}

/** Handles local discovery or redirects vectored datagrams to the redirect target. */
int WSAAPI send_buffers_to(SOCKET socket,
                           LPWSABUF buffers,
                           DWORD bufferCount,
                           LPDWORD bytesSent,
                           DWORD flags,
                           const sockaddr* destination,
                           int destinationLength,
                           LPWSAOVERLAPPED overlapped,
                           LPWSAOVERLAPPED_COMPLETION_ROUTINE completion) noexcept {
    const void* const probeCaller = _ReturnAddress();
    netprobe::enter("wsasendto",
                    g_probeWsaSendTo,
                    socket,
                    destination,
                    destinationLength,
                    buffers != nullptr && bufferCount == 1
                        ? static_cast<int>(buffers[0].len)
                        : -1,
                    probeCaller);
    const auto call = original<decltype(&::WSASendTo)>(HookSlot::wsaSendTo);
    const auto sendTo = original<decltype(&::sendto)>(HookSlot::sendTo);
    const discovery::Result discoveryResult = handle_buffer_discovery(socket,
                                                                      buffers,
                                                                      bufferCount,
                                                                      flags,
                                                                      destination,
                                                                      destinationLength,
                                                                      overlapped,
                                                                      completion,
                                                                      sendTo);
    if (discoveryResult.handled) {
        const bool succeeded = discoveryResult.result != SOCKET_ERROR;
        if (bytesSent != nullptr) {
            *bytesSent = succeeded ? buffers[0].len : 0;
        }
        log_discovery(succeeded);
        netprobe::exit_call("wsasendto", g_probeWsaSendTo, succeeded ? 0 : SOCKET_ERROR);
        return succeeded ? 0 : SOCKET_ERROR;
    }

    sockaddr_in redirected{};
    sockaddr* forwardedDestination = nullptr;
    int forwardedLength = 0;
    const bool targetsRedirect = prepare_destination(
        socket, destination, destinationLength, redirected, forwardedDestination, forwardedLength);
    if (call == nullptr
        || !policy::allow_socket_call(policy::SocketOperation::send, targetsRedirect, true)) {
        clear_bytes(bytesSent);
        netprobe::exit_call("wsasendto", g_probeWsaSendTo, policy::deny_socket_call());
        return SOCKET_ERROR;
    }
    const int sent = call(socket,
                          buffers,
                          bufferCount,
                          bytesSent,
                          flags,
                          forwardedDestination,
                          forwardedLength,
                          overlapped,
                          completion);
    netprobe::exit_call("wsasendto", g_probeWsaSendTo, sent);
    return sent;
}

} // namespace sunrise::client::hooks::egress::winsock::transmission
