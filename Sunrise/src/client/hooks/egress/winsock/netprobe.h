#pragma once

#include <cstdint>
#include <winsock2.h>
#include <ws2tcpip.h>

#include "../../../../core/logging/log.h"

namespace sunrise::client::hooks::egress::winsock::netprobe {

/**
 * FINDINGS 20.125 instrument: per-call observation on the interposed socket funnel.
 *
 * The rig's client wedges its `network_send` mainloop job at the first join-path send
 * ('peer-creating', +20.000 s hitch assert), and the server never sees one packet, so the
 * wedge is somewhere between the session layer and the socket. These hooks are the one
 * funnel every outbound datagram and connection crosses, so logging each call's entry,
 * destination, result, and caller RVA discriminates all three candidate wedges:
 *   - never entered  -> the wedge is upstream of the socket layer,
 *   - entered, no exit -> the wedge is inside the interposed call itself,
 *   - entered+exited -> the destination and result say where the bytes went.
 * Log-only, rate-limited per stage; it changes no behavior (LESSONS 18 corollary 1).
 *
 * `_ReturnAddress()` must be captured in the replacement function's own frame (they are
 * exported WSAAPI bodies the hook table addresses, never inlined) and passed here.
 */

/** Per-stage log budget before sparse sampling: the join path is low-volume pre-dial. */
constexpr std::uint32_t kFirstLogged = 96;
constexpr std::uint32_t kSampleEvery = 1024;

/** Counts one call per stage and answers whether this call prints. */
[[nodiscard]] inline bool sample(std::uint32_t& counter) noexcept {
    const std::uint32_t n = counter++;
    return n < kFirstLogged || (n % kSampleEvery) == 0;
}

/** Formats one IPv4 sockaddr_in as ip:port, or "connected"/"none". */
inline void format_destination(const sockaddr* destination,
                               int destinationLength,
                               char* output,
                               std::size_t capacity) noexcept {
    if (destination == nullptr || destinationLength < static_cast<int>(sizeof(sockaddr_in))) {
        std::snprintf(output, capacity, "%s",
                      destination == nullptr ? "connected" : "short");
        return;
    }
    const sockaddr_in& endpoint = *reinterpret_cast<const sockaddr_in*>(destination);
    if (endpoint.sin_family != AF_INET) {
        std::snprintf(output, capacity, "family=%u", static_cast<unsigned>(endpoint.sin_family));
        return;
    }
    const auto* raw = reinterpret_cast<const unsigned char*>(&endpoint.sin_addr);
    std::snprintf(output,
                  capacity,
                  "%u.%u.%u.%u:%u",
                  raw[0],
                  raw[1],
                  raw[2],
                  raw[3],
                  static_cast<unsigned>(ntohs(endpoint.sin_port)));
}

/** Emits one entry line with the destination and the game-relative caller RVA. */
inline void enter(const char* stage,
                  std::uint32_t& counter,
                  SOCKET socket,
                  const sockaddr* destination,
                  int destinationLength,
                  int length,
                  const void* caller) noexcept {
    if (!core::log::accepts(core::log::Channel::client, core::log::Level::info)
        || !sample(counter)) {
        return;
    }
    char destinationText[64]{};
    format_destination(destination, destinationLength, destinationText, sizeof(destinationText));
    const std::uintptr_t game = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
    std::array<char, 160> line{};
    const int written = std::snprintf(line.data(),
                                      line.size(),
                                      "ev=netprobe stage=%s socket=%llu dest=%s len=%d "
                                      "caller=+0x%llX",
                                      stage,
                                      static_cast<unsigned long long>(socket),
                                      destinationText,
                                      length,
                                      static_cast<unsigned long long>(
                                          reinterpret_cast<std::uintptr_t>(caller) - game));
    if (written > 0) {
        core::log::write(core::log::Channel::client, core::log::Level::info, line.data());
    }
}

/** Emits one exit line, always for errors, sparsely for successes. */
inline void exit_call(const char* stage, std::uint32_t& counter, int result) noexcept {
    const bool error = result == SOCKET_ERROR;
    if (!error && !sample(counter)) {
        return;
    }
    std::array<char, 128> line{};
    const int written = std::snprintf(line.data(),
                                      line.size(),
                                      "ev=netprobe stage=%s result=%d wsa=%d",
                                      stage,
                                      result,
                                      error ? static_cast<int>(WSAGetLastError()) : 0);
    if (written > 0) {
        core::log::write(core::log::Channel::client, core::log::Level::info, line.data());
    }
}

} // namespace sunrise::client::hooks::egress::winsock::netprobe
