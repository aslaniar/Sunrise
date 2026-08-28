#pragma once

#include <cstdint>
#include <cstdio>
#include <cstring>

#include <iphlpapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include "../../../../core/logging/log.h"
#include "../platform/sdk.h"
#include "redirect.h"

namespace sunrise::client::hooks::egress::resolver::self_address {

/**
 * FINDINGS 20.125 / claims rig-stall-self-address.md STEP 1.
 *
 * The redirect answers EVERY name lookup with the server's address, including the game's
 * own "what is my address" lookup. On the server's own machine that answer is true; on
 * every other client it is the lie "you are the machine you are trying to join", and the
 * rig's join wedges on exactly that record. This helper recognizes the self-name lookups
 * and answers them with THIS machine's own LAN address - chosen numerically from the
 * local adapters, so no DNS ever leaves the box (the property the AI_NUMERICHOST redirect
 * exists to keep).
 */

/** Lowercase compare of one ASCII name against the stored lowercase candidate. */
[[nodiscard]] inline bool equals_ci(std::string_view node, std::string_view candidate) noexcept {
    if (node.size() != candidate.size()) {
        return false;
    }
    for (std::size_t index = 0; index < node.size(); ++index) {
        const char a = node[index] >= 'A' && node[index] <= 'Z'
                           ? static_cast<char>(node[index] - 'A' + 'a')
                           : node[index];
        const char b = candidate[index] >= 'A' && candidate[index] <= 'Z'
                           ? static_cast<char>(candidate[index] - 'A' + 'a')
                           : candidate[index];
        if (a != b) {
            return false;
        }
    }
    return true;
}

/**
 * Copies the machine's hostname into @p output, truncated at its first dot.
 * @return The stored name, or an empty view when Windows refused.
 */
[[nodiscard]] inline std::string_view hostname_label(char* output, std::size_t capacity) noexcept {
    if (gethostname(output, static_cast<int>(capacity)) != 0) {
        return {};
    }
    output[capacity - 1] = '\0';
    for (std::size_t index = 0; index < capacity && output[index] != '\0'; ++index) {
        if (output[index] == '.') {
            output[index] = '\0';
            break;
        }
    }
    return std::string_view{output};
}

/**
 * @param node The requested lookup name, narrow or wide ASCII.
 * @return True when @p node names THIS machine (its hostname, that name up to its first
 *         dot, or "localhost") and the self-exception switch is on.
 */
template <typename Character>
[[nodiscard]] inline bool is_self_name(const Character* node) noexcept {
    if (node == nullptr || node[0] == Character{'\0'}) {
        return false;
    }
    if (!core::settings::get().client.externalServer.resolveSelfLocally) {
        return false;
    }
    char hostname[256]{};
    const std::string_view label = hostname_label(hostname, sizeof(hostname));
    if (label.empty()) {
        return false;
    }
    std::string_view narrow{};
    char converted[256]{};
    if constexpr (sizeof(Character) > 1) {
        for (std::size_t index = 0; index + 1 < sizeof(converted) && node[index] != Character{'\0'};
             ++index) {
            converted[index] = static_cast<char>(node[index]);
        }
        narrow = std::string_view{converted};
    } else {
        narrow = std::string_view{node};
    }
    return equals_ci(narrow, label) || equals_ci(narrow, "localhost");
}

/**
 * Picks this machine's own IPv4 address from the local adapters: the unicast address
 * inside `client.external_server.peer_subnet / peer_prefix_bits`. No DNS, no network
 * traffic - the adapter table is a local kernel read.
 * @param output Receives the dotted-quad text, numeric, for the AI_NUMERICHOST forward.
 * @param address Receives the same address in network order, for host_by_name.
 * @return True when an adapter address inside the configured peer prefix was found.
 */
[[nodiscard]] inline bool self_address(char* output,
                                       std::size_t capacity,
                                       in_addr& address) noexcept {
    const core::settings::client::external::Settings& external =
        core::settings::get().client.externalServer;
    if (!external.enabled || external.peerPrefixBits == 0 || external.peerPrefixBits > 32) {
        return false;
    }
    const std::uint32_t mask = external.peerPrefixBits == 32
                                   ? 0xFFFFFFFFU
                                   : static_cast<std::uint32_t>(
                                         ~((1ULL << (32U - external.peerPrefixBits)) - 1ULL));
    const std::uint32_t subnet =
        (static_cast<std::uint32_t>(external.peerSubnet[0]) << 24)
        | (static_cast<std::uint32_t>(external.peerSubnet[1]) << 16)
        | (static_cast<std::uint32_t>(external.peerSubnet[2]) << 8)
        | static_cast<std::uint32_t>(external.peerSubnet[3]);

    ULONG size = 64 * 1024;
    std::byte storage[64 * 1024]{};
    auto* const adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(storage);
    const ULONG error = GetAdaptersAddresses(AF_INET,
                                             GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST
                                                 | GAA_FLAG_SKIP_DNS_SERVER,
                                             nullptr,
                                             adapters,
                                             &size);
    if (error != NO_ERROR) {
        // A home LAN fits 64 KB with room to spare; an overflow here is a broken platform,
        // and the safe answer is today's behavior, not a half-read adapter table.
        return false;
    }
    for (const IP_ADAPTER_ADDRESSES* adapter = adapters; adapter != nullptr;
         adapter = adapter->Next) {
        if (adapter->OperStatus != IfOperStatusUp) {
            continue;
        }
        for (const IP_ADAPTER_UNICAST_ADDRESS* unicast = adapter->FirstUnicastAddress;
             unicast != nullptr;
             unicast = unicast->Next) {
            const sockaddr_in* const endpoint =
                reinterpret_cast<const sockaddr_in*>(unicast->Address.lpSockaddr);
            if (endpoint == nullptr || endpoint->sin_family != AF_INET) {
                continue;
            }
            std::uint32_t value = 0;
            std::memcpy(&value, &endpoint->sin_addr, sizeof(value));
            const std::uint32_t bigEndian = (value >> 24) | ((value >> 8) & 0xFF00U)
                                            | ((value << 8) & 0xFF0000U) | (value << 24);
            if ((bigEndian & mask) != (subnet & mask)) {
                continue;
            }
            address = endpoint->sin_addr;
            const auto* raw = reinterpret_cast<const unsigned char*>(&endpoint->sin_addr);
            std::snprintf(output, capacity, "%u.%u.%u.%u", raw[0], raw[1], raw[2], raw[3]);
            return true;
        }
    }
    return false;
}

/** Emits the one line a boot reads to know the exception fired (L13: silence is data). */
inline void log_self(const char* name, const char* address) noexcept {
    std::array<char, 160> line{};
    const int written = std::snprintf(line.data(),
                                      line.size(),
                                      "ev=egress stage=resolve target=self name=%s addr=%s",
                                      name != nullptr ? name : "(null)",
                                      address);
    if (written > 0) {
        core::log::write(core::log::Channel::client, core::log::Level::info, line.data());
    }
}

} // namespace sunrise::client::hooks::egress::resolver::self_address
