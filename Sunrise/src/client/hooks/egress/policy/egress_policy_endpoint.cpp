#include <array>
#include <cstdint>
#include <cstring>

#include "../../../../core/settings/settings.h"
#include "egress_policy_logging.h"

namespace sunrise::client::hooks::egress::policy {
namespace {

/** Access denied marks every outbound socket call blocked by policy. */
constexpr int kBlockedSocketError = WSAEACCES;
/** The policy accepts one exact IPv4 address, not a range. */
constexpr std::array<unsigned char, 4> kLoopbackOctets{127, 0, 0, 1};

} // namespace

/** Reads the single address every redirected socket operation may reach. */
std::array<unsigned char, 4> redirect_octets() noexcept {
    const core::settings::client::external::Settings& external =
        core::settings::get().client.externalServer;
    if (!external.enabled) {
        return kLoopbackOctets;
    }
    return {external.address[0], external.address[1], external.address[2], external.address[3]};
}

/** Checks one caller-owned socket address without a name lookup. */
bool is_redirect_target(const sockaddr* address, int addressLength) noexcept {
    if (address == nullptr || addressLength < static_cast<int>(sizeof(sockaddr_in))) {
        return false;
    }

    sockaddr_in endpoint{};
    std::memcpy(&endpoint, address, sizeof(endpoint));
    const std::array<unsigned char, 4> octets = redirect_octets();
    return endpoint.sin_family == AF_INET
           && std::memcmp(&endpoint.sin_addr, octets.data(), octets.size()) == 0;
}

/**
 * Reports whether one destination is a directly reachable peer.
 *
 * A posse - the session behind a fireteam - is peer-to-peer: one client hosts and the others
 * connect to it. With every destination rewritten to the server, a second player can never
 * reach the first (claims/posse-transport-options.md). This is the one exception, and it is
 * OFF unless a prefix is configured, in which case the policy is exactly the old one.
 *
 * @param address Caller-owned destination, already known to be AF_INET.
 * @return True only when a prefix is configured and the address falls inside it.
 */
[[nodiscard]] bool is_peer_address(const sockaddr_in& address) noexcept {
    const core::settings::client::external::Settings& external =
        core::settings::get().client.externalServer;
    if (!external.enabled || external.peerPrefixBits == 0 || external.peerPrefixBits > 32) {
        return false;
    }
    // Dotted-quad order on both sides, compared as one big-endian value so the prefix is the
    // high bits exactly as written.
    std::uint32_t destination = 0;
    std::uint32_t subnet = 0;
    std::array<unsigned char, 4> raw{};
    std::memcpy(raw.data(), &address.sin_addr, raw.size());
    for (std::size_t index = 0; index < raw.size(); ++index) {
        destination = (destination << 8) | raw[index];
        subnet = (subnet << 8) | external.peerSubnet[index];
    }
    const std::uint32_t mask =
        external.peerPrefixBits == 32
            ? 0xFFFFFFFFU
            : static_cast<std::uint32_t>(~((1ULL << (32U - external.peerPrefixBits)) - 1ULL));
    return (destination & mask) == (subnet & mask);
}

/** Copies one valid IPv4 endpoint and replaces only its address bytes. */
bool redirect_ipv4(const sockaddr* address, int addressLength, sockaddr_in& redirected) noexcept {
    if (address == nullptr || addressLength < static_cast<int>(sizeof(redirected))) {
        return false;
    }

    std::memcpy(&redirected, address, sizeof(redirected));
    if (redirected.sin_family != AF_INET) {
        return false;
    }
    // A configured peer is reached AS ADDRESSED - the whole point is that the packet arrives at
    // the other client rather than at us. Everything else still redirects to the one server.
    if (is_peer_address(redirected)) {
        return true;
    }
    const std::array<unsigned char, 4> octets = redirect_octets();
    std::memcpy(&redirected.sin_addr, octets.data(), octets.size());
    return true;
}

/** Reads the peer of one connected socket and applies the endpoint policy. */
bool has_redirect_target_peer(SOCKET socket) noexcept {
    sockaddr_storage peer{};
    int peerLength = static_cast<int>(sizeof(peer));
    if (::getpeername(socket, reinterpret_cast<sockaddr*>(&peer), &peerLength) == SOCKET_ERROR) {
        return false;
    }
    if (is_redirect_target(reinterpret_cast<const sockaddr*>(&peer), peerLength)) {
        return true;
    }
    // A socket already connected to a configured peer stays usable, or a posse link would be
    // built by connect() and then refused on every send.
    if (peerLength < static_cast<int>(sizeof(sockaddr_in))) {
        return false;
    }
    sockaddr_in peerAddress{};
    std::memcpy(&peerAddress, &peer, sizeof(peerAddress));
    return peerAddress.sin_family == AF_INET && is_peer_address(peerAddress);
}

/** Applies the fail-closed gate and logs its decision. */
bool allow_socket_call(SocketOperation operation,
                       bool targetsRedirect,
                       bool originalAvailable) noexcept {
    const bool allowed = targetsRedirect && originalAvailable;
    log_decision(operation, targetsRedirect, allowed);
    return allowed;
}

/** @return SOCKET_ERROR after publishing the stable policy error. */
int deny_socket_call() noexcept {
    WSASetLastError(kBlockedSocketError);
    return SOCKET_ERROR;
}

} // namespace sunrise::client::hooks::egress::policy
