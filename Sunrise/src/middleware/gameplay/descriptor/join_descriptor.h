#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace sunrise::middleware::gameplay::descriptor {

/** The join descriptor is exactly 128 bytes, and a different count makes it absent. */
inline constexpr std::size_t kDescriptorSize = 128;

/** A peer NetAddr is exactly 86 bytes wherever it appears. */
inline constexpr std::size_t kNetAddrSize = 86;

/** Everything one direct-path join descriptor publishes. */
struct JoinEndpoint {
    /** Nonzero machine identity. A zero identity makes the descriptor read as absent. */
    std::uint64_t machineId{};
    /** Advertised IPv4 in host order. */
    std::uint32_t address{};
    /** Advertised UDP port in host order. It must be even. */
    std::uint16_t port{};
    /** Nonzero online session id. Its low 64 bits are the lobby the client joins. */
    std::uint64_t onlineSessionId{};
};

/**
 * Everything one decoder recovers from a descriptor another party published.
 * The writer's mirror: we have always built these and never read one, so a peer's advertised
 * endpoint has never been inspected (FINDINGS 20.38).
 */
struct JoinReading {
    /** Machine identity, local entry 0 address and port, and the online session id. */
    JoinEndpoint endpoint{};
    /** Public-entry IPv4 in host order. Zero means the descriptor carries no public entry. */
    std::uint32_t publicAddress{};
    /** Public-entry UDP port in host order. */
    std::uint16_t publicPort{};
    /** NAT type byte. 1 reads as open; zero leaves the address unroutable. */
    std::uint8_t natType{};
    /** Transport method. 0 is the direct path; 6 and 7 select the relay. */
    std::uint8_t method{};
};

/**
 * Reads one published join descriptor.
 * Total inverse of build(): every field build() writes, this recovers, so a descriptor we
 * forward can be checked against what the peer must actually be reachable at.
 * @param input All 128 published bytes.
 * @param output Receives every recovered field, whether or not the descriptor is usable.
 * @return True when the reading names a routable direct-path endpoint, matching build()'s
 *         own acceptance rule plus a public entry, without which the client falls back to
 *         NAT traversal.
 */
[[nodiscard]] bool read(const std::array<std::byte, kDescriptorSize>& input,
                        JoinReading& output) noexcept;

/**
 * Builds one NetAddr for the direct method-0 path.
 * The endpoint goes in twice, as local entry 0 and as the public entry. A peer with no public
 * entry is unroutable and the client falls back to NAT traversal.
 * @param address IPv4 in host order.
 * @param port UDP port in host order.
 * @param output Receives all 86 bytes.
 */
void write_net_addr(std::uint32_t address,
                    std::uint16_t port,
                    std::array<std::byte, kNetAddrSize>& output) noexcept;

/**
 * Builds one join descriptor for the direct method-0 path.
 * @param endpoint Advertised identity and endpoint.
 * @param output Receives all 128 bytes only on success.
 * @return True when the identity, address, port, and session id are all usable.
 */
[[nodiscard]] bool build(const JoinEndpoint& endpoint,
                         std::array<std::byte, kDescriptorSize>& output) noexcept;

} // namespace sunrise::middleware::gameplay::descriptor
