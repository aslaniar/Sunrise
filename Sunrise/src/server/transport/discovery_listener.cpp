#include "discovery_listener.h"

#include <WS2tcpip.h>
#include <WinSock2.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <span>

#include "../../core/logging/log.h"

namespace sunrise::server::transport::discovery {
namespace {

/** Demonware discovery uses these two fixed destination ports. */
constexpr std::uint16_t kFirstDiscoveryPort = 3074;
constexpr std::uint16_t kSecondDiscoveryPort = 3075;
/** A NatProbe request is two big-endian 16-bit fields. */
constexpr std::size_t kNatProbeRequestSize = 4;
/** The decoder needs the whole 128-bit NatProbe reply. */
constexpr std::size_t kNatProbeReplySize = 16;
/** The verified IP-discovery request is one type byte and a native-order version. */
constexpr std::size_t kIpDiscoveryRequestSize = 3;
/** Version 2 carries one address in 9 bytes. */
constexpr std::size_t kIpDiscoveryReplySize = 9;
/** NatProbe requests use this fixed big-endian magic value. */
constexpr std::uint16_t kNatProbeMagic = 1;
/** The verified NatProbe state machine sends request indices 1 and 2. */
constexpr std::uint16_t kFirstNatProbeIndex = 1;
constexpr std::uint16_t kSecondNatProbeIndex = 2;
/** IP-discovery reply types fill this inclusive range. */
constexpr unsigned kFirstIpDiscoveryType = 30;
constexpr unsigned kLastIpDiscoveryType = 39;
/** Version 2 picks the single-address IP-discovery reply. */
constexpr std::uint16_t kIpDiscoveryReplyVersion = 2;
/** NatProbe masks protect the echoed address and port fields. */
constexpr std::uint32_t kNatProbeAddressMask = 0x76C3F6BC;
constexpr std::uint16_t kNatProbePortMask = 0xF6BC;
/** A bounded receive window; discovery datagrams are 3-4 bytes. */
constexpr std::size_t kDatagramCapacity = 64;
/** The worker wakes this often, bounding shutdown latency. */
constexpr long kPollIntervalMilliseconds = 50;
/** One wake answers at most this many queued datagrams. */
constexpr unsigned kMaxDatagramsPerWake = 8;

enum class RequestKind {
    none,
    natProbe,
    ipDiscovery,
};

/** Fixed listener state; the worker thread owns both sockets while running. */
struct Listener {
    SRWLOCK lock{SRWLOCK_INIT};
    std::array<SOCKET, 2> sockets{INVALID_SOCKET, INVALID_SOCKET};
    HANDLE thread{};
    std::atomic_bool running{};
    bool winsockOwned{};
};

Listener g_listener;

/** @return One big-endian 16-bit value from a verified request offset. */
[[nodiscard]] std::uint16_t read_big_u16(std::span<const std::byte> input,
                                         std::size_t offset) noexcept {
    return static_cast<std::uint16_t>(std::to_integer<unsigned>(input[offset]) << 8U)
           | static_cast<std::uint16_t>(std::to_integer<unsigned>(input[offset + 1]));
}

/** Writes one big-endian 32-bit value into fixed reply storage. */
void write_big_u32(std::span<std::byte> output, std::size_t offset, std::uint32_t value) noexcept {
    output[offset] = static_cast<std::byte>(value >> 24U);
    output[offset + 1] = static_cast<std::byte>(value >> 16U);
    output[offset + 2] = static_cast<std::byte>(value >> 8U);
    output[offset + 3] = static_cast<std::byte>(value);
}

/** Writes one big-endian 16-bit value into fixed reply storage. */
void write_big_u16(std::span<std::byte> output, std::size_t offset, std::uint16_t value) noexcept {
    output[offset] = static_cast<std::byte>(value >> 8U);
    output[offset + 1] = static_cast<std::byte>(value);
}

/** Writes one little-endian 16-bit value into fixed reply storage. */
void write_little_u16(std::span<std::byte> output,
                      std::size_t offset,
                      std::uint16_t value) noexcept {
    output[offset] = static_cast<std::byte>(value);
    output[offset + 1] = static_cast<std::byte>(value >> 8U);
}

/** @return The verified discovery request kind, or none for unrelated bytes. */
[[nodiscard]] RequestKind classify(std::span<const std::byte> payload) noexcept {
    if (payload.size() == kNatProbeRequestSize && read_big_u16(payload, 0) == kNatProbeMagic) {
        const std::uint16_t index = read_big_u16(payload, 2);
        if (index == kFirstNatProbeIndex || index == kSecondNatProbeIndex) {
            return RequestKind::natProbe;
        }
    }
    if (payload.size() == kIpDiscoveryRequestSize) {
        const unsigned type = std::to_integer<unsigned>(payload.front());
        if (type >= kFirstIpDiscoveryType && type <= kLastIpDiscoveryType) {
            return RequestKind::ipDiscovery;
        }
    }
    return RequestKind::none;
}

/**
 * Builds one exact verified reply and returns its byte count.
 * Mirrors the client-side responder's build_reply byte-for-byte: the NatProbe reply echoes
 * the request and masks the sender address/port; the IP-discovery reply carries the version
 * in little-endian and the address in big-endian.
 */
[[nodiscard]] std::size_t build_reply(RequestKind kind,
                                      std::span<const std::byte> request,
                                      const sockaddr_in& client,
                                      std::span<std::byte> reply) noexcept {
    const std::uint32_t clientIp = ntohl(client.sin_addr.s_addr);
    const std::uint16_t clientPort = ntohs(client.sin_port);
    if (kind == RequestKind::natProbe) {
        reply[0] = request[0];
        reply[1] = request[1];
        reply[2] = request[2];
        reply[3] = request[3];
        write_big_u32(reply, 4, clientIp ^ kNatProbeAddressMask);
        write_big_u16(reply, 8, clientPort ^ kNatProbePortMask);
        return kNatProbeReplySize;
    }
    reply[0] = request[0];
    write_little_u16(reply, 1, kIpDiscoveryReplyVersion);
    write_big_u32(reply, 3, clientIp);
    write_little_u16(reply, 7, clientPort);
    return kIpDiscoveryReplySize;
}

/**
 * Serves one readable discovery socket: answers up to a bounded run of queued datagrams.
 * @param socket One bound loopback UDP socket reported readable.
 */
void serve_socket(SOCKET socket) noexcept {
    for (unsigned served = 0; served < kMaxDatagramsPerWake; ++served) {
        std::array<std::byte, kDatagramCapacity> request{};
        sockaddr_in client{};
        int clientLength = static_cast<int>(sizeof(client));
        const int received = recvfrom(socket,
                                      reinterpret_cast<char*>(request.data()),
                                      static_cast<int>(request.size()),
                                      0,
                                      reinterpret_cast<sockaddr*>(&client),
                                      &clientLength);
        if (received <= 0) {
            break;
        }
        const auto payload = std::span(request).first(static_cast<std::size_t>(received));
        const RequestKind kind = classify(payload);
        if (kind == RequestKind::none || clientLength != static_cast<int>(sizeof(client))
            || client.sin_family != AF_INET) {
            continue;
        }
        std::array<std::byte, kNatProbeReplySize> reply{};
        const std::size_t replySize = build_reply(kind, payload, client, reply);
        if (replySize == 0) {
            continue;
        }
        const int sent = sendto(socket,
                                reinterpret_cast<const char*>(reply.data()),
                                static_cast<int>(replySize),
                                0,
                                reinterpret_cast<const sockaddr*>(&client),
                                static_cast<int>(sizeof(client)));
        if (sent == SOCKET_ERROR) {
            continue;
        }
        std::array<char, 96> line{};
        const int written = std::snprintf(line.data(),
                                          line.size(),
                                          "ev=discovery stage=reply kind=%s result=ok",
                                          kind == RequestKind::natProbe ? "nat_probe"
                                                                        : "ip_discovery");
        if (written > 0) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(written)});
        }
    }
}

/**
 * Listener worker: polls both discovery sockets and answers each readable one.
 * @return Thread exit code, always zero.
 */
DWORD WINAPI listener_main(void*) noexcept {
    for (;;) {
        if (!g_listener.running.load(std::memory_order_acquire)) {
            break;
        }
        fd_set readable;
        FD_ZERO(&readable);
        SOCKET maximum = 0;
        for (const SOCKET socket : g_listener.sockets) {
            if (socket != INVALID_SOCKET) {
                FD_SET(socket, &readable);
                maximum = socket > maximum ? socket : maximum;
            }
        }
        timeval timeout{};
        timeout.tv_sec = 0;
        timeout.tv_usec = kPollIntervalMilliseconds * 1000;
        const int selected =
            select(static_cast<int>(maximum + 1), &readable, nullptr, nullptr, &timeout);
        if (selected == SOCKET_ERROR) {
            if (!g_listener.running.load(std::memory_order_acquire)) {
                break;
            }
            Sleep(static_cast<DWORD>(kPollIntervalMilliseconds));
            continue;
        }
        if (selected == 0) {
            continue;
        }
        for (const SOCKET socket : g_listener.sockets) {
            if (socket != INVALID_SOCKET && FD_ISSET(socket, &readable)) {
                serve_socket(socket);
            }
        }
    }
    return 0;
}

/** Binds one nonblocking loopback UDP socket. @return The socket, or INVALID_SOCKET. */
[[nodiscard]] SOCKET bind_loopback_udp(std::uint16_t port) noexcept {
    const SOCKET created = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (created == INVALID_SOCKET) {
        return INVALID_SOCKET;
    }
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    u_long enabled = 1;
    if (ioctlsocket(created, FIONBIO, &enabled) == SOCKET_ERROR
        || bind(created, reinterpret_cast<const sockaddr*>(&address), sizeof address)
               == SOCKET_ERROR) {
        closesocket(created);
        return INVALID_SOCKET;
    }
    return created;
}

} // namespace

/** Starts the loopback UDP discovery listener thread on ports 3074 and 3075. */
bool initialize() noexcept {
    AcquireSRWLockExclusive(&g_listener.lock);
    if (g_listener.running.load(std::memory_order_acquire)) {
        ReleaseSRWLockExclusive(&g_listener.lock);
        return true;
    }
    WSADATA winsock{};
    if (WSAStartup(MAKEWORD(2, 2), &winsock) != 0) {
        ReleaseSRWLockExclusive(&g_listener.lock);
        return false;
    }
    g_listener.winsockOwned = true;
    g_listener.sockets[0] = bind_loopback_udp(kFirstDiscoveryPort);
    if (g_listener.sockets[0] == INVALID_SOCKET) {
        WSACleanup();
        g_listener.winsockOwned = false;
        ReleaseSRWLockExclusive(&g_listener.lock);
        return false;
    }
    g_listener.sockets[1] = bind_loopback_udp(kSecondDiscoveryPort);
    if (g_listener.sockets[1] == INVALID_SOCKET) {
        closesocket(g_listener.sockets[0]);
        g_listener.sockets[0] = INVALID_SOCKET;
        WSACleanup();
        g_listener.winsockOwned = false;
        ReleaseSRWLockExclusive(&g_listener.lock);
        return false;
    }
    g_listener.running.store(true, std::memory_order_release);
    g_listener.thread = CreateThread(nullptr, 0, &listener_main, nullptr, 0, nullptr);
    if (g_listener.thread == nullptr) {
        g_listener.running.store(false, std::memory_order_release);
        closesocket(g_listener.sockets[1]);
        closesocket(g_listener.sockets[0]);
        g_listener.sockets = {INVALID_SOCKET, INVALID_SOCKET};
        WSACleanup();
        g_listener.winsockOwned = false;
        ReleaseSRWLockExclusive(&g_listener.lock);
        return false;
    }
    for (const std::uint16_t port : {kFirstDiscoveryPort, kSecondDiscoveryPort}) {
        std::array<char, 96> line{};
        const int written = std::snprintf(line.data(),
                                          line.size(),
                                          "ev=discovery stage=listen result=ok port=%u",
                                          static_cast<unsigned>(port));
        if (written > 0) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(written)});
        }
    }
    ReleaseSRWLockExclusive(&g_listener.lock);
    return true;
}

/** Stops the worker thread and closes every discovery socket. */
void shutdown() noexcept {
    g_listener.running.store(false, std::memory_order_release);
    if (g_listener.thread != nullptr) {
        // The worker wakes within one poll interval; a datagram burst may take longer.
        WaitForSingleObject(g_listener.thread, 5000);
        CloseHandle(g_listener.thread);
        g_listener.thread = nullptr;
    }
    AcquireSRWLockExclusive(&g_listener.lock);
    for (SOCKET& socket : g_listener.sockets) {
        if (socket != INVALID_SOCKET) {
            closesocket(socket);
            socket = INVALID_SOCKET;
        }
    }
    if (g_listener.winsockOwned) {
        WSACleanup();
        g_listener.winsockOwned = false;
    }
    ReleaseSRWLockExclusive(&g_listener.lock);
}

} // namespace sunrise::server::transport::discovery
