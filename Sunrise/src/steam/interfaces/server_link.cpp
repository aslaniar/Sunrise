#include "server_link.h"

#include <WS2tcpip.h>
#include <WinSock2.h>
#include <Windows.h>

#include <cstdint>
#include <cstdio>
#include <cstring>

#include "../../core/settings/settings.h"

namespace sunrise::steam::interfaces {
namespace {

/** Admin listener port on the standalone server. Plaintext; see the header note. */
constexpr std::uint16_t kPresencePort = 8099;
/** A LAN round trip is sub-millisecond; this only bounds the case where nothing answers. */
constexpr DWORD kSocketTimeoutMilliseconds = 1500;

} // namespace

/**
 * One plaintext HTTP/1.1 exchange with the server's admin listener.
 * @param body Response body, null terminated. May be null when the answer is not read.
 * @return HTTP status code, or 0 when the exchange did not complete.
 */
unsigned http_exchange(const char* verb,
                       const char* target,
                       char* body,
                       std::size_t capacity) noexcept {
    if (body != nullptr && capacity > 0) {
        body[0] = '\0';
    }
    const char* host = core::settings::get().client.externalServer.host.data();
    if (host == nullptr || host[0] == '\0') {
        return 0;
    }
    WSADATA winsock{};
    // Refcounted: the Client is long past its own WSAStartup, so this only adds a reference.
    if (WSAStartup(MAKEWORD(2, 2), &winsock) != 0) {
        return 0;
    }
    unsigned status = 0;
    const SOCKET handle = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (handle != INVALID_SOCKET) {
        DWORD timeout = kSocketTimeoutMilliseconds;
        (void)::setsockopt(handle, SOL_SOCKET, SO_RCVTIMEO,
                           reinterpret_cast<const char*>(&timeout), sizeof timeout);
        (void)::setsockopt(handle, SOL_SOCKET, SO_SNDTIMEO,
                           reinterpret_cast<const char*>(&timeout), sizeof timeout);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(kPresencePort);
        // The host is always a dotted quad here (settings store it as one), so no resolver
        // is involved - and no resolver hook can rewrite what was never looked up.
        if (::inet_pton(AF_INET, host, &address.sin_addr) == 1
            && ::connect(handle, reinterpret_cast<const sockaddr*>(&address), sizeof address) == 0) {
            char request[512]{};
            const int requestSize = std::snprintf(
                request, sizeof request,
                "%s %s HTTP/1.1\r\nHost: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                verb, target, host);
            if (requestSize > 0 && ::send(handle, request, requestSize, 0) == requestSize) {
                char response[2048]{};
                std::size_t used = 0;
                for (;;) {
                    const int received = ::recv(handle, response + used,
                                                static_cast<int>(sizeof response - 1 - used), 0);
                    if (received <= 0) {
                        break;
                    }
                    used += static_cast<std::size_t>(received);
                    if (used >= sizeof response - 1) {
                        break;
                    }
                }
                response[used] = '\0';
                unsigned code = 0;
                if (std::sscanf(response, "HTTP/1.%*u %u", &code) == 1) {
                    status = code;
                }
                const char* separator = std::strstr(response, "\r\n\r\n");
                if (body != nullptr && capacity > 0 && separator != nullptr) {
                    std::snprintf(body, capacity, "%s", separator + 4);
                }
            }
        }
        (void)::closesocket(handle);
    }
    (void)WSACleanup();
    return status;
}


} // namespace sunrise::steam::interfaces
