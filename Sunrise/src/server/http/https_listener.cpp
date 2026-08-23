#include "https_listener.h"

#include <WS2tcpip.h>
#include <WinSock2.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string_view>

#include "../../client/network/consumer.h"
#include "../../core/logging/log.h"
#include "../../core/settings/settings.h"
#include "../../middleware/content/manifest/encoder.h"
#include "../../state/content_manifest/content_manifest_state_runtime.h"
#include "../../state/entitlements/entitlement_runtime.h"
#include "server_http.h"
#include "tls.h"

namespace sunrise::server::https {
namespace {

/** The one config manifest route the Client's default config_url names. */
constexpr std::string_view kConfigRoute = "/config/";
/** URL marker shared with the in-process SignOn consumer. */
constexpr std::string_view kSignOnMarker = "/SignOn";
/** One request (request line, headers, and body) fits this fixed window. */
constexpr std::size_t kRequestCapacity = 64 * 1024;
/** The SignOn response needs under 1.2 KiB; 4 KiB matches SPEC A. */
constexpr std::size_t kSignOnResponseCapacity = 4 * 1024;
/** The manifest body needs headroom for 4000 package rows plus entitlements. */
constexpr std::size_t kManifestCapacity = 2 * 1024 * 1024;
/** One decrypted read delivers at most one full TLS record. */
constexpr std::size_t kReadChunk = tls::kRecordPlaintextCapacity;
/** The accept poll wakes this often, bounding shutdown latency. */
constexpr long kPollIntervalMilliseconds = 50;
/** A stuck connection gives up its socket after this long. */
constexpr DWORD kSocketTimeoutMilliseconds = 2000;
/** HTTP statuses the standalone route table can answer. */
constexpr unsigned kHttpOk = 200;
constexpr unsigned kHttpUnavailable = 503;
constexpr unsigned kHttpInternalError = 500;
constexpr unsigned kHttpNotFound = 404;
constexpr unsigned kHttpLengthRequired = 411;
constexpr unsigned kHttpPayloadTooLarge = 413;
/** Canonical UUID hyphens sit at text offsets 8, 13, 18, and 23. */
constexpr std::array<std::size_t, 4> kGuidHyphens{8, 13, 18, 23};

/** Fixed listener state; the worker thread owns the sockets while running. */
struct Listener {
    SRWLOCK lock{SRWLOCK_INIT};
    SOCKET acceptor{INVALID_SOCKET};
    HANDLE thread{};
    std::atomic_bool running{};
    bool winsockOwned{};
    std::uint32_t connections{};
};

Listener g_listener;
tls::Context g_tlsContext;
std::atomic_bool g_tlsReady{};
/** ContentConfig id served for the whole process lifetime. */
std::array<char, 37> g_servedGuid{};
std::size_t g_servedGuidLength{};
bool g_servedGuidOverride{};
/** One fixed response body, used only by the single listener thread. */
std::array<std::byte, kManifestCapacity> g_responseBody{};

/** @param value ASCII byte. @return True for lowercase hex text. */
[[nodiscard]] bool is_lower_hex(char value) noexcept {
    return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f');
}

/** One framed HTTP request parsed out of the fixed request window. */
struct Request {
    std::string_view method;
    std::string_view target;
    std::string_view contentType;
    std::span<const std::byte> body;
};

/** Caller-owned manifest output carried through the State snapshot visitor. */
struct EncodeContext {
    std::span<std::byte> output;
    std::size_t size{};
};

/**
 * Encodes a borrowed State view into the request's response storage.
 * @param context EncodeContext supplied by the config route.
 * @param view Read-only package rows and the stable public GUID.
 * @return True when the whole body fits.
 */
[[nodiscard]] bool encode_view(void* context, const state::content_manifest::View& view) noexcept {
    auto& encode = *static_cast<EncodeContext*>(context);
    const std::string_view guid =
        g_servedGuidOverride ? std::string_view(g_servedGuid.data(), g_servedGuidLength) : view.guid;
    return middleware::content::manifest::encode(
        state::entitlements::get(), view.rows, guid, encode.output, encode.size);
}

/**
 * Splits one request line into method and target.
 * @param line Bytes up to the CRLF after the request line.
 * @param request Receives the borrowed views.
 * @return True when the line carries one space-separated method and target.
 */
[[nodiscard]] bool parse_request_line(std::string_view line, Request& request) noexcept {
    const std::size_t firstSpace = line.find(' ');
    if (firstSpace == std::string_view::npos || firstSpace == 0) {
        return false;
    }
    const std::size_t secondSpace = line.find(' ', firstSpace + 1);
    if (secondSpace == std::string_view::npos) {
        return false;
    }
    request.method = line.substr(0, firstSpace);
    request.target = line.substr(firstSpace + 1, secondSpace - firstSpace - 1);
    return !request.target.empty();
}

/** @param name Header name. @return True when it equals Content-Length, ignoring case. */
[[nodiscard]] bool is_content_length(std::string_view name) noexcept {
    return name.size() == 14
           && (name[0] == 'c' || name[0] == 'C') && (name[1] == 'o' || name[1] == 'O')
           && (name[2] == 'n' || name[2] == 'N') && (name[3] == 't' || name[3] == 'T')
           && (name[4] == 'e' || name[4] == 'E') && (name[5] == 'n' || name[5] == 'N')
           && (name[6] == 't' || name[6] == 'T') && name[7] == '-'
           && (name[8] == 'L' || name[8] == 'l') && (name[9] == 'e' || name[9] == 'E')
           && (name[10] == 'n' || name[10] == 'N') && (name[11] == 'g' || name[11] == 'G')
           && (name[12] == 't' || name[12] == 'T') && (name[13] == 'h' || name[13] == 'H');
}

/** @param name Header name. @return True when it equals Content-Type, ignoring case. */
[[nodiscard]] bool is_content_type(std::string_view name) noexcept {
    return name.size() == 12
           && (name[0] == 'c' || name[0] == 'C') && (name[1] == 'o' || name[1] == 'O')
           && (name[2] == 'n' || name[2] == 'N') && (name[3] == 't' || name[3] == 'T')
           && (name[4] == 'e' || name[4] == 'E') && (name[5] == 'n' || name[5] == 'N')
           && (name[6] == 't' || name[6] == 'T') && name[7] == '-'
           && (name[8] == 'T' || name[8] == 't') && (name[9] == 'y' || name[9] == 'Y')
           && (name[10] == 'p' || name[10] == 'P') && (name[11] == 'e' || name[11] == 'E');
}

/** @param name Header name. @return True when it equals Transfer-Encoding, ignoring case. */
[[nodiscard]] bool is_transfer_encoding(std::string_view name) noexcept {
    return name.size() == 17
           && (name[0] == 't' || name[0] == 'T') && (name[1] == 'r' || name[1] == 'R')
           && (name[2] == 'a' || name[2] == 'A') && (name[3] == 'n' || name[3] == 'N')
           && (name[4] == 's' || name[4] == 'S') && (name[5] == 'f' || name[5] == 'F')
           && (name[6] == 'e' || name[6] == 'E') && (name[7] == 'r' || name[7] == 'R')
           && name[8] == '-' && (name[9] == 'E' || name[9] == 'e')
           && (name[10] == 'n' || name[10] == 'N') && (name[11] == 'c' || name[11] == 'C')
           && (name[12] == 'o' || name[12] == 'O') && (name[13] == 'd' || name[13] == 'D')
           && (name[14] == 'i' || name[14] == 'I') && (name[15] == 'n' || name[15] == 'N')
           && (name[16] == 'g' || name[16] == 'G');
}

/** @param value Decimal digits. @return True when the value fits a size_t. */
[[nodiscard]] bool parse_decimal(std::string_view value, std::size_t& length) noexcept {
    length = 0;
    if (value.empty()) {
        return false;
    }
    for (const char digit : value) {
        if (digit < '0' || digit > '9') {
            return false;
        }
        const std::size_t next = length * 10 + static_cast<std::size_t>(digit - '0');
        if (next < length) {
            return false;
        }
        length = next;
    }
    return true;
}

/**
 * Parses the request line and headers of one framed request.
 * @param requestLine Bytes through the first CRLF.
 * @param headers Bytes after the request line, through the blank line.
 * @param request Receives the parsed views.
 * @param chunked Receives whether Transfer-Encoding was present.
 * @param contentLength Receives the framed body size, or 0 without a header.
 * @return True when the request line parses and the headers are supported.
 */
[[nodiscard]] bool parse_headers(std::string_view requestLine,
                                 std::string_view headers,
                                 Request& request,
                                 bool& chunked,
                                 std::size_t& contentLength) noexcept {
    chunked = false;
    contentLength = 0;
    if (!parse_request_line(requestLine, request)) {
        return false;
    }
    std::size_t position = 0;
    while (position < headers.size()) {
        const std::size_t lineEnd = headers.find("\r\n", position);
        const std::size_t end =
            lineEnd == std::string_view::npos ? headers.size() : lineEnd;
        const std::string_view line = headers.substr(position, end - position);
        const std::size_t colon = line.find(':');
        if (colon != std::string_view::npos) {
            const std::string_view name = line.substr(0, colon);
            std::string_view value = line.substr(colon + 1);
            while (!value.empty() && value.front() == ' ') {
                value.remove_prefix(1);
            }
            if (is_content_length(name)) {
                if (!parse_decimal(value, contentLength)) {
                    return false;
                }
            } else if (is_content_type(name)) {
                request.contentType = value;
            } else if (is_transfer_encoding(name)) {
                chunked = true;
            }
        }
        if (lineEnd == std::string_view::npos) {
            break;
        }
        position = lineEnd + 2;
    }
    return true;
}

/**
 * Routes one framed request into fixed response storage.
 * @param request Parsed request.
 * @param response Caller-owned response body storage.
 * @param responseSize Receives the body byte count.
 * @param status Receives the HTTP status.
 * @param route Receives the matched route name for the request log.
 */
void route_request(const Request& request,
                   std::span<std::byte> response,
                   std::size_t& responseSize,
                   unsigned& status,
                   std::string_view& route) noexcept {
    responseSize = 0;
    route = "unmatched";
    if (request.method == "POST" && request.target.find(kSignOnMarker) != std::string_view::npos) {
        route = "signon";
        const client::network::HttpRequest httpRequest{
            .url = request.target,
            .contentType = request.contentType,
            .body = request.body,
            .response = response,
        };
        client::network::HttpResponse httpResponse{};
        if (http::consume(httpRequest, httpResponse)) {
            status = kHttpOk;
            responseSize = httpResponse.size;
        } else {
            status = kHttpInternalError;
        }
        return;
    }
    if (request.method == "GET") {
        const std::size_t query = request.target.find('?');
        const std::string_view path = request.target.substr(0, query);
        if (path == kConfigRoute) {
            route = "config";
            EncodeContext context{response, 0};
            if (state::content_manifest::visit_snapshot(&encode_view, &context)) {
                status = kHttpOk;
                responseSize = context.size;
            } else {
                status = kHttpUnavailable;
            }
            return;
        }
    }
    // Unmapped routes finish here with an empty success, mirroring the in-process
    // ContentConfig GET hook (content_config_get_replacement.cpp:182-188): the game's
    // content fetches (the cfg_a/b/c URLs from the SignOn response and the other content
    // endpoints) succeed on HTTP 200 + an empty body and the game proceeds on its local
    // packages. The catch-all is the LAST branch — SignOn and /config/ still match first.
    route = "unmapped";
    status = kHttpOk;
    {
        std::array<char, 128> line{};
        const int written = std::snprintf(line.data(),
                                          line.size(),
                                          "ev=http method=%.*s route=unmapped status=%u",
                                          static_cast<int>(request.method.size()),
                                          request.method.data(),
                                          status);
        if (written > 0) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(written)});
        }
    }
}

/**
 * Writes one complete HTTP response over the TLS connection.
 * @param connection Established TLS connection.
 * @param status HTTP status code.
 * @param body Response body bytes, or empty.
 */
void write_response(tls::Connection& connection, unsigned status, std::span<const std::byte> body) noexcept {
    const char* reason = "Not Found";
    if (status == kHttpOk) {
        reason = "OK";
    } else if (status == kHttpInternalError) {
        reason = "Internal Server Error";
    } else if (status == kHttpUnavailable) {
        reason = "Service Unavailable";
    } else if (status == kHttpLengthRequired) {
        reason = "Length Required";
    } else if (status == kHttpPayloadTooLarge) {
        reason = "Payload Too Large";
    }
    std::array<char, 160> header{};
    const int written = std::snprintf(header.data(),
                                      header.size(),
                                      "HTTP/1.1 %u %s\r\n"
                                      "Content-Type: application/octet-stream\r\n"
                                      "Content-Length: %zu\r\n"
                                      "Cache-Control: no-store\r\n"
                                      "Connection: close\r\n"
                                      "\r\n",
                                      status,
                                      reason,
                                      body.size());
    if (written <= 0) {
        return;
    }
    const auto headerBytes =
        std::as_bytes(std::span(header.data(), static_cast<std::size_t>(written)));
    if (tls::write_application(connection, headerBytes) && !body.empty()) {
        (void)tls::write_application(connection, body);
    }
}

/**
 * Runs one accepted connection through the TLS handshake and one request exchange.
 * @param socket Accepted socket. Owned by this function.
 * @param connectionId Sequence number used by the accept and request logs.
 */
void handle_connection(SOCKET socket, std::uint32_t connectionId) noexcept {
    const DWORD timeout = kSocketTimeoutMilliseconds;
    (void)setsockopt(socket,
                     SOL_SOCKET,
                     SO_RCVTIMEO,
                     reinterpret_cast<const char*>(&timeout),
                     sizeof timeout);
    (void)setsockopt(socket,
                     SOL_SOCKET,
                     SO_SNDTIMEO,
                     reinterpret_cast<const char*>(&timeout),
                     sizeof timeout);

    tls::Connection connection{};
    if (!tls::accept_connection(g_tlsContext, connection, socket)) {
        std::array<char, 96> line{};
        const int written = std::snprintf(line.data(),
                                          line.size(),
                                          "ev=https stage=handshake result=fail conn=%u",
                                          connectionId);
        if (written > 0) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::warn,
                             {line.data(), static_cast<std::size_t>(written)});
        }
        tls::close_connection(connection);
        closesocket(socket);
        return;
    }
    {
        std::array<char, 96> line{};
        const int written = std::snprintf(line.data(),
                                          line.size(),
                                          "ev=https stage=handshake result=ok conn=%u",
                                          connectionId);
        if (written > 0) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(written)});
        }
    }

    // The request window is read in whole TLS records until the blank header line arrives.
    std::array<std::byte, kRequestCapacity> request{};
    std::size_t requestSize = 0;
    std::size_t headerEnd = 0;
    bool headerComplete = false;
    while (!headerComplete) {
        for (std::size_t index = 0; index + 4 <= requestSize; ++index) {
            if (request[index] == static_cast<std::byte>('\r')
                && request[index + 1] == static_cast<std::byte>('\n')
                && request[index + 2] == static_cast<std::byte>('\r')
                && request[index + 3] == static_cast<std::byte>('\n')) {
                headerEnd = index + 4;
                headerComplete = true;
                break;
            }
        }
        if (headerComplete) {
            break;
        }
        if (request.size() - requestSize < kReadChunk) {
            write_response(connection, kHttpPayloadTooLarge, {});
            tls::close_connection(connection);
            closesocket(socket);
            return;
        }
        const auto chunk = std::span(request).subspan(requestSize, kReadChunk);
        const std::int64_t got = tls::read_application(connection, chunk);
        if (got <= 0) {
            tls::close_connection(connection);
            closesocket(socket);
            return;
        }
        requestSize += static_cast<std::size_t>(got);
    }

    const std::string_view headerText =
        std::string_view(reinterpret_cast<const char*>(request.data()), headerEnd);
    const std::size_t requestLineEnd = headerText.find("\r\n");
    const std::string_view requestLine =
        requestLineEnd == std::string_view::npos ? headerText : headerText.substr(0, requestLineEnd);
    const std::string_view headerRest =
        requestLineEnd == std::string_view::npos
            ? std::string_view()
            : headerText.substr(requestLineEnd + 2, headerEnd - requestLineEnd - 4);

    Request parsed{};
    bool chunked = false;
    std::size_t contentLength = 0;
    if (!parse_headers(requestLine, headerRest, parsed, chunked, contentLength)) {
        write_response(connection, kHttpNotFound, {});
        tls::close_connection(connection);
        closesocket(socket);
        return;
    }
    if (chunked || contentLength > request.size() - headerEnd) {
        write_response(connection,
                       chunked ? kHttpLengthRequired : kHttpPayloadTooLarge,
                       {});
        tls::close_connection(connection);
        closesocket(socket);
        return;
    }

    // Header reads deliver whole TLS records, so bytes past the blank line are already-drained
    // body bytes; the drain continues only past them, never re-reading the stream.
    std::size_t bodySize = requestSize - headerEnd;
    while (bodySize < contentLength) {
        if (request.size() - (headerEnd + bodySize) >= kReadChunk) {
            const auto chunk = std::span(request).subspan(headerEnd + bodySize, kReadChunk);
            const std::int64_t got = tls::read_application(connection, chunk);
            if (got <= 0) {
                tls::close_connection(connection);
                closesocket(socket);
                return;
            }
            bodySize += static_cast<std::size_t>(got);
        } else {
            std::array<std::byte, kReadChunk> scratch{};
            const std::int64_t got = tls::read_application(connection, scratch);
            if (got <= 0) {
                tls::close_connection(connection);
                closesocket(socket);
                return;
            }
            const std::size_t needed = contentLength - bodySize;
            const std::size_t take = (std::min)(needed, static_cast<std::size_t>(got));
            std::memcpy(request.data() + headerEnd + bodySize, scratch.data(), take);
            bodySize += take;
        }
    }
    parsed.body = std::span(request).subspan(headerEnd, contentLength);

    unsigned status = kHttpNotFound;
    std::size_t responseSize = 0;
    std::string_view route = "unmatched";
    route_request(parsed, g_responseBody, responseSize, status, route);
    write_response(connection, status, std::span(g_responseBody).first(responseSize));

    {
        std::array<char, 192> line{};
        const int written = std::snprintf(line.data(),
                                          line.size(),
                                          "ev=https stage=request method=%.*s route=%.*s "
                                          "status=%u bytes=%zu conn=%u",
                                          static_cast<int>(parsed.method.size()),
                                          parsed.method.data(),
                                          static_cast<int>(route.size()),
                                          route.data(),
                                          status,
                                          responseSize,
                                          connectionId);
        if (written > 0) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(written)});
        }
    }
    tls::close_connection(connection);
    closesocket(socket);
}

/**
 * Listener worker: polls the acceptor and runs one connection at a time.
 * @return Thread exit code, always zero.
 */
DWORD WINAPI listener_main(void*) noexcept {
    for (;;) {
        if (!g_listener.running.load(std::memory_order_acquire)) {
            break;
        }
        fd_set readable;
        FD_ZERO(&readable);
        FD_SET(g_listener.acceptor, &readable);
        timeval timeout{};
        timeout.tv_sec = 0;
        timeout.tv_usec = kPollIntervalMilliseconds * 1000;
        const int selected = select(0, &readable, nullptr, nullptr, &timeout);
        if (selected == SOCKET_ERROR) {
            if (!g_listener.running.load(std::memory_order_acquire)) {
                break;
            }
            Sleep(static_cast<DWORD>(kPollIntervalMilliseconds));
            continue;
        }
        if (selected == 0 || !FD_ISSET(g_listener.acceptor, &readable)) {
            continue;
        }
        const SOCKET accepted = accept(g_listener.acceptor, nullptr, nullptr);
        if (accepted == INVALID_SOCKET) {
            continue;
        }
        ++g_listener.connections;
        const std::uint32_t connectionId = g_listener.connections;
        {
            std::array<char, 96> line{};
            const int written = std::snprintf(line.data(),
                                              line.size(),
                                              "ev=https stage=accept result=ok conn=%u",
                                              connectionId);
            if (written > 0) {
                core::log::write(core::log::Channel::server,
                                 core::log::Level::info,
                                 {line.data(), static_cast<std::size_t>(written)});
            }
        }
        handle_connection(accepted, connectionId);
    }
    return 0;
}

} // namespace

/** @return True when the text is a canonical ContentConfig fetch id. */
bool valid_config_guid(std::string_view guid) noexcept {
    if (guid.size() != 36) {
        return false;
    }
    for (std::size_t index = 0; index < guid.size(); ++index) {
        bool hyphen = false;
        for (const std::size_t offset : kGuidHyphens) {
            hyphen = hyphen || index == offset;
        }
        if ((hyphen && guid[index] != '-') || (!hyphen && !is_lower_hex(guid[index]))) {
            return false;
        }
    }
    return true;
}

/** Starts the HTTPS listener thread on the configured loopback port. */
bool initialize() noexcept {
    AcquireSRWLockExclusive(&g_listener.lock);
    if (g_listener.running.load(std::memory_order_acquire)) {
        ReleaseSRWLockExclusive(&g_listener.lock);
        return true;
    }

    // The served ContentConfig id is fixed at boot: the configured override when one is set,
    // otherwise the State fingerprint id chosen by the operator's packages scan.
    g_servedGuidOverride = false;
    g_servedGuidLength = 0;
    const std::string_view configured(core::settings::get().server.configGuid.data());
    if (!configured.empty()) {
        g_servedGuidOverride = true;
        g_servedGuidLength = configured.size();
        std::copy(configured.begin(), configured.end(), g_servedGuid.begin());
    }

    if (!tls::initialize(g_tlsContext)) {
        ReleaseSRWLockExclusive(&g_listener.lock);
        return false;
    }
    g_tlsReady.store(true, std::memory_order_release);

    WSADATA winsock{};
    if (WSAStartup(MAKEWORD(2, 2), &winsock) != 0) {
        core::log::write(core::log::Channel::server,
                         core::log::Level::error,
                         "ev=https stage=listen result=fail reason=wsa");
        tls::shutdown(g_tlsContext);
        g_tlsReady.store(false, std::memory_order_release);
        ReleaseSRWLockExclusive(&g_listener.lock);
        return false;
    }
    g_listener.winsockOwned = true;
    g_listener.acceptor = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_listener.acceptor == INVALID_SOCKET) {
        const int error = WSAGetLastError();
        std::array<char, 128> line{};
        const int written = std::snprintf(line.data(),
                                          line.size(),
                                          "ev=https stage=listen result=fail error=%d "
                                          "reason=socket",
                                          error);
        if (written > 0) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::error,
                             {line.data(), static_cast<std::size_t>(written)});
        }
        WSACleanup();
        g_listener.winsockOwned = false;
        tls::shutdown(g_tlsContext);
        g_tlsReady.store(false, std::memory_order_release);
        ReleaseSRWLockExclusive(&g_listener.lock);
        return false;
    }
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(core::settings::get().server.httpsPort);
    const auto& bindOctets = core::settings::get().server.bindAddress;
    address.sin_addr.s_addr = htonl((std::uint32_t(bindOctets[0]) << 24)
                                  | (std::uint32_t(bindOctets[1]) << 16)
                                  | (std::uint32_t(bindOctets[2]) << 8)
                                  | std::uint32_t(bindOctets[3]));
    // The client holds connections to this port for a whole session, so a restart lands
    // inside their TIME_WAIT window and the bind fails. Same option the BAP acceptor sets
    // (bap_listener.cpp); the admin listener needed it for the same reason (2026-08-22).
    BOOL httpsReuse = TRUE;
    (void)setsockopt(g_listener.acceptor,
                     SOL_SOCKET,
                     SO_REUSEADDR,
                     reinterpret_cast<const char*>(&httpsReuse),
                     sizeof httpsReuse);
    if (bind(g_listener.acceptor,
             reinterpret_cast<const sockaddr*>(&address),
             sizeof address)
            == SOCKET_ERROR
        || listen(g_listener.acceptor, 8) == SOCKET_ERROR) {
        // Recorded verbatim: the Client forces port 443, so a bind failure needs elevation or
        // a freed port, never a silent fallback.
        const int error = WSAGetLastError();
        std::array<char, 128> line{};
        const int written = std::snprintf(
            line.data(),
            line.size(),
            "ev=https stage=listen result=fail error=%d port=%u",
            error,
            static_cast<unsigned>(core::settings::get().server.httpsPort));
        if (written > 0) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::error,
                             {line.data(), static_cast<std::size_t>(written)});
        }
        closesocket(g_listener.acceptor);
        g_listener.acceptor = INVALID_SOCKET;
        WSACleanup();
        g_listener.winsockOwned = false;
        tls::shutdown(g_tlsContext);
        g_tlsReady.store(false, std::memory_order_release);
        ReleaseSRWLockExclusive(&g_listener.lock);
        return false;
    }

    g_listener.running.store(true, std::memory_order_release);
    g_listener.thread = CreateThread(nullptr, 0, &listener_main, nullptr, 0, nullptr);
    if (g_listener.thread == nullptr) {
        g_listener.running.store(false, std::memory_order_release);
        closesocket(g_listener.acceptor);
        g_listener.acceptor = INVALID_SOCKET;
        WSACleanup();
        g_listener.winsockOwned = false;
        tls::shutdown(g_tlsContext);
        g_tlsReady.store(false, std::memory_order_release);
        ReleaseSRWLockExclusive(&g_listener.lock);
        return false;
    }
    {
        std::array<char, 96> line{};
        const int written = std::snprintf(line.data(),
                                          line.size(),
                                          "ev=https stage=listen result=ok port=%u",
                                          static_cast<unsigned>(core::settings::get().server.httpsPort));
        if (written > 0) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(written)});
        }
    }
    ReleaseSRWLockExclusive(&g_listener.lock);
    return true;
}

/** Stops the worker thread and releases every socket and credential. */
void shutdown() noexcept {
    g_listener.running.store(false, std::memory_order_release);
    if (g_listener.thread != nullptr) {
        // The worker wakes within one poll interval; a connection in flight may take longer.
        WaitForSingleObject(g_listener.thread, 5000);
        CloseHandle(g_listener.thread);
        g_listener.thread = nullptr;
    }
    AcquireSRWLockExclusive(&g_listener.lock);
    if (g_listener.acceptor != INVALID_SOCKET) {
        closesocket(g_listener.acceptor);
        g_listener.acceptor = INVALID_SOCKET;
    }
    if (g_listener.winsockOwned) {
        WSACleanup();
        g_listener.winsockOwned = false;
    }
    ReleaseSRWLockExclusive(&g_listener.lock);
    if (g_tlsReady.exchange(false, std::memory_order_acq_rel)) {
        tls::shutdown(g_tlsContext);
    }
}

} // namespace sunrise::server::https
