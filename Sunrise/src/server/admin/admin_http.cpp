#include "admin_http.h"

#include <WS2tcpip.h>
#include <WinSock2.h>
#include <Windows.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string_view>

#include "../../core/filesystem/path.h"
#include "../../core/logging/log.h"
#include "../../state/build_data/cache/internal.h"
#include "../../state/runtime/equipment/configured_equipment_identity.h"
#include "../../state/runtime/runtime.h"
#include "../../state/unlocks/unlocks_runtime.h"
#include "../bap/internal.h"
#include "../persistence/persistence.h"

namespace sunrise::server::admin {
namespace {

/** The Layer-2 admin surface binds this loopback port. */
constexpr std::uint16_t kAdminPort = 8099;
/** Small curl-style requests fit this window. */
constexpr std::size_t kRequestCapacity = 4096;
/** The widest JSON answer (the flags' run list). */
constexpr std::size_t kResponseCapacity = 16384;
/** The worker wakes this often, bounding shutdown latency. */
constexpr long kPollIntervalMilliseconds = 50;

/** Fixed listener state; the worker thread owns the socket while running. */
struct Listener {
    SRWLOCK lock{SRWLOCK_INIT};
    SOCKET socket{INVALID_SOCKET};
    HANDLE thread{};
    std::atomic_bool running{};
    bool winsockOwned{};
};

Listener g_listener;

/** One parsed request line. */
struct Request {
    std::string_view verb{};
    std::string_view path{};
    std::string_view query{};
};

/** @return The value for one query key, or an empty view. */
std::string_view query_value(std::string_view query, std::string_view key) noexcept {
    std::size_t cursor = 0;
    while (cursor < query.size()) {
        const std::size_t ampersand = query.find('&', cursor);
        const std::string_view pair = query.substr(
            cursor, ampersand == std::string_view::npos ? query.size() - cursor
                                                        : ampersand - cursor);
        const std::size_t equals = pair.find('=');
        if (equals != std::string_view::npos && pair.substr(0, equals) == key) {
            return pair.substr(equals + 1);
        }
        if (ampersand == std::string_view::npos) {
            break;
        }
        cursor = ampersand + 1;
    }
    return {};
}

/** Parses one unsigned decimal, clamped to a bound. */
std::uint32_t query_number(std::string_view query,
                           std::string_view key,
                           std::uint32_t fallback) noexcept {
    const std::string_view value = query_value(query, key);
    if (value.empty()) {
        return fallback;
    }
    std::uint32_t parsed = 0;
    for (const char digit : value) {
        if (digit < '0' || digit > '9') {
            return fallback;
        }
        parsed = parsed * 10U + static_cast<std::uint32_t>(digit - '0');
    }
    return parsed;
}

/** Appends one line to the persistent intervention journal (the bookkeeping rule). */
void journal(std::string_view verb, std::string_view args, bool ok) noexcept {
    core::path::Buffer path;
    if (!core::path::artifact_directory(GetModuleHandleW(nullptr), path)
        || !core::path::append(path, L"\\journal.txt")) {
        return;
    }
    const HANDLE file = CreateFileW(path.chars.data(),
                                    FILE_APPEND_DATA,
                                    FILE_SHARE_READ,
                                    nullptr,
                                    OPEN_ALWAYS,
                                    FILE_ATTRIBUTE_NORMAL,
                                    nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return;
    }
    SYSTEMTIME now{};
    GetLocalTime(&now);
    char line[512]{};
    const int written = std::snprintf(line,
                                      sizeof line,
                                      "%04d-%02d-%02d %02d:%02d:%02d %.*s %.*s -> %s\r\n",
                                      static_cast<int>(now.wYear),
                                      static_cast<int>(now.wMonth),
                                      static_cast<int>(now.wDay),
                                      static_cast<int>(now.wHour),
                                      static_cast<int>(now.wMinute),
                                      static_cast<int>(now.wSecond),
                                      static_cast<int>(verb.size()),
                                      verb.data(),
                                      static_cast<int>(args.size()),
                                      args.data(),
                                      ok ? "ok" : "fail");
    if (written > 0) {
        DWORD sent = 0;
        (void)WriteFile(file, line, static_cast<DWORD>(written), &sent, nullptr);
    }
    (void)CloseHandle(file);
}

/** Sends one complete HTTP response and closes the connection. */
void respond(SOCKET client,
             const char* status,
             const char* contentType,
             std::string_view body) noexcept {
    char header[512]{};
    const int written = std::snprintf(header,
                                      sizeof header,
                                      "HTTP/1.1 %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\n"
                                      "Connection: close\r\n\r\n",
                                      status,
                                      contentType,
                                      body.size());
    if (written > 0) {
        (void)::send(client, header, written, 0);
    }
    (void)::send(client, body.data(), static_cast<int>(body.size()), 0);
}

/** The flags' bank for one scope name, or an empty span. */
std::span<const std::uint8_t> flag_bank(std::string_view scope) noexcept {
    const state::unlocks::Table& table = state::unlocks::get();
    if (scope == "account") {
        return table.accountFlags;
    }
    if (scope == "profile") {
        return table.profileFlags;
    }
    if (scope == "character") {
        return table.characterFlags;
    }
    if (scope == "character_object") {
        return table.characterObjectFlags;
    }
    return {};
}

/** Renders one session row into the body. */
std::size_t append_session_row(char* body,
                               std::size_t used,
                               const bap::LadderRow& row) noexcept {
    return used
           + static_cast<std::size_t>(std::snprintf(
               body + used,
               kResponseCapacity - used,
               "%s{\"id\":%u,\"authenticated\":%s,\"family4_active\":%s,"
               "\"family4_version\":%d,\"family0_version\":%d,\"root\":\"0x%llX\","
               "\"repush_armed\":%s}",
               used == 0 ? "" : ",",
               row.id,
               row.authenticated ? "true" : "false",
               row.family4Active ? "true" : "false",
               row.family4Version,
               row.family0Version,
               static_cast<unsigned long long>(row.family4RootSoid),
               row.family4RepushArmed ? "true" : "false"));
}

/** GET /state — the session mirrors. */
void handle_state(SOCKET client) noexcept {
    std::array<bap::LadderRow, bap::kSessionCount> rows{};
    const std::size_t count = bap::ladder_snapshot(rows);
    char body[kResponseCapacity]{};
    std::size_t used = 0;
    used += static_cast<std::size_t>(
        std::snprintf(body, sizeof body, "{\"sessions\":["));
    for (std::size_t index = 0; index < count; ++index) {
        used = append_session_row(body, used, rows[index]);
    }
    used += static_cast<std::size_t>(
        std::snprintf(body + used, kResponseCapacity - used, "],\"count\":%zu}", count));
    respond(client, "200 OK", "application/json", {body, used});
}

/** GET /ladder — the version mirrors, the Layer-1 counters from the horse's mouth. */
void handle_ladder(SOCKET client) noexcept {
    std::array<bap::LadderRow, bap::kSessionCount> rows{};
    const std::size_t count = bap::ladder_snapshot(rows);
    std::int32_t maxFamily4 = 0;
    std::int32_t maxFamily0 = 0;
    char body[kResponseCapacity]{};
    std::size_t used = 0;
    used += static_cast<std::size_t>(
        std::snprintf(body, sizeof body, "{\"sessions\":["));
    for (std::size_t index = 0; index < count; ++index) {
        used = append_session_row(body, used, rows[index]);
        maxFamily4 = rows[index].family4Version > maxFamily4 ? rows[index].family4Version
                                                             : maxFamily4;
        maxFamily0 = rows[index].family0Version > maxFamily0 ? rows[index].family0Version
                                                             : maxFamily0;
    }
    used += static_cast<std::size_t>(
        std::snprintf(body + used,
                      kResponseCapacity - used,
                      "],\"count\":%zu,\"max_family4\":%d,\"max_family0\":%d}",
                      count,
                      maxFamily4,
                      maxFamily0));
    respond(client, "200 OK", "application/json", {body, used});
}

/** GET /flags — the bank summary + the zero runs for one scope. */
void handle_flags(SOCKET client, std::string_view query) noexcept {
    const std::string_view scope = query_value(query, "scope");
    const std::string_view scopeName = scope.empty() ? "account" : scope;
    const std::span<const std::uint8_t> bank = flag_bank(scopeName);
    if (bank.empty()) {
        respond(client, "400 Bad Request", "application/json",
                "{\"ok\":false,\"reason\":\"unknown scope\"}");
        return;
    }
    std::size_t zeros = 0;
    std::size_t twos = 0;
    char body[kResponseCapacity]{};
    std::size_t used = 0;
    used += static_cast<std::size_t>(
        std::snprintf(body, sizeof body, "{\"scope\":\"%.*s\",\"total\":%zu,\"zeros\":",
                      static_cast<int>(scopeName.size()), scopeName.data(), bank.size()));
    // The zero runs first so the counts follow without re-encoding.
    std::size_t runs = 0;
    for (std::size_t index = 0; index < bank.size(); ++index) {
        const std::uint8_t value = bank[index];
        if (value == 0) {
            ++zeros;
        } else if (value == 2) {
            ++twos;
        }
        if (value == 0 && (index == 0 || bank[index - 1] != 0)) {
            ++runs;
        }
    }
    used += static_cast<std::size_t>(std::snprintf(body + used, kResponseCapacity - used,
                                                   "%zu,\"twos\":%zu,\"runs\":[", zeros, twos));
    bool firstRun = true;
    for (std::size_t index = 0; index < bank.size();) {
        if (bank[index] != 0) {
            ++index;
            continue;
        }
        const std::size_t start = index;
        while (index < bank.size() && bank[index] == 0) {
            ++index;
        }
        used += static_cast<std::size_t>(std::snprintf(
            body + used, kResponseCapacity - used, "%s[%zu,%zu]", firstRun ? "" : ",",
            start, index - 1));
        firstRun = false;
    }
    used += static_cast<std::size_t>(std::snprintf(body + used, kResponseCapacity - used,
                                                   "],\"run_count\":%zu}", runs));
    respond(client, "200 OK", "application/json", {body, used});
}

/** GET /journal — the intervention history. */
void handle_journal(SOCKET client) noexcept {
    core::path::Buffer path;
    if (!core::path::artifact_directory(GetModuleHandleW(nullptr), path)
        || !core::path::append(path, L"\\journal.txt")) {
        respond(client, "500 Internal Server Error", "text/plain", "journal unavailable");
        return;
    }
    const HANDLE file = CreateFileW(path.chars.data(),
                                    GENERIC_READ,
                                    FILE_SHARE_READ,
                                    nullptr,
                                    OPEN_EXISTING,
                                    FILE_ATTRIBUTE_NORMAL,
                                    nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        respond(client, "200 OK", "text/plain", "(the journal is empty)\n");
        return;
    }
    char buffer[8192]{};
    DWORD read = 0;
    const BOOL ok = ReadFile(file, buffer, sizeof buffer - 1, &read, nullptr);
    (void)CloseHandle(file);
    respond(client, "200 OK", "text/plain",
            ok ? std::string_view{buffer, read} : std::string_view{"(read failed)\n"});
}

/** POST /suppress + /restore — one flag range, the runtime + the DB + the journal. */
void handle_flag_write(SOCKET client,
                       std::string_view query,
                       std::uint8_t value,
                       std::string_view verbName) noexcept {
    const std::string_view scope = query_value(query, "scope");
    const std::string_view scopeName = scope.empty() ? "account" : scope;
    const std::uint32_t first = query_number(query, "first", 0);
    const std::uint32_t last = query_number(query, "last", 0);
    const std::span<const std::uint8_t> bank = flag_bank(scopeName);
    const bool bounded = !bank.empty() && first <= last && last < bank.size();
    const bool ok = bounded
                    && state::unlocks::mutate_flags(scopeName, first, last, value)
                    && sunrise::server::persistence::update_flag_range(
                        scopeName, first, last, value);
    char args[128]{};
    const int argsWritten = std::snprintf(args,
                                          sizeof args,
                                          "scope=%.*s first=%u last=%u value=%u",
                                          static_cast<int>(scopeName.size()),
                                          scopeName.data(),
                                          first,
                                          last,
                                          value);
    journal(verbName,
            argsWritten > 0 ? std::string_view{args, static_cast<std::size_t>(argsWritten)}
                            : std::string_view{"bad args"},
            ok);
    char body[512]{};
    const int written = std::snprintf(
        body,
        sizeof body,
        "{\"ok\":%s,\"scope\":\"%.*s\",\"first\":%u,\"last\":%u,\"value\":%u}",
        ok ? "true" : "false",
        static_cast<int>(scopeName.size()),
        scopeName.data(),
        first,
        last,
        value);
    respond(client, ok ? "200 OK" : "400 Bad Request", "application/json",
            {body, static_cast<std::size_t>(written)});
}

/** POST /restamp — the eqHash repair as a verb (the identity-pair bookkeeping). */
void handle_restamp(SOCKET client) noexcept {
    const std::uint64_t hash =
        state::runtime::equipment::configured_hash(state::account_snapshot());
    const bool ok = state::build_data::cache::restamp_equipment_hash(hash);
    char args[64]{};
    const int argsWritten =
        std::snprintf(args, sizeof args, "eqHash=0x%016llX", static_cast<unsigned long long>(hash));
    journal("restamp",
            argsWritten > 0 ? std::string_view{args, static_cast<std::size_t>(argsWritten)}
                            : std::string_view{""},
            ok);
    char body[256]{};
    const int written = std::snprintf(
        body, sizeof body, "{\"ok\":%s,\"eqHash\":\"0x%016llX\"}", ok ? "true" : "false",
        static_cast<unsigned long long>(hash));
    respond(client, ok ? "200 OK" : "500 Internal Server Error", "application/json",
            {body, static_cast<std::size_t>(written)});
}

/** POST /repush — arms the deferred Family-4 re-push on every active session. */
void handle_repush(SOCKET client) noexcept {
    const std::size_t armed = bap::arm_deferred_repush();
    char args[32]{};
    const int argsWritten = std::snprintf(args, sizeof args, "armed=%zu", armed);
    journal("repush",
            argsWritten > 0 ? std::string_view{args, static_cast<std::size_t>(argsWritten)}
                            : std::string_view{""},
            armed != 0);
    char body[128]{};
    const int written = std::snprintf(body, sizeof body, "{\"ok\":true,\"armed\":%zu}", armed);
    respond(client, "200 OK", "application/json",
            {body, static_cast<std::size_t>(written)});
}

/** Serves one accepted connection end to end. */
void serve_connection(SOCKET client) noexcept {
    char buffer[kRequestCapacity]{};
    const int received = ::recv(client, buffer, sizeof buffer - 1, 0);
    if (received <= 0) {
        (void)closesocket(client);
        return;
    }
    buffer[received] = '\0';
    // The first line: "VERB /path?query HTTP/1.1".
    const char* lineEnd = std::strstr(buffer, "\r\n");
    if (lineEnd == nullptr) {
        lineEnd = buffer + received;
    }
    Request request{};
    const std::string_view line{buffer, static_cast<std::size_t>(lineEnd - buffer)};
    const std::size_t firstSpace = line.find(' ');
    const std::size_t secondSpace = firstSpace == std::string_view::npos
                                        ? std::string_view::npos
                                        : line.find(' ', firstSpace + 1);
    if (firstSpace == std::string_view::npos || secondSpace == std::string_view::npos) {
        respond(client, "400 Bad Request", "application/json", "{\"ok\":false}");
        (void)closesocket(client);
        return;
    }
    request.verb = line.substr(0, firstSpace);
    const std::string_view target = line.substr(firstSpace + 1, secondSpace - firstSpace - 1);
    const std::size_t question = target.find('?');
    request.path = question == std::string_view::npos ? target : target.substr(0, question);
    request.query = question == std::string_view::npos ? std::string_view{} : target.substr(question + 1);

    if (request.verb == "GET" && request.path == "/state") {
        handle_state(client);
    } else if (request.verb == "GET" && request.path == "/ladder") {
        handle_ladder(client);
    } else if (request.verb == "GET" && request.path == "/flags") {
        handle_flags(client, request.query);
    } else if (request.verb == "GET" && request.path == "/journal") {
        handle_journal(client);
    } else if (request.verb == "POST" && request.path == "/suppress") {
        handle_flag_write(client, request.query, 0, "suppress");
    } else if (request.verb == "POST" && request.path == "/restore") {
        handle_flag_write(client, request.query, state::unlocks::kFlagSet, "restore");
    } else if (request.verb == "POST" && request.path == "/restamp") {
        handle_restamp(client);
    } else if (request.verb == "POST" && request.path == "/repush") {
        handle_repush(client);
    } else {
        respond(client, "404 Not Found", "application/json", "{\"ok\":false,\"reason\":\"no such verb\"}");
    }
    (void)closesocket(client);
}

/** The accept loop: one wake at most answers one pending connection. */
DWORD WINAPI listener_main(void*) noexcept {
    for (;;) {
        if (!g_listener.running.load(std::memory_order_acquire)) {
            break;
        }
        fd_set readable;
        FD_ZERO(&readable);
        FD_SET(g_listener.socket, &readable);
        timeval timeout{};
        timeout.tv_sec = 0;
        timeout.tv_usec = kPollIntervalMilliseconds * 1000;
        const int selected =
            select(static_cast<int>(g_listener.socket) + 1, &readable, nullptr, nullptr, &timeout);
        if (selected == SOCKET_ERROR) {
            if (!g_listener.running.load(std::memory_order_acquire)) {
                break;
            }
            Sleep(static_cast<DWORD>(kPollIntervalMilliseconds));
            continue;
        }
        if (selected == 0 || !FD_ISSET(g_listener.socket, &readable)) {
            continue;
        }
        sockaddr_in peer{};
        int peerSize = sizeof peer;
        const SOCKET client = accept(g_listener.socket,
                                     reinterpret_cast<sockaddr*>(&peer),
                                     &peerSize);
        if (client != INVALID_SOCKET) {
            serve_connection(client);
        }
    }
    return 0;
}

/** Binds the loopback TCP listener. */
[[nodiscard]] SOCKET bind_loopback_tcp(std::uint16_t port) noexcept {
    const SOCKET created = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (created == INVALID_SOCKET) {
        return INVALID_SOCKET;
    }
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(created, reinterpret_cast<const sockaddr*>(&address), sizeof address)
            == SOCKET_ERROR
        || listen(created, SOMAXCONN) == SOCKET_ERROR) {
        (void)closesocket(created);
        return INVALID_SOCKET;
    }
    return created;
}

} // namespace

/** Starts the loopback admin HTTP listener. */
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
    g_listener.socket = bind_loopback_tcp(kAdminPort);
    if (g_listener.socket == INVALID_SOCKET) {
        core::log::write(core::log::Channel::server,
                         core::log::Level::warn,
                         "ev=admin stage=listen result=fail reason=bind");
        ReleaseSRWLockExclusive(&g_listener.lock);
        return false;
    }
    g_listener.running.store(true, std::memory_order_release);
    g_listener.thread = CreateThread(nullptr, 0, listener_main, nullptr, 0, nullptr);
    if (g_listener.thread == nullptr) {
        g_listener.running.store(false, std::memory_order_release);
        (void)closesocket(g_listener.socket);
        g_listener.socket = INVALID_SOCKET;
        ReleaseSRWLockExclusive(&g_listener.lock);
        return false;
    }
    std::array<char, core::log::kLineCapacity> line{};
    const int written = std::snprintf(
        line.data(), line.size(), "ev=admin stage=listen result=ok port=%u", kAdminPort);
    if (written > 0) {
        core::log::write(core::log::Channel::server,
                         core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(written)});
    }
    ReleaseSRWLockExclusive(&g_listener.lock);
    return true;
}

/** Stops the admin listener and joins its thread. */
void shutdown() noexcept {
    AcquireSRWLockExclusive(&g_listener.lock);
    const bool wasRunning = g_listener.running.load(std::memory_order_acquire);
    g_listener.running.store(false, std::memory_order_release);
    if (g_listener.socket != INVALID_SOCKET) {
        (void)closesocket(g_listener.socket);
        g_listener.socket = INVALID_SOCKET;
    }
    const HANDLE thread = g_listener.thread;
    g_listener.thread = nullptr;
    ReleaseSRWLockExclusive(&g_listener.lock);
    if (wasRunning && thread != nullptr) {
        (void)WaitForSingleObject(thread, 2000);
        (void)CloseHandle(thread);
    }
}

} // namespace sunrise::server::admin
