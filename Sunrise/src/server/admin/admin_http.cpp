#include "admin_http.h"
#include "dashboard_page.h"

#include <WS2tcpip.h>
#include <WinSock2.h>
#include <Windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iterator>
#include <limits>
#include <optional>
#include <span>
#include <string_view>

#include "../../core/filesystem/path.h"
#include "../../core/logging/log.h"
#include "../../core/logging/snapshot/snapshot.h"
#include "../../core/logging/view/log_snapshot_view.h"
#include "../../core/settings/address_text.h"
#include "../../core/settings/settings.h"
#include "../../state/build_data/cache/internal.h"
#include "../../state/runtime/equipment/configured_equipment_identity.h"
#include "../../state/runtime/runtime.h"
#include "../../state/unlocks/unlocks_runtime.h"
#include "../bap/internal.h"
#include "../http/presence_state.h"
#include "../persistence/persistence.h"

namespace sunrise::server::admin {
namespace {

/** The Layer-2 admin surface binds this loopback port. */
constexpr std::uint16_t kAdminPort = 8099;
/** Small curl-style requests fit this window. */
constexpr std::size_t kRequestCapacity = 4096;
/** The widest JSON answer (the flags' run list). */
constexpr std::size_t kResponseCapacity = 16384;
/** The event feed pages fit this window; the snapshot itself is ~4 MiB. */
constexpr std::size_t kEventsResponseCapacity = 65536;
/** Room the row loop must leave for the closing "],\"emitted\":..,\"next\":..}" object. */
constexpr std::size_t kEventsTailReserve = 96;
/** One event page carries this many rows before the budget truncates it. */
constexpr std::uint32_t kEventsPageDefault = 300;
/** A caller may never page more than this many rows at once. */
constexpr std::uint32_t kEventsPageMaximum = 512;
/** One escaped row never needs more than this much working space. */
constexpr std::size_t kEventsRowEscapedCapacity = 8192;
/**
 * The events route stacks a value-owned 4096-entry snapshot (~4 MiB) plus
 * this page buffer, over the 1 MiB default thread stack. The worker thread
 * gets the server main thread's stack size instead.
 */
constexpr std::size_t kListenerThreadStackBytes = 8 * 1024 * 1024;
/** The worker wakes this often, bounding shutdown latency. */
constexpr long kPollIntervalMilliseconds = 50;

/** Names are the wire contract; indices must track the Channel enum. */
constexpr std::string_view kChannelNames[]{"core", "client", "state", "server", "middleware"};
static_assert(std::size(kChannelNames) == static_cast<std::size_t>(core::log::Channel::count),
              "channel names must enumerate every logging channel");
/** Names are the wire contract; indices must track the Level enum. */
constexpr std::string_view kLevelNames[]{"error", "warn", "info", "debug", "off"};
static_assert(std::size(kLevelNames) == static_cast<std::size_t>(core::log::Level::off) + 1,
              "level names must enumerate every logging level");

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

/** Parses one unsigned decimal cursor, clamped to a bound. */
std::uint64_t query_u64(std::string_view query,
                        std::string_view key,
                        std::uint64_t fallback) noexcept {
    const std::string_view value = query_value(query, key);
    if (value.empty()) {
        return fallback;
    }
    std::uint64_t parsed = 0;
    for (const char digit : value) {
        if (digit < '0' || digit > '9') {
            return fallback;
        }
        const std::uint64_t added = static_cast<std::uint64_t>(digit - '0');
        if (parsed > ((std::numeric_limits<std::uint64_t>::max)() - added) / 10U) {
            return fallback;
        }
        parsed = parsed * 10U + added;
    }
    return parsed;
}

/**
 * Decodes one query value's %XX escapes into ASCII storage.
 * The view's text filter is bounded, so an over-long query truncates.
 * @param encoded Borrowed percent-encoded text.
 * @param output Receives decoded bytes; never null-terminated by this call.
 * @return Bytes written, at most the output size.
 */
std::size_t decode_query_text(std::string_view encoded, std::span<char> output) noexcept {
    const auto hex_digit = [](char value) noexcept -> int {
        if (value >= '0' && value <= '9') {
            return value - '0';
        }
        if (value >= 'a' && value <= 'f') {
            return value - 'a' + 10;
        }
        if (value >= 'A' && value <= 'F') {
            return value - 'A' + 10;
        }
        return -1;
    };
    std::size_t written = 0;
    for (std::size_t index = 0; index < encoded.size() && written < output.size(); ++index) {
        const char value = encoded[index];
        if (value == '%' && index + 2 < encoded.size()) {
            const int high = hex_digit(encoded[index + 1]);
            const int low = hex_digit(encoded[index + 2]);
            if (high >= 0 && low >= 0) {
                output[written++] = static_cast<char>((high << 4) | low);
                index += 2;
                continue;
            }
        }
        output[written++] = value;
    }
    return written;
}

/** @return The channel one name denotes, or the channel count when unknown. */
std::size_t channel_index(std::string_view name) noexcept {
    for (std::size_t index = 0; index < std::size(kChannelNames); ++index) {
        if (kChannelNames[index] == name) {
            return index;
        }
    }
    return std::size(kChannelNames);
}

/** @return The level one name denotes, or the level count when unknown. */
std::size_t level_index(std::string_view name) noexcept {
    for (std::size_t index = 0; index < std::size(kLevelNames); ++index) {
        if (kLevelNames[index] == name) {
            return index;
        }
    }
    return std::size(kLevelNames);
}

/**
 * JSON-escapes one text value into fixed storage.
 * Quotes, backslashes, and control bytes are escaped; higher bytes pass
 * through raw because the structured log lines are ASCII by convention.
 * @param output Receives the escaped text and a trailing null.
 * @param capacity Bytes available at output.
 * @param text Borrowed value to escape.
 * @return Escaped length, truncated to what fits.
 */
std::size_t escape_json_text(char* output, std::size_t capacity, std::string_view text) noexcept {
    std::size_t used = 0;
    for (const char value : text) {
        const auto byte = static_cast<unsigned char>(value);
        if (value == '"' || value == '\\') {
            if (used + 2 >= capacity) {
                break;
            }
            output[used++] = '\\';
            output[used++] = value;
        } else if (byte < 0x20) {
            const int written = std::snprintf(output + used, capacity - used, "\\u%04X", byte);
            if (written <= 0 || static_cast<std::size_t>(written) >= capacity - used) {
                break;
            }
            used += static_cast<std::size_t>(written);
        } else {
            if (used + 1 >= capacity) {
                break;
            }
            output[used++] = value;
        }
    }
    output[used] = '\0';
    return used;
}

/**
 * Composes one event row into the response body.
 * @param body Response storage.
 * @param capacity Bytes available at body.
 * @param used Bytes written so far, raised only when the whole row fits.
 * @param entry Event to serialize.
 * @param first True when no row was written yet.
 * @return False when the row would exceed the remaining budget.
 */
bool append_event_row(char* body,
                      std::size_t capacity,
                      std::size_t& used,
                      const core::log::snapshot::Entry& entry,
                      bool first) noexcept {
    char escaped[kEventsRowEscapedCapacity]{};
    (void)escape_json_text(escaped, sizeof escaped, entry.text());
    const std::size_t channel =
        static_cast<std::size_t>(entry.channel());
    const std::size_t level = static_cast<std::size_t>(entry.level());
    const int written = std::snprintf(body + used,
                                      capacity - used,
                                      "%s{\"seq\":%llu,\"channel\":\"%.*s\",\"level\":\"%.*s\","
                                      "\"text\":\"%s\"}",
                                      first ? "" : ",",
                                      static_cast<unsigned long long>(entry.sequence()),
                                      static_cast<int>(kChannelNames[channel].size()),
                                      kChannelNames[channel].data(),
                                      static_cast<int>(kLevelNames[level].size()),
                                      kLevelNames[level].data(),
                                      escaped);
    if (written <= 0 || static_cast<std::size_t>(written) >= capacity - used) {
        return false;
    }
    used += static_cast<std::size_t>(written);
    return true;
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

/** Renders one session row into the body. @param first False for rows after the first. */
std::size_t append_session_row(char* body,
                               std::size_t used,
                               bool first,
                               const bap::LadderRow& row) noexcept {
    return used
           + static_cast<std::size_t>(std::snprintf(
               body + used,
               kResponseCapacity - used,
               "%s{\"id\":%u,\"authenticated\":%s,\"family4_active\":%s,"
               "\"family4_version\":%d,\"family0_version\":%d,\"root\":\"0x%llX\","
               "\"repush_armed\":%s}",
               first ? "" : ",",
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
        used = append_session_row(body, used, index == 0, rows[index]);
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
        used = append_session_row(body, used, index == 0, rows[index]);
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
    // snprintf returns the length it WOULD have written, so an overflowing append pushes
    // `used` past the buffer; `kResponseCapacity - used` is size_t and underflows to a huge
    // value, handing every later append an effectively unbounded size and writing off the end
    // of this stack buffer. Clamp after every write, and stop emitting runs while the closing
    // object still fits. A fragmented bank can produce far more runs than 16 KiB holds
    // (measured 2026-08-22: account 333 runs / 3,998 B; the buffer fills near 1,260 runs).
    const auto remaining = [&used]() noexcept -> std::size_t {
        return used < kResponseCapacity ? kResponseCapacity - used : 0;
    };
    const auto advance = [&used](int written) noexcept {
        if (written <= 0) {
            return;
        }
        used += static_cast<std::size_t>(written);
        if (used >= kResponseCapacity) {
            used = kResponseCapacity - 1;
        }
    };
    advance(std::snprintf(body, sizeof body, "{\"scope\":\"%.*s\",\"total\":%zu,\"zeros\":",
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
    advance(std::snprintf(body + used, remaining(), "%zu,\"twos\":%zu,\"runs\":[",
                          zeros, twos));
    // Room for the closing "],\"run_count\":N,\"truncated\":true}" in the worst case.
    constexpr std::size_t kTailReserve = 64;
    bool firstRun = true;
    bool truncated = false;
    for (std::size_t index = 0; index < bank.size();) {
        if (bank[index] != 0) {
            ++index;
            continue;
        }
        const std::size_t start = index;
        while (index < bank.size() && bank[index] == 0) {
            ++index;
        }
        if (remaining() <= kTailReserve) {
            truncated = true;
            break;
        }
        advance(std::snprintf(body + used, remaining(), "%s[%zu,%zu]", firstRun ? "" : ",",
                              start, index - 1));
        firstRun = false;
    }
    advance(std::snprintf(body + used, remaining(), "],\"run_count\":%zu,\"truncated\":%s}",
                          runs, truncated ? "true" : "false"));
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

/** GET / — the self-contained dashboard page. */
void handle_dashboard(SOCKET client) noexcept {
    respond(client, "200 OK", "text/html; charset=utf-8", dashboard_page());
}

/**
 * GET /events — one paged, filtered page of the in-process log ring.
 * Filtering happens server-side through the same view the in-game panel
 * uses; the page's cursor is the monotonic log sequence, so a consumer can
 * detect events the ring overwrote between polls.
 */
void handle_events(SOCKET client, std::string_view query) noexcept {
    const std::uint64_t since = query_u64(query, "since", 0);
    const std::uint32_t limit = query_number(query, "limit", kEventsPageDefault);
    const std::uint32_t pageLimit = (std::min)(limit, kEventsPageMaximum);

    const std::string_view channelName = query_value(query, "channel");
    const std::string_view levelName = query_value(query, "level");
    core::log::view::Filter filter{};
    if (!channelName.empty() && channelName != "all") {
        const std::size_t index = channel_index(channelName);
        if (index == std::size(kChannelNames)) {
            respond(client, "400 Bad Request", "application/json",
                    "{\"ok\":false,\"reason\":\"unknown channel\"}");
            return;
        }
        filter.channel = static_cast<core::log::Channel>(index);
    }
    if (!levelName.empty() && levelName != "all") {
        const std::size_t index = level_index(levelName);
        if (index == std::size(kLevelNames)) {
            respond(client, "400 Bad Request", "application/json",
                    "{\"ok\":false,\"reason\":\"unknown level\"}");
            return;
        }
        filter.level = static_cast<core::log::Level>(index);
    }
    std::array<char, core::log::view::kTextFilterCapacity> textQuery{};
    const std::size_t textLength =
        decode_query_text(query_value(query, "text"), textQuery);
    if (textLength != 0) {
        (void)core::log::view::set_text(filter, {textQuery.data(), textLength});
    }

    // The snapshot is value-owned (~4 MiB at the server ring size); the
    // listener thread carries kListenerThreadStackBytes for this purpose.
    const core::log::snapshot::Snapshot snapshot = core::log::snapshot::take();
    const core::log::view::Result result = core::log::view::select(snapshot, filter);

    char body[kEventsResponseCapacity]{};
    std::size_t used = 0;
    if (filter.channel.has_value()) {
        const std::string_view name =
            kChannelNames[static_cast<std::size_t>(*filter.channel)];
        used += static_cast<std::size_t>(std::snprintf(
            body,
            sizeof body,
            "{\"since\":%llu,\"limit\":%u,\"count\":%zu,\"first\":%llu,\"last\":%llu,"
            "\"channel\":\"%.*s\",",
            static_cast<unsigned long long>(since),
            static_cast<unsigned>(pageLimit),
            snapshot.entries().size(),
            static_cast<unsigned long long>(snapshot.oldest_sequence()),
            static_cast<unsigned long long>(snapshot.newest_sequence()),
            static_cast<int>(name.size()),
            name.data()));
    } else {
        used += static_cast<std::size_t>(std::snprintf(
            body,
            sizeof body,
            "{\"since\":%llu,\"limit\":%u,\"count\":%zu,\"first\":%llu,\"last\":%llu,"
            "\"channel\":null,",
            static_cast<unsigned long long>(since),
            static_cast<unsigned>(pageLimit),
            snapshot.entries().size(),
            static_cast<unsigned long long>(snapshot.oldest_sequence()),
            static_cast<unsigned long long>(snapshot.newest_sequence())));
    }
    if (filter.level.has_value()) {
        const std::string_view name = kLevelNames[static_cast<std::size_t>(*filter.level)];
        used += static_cast<std::size_t>(std::snprintf(
            body + used,
            kEventsResponseCapacity - used,
            "\"level\":\"%.*s\",\"rows\":[",
            static_cast<int>(name.size()),
            name.data()));
    } else {
        used += static_cast<std::size_t>(std::snprintf(
            body + used,
            kEventsResponseCapacity - used,
            "\"level\":null,\"rows\":["));
    }

    std::size_t emitted = 0;
    bool truncated = false;
    std::uint64_t next = since;
    for (const core::log::snapshot::Entry* entry : result.entries()) {
        if (entry->sequence() <= since) {
            continue;
        }
        if (emitted >= pageLimit) {
            truncated = true;
            break;
        }
        const std::size_t rowStart = used;
        // Rows may only fill up to the reserved tail: append_event_row bounds itself
        // correctly, but the closing object below does not, and snprintf's would-be
        // return length would then push `used` past the buffer and make respond() send
        // stack memory off the end of it (observed: 65,576 bytes out of a 65,536 buffer,
        // trailing NULs and a fragment of an unrelated log line).
        if (!append_event_row(body, kEventsResponseCapacity - kEventsTailReserve, used,
                              *entry, emitted == 0)) {
            used = rowStart;
            truncated = true;
            break;
        }
        next = entry->sequence();
        ++emitted;
    }
    const int tailWritten =
        std::snprintf(body + used,
                      used < kEventsResponseCapacity ? kEventsResponseCapacity - used : 0,
                      "],\"emitted\":%zu,\"truncated\":%s,\"next\":%llu}",
                      emitted,
                      truncated ? "true" : "false",
                      static_cast<unsigned long long>(next));
    if (tailWritten > 0) {
        used += static_cast<std::size_t>(tailWritten);
        if (used >= kEventsResponseCapacity) {
            used = kEventsResponseCapacity - 1;
        }
    }
    respond(client, "200 OK", "application/json", {body, used});
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
    // A2(c): repair means restoring the STABLE provisioned-union identity, matching what
    // every boot pass now writes - never a single peer's account hash.
    const std::uint64_t hash =
        state::runtime::equipment::configured_hash_provisioned();
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

/** Bytes of the client log's tail read for one request. */
constexpr std::size_t kClientLogTailBytes = 262144;
/** Rows returned when the caller names no count. */
constexpr std::uint32_t kClientLogDefault = 400;
/** Upper bound on rows one request may return. */
constexpr std::uint32_t kClientLogMaximum = 2000;

/** @return True when needle occurs in haystack, compared without case. */
bool contains_nocase(std::string_view haystack, std::string_view needle) noexcept {
    if (needle.empty()) {
        return true;
    }
    if (needle.size() > haystack.size()) {
        return false;
    }
    const auto lower = [](char c) noexcept {
        return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c;
    };
    for (std::size_t start = 0; start + needle.size() <= haystack.size(); ++start) {
        std::size_t index = 0;
        while (index < needle.size()
               && lower(haystack[start + index]) == lower(needle[index])) {
            ++index;
        }
        if (index == needle.size()) {
            return true;
        }
    }
    return false;
}

/**
 * GET /clientlog - the CLIENT process's own log tail.
 * The client channel is written by the mod DLL inside the game process, which keeps a
 * separate in-memory ring this process cannot reach. Reading its log FILE is the only
 * way to surface those lines on the dashboard, so this route exists beside /events
 * rather than inside it: different source, no shared sequence space.
 */
void handle_client_log(SOCKET client, std::string_view query) noexcept {
    const auto& configured = core::settings::get().server.clientLogPath;
    if (configured[0] == L'\0') {
        respond(client, "200 OK", "application/json",
                "{\"ok\":false,\"reason\":\"server.client_log_path is not set\","
                "\"rows\":[],\"emitted\":0}");
        return;
    }
    const std::uint32_t limit = query_number(query, "limit", kClientLogDefault);
    const std::uint32_t pageLimit = (std::min)(limit, kClientLogMaximum);

    const std::string_view channelName = query_value(query, "channel");
    const std::string_view levelName = query_value(query, "level");
    std::size_t wantChannel = std::size(kChannelNames);
    std::size_t wantLevel = std::size(kLevelNames);
    if (!channelName.empty() && channelName != "all") {
        wantChannel = channel_index(channelName);
        if (wantChannel == std::size(kChannelNames)) {
            respond(client, "400 Bad Request", "application/json",
                    "{\"ok\":false,\"reason\":\"unknown channel\"}");
            return;
        }
    }
    if (!levelName.empty() && levelName != "all") {
        wantLevel = level_index(levelName);
        if (wantLevel == std::size(kLevelNames)) {
            respond(client, "400 Bad Request", "application/json",
                    "{\"ok\":false,\"reason\":\"unknown level\"}");
            return;
        }
    }
    std::array<char, core::log::view::kTextFilterCapacity> textQuery{};
    const std::size_t textLength = decode_query_text(query_value(query, "text"), textQuery);
    const std::string_view wantText{textQuery.data(), textLength};

    // FILE_SHARE_WRITE matters: the game process holds this file open and is actively
    // appending to it. Without it the open fails while the client is running - exactly
    // when the dashboard is most useful.
    const HANDLE file = CreateFileW(configured.data(),
                                    GENERIC_READ,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                    nullptr,
                                    OPEN_EXISTING,
                                    FILE_ATTRIBUTE_NORMAL,
                                    nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        respond(client, "200 OK", "application/json",
                "{\"ok\":false,\"reason\":\"client log not readable\",\"rows\":[],"
                "\"emitted\":0}");
        return;
    }
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size)) {
        (void)CloseHandle(file);
        respond(client, "200 OK", "application/json",
                "{\"ok\":false,\"reason\":\"client log size unavailable\",\"rows\":[],"
                "\"emitted\":0}");
        return;
    }
    const auto total = static_cast<unsigned long long>(size.QuadPart);
    const auto tailBytes = static_cast<unsigned long long>(kClientLogTailBytes);
    const unsigned long long start = total > tailBytes ? total - tailBytes : 0;
    LARGE_INTEGER move{};
    move.QuadPart = static_cast<LONGLONG>(start);
    (void)SetFilePointerEx(file, move, nullptr, FILE_BEGIN);
    static thread_local char tail[kClientLogTailBytes];
    DWORD read = 0;
    const BOOL readOk = ReadFile(file, tail, static_cast<DWORD>(sizeof tail), &read, nullptr);
    (void)CloseHandle(file);
    if (!readOk) {
        respond(client, "200 OK", "application/json",
                "{\"ok\":false,\"reason\":\"client log read failed\",\"rows\":[],"
                "\"emitted\":0}");
        return;
    }
    std::string_view body{tail, read};
    if (start != 0) {
        // The seek landed mid-line; drop the partial head so no row is malformed.
        const std::size_t newline = body.find('\n');
        body = newline == std::string_view::npos ? std::string_view{}
                                                 : body.substr(newline + 1);
    }

    // Collect the matching lines, keeping only the newest pageLimit of them.
    static thread_local std::string_view matched[kClientLogMaximum];
    std::size_t matchCount = 0;
    std::size_t oldest = 0;
    std::size_t scanned = 0;
    while (!body.empty()) {
        const std::size_t newline = body.find('\n');
        std::string_view line =
            newline == std::string_view::npos ? body : body.substr(0, newline);
        body = newline == std::string_view::npos ? std::string_view{}
                                                 : body.substr(newline + 1);
        while (!line.empty() && (line.back() == '\r' || line.back() == '\0')) {
            line.remove_suffix(1);
        }
        if (line.empty()) {
            continue;
        }
        ++scanned;
        const std::size_t space = line.find(' ');
        const std::string_view channelText =
            space == std::string_view::npos ? line : line.substr(0, space);
        const std::size_t channelIndex = channel_index(channelText);
        if (wantChannel != std::size(kChannelNames) && channelIndex != wantChannel) {
            continue;
        }
        std::size_t levelIndex = std::size(kLevelNames);
        const std::size_t levelAt = line.find("level=");
        if (levelAt != std::string_view::npos) {
            std::string_view rest = line.substr(levelAt + 6);
            const std::size_t end = rest.find(' ');
            levelIndex = level_index(end == std::string_view::npos ? rest : rest.substr(0, end));
        }
        if (wantLevel != std::size(kLevelNames) && levelIndex != wantLevel) {
            continue;
        }
        if (!contains_nocase(line, wantText)) {
            continue;
        }
        matched[(oldest + matchCount) % kClientLogMaximum] = line;
        if (matchCount < pageLimit) {
            ++matchCount;
        } else {
            oldest = (oldest + 1) % kClientLogMaximum;
        }
    }

    char out[kEventsResponseCapacity]{};
    std::size_t used = 0;
    const auto advance = [&used](int written) noexcept {
        if (written <= 0) {
            return;
        }
        used += static_cast<std::size_t>(written);
        if (used >= kEventsResponseCapacity) {
            used = kEventsResponseCapacity - 1;
        }
    };
    advance(std::snprintf(out, sizeof out,
                          "{\"ok\":true,\"source\":\"client_log\",\"bytes\":%llu,"
                          "\"scanned\":%zu,\"rows\":[",
                          total, scanned));
    std::size_t emitted = 0;
    bool truncated = false;
    for (std::size_t index = 0; index < matchCount; ++index) {
        const std::string_view line = matched[(oldest + index) % kClientLogMaximum];
        char escaped[kEventsRowEscapedCapacity]{};
        (void)escape_json_text(escaped, sizeof escaped, line);
        const std::size_t space = line.find(' ');
        const std::string_view channelText =
            space == std::string_view::npos ? line : line.substr(0, space);
        const std::size_t channelIndex = channel_index(channelText);
        const std::string_view channelOut = channelIndex == std::size(kChannelNames)
                                                ? std::string_view{"client"}
                                                : kChannelNames[channelIndex];
        std::size_t levelIndex = std::size(kLevelNames);
        const std::size_t levelAt = line.find("level=");
        if (levelAt != std::string_view::npos) {
            std::string_view rest = line.substr(levelAt + 6);
            const std::size_t end = rest.find(' ');
            levelIndex = level_index(end == std::string_view::npos ? rest : rest.substr(0, end));
        }
        const std::string_view levelOut =
            levelIndex == std::size(kLevelNames) ? std::string_view{"info"}
                                                 : kLevelNames[levelIndex];
        // The client log has no sequence space of its own, and reusing "seq" here would
        // collide with /events' genuine monotonic ring sequence under the same name and
        // in the same column. Emit the line's OWN t= instead (ms since the client process
        // started) - the clock merge_logs.py and boot_record.py already treat as the
        // client clock. -1 when a line carries no t=.
        long long lineT = -1;
        const std::size_t tAt = line.find("t=");
        if (tAt != std::string_view::npos
            && (tAt == 0 || line[tAt - 1] == ' ')) {
            std::string_view rest = line.substr(tAt + 2);
            long long parsed = 0;
            std::size_t digits = 0;
            while (digits < rest.size() && rest[digits] >= '0' && rest[digits] <= '9') {
                parsed = parsed * 10 + (rest[digits] - '0');
                ++digits;
            }
            if (digits != 0) {
                lineT = parsed;
            }
        }
        if (used + kEventsTailReserve >= kEventsResponseCapacity) {
            truncated = true;
            break;
        }
        const std::size_t before = used;
        advance(std::snprintf(out + used,
                              kEventsResponseCapacity - kEventsTailReserve - used,
                              "%s{\"t\":%lld,\"channel\":\"%.*s\",\"level\":\"%.*s\","
                              "\"text\":\"%s\"}",
                              emitted == 0 ? "" : ",",
                              lineT,
                              static_cast<int>(channelOut.size()), channelOut.data(),
                              static_cast<int>(levelOut.size()), levelOut.data(),
                              escaped));
        if (used + kEventsTailReserve >= kEventsResponseCapacity) {
            used = before;
            truncated = true;
            break;
        }
        ++emitted;
    }
    advance(std::snprintf(out + used,
                          used < kEventsResponseCapacity ? kEventsResponseCapacity - used : 0,
                          "],\"emitted\":%zu,\"matched\":%zu,\"truncated\":%s}",
                          emitted, matchCount, truncated ? "true" : "false"));
    respond(client, "200 OK", "application/json", {out, used});
}


/**
 * FRIENDS RICH-PRESENCE CROSS-INTRODUCTION over the PLAINTEXT admin listener (p2(65)).
 *
 * p2(64) put these two routes on the TLS listener (8443) and had the shim reach them
 * through client::network::consume_http. That call never left the client: the only
 * in-process consumer registered in the Client DLL is server::http::consume, which
 * answers "/SignOn" and returns false for everything else - so every store was a no-op
 * and every fetch returned nothing (FINDINGS 20.99). 8443's handshake fails besides
 * (SEC_E_UNSUPPORTED_FUNCTION, 0x80090302). This listener is plaintext, already bound,
 * and verified reachable from BOTH machines, so the relay rides here instead.
 *
 * The value travels as a query parameter, not a body: serve_connection reads exactly one
 * recv(), so a request that fits one segment needs no body reassembly.
 */
void handle_presence_get(SOCKET client) noexcept {
    char body[kResponseCapacity]{};
    const std::size_t written = sunrise::server::http::presence::snapshot(body, sizeof body);
    std::array<char, core::log::kLineCapacity> line{};
    const int logged = std::snprintf(line.data(), line.size(),
                                     "ev=presence stage=snapshot bytes=%zu result=ok", written);
    if (logged > 0) {
        core::log::write(core::log::Channel::server, core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(logged)});
    }
    respond(client, "200 OK", "text/plain", {body, written});
}

/** POST /presence/store?xuid=<hex>&key=<key>&value=<value> */
void handle_presence_store(SOCKET client, std::string_view query) noexcept {
    const std::string_view xuidText = query_value(query, "xuid");
    const std::string_view key = query_value(query, "key");
    const std::string_view value = query_value(query, "value");
    std::uint64_t xuid = 0;
    bool parsed = !xuidText.empty() && xuidText.size() <= 16;
    for (const char character : xuidText) {
        xuid <<= 4U;
        if (character >= '0' && character <= '9') {
            xuid |= static_cast<std::uint64_t>(character - '0');
        } else if (character >= 'a' && character <= 'f') {
            xuid |= static_cast<std::uint64_t>(character - 'a' + 10);
        } else if (character >= 'A' && character <= 'F') {
            xuid |= static_cast<std::uint64_t>(character - 'A' + 10);
        } else {
            parsed = false;
        }
    }
    const bool stored =
        parsed && sunrise::server::http::presence::store(xuid, key, value);
    std::array<char, core::log::kLineCapacity> line{};
    const int logged = std::snprintf(line.data(), line.size(),
                                     "ev=presence stage=store xuid=%llx key=%.*s value=%.*s result=%s",
                                     static_cast<unsigned long long>(xuid),
                                     static_cast<int>(key.size()), key.data(),
                                     static_cast<int>(value.size()), value.data(),
                                     stored ? "ok" : "fail");
    if (logged > 0) {
        core::log::write(core::log::Channel::server,
                         stored ? core::log::Level::info : core::log::Level::warn,
                         {line.data(), static_cast<std::size_t>(logged)});
    }
    respond(client,
            stored ? "200 OK" : "400 Bad Request",
            "application/json",
            stored ? "{\"ok\":true}" : "{\"ok\":false}");
}

/** Parses a hex query value. @return True when every character was a hex digit. */
bool parse_hex(std::string_view text, std::uint64_t& value) noexcept {
    if (text.empty() || text.size() > 16) {
        return false;
    }
    value = 0;
    for (const char character : text) {
        value <<= 4U;
        if (character >= '0' && character <= '9') {
            value |= static_cast<std::uint64_t>(character - '0');
        } else if (character >= 'a' && character <= 'f') {
            value |= static_cast<std::uint64_t>(character - 'a' + 10);
        } else if (character >= 'A' && character <= 'F') {
            value |= static_cast<std::uint64_t>(character - 'A' + 10);
        } else {
            return false;
        }
    }
    return true;
}

/**
 * POST /lobby/claim?seq=<hex>&lobby=<hex> -> the WINNING lobby id as 16 hex digits.
 *
 * The pairing point for the lobby lane (FINDINGS 20.101). First claimant for an ordinal
 * keeps its own id; every later one is told that id instead. The answer is deliberately
 * bare hex so the shim can parse it without a JSON reader on the game's side.
 */
void handle_lobby_claim(SOCKET client, std::string_view query) noexcept {
    std::uint64_t sequence = 0;
    std::uint64_t candidate = 0;
    std::uint64_t xuid = 0;
    if (!parse_hex(query_value(query, "seq"), sequence)
        || !parse_hex(query_value(query, "lobby"), candidate)) {
        respond(client, "400 Bad Request", "application/json", "{\"ok\":false}");
        return;
    }
    // xuid is optional so a p2(67) client still gets a valid answer from a p2(68) server.
    (void)parse_hex(query_value(query, "xuid"), xuid);
    std::array<std::uint64_t, sunrise::server::http::presence::kMaxLobbyMembers> members{};
    std::size_t memberCount = 0;
    const std::uint64_t winner = sunrise::server::http::presence::claim_lobby(
        sequence, candidate, xuid, members.data(), members.size(), memberCount);
    // "<winner> <member> <member>..." - all bare hex, so the shim parses it without a
    // JSON reader on the game's side.
    char body[160]{};
    int written = std::snprintf(body, sizeof body, "%016llX",
                                static_cast<unsigned long long>(winner));
    for (std::size_t i = 0; i < memberCount && written > 0; ++i) {
        const int more = std::snprintf(body + written,
                                       sizeof body - static_cast<std::size_t>(written),
                                       " %016llX",
                                       static_cast<unsigned long long>(members[i]));
        if (more <= 0) {
            break;
        }
        written += more;
    }
    std::array<char, core::log::kLineCapacity> line{};
    const int logged = std::snprintf(
        line.data(), line.size(),
        "ev=lobby stage=claim seq=%llu candidate=0x%016llX winner=0x%016llX xuid=0x%llX "
        "members=%zu result=%s",
        static_cast<unsigned long long>(sequence),
        static_cast<unsigned long long>(candidate),
        static_cast<unsigned long long>(winner),
        static_cast<unsigned long long>(xuid),
        memberCount,
        winner == candidate ? "host" : "join");
    if (logged > 0) {
        core::log::write(core::log::Channel::server, core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(logged)});
    }
    respond(client, "200 OK", "text/plain",
            {body, written > 0 ? static_cast<std::size_t>(written) : 0});
}

/** GET /lobby -> the claim table as "sequence lobby" lines. */
void handle_lobby_get(SOCKET client) noexcept {
    char body[1024]{};
    const std::size_t written =
        sunrise::server::http::presence::lobby_snapshot(body, sizeof body);
    respond(client, "200 OK", "text/plain", {body, written});
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

    if (request.verb == "GET" && request.path == "/") {
        handle_dashboard(client);
    } else if (request.verb == "GET" && request.path == "/state") {
        handle_state(client);
    } else if (request.verb == "GET" && request.path == "/ladder") {
        handle_ladder(client);
    } else if (request.verb == "GET" && request.path == "/flags") {
        handle_flags(client, request.query);
    } else if (request.verb == "GET" && request.path == "/journal") {
        handle_journal(client);
    } else if (request.verb == "GET" && request.path == "/clientlog") {
        handle_client_log(client, request.query);
    } else if (request.verb == "GET" && request.path == "/events") {
        handle_events(client, request.query);
    } else if (request.verb == "GET" && request.path == "/presence") {
        handle_presence_get(client);
    } else if (request.verb == "POST" && request.path == "/presence/store") {
        handle_presence_store(client, request.query);
    } else if (request.verb == "GET" && request.path == "/lobby") {
        handle_lobby_get(client);
    } else if (request.verb == "POST" && request.path == "/lobby/claim") {
        handle_lobby_claim(client, request.query);
        // LANE D INSERTION POINT: the GET /health route (and its handler)
        // lands next to /events, before the write verbs below.
    } else if (request.verb == "POST" && request.path == "/suppress") {
        handle_flag_write(client, request.query, 0, "suppress");
    } else if (request.verb == "POST" && request.path == "/restore") {
        handle_flag_write(client, request.query, state::unlocks::kFlagSet, "restore");
    } else if (request.verb == "POST" && request.path == "/restamp") {
        handle_restamp(client);
    } else if (request.verb == "POST" && request.path == "/repush") {
        handle_repush(client);
    } else if (request.verb == "POST" && request.path == "/settings/reload") {
        // THE WEASEL/MARIONBERRY ARC'S FIX B (p2225_weasel_marionberry.md): the
        // settings re-read WITHOUT a restart - most flag flips stop requiring the
        // clients to be bounced. The boot-time identity/transport fields are
        // preserved inside the reload itself.
        const bool ok = core::settings::reload();
        journal("settings_reload", ok ? "ok" : "failed", ok);
        char body[128]{};
        const int written = std::snprintf(body, sizeof body,
                                          "{\"ok\":%s,\"verb\":\"settings_reload\"}",
                                          ok ? "true" : "false");
        respond(client, ok ? "200 OK" : "500 Internal Server Error", "application/json",
                {body, static_cast<std::size_t>(written)});
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

/**
 * Folds configured octets into one address value.
 * @param octets Dotted-quad order.
 * @return Host-order IPv4 value.
 */
[[nodiscard]] std::uint32_t
host_address(const std::array<unsigned char, core::settings::address::kOctets>& octets) noexcept {
    /** One IPv4 octet is 8 bits, so each fold shifts by that much. */
    constexpr unsigned kOctetBits = 8;
    std::uint32_t value = 0;
    for (const unsigned char octet : octets) {
        value = (value << kOctetBits) | octet;
    }
    return value;
}

/** Binds the TCP listener to one configured IPv4 address. */
[[nodiscard]] SOCKET bind_address_tcp(
    std::uint16_t port, const std::array<unsigned char, core::settings::address::kOctets>& octets) noexcept {
    const SOCKET created = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (created == INVALID_SOCKET) {
        return INVALID_SOCKET;
    }
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(host_address(octets));
    // The dashboard polls this port every second, so a restart lands inside the
    // TIME_WAIT window of its own just-closed connections. Without this the bind
    // fails and admin failure is fatal to the whole server. Same option the BAP
    // acceptor already sets (bap_listener.cpp).
    BOOL reuse = TRUE;
    (void)setsockopt(created,
                     SOL_SOCKET,
                     SO_REUSEADDR,
                     reinterpret_cast<const char*>(&reuse),
                     sizeof reuse);
    if (bind(created, reinterpret_cast<const sockaddr*>(&address), sizeof address)
            == SOCKET_ERROR
        || listen(created, SOMAXCONN) == SOCKET_ERROR) {
        (void)closesocket(created);
        return INVALID_SOCKET;
    }
    return created;
}

/** Formats one configured address as a dotted quad. */
std::string_view
format_bind_address(const std::array<unsigned char, core::settings::address::kOctets>& octets,
                    std::span<char> output) noexcept {
    const int written = std::snprintf(output.data(),
                                      output.size(),
                                      "%u.%u.%u.%u",
                                      static_cast<unsigned>(octets[0]),
                                      static_cast<unsigned>(octets[1]),
                                      static_cast<unsigned>(octets[2]),
                                      static_cast<unsigned>(octets[3]));
    if (written <= 0) {
        return {};
    }
    return {output.data(), static_cast<std::size_t>(written)};
}

} // namespace

/** Starts the admin HTTP listener on the configured bind address. */
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
    const std::array<unsigned char, core::settings::address::kOctets>& bindAddress =
        core::settings::get().server.bindAddress;
    g_listener.socket = bind_address_tcp(kAdminPort, bindAddress);
    if (g_listener.socket == INVALID_SOCKET) {
        core::log::write(core::log::Channel::server,
                         core::log::Level::warn,
                         "ev=admin stage=listen result=fail reason=bind");
        ReleaseSRWLockExclusive(&g_listener.lock);
        return false;
    }
    g_listener.running.store(true, std::memory_order_release);
    // The events route stacks a multi-megabyte snapshot, so the worker gets
    // the server main thread's stack size instead of the 1 MiB default.
    g_listener.thread =
        CreateThread(nullptr, kListenerThreadStackBytes, listener_main, nullptr, 0, nullptr);
    if (g_listener.thread == nullptr) {
        g_listener.running.store(false, std::memory_order_release);
        (void)closesocket(g_listener.socket);
        g_listener.socket = INVALID_SOCKET;
        ReleaseSRWLockExclusive(&g_listener.lock);
        return false;
    }
    std::array<char, core::log::kLineCapacity> line{};
    std::array<char, 64> bind{};
    const std::string_view bindText = format_bind_address(bindAddress, bind);
    const int written = std::snprintf(
        line.data(),
        line.size(),
        "ev=admin stage=listen result=ok port=%u bind=%.*s",
        kAdminPort,
        static_cast<int>(bindText.size()),
        bindText.data());
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
