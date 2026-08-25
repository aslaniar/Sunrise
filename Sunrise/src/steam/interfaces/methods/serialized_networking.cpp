#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "../../../core/logging/log.h"
#include "../internal.h"

namespace sunrise::steam::interfaces::methods {
namespace {

/**
 * INSTRUMENT (FINDINGS 20.40): traces every ISteamNetworkingSocketsSerialized call.
 *
 * The Client asks Steam to deliver peer connection requests through this table and this shim
 * drops them all by design, so the rendezvous path has never been observed: we do not know
 * whether it fires, when it fires, or what the message blob carries. This trace answers that
 * from one boot, on both machines. The sequence number carries the ORDER, which matters as
 * much as the contents - it shows how far the Client gets before giving up.
 *
 * Liveness: `get_generic_interface` emits stage=interface_acquired when the table is handed
 * out, so a boot with ZERO ev=steamnet lines means the Client never asked for the table at
 * all - an acquisition failure, not a quiet rendezvous path. Strip the whole instrument once
 * the peer link forms.
 */

/** Monotonic call counter; the log order of these lines IS the finding. */
std::atomic<std::uint64_t> g_callSequence{0};

/** Longest blob prefix dumped per line; two hex digits per byte keep one line under the cap. */
constexpr std::size_t kDumpChunkBytes = 96;
/** Largest total blob dump per call. A larger message reports truncated=1 with its real size. */
constexpr std::size_t kDumpTotalCapBytes = 1024;

/** Emits one client-channel line; this shim runs inside the Client process. */
void emit(const char* text, std::size_t length) noexcept {
    core::log::write(core::log::Channel::client, core::log::Level::info, {text, length});
}

/** @return The next call number, starting at one. */
std::uint64_t next_sequence() noexcept {
    return g_callSequence.fetch_add(1, std::memory_order_relaxed) + 1;
}

/**
 * Appends a hex rendering of a byte range.
 * @param output Destination buffer.
 * @param capacity Destination size, including room for the trailing null.
 * @param bytes Borrowed source bytes.
 * @param count Byte count, at most kDumpChunkBytes.
 * @return The number of characters written, or zero when nothing fit.
 */
std::size_t append_hex(char* output, std::size_t capacity, const unsigned char* bytes,
                       std::size_t count) noexcept {
    static constexpr char kDigits[] = "0123456789ABCDEF";
    std::size_t written = 0;
    for (std::size_t index = 0; index < count && (written + 2) < capacity; ++index) {
        output[written++] = kDigits[bytes[index] >> 4];
        output[written++] = kDigits[bytes[index] & 0x0F];
    }
    if (written == 0) {
        return 0;
    }
    output[written] = '\0';
    return written;
}

/**
 * Dumps a call's blob payload in bounded chunks, so a Steam-signed certificate shows as much
 * of itself as a boot record can hold while a small rendezvous note fits on one line.
 * @param stage The call's stage name, shared with its argument line.
 * @param sequence The call's sequence number.
 * @param blob Borrowed payload bytes; null means the call carried no pointer.
 * @param size Payload size claimed by the caller.
 */
void dump_blob(const char* stage, std::uint64_t sequence, const void* blob,
               std::uint32_t size) noexcept {
    if (blob == nullptr || size == 0) {
        std::array<char, 128> line{};
        const int written = std::snprintf(line.data(),
                                          line.size(),
                                          "ev=steamnet seq=%llu stage=%s part=empty ptr=%d size=%u",
                                          static_cast<unsigned long long>(sequence),
                                          stage,
                                          blob == nullptr ? 0 : 1,
                                          static_cast<unsigned>(size));
        if (written > 0) {
            emit(line.data(), static_cast<std::size_t>(written));
        }
        return;
    }
    const auto* bytes = static_cast<const unsigned char*>(blob);
    const std::size_t shownTotal =
        size > kDumpTotalCapBytes ? kDumpTotalCapBytes : static_cast<std::size_t>(size);
    std::size_t part = 0;
    for (std::size_t offset = 0; offset < shownTotal; offset += kDumpChunkBytes) {
        const std::size_t count =
            shownTotal - offset < kDumpChunkBytes ? shownTotal - offset : kDumpChunkBytes;
        std::array<char, 160> head{};
        int written = std::snprintf(head.data(),
                                    head.size(),
                                    "ev=steamnet seq=%llu stage=%s part=%zu off=%zu hex=",
                                    static_cast<unsigned long long>(sequence),
                                    stage,
                                    part,
                                    offset);
        if (written <= 0) {
            break;
        }
        std::array<char, kDumpChunkBytes * 2 + 2> line{};
        std::memcpy(line.data(), head.data(), static_cast<std::size_t>(written));
        const std::size_t hexLength =
            append_hex(line.data() + written, line.size() - static_cast<std::size_t>(written),
                       bytes + offset, count);
        if (hexLength == 0) {
            break;
        }
        emit(line.data(), static_cast<std::size_t>(written) + hexLength);
        ++part;
    }
    if (shownTotal < size) {
        std::array<char, 128> line{};
        const int written = std::snprintf(line.data(),
                                          line.size(),
                                          "ev=steamnet seq=%llu stage=%s truncated=1 shown=%zu "
                                          "total=%u",
                                          static_cast<unsigned long long>(sequence),
                                          stage,
                                          shownTotal,
                                          static_cast<unsigned>(size));
        if (written > 0) {
            emit(line.data(), static_cast<std::size_t>(written));
        }
    }
}

} // namespace

/**
 * Asks Steam to deliver a connection request to a peer. THE load-bearing observation: whether
 * this fires, naming whom, and what the message carries decide how this front proceeds.
 * Nothing is sent.
 */
void serialized_send_rendezvous([[maybe_unused]] void* self,
                                std::uint64_t remoteId,
                                DWORD sourceConnectionId,
                                const void* message,
                                DWORD messageSize) noexcept {
    const std::uint64_t sequence = next_sequence();
    std::array<char, 160> line{};
    const int written = std::snprintf(line.data(),
                                      line.size(),
                                      "ev=steamnet seq=%llu stage=send_rendezvous "
                                      "remote=0x%016llX conn=%u size=%u",
                                      static_cast<unsigned long long>(sequence),
                                      static_cast<unsigned long long>(remoteId),
                                      static_cast<unsigned>(sourceConnectionId),
                                      static_cast<unsigned>(messageSize));
    if (written > 0) {
        emit(line.data(), static_cast<std::size_t>(written));
    }
    dump_blob("send_rendezvous", sequence, message, messageSize);
}

/** Asks Steam to deliver a connection failure notice to a peer. Nothing is sent. */
void serialized_send_failure([[maybe_unused]] void* self,
                             std::uint64_t remoteId,
                             DWORD destinationConnectionId,
                             DWORD reason,
                             const char* reasonText) noexcept {
    const std::uint64_t sequence = next_sequence();
    std::array<char, 256> line{};
    const int written = std::snprintf(
        line.data(),
        line.size(),
        "ev=steamnet seq=%llu stage=send_failure remote=0x%016llX conn=%u reason=%u text=%s",
        static_cast<unsigned long long>(sequence),
        static_cast<unsigned long long>(remoteId),
        static_cast<unsigned>(destinationConnectionId),
        static_cast<unsigned>(reason),
        reasonText != nullptr ? reasonText : "(null)");
    if (written > 0) {
        emit(line.data(), static_cast<std::size_t>(written));
    }
}

/** @return Zero. This shim delivers no serialized certificates. */
ApiCall serialized_get_certificate([[maybe_unused]] void* self) noexcept {
    const std::uint64_t sequence = next_sequence();
    std::array<char, 96> line{};
    const int written = std::snprintf(line.data(),
                                      line.size(),
                                      "ev=steamnet seq=%llu stage=get_certificate result=0",
                                      static_cast<unsigned long long>(sequence));
    if (written > 0) {
        emit(line.data(), static_cast<std::size_t>(written));
    }
    return 0;
}

/**
 * Writes an empty network config.
 * @param output Optional text buffer.
 * @return Zero config bytes.
 */
int serialized_get_network_config([[maybe_unused]] void* self,
                                  void* output,
                                  DWORD capacity,
                                  const char* launcherPartner) noexcept {
    const std::uint64_t sequence = next_sequence();
    std::array<char, 192> line{};
    const int written = std::snprintf(
        line.data(),
        line.size(),
        "ev=steamnet seq=%llu stage=get_network_config cap=%u partner=%s out=%d",
        static_cast<unsigned long long>(sequence),
        static_cast<unsigned>(capacity),
        launcherPartner != nullptr ? launcherPartner : "(null)",
        output != nullptr ? 1 : 0);
    if (written > 0) {
        emit(line.data(), static_cast<std::size_t>(written));
    }
    if (output != nullptr && capacity > 0) {
        *static_cast<char*>(output) = '\0';
    }
    return 0;
}

/** Drops a relay ticket. Nothing is kept. */
void serialized_cache_relay_ticket([[maybe_unused]] void* self,
                                   const void* ticket,
                                   DWORD ticketSize) noexcept {
    const std::uint64_t sequence = next_sequence();
    std::array<char, 128> line{};
    const int written = std::snprintf(line.data(),
                                      line.size(),
                                      "ev=steamnet seq=%llu stage=cache_relay_ticket size=%u",
                                      static_cast<unsigned long long>(sequence),
                                      static_cast<unsigned>(ticketSize));
    if (written > 0) {
        emit(line.data(), static_cast<std::size_t>(written));
    }
    dump_blob("cache_relay_ticket", sequence, ticket, ticketSize);
}

/** @return Zero. No relay tickets are kept. */
DWORD serialized_relay_ticket_count([[maybe_unused]] void* self) noexcept {
    const std::uint64_t sequence = next_sequence();
    std::array<char, 112> line{};
    const int written = std::snprintf(line.data(),
                                      line.size(),
                                      "ev=steamnet seq=%llu stage=relay_ticket_count result=0",
                                      static_cast<unsigned long long>(sequence));
    if (written > 0) {
        emit(line.data(), static_cast<std::size_t>(written));
    }
    return 0;
}

/** @return Zero. There is no ticket at any index. */
int serialized_get_relay_ticket([[maybe_unused]] void* self,
                                DWORD index,
                                [[maybe_unused]] void* output,
                                DWORD capacity) noexcept {
    const std::uint64_t sequence = next_sequence();
    std::array<char, 144> line{};
    const int written = std::snprintf(line.data(),
                                      line.size(),
                                      "ev=steamnet seq=%llu stage=get_relay_ticket index=%u cap=%u",
                                      static_cast<unsigned long long>(sequence),
                                      static_cast<unsigned>(index),
                                      static_cast<unsigned>(capacity));
    if (written > 0) {
        emit(line.data(), static_cast<std::size_t>(written));
    }
    return 0;
}

/** Drops a connection-state message. Nothing is kept. */
void serialized_post_connection_state([[maybe_unused]] void* self,
                                      const void* message,
                                      DWORD messageSize) noexcept {
    const std::uint64_t sequence = next_sequence();
    std::array<char, 136> line{};
    const int written = std::snprintf(line.data(),
                                      line.size(),
                                      "ev=steamnet seq=%llu stage=post_connection_state size=%u",
                                      static_cast<unsigned long long>(sequence),
                                      static_cast<unsigned>(messageSize));
    if (written > 0) {
        emit(line.data(), static_cast<std::size_t>(written));
    }
    dump_blob("post_connection_state", sequence, message, messageSize);
}

} // namespace sunrise::steam::interfaces::methods
