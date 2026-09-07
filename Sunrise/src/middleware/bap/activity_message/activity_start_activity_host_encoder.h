#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace sunrise::middleware::bap::activity_message::start_activity_host {

/** Activity message type 9: the host designates one client to start hosting its activity session. */
inline constexpr std::uint32_t kMessageType = 9;

/**
 * The whole raw type-9 body. The client's decode variant (0x140E0DC20) reads the
 * decoded struct directly - byte 0 must be 1, a native-order u64 session id sits
 * at +1, and a native-order u32 sits at +9 (the apply 0x140C11B60 sets its flag
 * from `dword == 4`). Thirteen bytes, no presence bits.
 */
inline constexpr std::size_t kModeBytes = 1;
inline constexpr std::size_t kSessionIdBytes = 8;
inline constexpr std::size_t kValueBytes = 4;
inline constexpr std::size_t kEncodedSize = kModeBytes + kSessionIdBytes + kValueBytes;
/** The mode byte that selects the start path (any other value logs an error client-side). */
inline constexpr std::uint8_t kStartMode = 1;
/** The value dword the client's state machine reads its flag from. */
inline constexpr std::uint32_t kStartValue = 4;

/**
 * Encodes one type-9 body, raw-struct shape: the start-mode byte, the activity
 * session id in native (little-endian) byte order, the value dword in native
 * order. The session id must be the id the recipient client already knows for
 * its own activity session (the same id every notification frame for that
 * client carries); a mismatch makes the client's session lookup return null and
 * the whole apply is a no-op, so a wrong id degrades to silence, never to a
 * crash.
 */
[[nodiscard]] bool encode(std::uint64_t sessionId,
                          std::span<std::byte> output,
                          std::size_t& written) noexcept;

} // namespace sunrise::middleware::bap::activity_message::start_activity_host
