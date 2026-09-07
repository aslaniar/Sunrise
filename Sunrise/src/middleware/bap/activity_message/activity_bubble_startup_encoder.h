#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace sunrise::middleware::bap::activity_message::bubble_startup {

/** Activity message type 51: the host names a client the bubble-host startup. */
inline constexpr std::uint32_t kMessageType = 51;

/** The identity blob: "steamid:<id>#<token>" + zero pad + the 0x06 version byte. */
inline constexpr std::size_t kIdentityBytes = 0x56;
/** The blob sub-message wire: tag 0x0A + one length byte + the identity. */
inline constexpr std::size_t kSubMessageBytes = 2 + kIdentityBytes;
/** One sub-message field: tag + length byte + the sub-message. */
inline constexpr std::size_t kFieldOverhead = 2;
/** The trailing buffer field: tag 0x2A + varint 0x80 0x02 + 256 bytes. */
inline constexpr std::size_t kBufferFieldBytes = 3 + 256;

/** The whole body: field1 submsg + field2 submsg + scalars + the buffer. */
inline constexpr std::size_t kEncodedSize =
    kFieldOverhead + kSubMessageBytes + kFieldOverhead + kSubMessageBytes
    + 4 + kBufferFieldBytes;

/** The scalar values: nonzero (the validator reads their low bytes via the
 *  decoded-struct windows); the semantics live in the client's obfuscated
 *  epilogue and were not decoded — the first probe carries these. */
inline constexpr std::uint8_t kScalarF3 = 0x41;
inline constexpr std::uint8_t kScalarF4 = 0x42;

/**
 * Encodes one type-51 body, the femu-validated wire form (W8 in
 * RE_output/claims/type51-bubble-startup-spec.md): the two blob sub-messages
 * (field 1 = zeros, field 2 = the recipient's own SteamNetworkingIdentity
 * echoed byte-exact — "steamid:<id>#<token>" + zero pad + 0x06 at [0x55]),
 * the two nonzero varint scalars, and the 256-byte buffer. ALL FIELDS IN
 * ASCENDING ORDER — the client's schema cursor is forward-only and skips
 * out-of-order fields.
 * @param identity The recipient's 0x56-byte identity form (the captured
 *                 advertisement region; [0x55] must be the 0x06 version byte).
 * @param output Caller storage, written only on success.
 * @param written Receives the body size (kEncodedSize) on success.
 */
[[nodiscard]] bool encode(std::span<const std::byte, kIdentityBytes> identity,
                          std::span<std::byte> output,
                          std::size_t& written) noexcept;

} // namespace sunrise::middleware::bap::activity_message::bubble_startup
