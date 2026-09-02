#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace sunrise::middleware::bap::activity_message::entity_index_grant {

/** Activity message type 21: the host pushes one participant's free-slot bitmap. */
inline constexpr std::uint32_t kMessageType = 21;

/**
 * The wire payload opens with one reserved 32-bit word. The client's type-21
 * consumer (0x14170CFB0, see RE_output/claims/entity-index-allocation-schema.md
 * claim K) reads the 8192-bit grant mask at payload+4 and one owner byte at
 * payload+0x404, so the reserved word must exist on the wire even though the
 * visible consumer path never reads it.
 */
inline constexpr std::size_t kReservedBytes = 4;
/** The grant mask is the fixed entity-slot mask: 256 words, 1,024 bytes. */
inline constexpr std::size_t kMaskBytes = 1024;
/** One byte names who the granted slots belong to; the host pushes zero. */
inline constexpr std::size_t kOwnerBytes = 1;
/** The whole raw type-21 body: reserved word, mask, owner byte. */
inline constexpr std::size_t kEncodedSize = kReservedBytes + kMaskBytes + kOwnerBytes;
/** The flat variant: the 256 mask words alone, each serialized MSB-first. */
inline constexpr std::size_t kFlatSize = kMaskBytes;

/**
 * Encodes one type-21 body, raw-struct shape: one reserved 32-bit word, the
 * 1024-byte grant mask in entity-slot wire order (slot i -> byte i / 8, low bit
 * i % 8), one owner byte. Matches the client consumer's decoded struct
 * {dword @0, mask @4, owner @0x404} (claim K). The mask is the joiner's own
 * lease — the same bytes the type-0 notification carries — not a derived range.
 */
[[nodiscard]] bool encode(std::span<const std::byte, kMaskBytes> mask,
                          std::span<std::byte> output,
                          std::size_t& written) noexcept;

/**
 * Encodes one type-21 body, flat shape: the 256 mask words with each 32-bit
 * element serialized most-significant-bit-first — the byte transformation the
 * client's own pool sender applies (claim M, femu-verified). 1,024 bytes.
 */
[[nodiscard]] bool encode_flat(std::span<const std::byte, kMaskBytes> mask,
                               std::span<std::byte> output,
                               std::size_t& written) noexcept;

} // namespace sunrise::middleware::bap::activity_message::entity_index_grant
