#include "activity_peer_contact_encoder.h"

#include <algorithm>

namespace sunrise::middleware::bap::activity_message::peer_contact {

namespace {

/** Bits in one byte, named so the packing loops read as bit arithmetic. */
constexpr std::size_t kByteBits = 8;
/** The count field's width, fixed by schema 0x8080868B's type-5 leaf. */
constexpr std::size_t kCountBits = 6;
/** One machine id occupies its whole 64 bits on the wire. */
constexpr std::size_t kMachineIdBits = 64;

/** Appends one value's low `bits` bits, most significant first. */
void push_bits(std::span<std::byte> output,
               std::size_t& bitCursor,
               std::uint64_t value,
               std::size_t bits) noexcept {
    for (std::size_t index = bits; index-- > 0;) {
        const auto bit = static_cast<unsigned>((value >> index) & 1U);
        if (bit != 0) {
            output[bitCursor / kByteBits] |=
                static_cast<std::byte>(1U << (kByteBits - 1 - bitCursor % kByteBits));
        }
        ++bitCursor;
    }
}

} // namespace

/** Encodes one type-45 body: 6-bit count then each machine id's LE bytes, MSB-first. */
bool encode(std::span<const std::uint64_t> machineIds,
            std::span<std::byte> output,
            std::size_t& written) noexcept {
    written = {};
    if (machineIds.size() > kMaximumMachineIds) {
        return false;
    }
    const std::size_t size = kEncodedSize(machineIds.size());
    if (output.size() < size) {
        return false;
    }

    std::fill(output.begin(), output.begin() + size, std::byte{0});
    std::size_t bitCursor = 0;
    push_bits(output, bitCursor, machineIds.size(), kCountBits);
    for (const std::uint64_t machineId : machineIds) {
        // The id rides as its LITTLE-ENDIAN byte string - byte 0 (the low byte)
        // first - with each byte most-significant-bit first. The client's array
        // reader copies the eight bytes in order into the record's u64, so this
        // is the order that reads back as the same value.
        for (std::size_t byte = 0; byte < kMachineIdBits / kByteBits; ++byte) {
            const auto value = static_cast<std::uint64_t>((machineId >> (byte * kByteBits)) & 0xFFU);
            push_bits(output, bitCursor, value, kByteBits);
        }
    }
    written = size;
    return true;
}

} // namespace sunrise::middleware::bap::activity_message::peer_contact
