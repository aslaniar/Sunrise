#include "activity_entity_index_grant_encoder.h"

#include <algorithm>

#include "entity_slots.h"

namespace sunrise::middleware::bap::activity_message::entity_index_grant {

/** Encodes one type-21 body, raw-struct shape: reserved word, mask, owner byte. */
bool encode(std::span<const std::byte, kMaskBytes> mask,
            std::span<std::byte> output,
            std::size_t& written) noexcept {
    written = {};
    if (output.size() < kEncodedSize) {
        return false;
    }

    std::fill(output.begin(), output.begin() + kEncodedSize, std::byte{0});
    std::copy_n(mask.begin(), kMaskBytes, output.begin() + kReservedBytes);
    written = kEncodedSize;
    return true;
}

/** Encodes one type-21 body, flat shape: 256 mask words, each MSB-first. */
bool encode_flat(std::span<const std::byte, kMaskBytes> mask,
                 std::span<std::byte> output,
                 std::size_t& written) noexcept {
    written = {};
    if (output.size() < kFlatSize) {
        return false;
    }

    for (std::size_t word = 0; word < entity_slots::kWordCount; ++word) {
        for (std::size_t byte = 0; byte < 4; ++byte) {
            // MSB-first serialization of one 32-bit element: its most significant
            // byte (memory offset +3) hits the wire first.
            output[word * 4 + byte] = mask[word * 4 + (3 - byte)];
        }
    }
    written = kFlatSize;
    return true;
}

} // namespace sunrise::middleware::bap::activity_message::entity_index_grant
