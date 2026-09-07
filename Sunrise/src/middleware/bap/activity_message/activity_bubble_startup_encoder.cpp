#include "activity_bubble_startup_encoder.h"

#include <algorithm>

namespace sunrise::middleware::bap::activity_message::bubble_startup {

namespace {

/** One blob sub-message field: tag, length byte, inner tag, inner length, payload. */
void write_blob_field(std::byte tag, std::span<const std::byte> blob,
                      std::span<std::byte>& out) noexcept {
    out[0] = tag;
    out[1] = static_cast<std::byte>(kSubMessageBytes);
    out[2] = std::byte{0x0A};
    out[3] = static_cast<std::byte>(kIdentityBytes);
    std::copy_n(blob.begin(), kIdentityBytes, out.begin() + 4);
    out = out.subspan(kFieldOverhead + kSubMessageBytes);
}

} // namespace

bool encode(std::span<const std::byte, kIdentityBytes> identity,
            std::span<std::byte> output,
            std::size_t& written) noexcept {
    written = {};
    if (output.size() < kEncodedSize) {
        return false;
    }

    std::fill(output.begin(), output.begin() + kEncodedSize, std::byte{0});
    std::span<std::byte> cursor(output);

    // Field 1: the blob sub-message (zeros — the epilogue's semantics are
    // undecoded; the validator only requires the field present).
    write_blob_field(std::byte{0x0A}, identity, cursor);
    // Field 2: the identity echo. The compare (FUN_140406F90) is a full
    // 0x56-byte memcmp against the client's OWN SteamNetworkingIdentity, so
    // this MUST be the recipient's live per-session identity, zeros and the
    // 0x06 version byte exactly as captured.
    std::span<std::byte> f2 = cursor;
    write_blob_field(std::byte{0x12}, identity, f2);
    cursor = cursor.subspan(kFieldOverhead + kSubMessageBytes);

    // Fields 3/4: the two nonzero varint scalars.
    cursor[0] = std::byte{0x18};
    cursor[1] = static_cast<std::byte>(kScalarF3);
    cursor[2] = std::byte{0x21};
    cursor[3] = static_cast<std::byte>(kScalarF4);
    cursor = cursor.subspan(4);

    // Field 5: the 256-byte buffer (tag 0x2A, varint length 256 = 0x80 0x02).
    cursor[0] = std::byte{0x2A};
    cursor[1] = static_cast<std::byte>(0x80);
    cursor[2] = static_cast<std::byte>(0x02);
    std::array<std::byte, 256> filler{};
    for (std::size_t index = 0; index < filler.size(); ++index) {
        cursor[3 + index] = static_cast<std::byte>(index & 0xFF);
    }

    written = kEncodedSize;
    return true;
}

} // namespace sunrise::middleware::bap::activity_message::bubble_startup
