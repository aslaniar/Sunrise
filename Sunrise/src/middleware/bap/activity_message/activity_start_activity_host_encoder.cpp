#include "activity_start_activity_host_encoder.h"

#include <algorithm>

namespace sunrise::middleware::bap::activity_message::start_activity_host {

/** Encodes one type-9 body: mode byte, native-order session id, native-order value dword. */
bool encode(std::uint64_t sessionId,
            std::span<std::byte> output,
            std::size_t& written) noexcept {
    written = {};
    if (output.size() < kEncodedSize) {
        return false;
    }

    std::fill(output.begin(), output.begin() + kEncodedSize, std::byte{0});
    output[0] = static_cast<std::byte>(kStartMode);
    // Native (little-endian) order: the client's decode variant reads the struct
    // fields directly out of these bytes (0x140E0DC20 -> the apply's own reads).
    for (std::size_t index = 0; index < kSessionIdBytes; ++index) {
        output[kModeBytes + index] = static_cast<std::byte>((sessionId >> (index * 8)) & 0xFF);
    }
    const std::size_t valueBase = kModeBytes + kSessionIdBytes;
    for (std::size_t index = 0; index < kValueBytes; ++index) {
        output[valueBase + index] =
            static_cast<std::byte>((kStartValue >> (index * 8)) & 0xFF);
    }
    written = kEncodedSize;
    return true;
}

} // namespace sunrise::middleware::bap::activity_message::start_activity_host
