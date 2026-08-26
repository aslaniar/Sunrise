#include "replicate_membership.h"

namespace sunrise::middleware::bap::activity_message::replicate_membership {
namespace {

/**
 * The top-level member masks name populated slots by bit. The local member always sits in
 * slot zero; a published peer sets bit one of both masks, which is what the client's own
 * `peers valid` / `players valid` dump fields read back.
 */
constexpr std::uint32_t kLocalMemberMask = 1;
constexpr std::uint32_t kPeerMemberMask = 0b11;

static_assert(kMeaningfulBitCount == kEncodedSize * 8U);

} // namespace

/** Encodes one fixed full-player membership snapshot without allocation. */
bool encode_replicate_membership(const MembershipSnapshot& snapshot,
                                 std::span<std::byte> output,
                                 std::size_t& written) noexcept {
    written = 0;
    const std::size_t size = encoded_size(snapshot);
    if (output.size() < size || !valid(snapshot)) {
        return false;
    }

    const std::uint32_t historical = snapshot.peerPresent ? kPeerMemberMask : kLocalMemberMask;
    // Zero means "unchanged", so a caller that sets neither field reproduces every body this
    // encoder has ever produced, byte for byte.
    const std::uint32_t first =
        snapshot.trailingFirst != 0 ? snapshot.trailingFirst : historical;
    const std::uint32_t second =
        snapshot.trailingSecond != 0 ? snapshot.trailingSecond : historical;
    encoding::bits::Writer writer(output.first(size));
    const bool encoded = writer.write(1, 1) && writer.write(snapshot.revision, 32)
                         && writer.write(snapshot.epoch, 32)
                         && write_member_table(writer, snapshot.identity, snapshot.peer,
                                               snapshot.peerPresent)
                         && writer.write(1, 1) && write_region_block(writer, snapshot)
                         && writer.write(1, 1) && writer.write(first, 32) && writer.write(1, 1)
                         && writer.write(second, 32) && writer.write(0, 1)
                         && writer.write(0, 1) && writer.write(0, 1);
    std::size_t encodedSize = 0;
    const std::size_t meaningfulBits = meaningful_bit_count(snapshot);
    if (!encoded || writer.bit_count() != meaningfulBits || !writer.finish(encodedSize)
        || encodedSize != size) {
        return false;
    }

    written = encodedSize;
    return true;
}

} // namespace sunrise::middleware::bap::activity_message::replicate_membership
