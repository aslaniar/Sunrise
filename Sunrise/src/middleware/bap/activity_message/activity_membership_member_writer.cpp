#include <bit>
#include <limits>

#include "replicate_membership.h"

namespace sunrise::middleware::bap::activity_message::replicate_membership {
namespace {

/** 8 elements, low byte first, encode a member or host key. */
constexpr std::size_t kMemberKeyByteCount = 8;
/** The membership table has 32 fixed member slots. */
constexpr std::size_t kMemberCount = 32;
/** Each absent member adds 3 clear presence bits. */
constexpr std::uint8_t kAbsentMemberBitCount = 3;
/** Member field 1 uses 10 bits with a bias of 1. */
/**
 * Member field 1 is a skip test, not a value. The client drops the member when the stored value
 * read as unsigned is at or below 0x1FF, so the only usable wire value is the one that stores -1.
 * Wire 1 stores zero, and the member is dropped with nothing reported.
 */
constexpr std::uint32_t kField1Bias = 1;
/** Member field 2 uses the signed 32-bit midpoint as its bias. */
constexpr std::uint32_t kField2Bias = 0x80000000U;
/** A present local member carries a zero logical leave reason at bias 1. */
constexpr std::uint8_t kLeaveReasonWire = 1;
/** The nested identity block has presence bits on fields 0 through 14. */
constexpr std::size_t kIdentityPresenceFieldCount = 15;
/** The minimal nested player blob is 18 bytes, including one zero pad bit. */
constexpr std::uint16_t kPlayerBlobByteCount = 18;

/**
 * Bit groups of a member row this encoder has always written as zero, addressable so the
 * PEER row can publish them as ones under `membership_peer_row_flags`. See that setting for
 * why: cond5 (bit 4 of participant record +0x38) is the last gate, no wire field is known to
 * feed it, and these are the row's only size-preserving zero-valued bits - each keeps its
 * wire width, so the body length and every later field offset are unchanged.
 *
 * The mask reaches the peer row only. The local row always encodes with flags == 0.
 */
enum RowFlag : std::uint32_t {
    /** The row's trailing 3 bits, before the set flag: 0 -> 7. */
    kRowFlagTrailingTriple = 1U << 0,
    /** The player-identity block's tail bit: 0 -> 1. */
    kRowFlagIdentityTail = 1U << 1,
    /** The player blob's leading pad bit: 0 -> 1. */
    kRowFlagBlobLeadPad = 1U << 2,
    /** The player blob's 10-bit field: 0 -> 0x3FF. */
    kRowFlagBlobWide = 1U << 3,
    /** The player blob's trailing pad bit: 0 -> 1. */
    kRowFlagBlobTailPad = 1U << 4,
};

/** @return `set` when the group is selected, 0 otherwise - the width never changes. */
[[nodiscard]] constexpr std::uint32_t
flagged(std::uint32_t flags, std::uint32_t group, std::uint32_t set) noexcept {
    return (flags & group) != 0U ? set : 0U;
}

/**
 * Writes one 8-element key, low byte first.
 * @param writer Fixed-buffer MSB-first writer.
 * @param key Host-order key to split into byte elements.
 * @return True when all 8 elements fit.
 */
[[nodiscard]] bool write_member_key(encoding::bits::Writer& writer, std::uint64_t key) noexcept {
    for (std::size_t index = 0; index < kMemberKeyByteCount; ++index) {
        if (!writer.write((key >> (index * 8U)) & 0xFFU, 8)) {
            return false;
        }
    }
    return true;
}

/**
 * Writes the nested 18-byte player blob with matching identity values.
 * @param writer Fixed-buffer writer sitting after the 14-bit byte count.
 * @param identity Identity values repeated inside the nested player record.
 * @return True when all 144 blob bits fit.
 */
[[nodiscard]] bool write_player_blob(encoding::bits::Writer& writer,
                                     const client_identity::ClientIdentity& identity,
                                     const std::uint32_t flags) noexcept {
    return writer.write(1, 3) && writer.write(flagged(flags, kRowFlagBlobLeadPad, 1U), 1)
           && writer.write(flagged(flags, kRowFlagBlobWide, 0x3FFU), 10) && writer.write(1, 1)
           && writer.write(identity.accountSoid, 64) && writer.write(identity.field5, 64)
           && writer.write(flagged(flags, kRowFlagBlobTailPad, 1U), 1);
}

/**
 * Writes the present fields of the nested player identity block.
 * @param writer Fixed-buffer writer sitting at identity field zero.
 * @param identity Values mirrored from the client identity update.
 * @return True when fields 3, 5 and 14 and all presence bits fit.
 */
[[nodiscard]] bool write_player_identity(encoding::bits::Writer& writer,
                                         const client_identity::ClientIdentity& identity,
                                         const std::uint32_t flags) noexcept {
    for (std::size_t field = 0; field < kIdentityPresenceFieldCount; ++field) {
        const bool present = field == 3 || field == 5 || field == 14;
        if (!writer.write(present ? 1U : 0U, 1)) {
            return false;
        }
        if (field == 3 && !writer.write(identity.accountSoid, 64)) {
            return false;
        }
        if (field == 5 && !writer.write(identity.field5, 64)) {
            return false;
        }
        if (field == 14
            && (!writer.write(kPlayerBlobByteCount, 14)
                || !write_player_blob(writer, identity, flags))) {
            return false;
        }
    }
    return writer.write(flagged(flags, kRowFlagIdentityTail, 1U), 1);
}

/** Writes the populated row for one member, then its trailing state bits. */
[[nodiscard]] bool write_member_row(encoding::bits::Writer& writer,
                                    const client_identity::ClientIdentity& identity,
                                    const std::uint32_t flags) noexcept {
    const std::uint32_t field1Wire = std::bit_cast<std::uint32_t>(identity.field1) + kField1Bias;
    const std::uint32_t field2Wire = std::bit_cast<std::uint32_t>(identity.field2) + kField2Bias;
    // The trailing 3+1+5 bits mirror the local row: presence of the nested block's tail, a
    // set flag, and the zero leave reason at bias 1. Whether a REMOTE member carries the same
    // values is exactly what the next boot observes.
    return writer.write(1, 1) && write_member_key(writer, identity.memberKey)
           && writer.write(field1Wire, 10) && writer.write(field2Wire, 32)
           && writer.write(identity.field3, 64) && writer.write(identity.accountSoid, 64)
           && writer.write(identity.field5, 64) && writer.write(identity.field6, 64)
           && writer.write(1, 1) && writer.write(1, 1)
           && write_player_identity(writer, identity, flags)
           && writer.write(flagged(flags, kRowFlagTrailingTriple, 7U), 3)
           && writer.write(1, 1) && writer.write(kLeaveReasonWire, 5);
}

} // namespace

/** Checks the one field that could otherwise encode outside its own wire width. */
bool valid(const MembershipSnapshot& snapshot) noexcept {
    namespace authoritative = client_authoritative_data;
    return snapshot.teleport.sliceSetIndex >= authoritative::kAbsentSliceSetIndex
           && snapshot.teleport.sliceSetIndex <= authoritative::kMaximumSliceSetIndex;
}

/** Writes the populated members and the absent slots after them. */
bool write_member_table(encoding::bits::Writer& writer,
                        const client_identity::ClientIdentity& identity,
                        const client_identity::ClientIdentity& peer,
                        bool peerPresent,
                        const std::uint32_t peerRowFlags) noexcept {
    // The LOCAL row always encodes with flags == 0: only the peer row is under test, and
    // changing what the client is told about itself is a different experiment.
    bool encoded = writer.bit_count() == kMemberStartBit && write_member_row(writer, identity, 0U);
    if (encoded && peerPresent) {
        encoded = write_member_row(writer, peer, peerRowFlags);
    }
    for (std::size_t member = peerPresent ? 2 : 1; encoded && member < kMemberCount; ++member) {
        encoded = writer.write(0, kAbsentMemberBitCount);
    }
    return encoded && writer.bit_count() + 1 == kRegionBlockStartBit + (peerPresent
                                                                            ? kPeerRowExtraBits
                                                                            : 0);
}

} // namespace sunrise::middleware::bap::activity_message::replicate_membership
