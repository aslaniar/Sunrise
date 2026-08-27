#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "../../encoding/bit_writer.h"
#include "../../gameplay/descriptor/join_descriptor.h"
#include "activity_client_identity_parser.h"
#include "client_authoritative_data.h"

namespace sunrise::middleware::bap::activity_message::replicate_membership {

/** Membership snapshots use activity message type 12. */
inline constexpr std::uint32_t kMessageType = 12;
/**
 * One local player plus a reflected host is 30,032 meaningful bits.
 *
 * Was 29,968 through p2(46). The client's own schema for type 12 (packed key 0x808086A8,
 * read out of the registry in FINDINGS 20.61/20.62) declares FOUR presence-flagged 32-bit
 * fields after the region block - presence indices 996, 997, 998, 999 - and we published
 * only TWO of them, marking the other two absent. Lane M's parsed-struct field registry
 * names exactly four in that order: peer_and_player_counts, peer_updates, player_updates,
 * player_seq_number. Publishing all four adds 2 x (1 presence bit + 32 value bits) and
 * removes the 2 absent-bits they replaced: +64 bits.
 */
inline constexpr std::size_t kMeaningfulBitCount = 30'032;
/** The host-present snapshot is byte-aligned at 3,754 bytes. */
inline constexpr std::size_t kEncodedSize = 3'754;
/** One filled descriptor makes its record 1,024 bits longer and shifts every later field. */
inline constexpr std::size_t kDescriptorBitCount = gameplay::descriptor::kDescriptorSize * 8U;
/** Byte size once one record carries a descriptor. */
inline constexpr std::size_t kCitizenEncodedSize =
    kEncodedSize + gameplay::descriptor::kDescriptorSize;

/**
 * Bits one populated member row adds over the 3 absent bits that otherwise hold its slot.
 * Derived from the fixed layout: the member table spans bits 65..834 (769 bits) with the
 * local row plus 31 absent slots, which makes a populated row 676 bits; 676 minus 3 is 673.
 */
inline constexpr std::size_t kPeerRowExtraBits = 673;

/**
 * One remote-citizen advertisement placed in a single region record.
 * The record is picked by region index. The client adopts only the record whose index matches
 * its pending region.
 */
struct CitizenAdvertisement final {
    std::array<std::byte, gameplay::descriptor::kDescriptorSize> descriptor{};
    /** The ambassador's activity-host id. It is not the descriptor's own session id. */
    std::uint64_t onlineSessionId{};
    /** Region index of the record that carries it. */
    std::int32_t regionIndex{};
    /**
     * Ambassador member slot. It must differ from the joining client's own slot. An equal slot
     * picks the local-ambassador stage instead of the citizen stage.
     */
    std::uint8_t ambassadorSlot{};
    bool present{};
};

/** Inputs for one local-player membership snapshot. */
struct MembershipSnapshot final {
    client_identity::ClientIdentity identity{};
    client_authoritative_data::SpawnState spawn{};
    client_authoritative_data::TeleportState teleport{};
    /** Empty unless the gameplay channel is advertising an endpoint this run. */
    CitizenAdvertisement citizen{};
    /**
     * 20.74.4: the foreign host's own advertisement, placed in ITS region slot. Without it
     * the peer row arrives with no joinable endpoint and every host fixup-releases it.
     */
    CitizenAdvertisement peerCitizen{};
    std::uint32_t revision{};
    /** Stable session epoch; changing it clears the client's peer table. */
    std::uint32_t epoch{};
    /** Transition token copied into every member lane of every region. */
    std::uint8_t transitionToken{};
    /**
     * FINDINGS 20.44: another joined session in the same destination publishes its identity
     * into member slot 1, so the client's own peer table gains peer # 1. The row shape mirrors
     * the local row exactly; whether the client accepts that for a remote player is exactly
     * what the next boot tests.
     */
    client_identity::ClientIdentity peer{};
    bool peerPresent{};
    /**
     * INSTRUMENT (Track 1): override for the first trailing 32-bit field, zero meaning
     * "keep the historical value". With ONE member a slot MASK and a member COUNT are the
     * same number (1), which is why the two readings were indistinguishable for months;
     * with two members a mask is 3 and a count is 2. Lane M U2 records the ambiguity, and
     * its field registry names `peer_and_player_counts` ahead of `peer_updates`.
     */
    std::uint32_t trailingFirst{};
    /** Override for the second trailing 32-bit field. Zero keeps the historical value. */
    std::uint32_t trailingSecond{};
    /**
     * Override for the THIRD trailing 32-bit field. Zero keeps the historical value.
     *
     * This field and the next were never published at all before p2(47) - the encoder wrote
     * an absent-bit for each. The client's schema declares them (presence indices 998 and
     * 999) and lesson 17 says a declared field we never send is a missing requirement, not
     * a spare. Under the field-registry order this is `player_updates`.
     */
    std::uint32_t trailingThird{};
    /** Override for the fourth trailing 32-bit field; `player_seq_number` by the same order. */
    std::uint32_t trailingFourth{};
};

/** @return Bits the whole body carries before byte padding. */
[[nodiscard]] constexpr std::size_t
meaningful_bit_count(const MembershipSnapshot& snapshot) noexcept {
    std::size_t bits = kMeaningfulBitCount;
    if (snapshot.peerPresent) {
        bits += kPeerRowExtraBits;
    }
    if (snapshot.citizen.present) {
        bits += kDescriptorBitCount;
    }
    return bits;
}

/** @return Encoded byte size for one snapshot: meaningful bits padded to a whole byte. */
[[nodiscard]] constexpr std::size_t encoded_size(const MembershipSnapshot& snapshot) noexcept {
    const std::size_t bits = meaningful_bit_count(snapshot);
    return bits / 8 + (bits % 8 != 0 ? 1 : 0);
}

/**
 * Encodes one full-player membership snapshot. No allocation.
 * @param snapshot Checked identity, revision, transition, and host-echo values.
 * @param output Caller storage, left unchanged when validation fails or it is too small.
 * @param written Receives the encoded byte count on success or zero on failure.
 * @return True when the host-present body was encoded.
 */
[[nodiscard]] bool encode_replicate_membership(const MembershipSnapshot& snapshot,
                                               std::span<std::byte> output,
                                               std::size_t& written) noexcept;

/** The local member begins after root, revision, and epoch fields. */
inline constexpr std::size_t kMemberStartBit = 65;
/** The full identity shifts the region block to bit 835. */
inline constexpr std::size_t kRegionBlockStartBit = 835;
/** The host-present region block ends before top-level field four. */
inline constexpr std::size_t kRegionBlockEndBit = 29'899;

/** @return Bit at which the region block starts for one snapshot. */
[[nodiscard]] constexpr std::size_t
region_block_start_bit(const MembershipSnapshot& snapshot) noexcept {
    return snapshot.peerPresent ? kRegionBlockStartBit + kPeerRowExtraBits
                                : kRegionBlockStartBit;
}

/** @return Bit at which the region block ends for one snapshot. */
[[nodiscard]] constexpr std::size_t
region_block_end_bit(const MembershipSnapshot& snapshot) noexcept {
    std::size_t bits = kRegionBlockEndBit;
    if (snapshot.peerPresent) {
        bits += kPeerRowExtraBits;
    }
    if (snapshot.citizen.present) {
        bits += kDescriptorBitCount;
    }
    return bits;
}

/** @return True when the teleport slice-set index fits its fixed wire field. */
[[nodiscard]] bool valid(const MembershipSnapshot& snapshot) noexcept;

/**
 * Writes the populated members and the absent member slots after them.
 * @param writer Fixed-buffer writer positioned at bit 65.
 * @param identity Exact client identity accepted for the current join; occupies slot 0.
 * @param peer The other joined session's identity; occupies slot 1 when present.
 * @param peerPresent True when a peer row is published this revision.
 * @return True when the writer reaches the region-block presence bit.
 */
[[nodiscard]] bool write_member_table(encoding::bits::Writer& writer,
                                      const client_identity::ClientIdentity& identity,
                                      const client_identity::ClientIdentity& peer,
                                      bool peerPresent) noexcept;

/**
 * Writes all 64 state-zero regions and the host-present tail.
 * @param writer Fixed-buffer writer positioned at bit 835.
 * @param snapshot Transition token and reflected host state.
 * @return True when the writer reaches top-level field four.
 */
[[nodiscard]] bool write_region_block(encoding::bits::Writer& writer,
                                      const MembershipSnapshot& snapshot) noexcept;

} // namespace sunrise::middleware::bap::activity_message::replicate_membership
