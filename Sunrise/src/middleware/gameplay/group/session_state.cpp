#include "session_state.h"

#include <string_view>

#include "../../../core/settings/server/definition.h"
#include "../../crypto/lookup3.h"

namespace sunrise::middleware::gameplay::group {

namespace {

// --- Protobuf region offsets ------------------------------------------------------------------
// These are absolute byte offsets into the replica. The peer hashes the whole struct, so every
// one of them must match its own layout exactly.

/** Membership revision, protobuf field 1. */
constexpr std::size_t kRevisionOffset = 4;
/** Host member index, field 2. */
constexpr std::size_t kHostIndexOffset = 12;
/** Host-succession candidate, field 3. */
constexpr std::size_t kSuccessionOffset = 20;
/** Member count, field 4. */
constexpr std::size_t kMemberCountOffset = 28;
/** Member-slot bitmask, field 5. */
constexpr std::size_t kMemberMaskOffset = 40;
/** Element count of the repeated member field, which the apply copies as eight bytes. */
constexpr std::size_t kMemberArrayCountOffset = 48;
/** First member entry, field 6. */
constexpr std::size_t kMemberArrayOffset = 56;
/** Bytes one member entry occupies. */
constexpr std::size_t kMemberStride = 184;

/** NetAddr length, member field 1. The value slot holds 88 bytes and the blob fills 86. */
constexpr std::size_t kMemberAddressLengthOffset = 8;
/** See kMemberAddressLengthOffset. */
constexpr std::size_t kMemberAddressOffset = 16;
/** Machine-id length, member field 2. */
constexpr std::size_t kMemberMachineLengthOffset = 112;
/** See kMemberMachineLengthOffset. */
constexpr std::size_t kMemberMachineOffset = 120;
/** Join id, member field 3. */
constexpr std::size_t kMemberJoinIdOffset = 136;
/** p2-186: the member's second identity (protobuf field 8, `idB`) - the true offset from
 *  the descriptor copier's walk (the +152 landing, validated against every hash-validated
 *  model offset and the 184 stride; p2-185's 144 was 8 bytes low). */
constexpr std::size_t kMemberIdBOffset = 152;
/** Element count of the repeated player-slot field, member field 10. */
constexpr std::size_t kMemberPlayerCountOffset = 168;
/** See kMemberPlayerCountOffset. */
constexpr std::size_t kMemberPlayerSlotOffset = 176;

// --- Peer table -------------------------------------------------------------------------------
// The only region outside the protobuf a complete snapshot writes. Indexed by member index.

/** First peer entry. */
constexpr std::size_t kPeerTableOffset = 5968;
/** Bytes one peer entry occupies. */
constexpr std::size_t kPeerStride = 288;
/** Connection state, the field the consumer's own scan reads. */
constexpr std::size_t kPeerStateOffset = 0;
/** The eight-bit delta field, stored as a word. */
constexpr std::size_t kPeerValueOffset = 4;
/** Join compatibility. */
constexpr std::size_t kPeerCompatibilityOffset = 8;
/** Join timestamp. */
constexpr std::size_t kPeerTimestampOffset = 16;

// --- Player table -----------------------------------------------------------------------------
// Mirrors the peer table. An applied row also sets two words to all ones.

/** Live player count. */
constexpr std::size_t kPlayerCountOffset = 15184;
/**
 * The client's apply pins its player-table header 8 bytes ABOVE our model
 * (count@0x3b58/mask@0x3b5c/table@0x3b60 vs our 0x3b50/54/58 - l9-profile-layout
 * ADDENDUM). With the shift the layout is also self-consistent: 15200 + 32x424
 * = 28768 = kSessionStateSize exactly, where our base leaves 8 bytes of slack.
 * The hash mismatch this shift causes is OBSERVED (2026-08-30: membership
 * checksum rejections escalating to force-disconnect at peer arrival), which is
 * the addendum's named re-open condition.
 */
constexpr std::size_t kPlayerBaseShift = 8;
/** Occupied player-slot mask. */
constexpr std::size_t kPlayerMaskOffset = 15188;
/** Player identity. */
constexpr std::size_t kPlayerIdOffset = 4;
/** Member index that owns the player. */
constexpr std::size_t kPlayerMemberOffset = 12;
/** The owning member's own player index, which the decoder forces to zero. */
constexpr std::size_t kPlayerOwnedIndexOffset = 16;
/** Session player-add counter. */
constexpr std::size_t kPlayerSequenceOffset = 20;
/** The one-bit field, stored as a byte. */
constexpr std::size_t kPlayerFlagOffset = 24;
/** First of the two words the apply sets to all ones. */
constexpr std::size_t kPlayerClearedFirstOffset = 28;
/** Second of the two words the apply sets to all ones. */
constexpr std::size_t kPlayerClearedSecondOffset = 264;
/** Value both cleared words take. */
constexpr std::uint64_t kPlayerCleared = 0xFFFFFFFF;

// --- The stored profile image -----------------------------------------------------------------
// RE_output/claims/session-state-profile-image.md, derived from the client's own apply
// (0x141781800: `mov dword [entry+0x1c],0xffffffff` @0x141782408 and `[entry+0x108]`
// @0x141782410, both gated by the profile flag at `cmp byte [rbx+0x19],0` @0x14178241b),
// its helpers, and FINDINGS 20.202's field-by-field region-A decode. The session layer
// copies the block VERBATIM - it does not interpret it - so every byte below is a pure
// function of what our own encoder wrote.

/** Region-A header word. The encoder writes kProfileHeader1 = 0 and the apply copies it. */
constexpr std::size_t kProfileHeader1Offset = 0;
/** Region-A header two. The encoder writes 1 into a 3-bit field the decoder DECREMENTS,
 *  so the STORED value is 0 - not the 0xFFFFFFFF absent marker that sits here otherwise. */
constexpr std::size_t kProfileHeader2Offset = kPlayerClearedFirstOffset;
/** Stored value of that decremented header. */
constexpr std::uint64_t kProfileHeader2Stored = 0;
/** Region A begins here and runs 232 bytes. */
constexpr std::size_t kRegionAOffset = 32;
/** Bytes region A occupies. */
constexpr std::size_t kRegionASize = 232;
/** Region B begins where the second absent marker otherwise sits, and runs 136 bytes.
 *  Our encoder publishes all four of its presence flags clear, so the raw copy moves a
 *  zeroed delta and the stored bytes are zero - again NOT the 0xFFFFFFFF marker. */
constexpr std::size_t kRegionBOffset = kPlayerClearedSecondOffset;
/** The 20-byte tail: three words the apply copies verbatim, then its small fields. */
constexpr std::size_t kTailOffset = 400;
/** Tail word two carries the encoder's kProfileTailWord2. */
constexpr std::size_t kTailWord2Offset = 8;
/** See kTailWord2Offset. */
constexpr std::uint64_t kTailWord2 = 0x01000000;
/** The tail's 5-bit field, stored as a dword at tail+0x0c (measured, FINDINGS 20.207). */
constexpr std::size_t kTailFieldOffset = 12;
/** The tail's 5-bit field stores this; its 0x10 bit must stay clear or the reader desyncs. */
constexpr std::uint64_t kTailField3Stored = 1;

/** Region-A chunk 1: the name, 128 bytes of 16-bit words plus a zero terminator. */
constexpr std::size_t kNameChunkOffset = 0;
/** See kNameChunkOffset. */
constexpr std::size_t kNameChunkSize = 128;
/** Words the encoder will publish at most, matching kProfileNameMaxWords. */
constexpr std::size_t kNameMaxWords = 32;
/** Region-A chunks 4 and 5: each reads 6 bits and DECs, so the encoder's 1 stores 0. */
constexpr std::size_t kDecByteFourOffset = 178;
/** See kDecByteFourOffset. */
constexpr std::size_t kDecByteFiveOffset = 179;
/** Region-A chunk 7: the account SOID then the character SOID, 16 bytes (FINDINGS 20.202). */
constexpr std::size_t kAccountSoidOffset = 192;
/** See kAccountSoidOffset. */
constexpr std::size_t kCharacterSoidOffset = 200;

/** Name obfuscation, writer side (FINDINGS 20.179 R1) - the same constants the encoder uses. */
constexpr std::uint16_t kNameMultiplierInverse = 0xBBAFU;
/** See kNameMultiplierInverse. */
constexpr std::uint32_t kNameKeySeed = 0xC245B0C4U;
/** See kNameMultiplierInverse. */
constexpr std::size_t kNameKeyPeriod = 31U;
/** Bits one stored name word occupies. */
constexpr std::size_t kNameWordBytes = 2;

/** @return The name obfuscation key for one word index. Mirrors session_messages.cpp. */
[[nodiscard]] std::uint16_t name_key16(std::size_t index) noexcept {
    if (index == 0) {
        return 0U;
    }
    const auto rotation = static_cast<unsigned>(index % kNameKeyPeriod);
    const std::uint32_t rotated =
        rotation == 0U ? kNameKeySeed
                       : ((kNameKeySeed << rotation) | (kNameKeySeed >> (32U - rotation)));
    return static_cast<std::uint16_t>(rotated & 0xFFFFU);
}

/** Length the consumer requires of a member NetAddr. */
constexpr std::uint64_t kAddressLength = 86;
/** Length the consumer requires of a member machine id. */
constexpr std::uint64_t kMachineIdLength = 8;
/** Player slots one member may own. */
constexpr std::uint64_t kOwnedPlayerCount = 1;

/** Starting value the three lookup3 accumulators share. It is a fixed literal, not length-derived.
 */
constexpr std::uint32_t kHashInitial = 0xDEAE2F4E;

/** Bits in one byte. */
constexpr unsigned kByteBits = 8;
/** Mask of one byte. */
constexpr std::uint64_t kByteMask = 0xFF;

/**
 * Writes one little-endian integer into the replica.
 * @param output Replica being filled.
 * @param offset Byte offset of the field.
 * @param value Value to store.
 * @param width Bytes the field occupies.
 */
void write_integer(SessionState& output,
                   std::size_t offset,
                   std::uint64_t value,
                   std::size_t width) noexcept {
    for (std::size_t index = 0; index < width; ++index) {
        output[offset + index] = static_cast<std::byte>((value >> (index * kByteBits)) & kByteMask);
    }
}

/**
 * Writes one player row's stored profile image over the two absent markers.
 * @param output Replica being filled.
 * @param entry Byte offset of the player entry.
 * @param player Row whose identity chunk is published.
 * @param name Per-row name text the encoder published (slot digit already appended).
 * @param variant Which unresolved image variant to build.
 */
void write_profile_image(SessionState& output,
                         std::size_t entry,
                         const MembershipPlayer& player,
                         std::string_view name,
                         const ProfileVariant& variant) noexcept {
    write_integer(output, entry + kProfileHeader1Offset, 0, sizeof(std::uint32_t));
    write_integer(
        output, entry + kProfileHeader2Offset, kProfileHeader2Stored, sizeof(std::uint32_t));

    const std::size_t regionA = entry + kRegionAOffset;
    const std::size_t words = name.size() < kNameMaxWords ? name.size() : kNameMaxWords;
    for (std::size_t index = 0; index < words; ++index) {
        const auto plain = static_cast<std::uint16_t>(static_cast<unsigned char>(name[index]));
        const auto stored =
            variant.nameObfuscated
                ? static_cast<std::uint16_t>(
                      ((plain ^ name_key16(index)) * kNameMultiplierInverse) & 0xFFFFU)
                : plain;
        write_integer(
            output, regionA + kNameChunkOffset + index * kNameWordBytes, stored, kNameWordBytes);
    }
    // THE TERMINATOR IS NOT ZERO. The reader's loop (0x1416d3460) stores
    // key ^ (source * multiplier) for EVERY word INCLUDING the zero terminator, and only
    // then tests the SOURCE word for zero and exits. So the stored word at index L is
    // key16(L) ^ 0 = key16(L) - a NON-ZERO value that our cleared entry leaves at zero.
    // p2(133) missed this and every hash it published was wrong by that one word.
    // name_codec.py's own selftest documents it ("terminator-stores-key16(L)").
    write_integer(output,
                  regionA + kNameChunkOffset + words * kNameWordBytes,
                  name_key16(words),
                  kNameWordBytes);
    // Everything past the terminator stays zero, which a cleared entry already holds.

    // Chunks 4 and 5: the encoder writes 1 into each 6-bit field and the decoder DECs it.
    write_integer(output, regionA + kDecByteFourOffset, 0, sizeof(std::uint8_t));
    write_integer(output, regionA + kDecByteFiveOffset, 0, sizeof(std::uint8_t));

    // Chunk 7 is absent unless the encoder had both SOIDs, which is the encoder's own rule.
    if (player.accountSoid != 0 && player.characterSoid != 0) {
        write_integer(
            output, regionA + kAccountSoidOffset, player.accountSoid, sizeof(std::uint64_t));
        write_integer(
            output, regionA + kCharacterSoidOffset, player.characterSoid, sizeof(std::uint64_t));
    }

    // Region B: four presence flags all clear, so its 136 raw-copied bytes are zero. The
    // cleared entry already holds that; the point is that the absent MARKER must not be here.
    write_integer(output, entry + kRegionBOffset, 0, sizeof(std::uint32_t));

    // The tail, MEASURED from the client's own decode of a body we published
    // (`ev=ingress stage=dump tag=tail`, caller_rva=0x178245D = the apply's helper-A call):
    //     0000000000000000 00000001 01000000 00000000
    // i.e. tail+0x00 = 0, tail+0x04 = 0, tail+0x08 = 0x01000000 (our kProfileTailWord2),
    // and tail+0x0c = 0x00000001 - the 5-bit field, stored as a DWORD. p2(133) published
    // nothing at +0x0c and every hash it sent was short by that word. Not derived: read
    // off the wire path in a live run (FINDINGS 20.207).
    const std::size_t tail = entry + kTailOffset;
    write_integer(output, tail + kTailWord2Offset, kTailWord2, sizeof(std::uint32_t));
    write_integer(output, tail + kTailFieldOffset, kTailField3Stored, sizeof(std::uint32_t));
    (void)variant;
}

} // namespace

static_assert(kProfileVariantCount == core::settings::server::kProfileStateVariantCount,
              "the settings bound and the variant enumeration must not drift apart");

/** @return The variant at `index` in the canonical enumeration order. */
ProfileVariant profile_variant(const std::size_t index) noexcept {
    const std::size_t bounded = index % kProfileVariantCount;
    const std::size_t position = bounded % kTailFieldPositions;
    ProfileVariant variant{};
    variant.nameObfuscated = bounded >= kTailFieldPositions;
    variant.tailFieldOffset = position == 0U ? kTailFieldAbsent
                                             : static_cast<std::uint8_t>(position - 1U);
    return variant;
}

/** Fills a replica of the session state a peer holds after applying one complete snapshot. */
void build_session_state(const MembershipUpdate& body, SessionState& output,
                         const bool clientBase, const ProfileModel& profile) noexcept {
    output = {};
    const std::uint64_t count = static_cast<std::uint64_t>(body.members.size());
    // Members occupy indices 0 upward, so the mask follows from the count. The encoder derives
    // it the same way, and a mismatch changes the hash.
    const std::uint64_t mask = count == 0 ? 0 : (std::uint64_t{1} << count) - 1;

    write_integer(output, kRevisionOffset, body.revision, sizeof(std::uint32_t));
    write_integer(output, kHostIndexOffset, body.hostMemberIndex, sizeof(std::uint32_t));
    write_integer(output, kSuccessionOffset, body.successionIndex, sizeof(std::uint32_t));
    write_integer(output, kMemberCountOffset, count, sizeof(std::uint32_t));
    write_integer(output, kMemberMaskOffset, mask, sizeof(std::uint64_t));
    write_integer(output, kMemberArrayCountOffset, count, sizeof(std::uint64_t));

    for (std::size_t index = 0; index < body.members.size(); ++index) {
        const MembershipMember& member = body.members[index];
        const std::size_t entry = kMemberArrayOffset + kMemberStride * index;
        write_integer(
            output, entry + kMemberAddressLengthOffset, kAddressLength, sizeof(kAddressLength));
        for (std::size_t byte = 0; byte < member.address.size(); ++byte) {
            output[entry + kMemberAddressOffset + byte] = member.address[byte];
        }
        write_integer(
            output, entry + kMemberMachineLengthOffset, kMachineIdLength, sizeof(kMachineIdLength));
        write_integer(
            output, entry + kMemberMachineOffset, member.machineId, sizeof(std::uint64_t));
        write_integer(output, entry + kMemberJoinIdOffset, member.joinId, sizeof(std::uint64_t));
        // p2-186: the member's idB (protobuf field 8) lands at entry+152 - derived from the
        // descriptor copier's walk (0x1416E2350: field address = walker + entry[8] +
        // entry[9] signed, advancing by size; walker starts at entry+8 - the walk matches
        // every hash-validated model offset AND sums to the 184 stride exactly). p2-185's
        // entry+144 was 8 bytes low, which diverged the state hash (outcome (c)).
        write_integer(output, entry + kMemberIdBOffset, member.idB, sizeof(std::uint64_t));
        if (member.ownsPlayerSlot) {
            write_integer(output,
                          entry + kMemberPlayerCountOffset,
                          kOwnedPlayerCount,
                          sizeof(kOwnedPlayerCount));
            write_integer(
                output, entry + kMemberPlayerSlotOffset, member.playerSlot, sizeof(std::uint32_t));
        }

        // One peer entry per member, matching what the encoder publishes. The peer clears this
        // table before applying, so a member with no connection block leaves the values zero.
        const std::size_t peer = kPeerTableOffset + kPeerStride * index;
        write_integer(output,
                      peer + kPeerStateOffset,
                      static_cast<std::uint64_t>(member.state),
                      sizeof(std::uint32_t));
        if (member.connectionPresent) {
            write_integer(
                output, peer + kPeerValueOffset, member.connectionValue, sizeof(std::uint32_t));
            write_integer(output,
                          peer + kPeerCompatibilityOffset,
                          member.joinCompatibility,
                          sizeof(std::uint32_t));
            write_integer(
                output, peer + kPeerTimestampOffset, member.joinTimestamp, sizeof(std::uint64_t));
        }
    }

    std::uint64_t playerMask = 0;
    const std::size_t baseShift = clientBase ? kPlayerBaseShift : 0U;
    for (const MembershipPlayer& player : body.players) {
        playerMask |= std::uint64_t{1} << player.slot;
        const std::size_t entry =
            kPlayerTableOffset + baseShift + kPlayerStride * player.slot;
        write_integer(output, entry + kPlayerIdOffset, player.playerId, sizeof(std::uint64_t));
        write_integer(
            output, entry + kPlayerMemberOffset, player.memberIndex, sizeof(std::uint32_t));
        write_integer(output, entry + kPlayerOwnedIndexOffset, 0, sizeof(std::uint32_t));
        write_integer(
            output, entry + kPlayerSequenceOffset, player.addSequence, sizeof(std::uint32_t));
        write_integer(
            output, entry + kPlayerFlagOffset, player.flag ? 1U : 0U, sizeof(std::uint8_t));
        if (!profile.publish) {
            // The pre-profile bytes, byte for byte. Arm A (FINDINGS 20.205 R3) proved this
            // path correct against the live client: 9 of 9 bodies accepted.
            write_integer(
                output, entry + kPlayerClearedFirstOffset, kPlayerCleared, sizeof(std::uint32_t));
            write_integer(
                output, entry + kPlayerClearedSecondOffset, kPlayerCleared, sizeof(std::uint32_t));
            continue;
        }
        // The encoder gives every row a DISTINCT name - the configured text with the slot
        // digit appended - so the replica has to build the same per-row string. An empty
        // setting publishes the empty name and appends nothing, which write_player_delta
        // does too.
        std::array<char, kNameMaxWords + 1U> named{};
        std::size_t length = 0;
        for (; length < profile.name.size() && length + 2U < named.size(); ++length) {
            named[length] = profile.name[length];
        }
        if (length != 0 && length + 1U < named.size()) {
            named[length] = static_cast<char>('0' + static_cast<int>(player.slot % 10U));
            ++length;
        }
        write_profile_image(output,
                            entry,
                            player,
                            std::string_view{named.data(), length},
                            profile.variant);
    }
    write_integer(output,
                  kPlayerCountOffset + baseShift,
                  body.players.size(),
                  sizeof(std::uint32_t));
    write_integer(output, kPlayerMaskOffset + baseShift, playerMask, sizeof(std::uint32_t));
}

/** Computes the state hash a peer will expect for one complete snapshot. */
std::uint32_t session_state_hash(const MembershipUpdate& body,
                                 const bool clientBase,
                                 const ProfileModel& profile) noexcept {
    // The replica is 28 KiB, too large for a stack frame on a game thread.
    static thread_local SessionState state{};
    build_session_state(body, state, clientBase, profile);
    return crypto::lookup3::hash_bytes(state, kHashInitial);
}

} // namespace sunrise::middleware::gameplay::group
