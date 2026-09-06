#include "session_messages.h"

#include <array>

#include "../../encoding/bit_raw.h"
#include "../../protobuf/codec.h"
#include "session_state.h"

namespace sunrise::middleware::gameplay::group {

namespace {

namespace bits = encoding::bits;

/** The protocol version is a 16-bit value field. */
constexpr std::uint8_t kProtocolWidth = 16;
/** The join sequence is a 32-bit value field. */
constexpr std::uint8_t kSequenceWidth = 32;
/** Single-bit flags. */
constexpr std::uint8_t kFlagWidth = 1;
/** The boot kind is three bits. */
constexpr std::uint8_t kBootKindWidth = 3;
/** The boot reason is five bits. */
constexpr std::uint8_t kBootReasonWidth = 5;
/** Time samples are 64-bit value fields. */
constexpr std::uint8_t kSampleWidth = 64;

// --- Membership update, message id 30 -------------------------------------------------------

/** Protobuf field numbers of the membership root. */
constexpr std::uint32_t kRootRevision = 1;
/** See kRootRevision. */
constexpr std::uint32_t kRootHostIndex = 2;
/** See kRootRevision. */
constexpr std::uint32_t kRootSuccession = 3;
/** See kRootRevision. */
constexpr std::uint32_t kRootMemberCount = 4;
/** See kRootRevision. */
constexpr std::uint32_t kRootMemberMask = 5;
/** See kRootRevision. */
constexpr std::uint32_t kRootMember = 6;

/** Protobuf field numbers of one member. Field 9 is not published. */
constexpr std::uint32_t kMemberAddress = 1;
/** See kMemberAddress. */
constexpr std::uint32_t kMemberMachineId = 2;
/** See kMemberAddress. */
constexpr std::uint32_t kMemberJoinId = 3;
/** See kMemberAddress. */
constexpr std::uint32_t kMemberIdB = 8;
/** See kMemberAddress. */
constexpr std::uint32_t kMemberPlayerSlot = 10;
/** See kMemberAddress. */
constexpr std::uint32_t kMemberFlagA = 11;
/** See kMemberAddress. */
constexpr std::uint32_t kMemberFlagB = 12;

/** Member field 8 has no recovered meaning. Zero is the value an empty id decodes to. */
constexpr std::uint64_t kMemberIdEmpty = 0;
/** Member fields 11 and 12 have no recovered meaning. Zero is their cleared value. */
constexpr std::uint64_t kMemberFlagClear = 0;

/** The protobuf body is length-prefixed with thirteen bits. */
constexpr std::uint8_t kProtobufLengthWidth = 13;
/** Both revision words are 32 bits. */
constexpr std::uint8_t kRevisionWidth = 32;
/** Both delta counts are six bits. */
constexpr std::uint8_t kDeltaCountWidth = 6;
/** A peer-delta index is six bits. */
constexpr std::uint8_t kDeltaIndexWidth = 6;
/** A member state is four bits. */
constexpr std::uint8_t kMemberStateWidth = 4;
/** The third connection value. */
constexpr std::uint8_t kConnectionValueWidth = 8;
/** The join compatibility word, and the trailing session-state hash. */
constexpr std::uint8_t kWordWidth = 32;
/** The join timestamp. It is a value field, so it goes out most significant byte first. */
constexpr std::uint8_t kJoinTimestampWidth = 64;

/** A clear flag ahead of the revision pair publishes it. Its absence decodes as -1. */
constexpr std::uint64_t kRevisionPairPresent = 0;
/** Base revision 0 selects a complete snapshot. Any other value is a delta against that revision.
 */
constexpr std::uint32_t kCompleteSnapshotBase = 0;
/** The word after the base revision is never read by the consumer. */
constexpr std::uint32_t kUnreadWord = 0;
/** A set mode bit means a whole peer-delta entry follows the index. */
constexpr std::uint64_t kDeltaEntryFull = 1;
/** A player-delta index is five bits, one narrower than a peer-delta index. */
constexpr std::uint8_t kPlayerIndexWidth = 5;
/** The member index a player row names. */
constexpr std::uint8_t kPlayerMemberWidth = 6;
/** The member's own player index. The decoder refuses any value but zero, so a member publishes
 *  at most one player this way. */
constexpr std::uint8_t kPlayerOwnedIndexWidth = 1;
/** The session player-add counter, which the consumer keeps modulo 2^20. */
constexpr std::uint8_t kPlayerSequenceWidth = 20;
/** Value the decoder requires of the member's own player index. */
constexpr std::uint64_t kPlayerOwnedIndexZero = 0;
/** A clear flag ends a player row after its identity group: the profile block it would gate is
 *  not published. With `publish_player_profile` the row instead carries the gate SET plus the
 *  minimal block below. */
constexpr std::uint64_t kPlayerProfileAbsent = 0;

// --- The minimal player profile block (FINDINGS 20.177 RESULT 5, decoder 0x14173BFC0) --------
// Every width was read from the decoder, not inferred. The block is presence-bit-prefixed
// sub-chunks, never raw bytes; the field list below sums to 178 bits (36 header + 37 region A
// + 1 region B + 104 tail). FINDINGS 20.177's "total 150 bits" summary does not match its own
// field list; the decoder-read widths win (20.176 RESULT 3 corroborates each one).
/** The block header's first word. Its meaning is unread; replayed from the p2(113) harvest. */
constexpr std::uint64_t kProfileHeader1 = 0;
/** The block header's second field is read as 3 bits and then DECed, so a stored 0 is a
 *  written 1. Writing 0 would store 0xFF. */
constexpr std::uint64_t kProfileHeader2Stored = 1;
/** Region A chunk 1 is the name: 16-bit words until a zero word. One zero word IS the
 *  terminator, and the name scan needs that zero word to return true. */
constexpr std::uint8_t kProfileNameWidth = 16;

/**
 * THE NAME OBFUSCATION, WRITER SIDE (FINDINGS 20.179 RESULT 1, from the reader's
 * deobfuscation loop at 0x1416D3460):
 *     plain[i] = key16(i) ^ ((wire[i] * 0x7b4f) & 0xFFFF)
 *     key16(0) = 0,  key16(i>0) = rotl32(0xC245B0C4, i mod 31) & 0xFFFF
 * so the writer inverts the multiply: wire[i] = ((plain[i] ^ key16(i)) * inv) & 0xFFFF.
 * 0x7b4f is odd, so it is a unit mod 2^16 and the inverse exists. The static_assert below
 * is the guard - a mistyped inverse would silently publish garbage names.
 * NOTE the index-0 special case is NOT a consequence of the rotation: at i=31 the rotation
 * is by ZERO and key16(31) = 0xB0C4, not 0. Names 31+ words long depend on that.
 * Oracle: RE_scripts/name_codec.py --selftest (10/10), same constants, round-trips.
 */
constexpr std::uint16_t kNameMultiplier = 0x7B4FU;
constexpr std::uint16_t kNameMultiplierInverse = 0xBBAFU;
static_assert((kNameMultiplier * kNameMultiplierInverse) & 0xFFFFU,
              "the name multiplier inverse must exist");
static_assert(((kNameMultiplier * kNameMultiplierInverse) & 0xFFFFU) == 1U,
              "wire[i] = (plain[i] ^ key16(i)) * inverse requires a true modular inverse");
constexpr std::uint32_t kNameKeySeed = 0xC245B0C4U;
constexpr std::size_t kNameKeyPeriod = 31U;

/** Words the name field can hold. The stored field is 128 B = 64 words including the
 *  terminator, and we stay well inside it. */
constexpr std::size_t kProfileNameMaxWords = 32U;

/** Chunk 7's two identity words: 64-bit VALUE fields, MSB-first. */
constexpr std::uint8_t kSoidWidth = 64;
/** Region A chunks 4 and 5 each read 6 bits and then DEC it, so writing 1 stores 0 (the range
 *  check needs stored+1 <= 0x20). Writing 0 would store 0xFF and fail it. */
constexpr std::uint8_t kProfileDecByteWidth = 6;
/** See kProfileDecByteWidth. */
constexpr std::uint64_t kProfileDecByteStoredZero = 1;
/** Tail word [rdi+0x00], replayed from the p2(113) harvest. */
/**
 * Region B carries FOUR 1-bit presence flags, not one (the reader 0x1416D3C30, read to its
 * `mov al,1` return; the wrapper 0x1416D3DD0 reads no bits, which is what made the earlier
 * one-bit reading look right). Flag 1 gates an obfuscated name, flags 2/3 a 6-bit field
 * each, flag 4 a 2-bit then a 6-bit field. All four clear = an empty region B, which is
 * what a minimal block wants.
 * p2(116) proved the one-bit form is what breaks us: the client consumed our single bit as
 * flag 1, then ate the first three bits of the 104-bit tail as flags 2-4, and every field
 * after region B was read three bits early. The tail's zeros survived the shift but the
 * trailing 32-bit state hash was read past the body's bit count, the reader's error flag
 * set, and the decoder returned FALSE (20.188 R1: ret=0x0 on the player-bearing body,
 * ret=0x1 on the members-only one in the same millisecond).
 */
constexpr std::uint8_t kProfileRegionBFlags = 4;

constexpr std::uint64_t kProfileTailWord0 = 0;
/** Tail word [rdi+0x04], replayed from the p2(113) harvest. */
constexpr std::uint64_t kProfileTailWord1 = 0;
/** Tail word [rdi+0x08], replayed from the p2(113) harvest. */
constexpr std::uint64_t kProfileTailWord2 = 0x01000000;
/** The tail's 5-bit field. Bit 0x10 of the STORED byte must stay CLEAR or the decoder reads a
 *  further section and the stream desyncs. */
constexpr std::uint8_t kProfileTailField3Width = 5;
/** See kProfileTailField3Width. Value 1 has bit 0x10 clear. */
constexpr std::uint64_t kProfileTailField3 = 1;
/** The tail's 2-bit field. */
constexpr std::uint8_t kProfileTailField4Width = 2;
/** See kProfileTailField4Width, replayed from the p2(113) harvest. */
constexpr std::uint64_t kProfileTailField4 = 0;
/** The tail's trailing flag, replayed from the p2(113) harvest. */
constexpr std::uint64_t kProfileTailField5 = 0;
/** This host publishes no 264-byte identity block and neither trailing delta-entry flag. */
constexpr std::uint64_t kEntryFieldAbsent = 0;
/** The four tail groups are all omitted, which leaves the consumer's own values alone. */
constexpr std::uint64_t kTailGroupAbsent = 0;
/** Tail groups omitted, one presence bit each. The encoder writes four, not five. */
constexpr std::size_t kTailGroupCount = 4;
/** Largest protobuf body the message codec accepts. */
constexpr std::size_t kProtobufCapacity = 5972;
/** One encoded member submessage cannot exceed this. */
constexpr std::size_t kMemberBytes = 128;
/** Machine identities are published as eight bytes in memory order. */
constexpr std::size_t kMachineIdBytes = 8;
/** Bits in one byte. */
constexpr unsigned kByteBits = 8;
/** Mask of one byte. */
constexpr std::uint64_t kByteMask = 0xFF;

/**
 * Appends one member as a length-delimited submessage.
 * @param writer Open protobuf writer for the root message.
 * @param member Member to publish.
 * @return True when the whole submessage fit.
 */
[[nodiscard]] bool write_member(protobuf::Writer& writer, const MembershipMember& member) noexcept {
    std::array<std::byte, kMachineIdBytes> machineId{};
    for (std::size_t index = 0; index < machineId.size(); ++index) {
        machineId[index] =
            static_cast<std::byte>((member.machineId >> (index * kByteBits)) & kByteMask);
    }

    std::array<std::byte, kMemberBytes> storage{};
    protobuf::Writer body(storage);
    if (!body.write_length_delimited(kMemberAddress, member.address)
        || !body.write_length_delimited(kMemberMachineId, machineId)
        || !body.write_varint(kMemberJoinId, member.joinId)
        // p2-186: field 8 carries the member's session-scope identity (the fork's sessionId) -
        // landed at member-entry +152 by the copier walk; the session apply copies it into the
        // session's identity blob, which the join gate's lookup compares against a join's own
        // sessionId (the one-qword compare). p2-185 published it at the wrong MODEL offset and
        // diverged the hash; the wire here was always the value's carrier.
        || !body.write_varint(kMemberIdB, member.idB)) {
        return false;
    }
    if (member.ownsPlayerSlot && !body.write_varint(kMemberPlayerSlot, member.playerSlot)) {
        return false;
    }
    if (!body.write_varint(kMemberFlagA, member.flagA)
        || !body.write_varint(kMemberFlagB, member.flagB)) {
        return false;
    }
    return writer.write_length_delimited(kRootMember, {storage.data(), body.size()});
}

/**
 * Encodes the membership protobuf body.
 * @param body Snapshot to publish.
 * @param storage Caller-owned protobuf storage.
 * @param size Receives the encoded byte count.
 * @return True when every field fit.
 */
[[nodiscard]] bool write_membership_protobuf(const MembershipUpdate& body,
                                             std::span<std::byte> storage,
                                             std::size_t& size) noexcept {
    const std::uint64_t count = static_cast<std::uint64_t>(body.members.size());
    // Members occupy indices 0 upward, so the occupied-slot mask follows from the count.
    const std::uint64_t mask = (std::uint64_t{1} << count) - 1;
    protobuf::Writer writer(storage);
    if (!writer.write_varint(kRootRevision, body.revision)
        || !writer.write_varint(kRootHostIndex, body.hostMemberIndex)
        || !writer.write_varint(kRootSuccession, body.successionIndex)
        || !writer.write_varint(kRootMemberCount, count)
        || !writer.write_varint(kRootMemberMask, mask)) {
        return false;
    }
    for (const MembershipMember& member : body.members) {
        if (!write_member(writer, member)) {
            return false;
        }
    }
    size = writer.size();
    return true;
}

/**
 * Writes one peer-delta entry.
 * @param writer Open writer.
 * @param index Member index the entry names.
 * @param member Member whose state the entry publishes.
 * @return True when every field fit.
 */
[[nodiscard]] bool
write_peer_delta(bits::Writer& writer, std::size_t index, const MembershipMember& member) noexcept {
    if (!writer.write(index, kDeltaIndexWidth) || !writer.write(kDeltaEntryFull, kFlagWidth)
        || !writer.write(static_cast<std::uint64_t>(member.state), kMemberStateWidth)
        || !writer.write(member.connectionPresent ? 1U : 0U, kFlagWidth)) {
        return false;
    }
    if (member.connectionPresent
        && (!writer.write(member.joinCompatibility, kWordWidth)
            || !writer.write(member.joinTimestamp, kJoinTimestampWidth)
            || !writer.write(member.connectionValue, kConnectionValueWidth))) {
        return false;
    }
    return writer.write(kEntryFieldAbsent, kFlagWidth)
           && writer.write(kEntryFieldAbsent, kFlagWidth)
           && writer.write(kEntryFieldAbsent, kFlagWidth);
}

/** The per-word key the reader XORs in. Index 0 is a special case, not a rotation. */
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

/**
 * Writes region A's chunk 1: the presence flag, the obfuscated name words, then the ZERO
 * WIRE WORD that terminates the reader's walk. An empty name writes just the terminator,
 * which is the shape every block carried before names existed - so an unset setting
 * reproduces the previous bytes exactly.
 * @param writer Open writer positioned at chunk 1's presence flag.
 * @param name Plain text to publish; truncated at kProfileNameMaxWords.
 * @return True when every field fit.
 */
[[nodiscard]] bool write_profile_name(bits::Writer& writer, std::string_view name) noexcept {
    if (!writer.write(1U, kFlagWidth)) {
        return false;
    }
    const std::size_t words = name.size() < kProfileNameMaxWords ? name.size()
                                                                 : kProfileNameMaxWords;
    for (std::size_t index = 0; index < words; ++index) {
        const auto plain = static_cast<std::uint16_t>(static_cast<unsigned char>(name[index]));
        const auto obfuscated = static_cast<std::uint16_t>(
            ((plain ^ name_key16(index)) * kNameMultiplierInverse) & 0xFFFFU);
        if (!writer.write(obfuscated, kProfileNameWidth)) {
            return false;
        }
    }
    return writer.write(0U, kProfileNameWidth);
}

/**
 * Writes the decoder-correct profile block (FINDINGS 20.177 RESULT 5): an empty
 * profile whose shape alone forces all four of region A's exit conditions true by
 * construction - chunk 6 absent keeps r15b at its entry value 1, chunk 1's single zero word
 * satisfies the name terminator, and chunks 4/5 store 0, passing both range checks. It
 * carries no identity and no appearance content.
 * @param writer Open writer positioned right after the profile-present gate bit.
 * @return True when every field fit.
 */
[[nodiscard]] bool write_profile_block(bits::Writer& writer,
                                       std::string_view name,
                                       std::uint64_t accountSoid,
                                       std::uint64_t characterSoid) noexcept {
    // Header, after the gate bit the caller wrote: one 32-bit word, then the 3-bit field the
    // decoder decrements.
    if (!writer.write(kProfileHeader1, kWordWidth)
        || !writer.write(kProfileHeader2Stored, 3)) {
        return false;
    }
    // Region A: nine 1-bit presence flags IN WIRE ORDER - not mask-value order; the 0x100
    // chunk is emitted FIFTH. The 9-bit mask is built by the reader and never travels the wire
    // as a field.
    //   #1 0x001 name (one zero word)  #2 0x002 absent  #3 0x004 absent
    //   #4 0x008 dec-byte              #5 0x100 dec-byte (still wire position five)
    //   #6 0x010 absent                #7 0x020 absent   #8 0x040 absent  #9 0x080 absent
    if (!write_profile_name(writer, name)
        || !writer.write(0U, kFlagWidth) || !writer.write(0U, kFlagWidth)
        || !writer.write(1U, kFlagWidth)
        || !writer.write(kProfileDecByteStoredZero, kProfileDecByteWidth)
        || !writer.write(1U, kFlagWidth)
        || !writer.write(kProfileDecByteStoredZero, kProfileDecByteWidth)
        || !writer.write(0U, kFlagWidth)) {
        return false;
    }
    // Chunk 7 (wire position seven, mask bit 0x020): two 64-bit words copied verbatim to the
    // stored profile at +0xc0 and +0xc8 - the account SOID then the character SOID. Absent
    // unless the caller supplied both, which keeps the pre-identity bytes reachable.
    const bool identity = accountSoid != 0 && characterSoid != 0;
    if (!writer.write(identity ? 1U : 0U, kFlagWidth)) {
        return false;
    }
    // A VALUE write (most-significant-bit first), NOT bits::write_raw_u64.
    // p2(124) shipped the raw helper here and the SOIDs landed byte-reversed:
    // 9EAA300100100100 stored where 000110000130AA9E was wanted. bit_raw.h states the
    // distinction outright - "raw fields copy bytes and keep engine order; VALUE fields are
    // most-significant-bit first" - and chunk 7's reader is read_wide(0x40), a 64-bit VALUE
    // read whose result is stored as a host integer. playerId legitimately uses the raw
    // helper because ITS reader is a byte-wise raw read; the two conventions coexist in the
    // same body and the field decides which applies, not the type.
    if (identity
        && (!writer.write(accountSoid, kSoidWidth)
            || !writer.write(characterSoid, kSoidWidth))) {
        return false;
    }
    if (!writer.write(0U, kFlagWidth) || !writer.write(0U, kFlagWidth)) {
        return false;
    }
    // Region B: four presence bits, all clear - body absent.
    // Tail: fixed and unconditional - three 32-bit words, a 5-bit field whose 0x10 bit stays
    // clear, a 2-bit field, and one flag. 104 bits.
    for (std::uint8_t flag = 0; flag < kProfileRegionBFlags; ++flag) {
        if (!writer.write(0U, kFlagWidth)) {
            return false;
        }
    }
    return writer.write(kProfileTailWord0, kWordWidth)
           && writer.write(kProfileTailWord1, kWordWidth)
           && writer.write(kProfileTailWord2, kWordWidth)
           && writer.write(kProfileTailField3, kProfileTailField3Width)
           && writer.write(kProfileTailField4, kProfileTailField4Width)
           && writer.write(kProfileTailField5, kFlagWidth);
}

/**
 * Writes one player-delta entry carrying an identity and either the absent flag or the
 * minimal profile block.
 * @param writer Open writer.
 * @param player Player row to publish.
 * @param publishProfile When true, set the profile-present gate and write the minimal block.
 * @return True when every field fit.
 */
[[nodiscard]] bool write_player_delta(bits::Writer& writer,
                                      const MembershipPlayer& player,
                                      bool publishProfile,
                                      std::string_view profileName) noexcept {
    if (!writer.write(player.slot, kPlayerIndexWidth) || !writer.write(kDeltaEntryFull, kFlagWidth)
        || !writer.write(1U, kFlagWidth) || !bits::write_raw_u64(writer, player.playerId)
        || !writer.write(player.memberIndex, kPlayerMemberWidth)
        || !writer.write(kPlayerOwnedIndexZero, kPlayerOwnedIndexWidth)
        || !writer.write(player.addSequence, kPlayerSequenceWidth)
        || !writer.write(player.flag ? 1U : 0U, kFlagWidth)) {
        return false;
    }
    if (!publishProfile) {
        return writer.write(kPlayerProfileAbsent, kFlagWidth);
    }
    // Each row gets a DISTINCT name - the configured text with the player's slot appended -
    // so a client applying two rows can be told which row it applied. Without that, both
    // guardians would carry the same string and a peer's row would be indistinguishable
    // from the local one in the logs. An empty setting publishes the empty name, which
    // reproduces the pre-name bytes exactly.
    std::array<char, kProfileNameMaxWords + 1U> named{};
    std::size_t length = 0;
    for (; length < profileName.size() && length + 2U < named.size(); ++length) {
        named[length] = profileName[length];
    }
    if (length != 0 && length + 1U < named.size()) {
        named[length] = static_cast<char>('0' + static_cast<int>(player.slot % 10U));
        ++length;
    }
    // The gate bit, then the block. A false return leaves the body truncated; the caller
    // refuses the whole message, which is the safe direction.
    return writer.write(1U, kFlagWidth)
           && write_profile_block(writer, std::string_view{named.data(), length},
                                  player.accountSoid, player.characterSoid);
}

} // namespace

/** Writes a peer-connect body. */
bool write_peer_connect(bits::Writer& writer, const PeerConnect& body) noexcept {
    return writer.write(body.protocolVersion, kProtocolWidth)
           && bits::write_raw_u64(writer, body.machineId)
           && bits::write_raw_u64(writer, body.sessionId);
}

/** Writes a join-complete body. */
bool write_join_complete(bits::Writer& writer, const JoinComplete& body) noexcept {
    return bits::write_raw_u64(writer, body.sessionId)
           && bits::write_raw_u64(writer, body.machineId)
           && writer.write(body.joinSequence, kSequenceWidth);
}

/** Reads a join-complete body. */
bool read_join_complete(bits::Reader& reader, JoinComplete& output) noexcept {
    JoinComplete candidate{};
    std::uint64_t sequence = 0;
    if (!bits::read_raw_u64(reader, candidate.sessionId)
        || !bits::read_raw_u64(reader, candidate.machineId)
        || !reader.read(kSequenceWidth, sequence)) {
        return false;
    }
    candidate.joinSequence = static_cast<std::uint32_t>(sequence);
    output = candidate;
    return true;
}

/** Reads a join-abort body. */
bool read_join_abort(bits::Reader& reader, SessionNotice& output) noexcept {
    std::uint64_t flag = 0;
    SessionNotice candidate{};
    if (!bits::read_raw_u64(reader, candidate.sessionId)
        || !bits::read_raw_u64(reader, candidate.machineId) || !reader.read(kFlagWidth, flag)) {
        return false;
    }
    candidate.flag = flag != 0;
    output = candidate;
    return true;
}

/** Reads a session-identity-only body. */
bool read_session_only(bits::Reader& reader, std::uint64_t& output) noexcept {
    return bits::read_raw_u64(reader, output);
}

/** Writes a session-identity-only body. */
bool write_session_only(bits::Writer& writer, std::uint64_t sessionId) noexcept {
    return bits::write_raw_u64(writer, sessionId);
}

/** Writes a session-disband body. */
bool write_session_disband(bits::Writer& writer, const SessionNotice& body) noexcept {
    return bits::write_raw_u64(writer, body.sessionId)
           && bits::write_raw_u64(writer, body.machineId)
           && writer.write(body.flag ? 1U : 0U, kFlagWidth);
}

/** Writes a session-boot body. */
bool write_session_boot(bits::Writer& writer, const SessionBoot& body) noexcept {
    return bits::write_raw_u64(writer, body.sessionId) && writer.write(body.kind, kBootKindWidth)
           && writer.write(body.reason, kBootReasonWidth)
           && bits::write_raw_u64(writer, body.machineId);
}

/** Reads a time-synchronize body. */
bool read_time_synchronize(bits::Reader& reader, TimeSynchronize& output) noexcept {
    std::uint64_t variant = 0;
    TimeSynchronize candidate{};
    if (!bits::read_raw_u64(reader, candidate.sessionId) || !reader.read(kFlagWidth, variant)
        || !reader.read(kSampleWidth, candidate.sampleA)) {
        return false;
    }
    candidate.threeSample = variant != 0;
    if (candidate.threeSample
        && (!reader.read(kSampleWidth, candidate.sampleB)
            || !reader.read(kSampleWidth, candidate.sampleC))) {
        return false;
    }
    output = candidate;
    return true;
}

/** Writes a time-synchronize body. */
bool write_time_synchronize(bits::Writer& writer, const TimeSynchronize& body) noexcept {
    if (!bits::write_raw_u64(writer, body.sessionId)
        || !writer.write(body.threeSample ? 1U : 0U, kFlagWidth)
        || !writer.write(body.sampleA, kSampleWidth)) {
        return false;
    }
    if (!body.threeSample) {
        return true;
    }
    return writer.write(body.sampleB, kSampleWidth) && writer.write(body.sampleC, kSampleWidth);
}

/** Writes a complete-snapshot membership update.
 *  @param publishProfile When true, every player row carries the profile block
 *  @param profileName Plain name text to publish; the player's slot digit is appended
 *                        (FINDINGS 20.177 RESULT 5) behind its set gate bit.
 *  @return True when the whole body fit and the revision and member count are encodable. */
bool write_membership_update(bits::Writer& writer,
                             const MembershipUpdate& body,
                             bool publishProfile,
                             std::string_view profileName,
                             bool clientStateBase,
                             std::size_t profileVariant) noexcept {
    // The consumer refuses the message unless the base revision is below the message revision,
    // and a complete snapshot always publishes base revision 0.
    if (body.revision == 0 || body.members.size() > kMemberCapacity
        || body.players.size() > kPlayerCapacity) {
        return false;
    }
    for (const MembershipPlayer& player : body.players) {
        if (player.slot >= kPlayerCapacity || player.memberIndex >= kMemberCapacity) {
            return false;
        }
    }
    std::array<std::byte, kProtobufCapacity> protobufStorage{};
    std::size_t protobufSize = 0;
    if (!write_membership_protobuf(body, protobufStorage, protobufSize)) {
        return false;
    }
    if (!bits::write_raw_u64(writer, body.hostMachineId)
        || !writer.write(protobufSize, kProtobufLengthWidth)
        || !bits::write_raw(writer, {protobufStorage.data(), protobufSize})
        || !writer.write(kRevisionPairPresent, kFlagWidth)
        || !writer.write(kCompleteSnapshotBase, kRevisionWidth)
        || !writer.write(kUnreadWord, kRevisionWidth)
        || !writer.write(body.members.size(), kDeltaCountWidth)
        || !writer.write(body.players.size(), kDeltaCountWidth)) {
        return false;
    }
    for (std::size_t index = 0; index < body.members.size(); ++index) {
        if (!write_peer_delta(writer, index, body.members[index])) {
            return false;
        }
    }
    for (const MembershipPlayer& player : body.players) {
        if (!write_player_delta(writer, player, publishProfile, profileName)) {
            return false;
        }
    }
    for (std::size_t group = 0; group < kTailGroupCount; ++group) {
        if (!writer.write(kTailGroupAbsent, kFlagWidth)) {
            return false;
        }
    }
    // The consumer hashes its own state after applying and compares. The replica layout must
    // stay in step with it.
    ProfileModel profile{};
    profile.publish = publishProfile;
    profile.name = profileName;
    profile.variant = profile_variant(profileVariant);
    return writer.write(session_state_hash(body, clientStateBase, profile), kWordWidth);
}

} // namespace sunrise::middleware::gameplay::group
