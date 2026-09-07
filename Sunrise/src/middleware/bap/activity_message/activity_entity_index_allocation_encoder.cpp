#include "activity_entity_index_allocation_encoder.h"

#include "../../encoding/bit_writer.h"

namespace sunrise::middleware::bap::activity_message::entity_index_allocation {
namespace {

/**
 * The participant id is a biased signed value on the wire: the decoder subtracts
 * 0x80000000 (the descriptor's stored base, same bias family as the type-21
 * request parser), so the wire carries value + 0x80000000.
 */
constexpr std::uint32_t kIdBias = 0x80000000U;

/** Fixed wire geometry, from the 0x80809445 schema tree (see the claims doc). */
constexpr std::uint8_t kBlockACountWidth = 9;   // 0x8080944B/0x8080944A count fields
constexpr std::uint8_t kBlockBCountWidth = 7;   // 0x80809449 participant count
constexpr std::uint8_t kSubCountWidth = 7;      // 0x80809451/0x80809450 counts
constexpr std::size_t kBlockAIdWords = 256;     // 0x80809448: 256 x u32
constexpr std::size_t kBlockAWords = 8;         // 0x80809B99: 8 x u32
constexpr std::size_t kBlockAFlags = 256;       // 0x80809447: 256 x u8
constexpr std::size_t kMemberIdBits = 32;       // 0x8080944D field[0]
constexpr std::size_t kMemberMapWords = 3;      // 0x80809748: 3 x u32

/** Writes BLOCK A. The 256 x u32 array is the session's free-slot bitmap: bit b set
 *  while b < freeSlots (the joiner's lease range), clear above. v1 zero-filled this
 *  array, which told the client "no free indices" — the direct cause of the p2(140)
 *  allocator -1 exits (claim E). */
void write_block_a(encoding::bits::Writer& writer, std::uint32_t freeSlots) noexcept {
    writer.write(1, 1);
    writer.write(1, 1);
    writer.write(kBlockAIdWords, kBlockACountWidth);
    for (std::size_t i = 0; i < kBlockAIdWords; ++i) {
        const std::size_t base = i * 32;
        std::uint32_t word = 0;
        if (base + 32 <= freeSlots) {
            word = 0xFFFFFFFFU;
        } else if (base < freeSlots) {
            word = (1U << (freeSlots - base)) - 1;
        }
        writer.write(word, 32);
    }
    writer.write(1, 1);
    for (std::size_t i = 0; i < kBlockAWords; ++i) {
        writer.write(0, 32);
    }
    writer.write(1, 1);
    writer.write(kBlockAFlags, kBlockACountWidth);
    for (std::size_t i = 0; i < kBlockAFlags; ++i) {
        writer.write(0, 8);
    }
}

/** Writes one populated participant row: id word plus its index block. */
void write_member(encoding::bits::Writer& writer, const Member& member) noexcept {
    const auto id = static_cast<std::uint32_t>(member.memberKey);
    writer.write(1, 1);
    writer.write((id + kIdBias) & 0xFFFFFFFFU, kMemberIdBits);
    writer.write(1, 1);
    writer.write(1, 1);
    writer.write(kIndicesPerParticipant, kSubCountWidth);
    for (std::size_t j = 0; j < kIndicesPerParticipant; ++j) {
        writer.write(member.indexBase + static_cast<std::uint32_t>(j), 32);
    }
    writer.write(1, 1);
    for (std::size_t j = 0; j < kMemberMapWords; ++j) {
        writer.write(0, 32);
    }
    writer.write(1, 1);
    writer.write(kIndicesPerParticipant, kSubCountWidth);
    for (std::size_t j = 0; j < kIndicesPerParticipant; ++j) {
        writer.write(0, 8);
    }
}

} // namespace

/** Encodes one type-20 body: BLOCK A snapshot, then BLOCK B participant rows. */
bool encode(std::span<const Member> members,
            std::uint32_t freeSlots,
            std::span<std::byte> output,
            std::size_t& written) noexcept {
    written = 0;
    if (members.size() > kParticipantSlots) {
        return false;
    }
    encoding::bits::Writer writer(output);

    // THE TWO LEADING BITS the client's full decoder (0x1404D92A0) reads before
    // the schema: its flag bit, then the resolver's schema gate. Without them
    // the BLOCK-A count reads as 0 and the whole decode collapses (the 20.323/
    // 20.324 femu arc: 15 of 14584 bits consumed, empty struct).
    writer.write(1, 1);
    writer.write(1, 1);

    // BLOCK A: present; the 256xu32 array carries the free-slot bitmap for the
    // joiner's lease range (v2, claim E fix).
    write_block_a(writer, freeSlots);

    // BLOCK B: present; the wire carries every participant slot, each named by
    // FIVE field-presence bits (id, sub, sub0, sub1, sub2 - schema node
    // 0x80809446: pmap 320 = 64 x 5), populated rows first in join order. The
    // populated row's leading "id present" bit is the first of its five.
    writer.write(1, 1);
    writer.write(kParticipantSlots, kBlockBCountWidth);
    for (std::size_t slot = 0; slot < kParticipantSlots; ++slot) {
        if (slot < members.size()) {
            write_member(writer, members[slot]);
        } else {
            writer.write(0, 1);
            writer.write(0, 1);
            writer.write(0, 1);
            writer.write(0, 1);
            writer.write(0, 1);
        }
    }

    // finish() fails when any write exceeded the buffer, which zeroes `written`.
    const bool ok = writer.finish(written);
    if (!ok) {
        written = 0;
    }
    return ok;
}

} // namespace sunrise::middleware::bap::activity_message::entity_index_allocation
