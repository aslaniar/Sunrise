#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace sunrise::middleware::bap::activity_message::entity_index_allocation {

/** Activity message type 20: the host pushes one participant's allocated indices. */
inline constexpr std::uint32_t kMessageType = 20;

/** The wire carries this many participant slots, per the 0x80809446 array node. */
inline constexpr std::size_t kParticipantSlots = 64;
/** Each participant entry names this many allocated 32-bit entity indices. */
inline constexpr std::size_t kIndicesPerParticipant = 96;
/** One participant's 96-index block, expressed on the wire as 96 x 32 bits. */
inline constexpr std::size_t kMemberBits =
    1 + 1 + 32 + 1 + 3 + (1 + 7 + kIndicesPerParticipant * 32) + (3 * 32)
    + (1 + 7 + kIndicesPerParticipant * 8);

/** One participant row: id (low 32 bits of the member key) and its index block base. */
struct Member final {
    std::uint64_t memberKey{};
    std::uint32_t indexBase{};
};

/**
 * Encodes one type-20 body (schema key 0x80809445, see
 * RE_output/claims/entity-index-allocation-schema.md): sequential MSB-first bits,
 * presence bit before each optional field, BLOCK A pool snapshot zero-filled,
 * BLOCK B one populated participant row per member and empty slots for the rest.
 * @param members Participant rows, in join order. At most kParticipantSlots.
 * @param freeSlots How many leading slots the free bitmap marks available (the
 *                  joiner's lease span; 8192 max).
 * @param output Caller-owned payload storage, cleared before the first bit is written.
 * @param written Receives the encoded byte count on success.
 * @return True when the whole body fits.
 */
[[nodiscard]] bool encode(std::span<const Member> members,
                          std::uint32_t freeSlots,
                          std::span<std::byte> output,
                          std::size_t& written) noexcept;

} // namespace sunrise::middleware::bap::activity_message::entity_index_allocation
