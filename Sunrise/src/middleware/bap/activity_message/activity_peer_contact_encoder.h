#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace sunrise::middleware::bap::activity_message::peer_contact {

/**
 * Activity message type 45 (0x2D): the host names the machine ids that are
 * CONTACTABLE. The client's handler 0x1404F3870 decodes the body against schema
 * 0x80808689 and, for every named id already present in its machine-id-keyed
 * tracking array at pool+0x602BC (stride 0x10), sets that row's byte at
 * +0x602C4 to 1.
 *
 * That byte is the last missing input of the per-tick peer evaluator
 * 0x140C171F0: FINDINGS 20.245 caught the evaluator running and aborting on
 * +0x602C4 == 0 (mac 3,996 / rig 2,297 reads, never nonzero), and 20.246 R6
 * established that the evaluator's other three per-entry probes are
 * informational byte writes rather than gates - so slot-present, state ==
 * 0x0A (both already satisfied live, lane K) and this byte are the whole
 * condition set before it writes state 5 and latches the row.
 */
inline constexpr std::uint32_t kMessageType = 45;

/**
 * Machine ids one body can name. The count field is SIX BITS WIDE (schema
 * 0x8080868B field 0, type-5 reader, width 6, bias 0), so 63 is the hard wire
 * bound; the fork sends one id per body and never approaches it.
 */
inline constexpr std::size_t kMaximumMachineIds = 63;
/** Six count bits plus 64 bits per id, rounded up to whole bytes. */
inline constexpr std::size_t kEncodedSize(std::size_t idCount) noexcept {
    return (6 + idCount * 64 + 7) / 8;
}
/** The body the fork actually sends: one machine id. Nine bytes. */
inline constexpr std::size_t kSingleIdSize = kEncodedSize(1);

/**
 * Encodes one type-45 body.
 *
 * WIRE SHAPE (derived and femu-verified end to end against both dumps -
 * RE_output/claims/night_0901_laneE_schema_descriptor.md claims 6-8, and
 * re-verified independently 2026-09-01): a contiguous MSB-first bit stream of
 * a 6-bit count followed, per machine id, by that id's 64 bits in
 * LITTLE-ENDIAN byte order (the u64's memory order), each byte
 * most-significant-bit first. The final partial byte is zero-padded.
 *
 * For machine id 0x846C8338F7D022E6 with count 1 this produces the nine bytes
 * 07 98 8B 43 DC E2 0D B2 10, which drives the real client handler to
 * completion (al = 1) and sets pool+0x602C4 = 1; a body naming any other id
 * leaves the byte at 0.
 *
 * @param machineIds Ids to mark contactable. Empty encodes a legal no-op body.
 * @param output Destination for the body bytes.
 * @param written Receives the encoded byte count; zero on failure.
 * @return True when the body fits and encodes.
 */
[[nodiscard]] bool encode(std::span<const std::uint64_t> machineIds,
                          std::span<std::byte> output,
                          std::size_t& written) noexcept;

} // namespace sunrise::middleware::bap::activity_message::peer_contact
