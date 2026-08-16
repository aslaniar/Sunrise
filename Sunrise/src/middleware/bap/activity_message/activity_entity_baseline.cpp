#include "activity_entity_baseline.h"

#include <bit>
#include <cmath>
#include <cstddef>
#include <cstdint>

#include "../../encoding/bit_writer.h"

namespace sunrise::middleware::bap::activity_message::entity_baseline {
namespace {

/**
 * The RESOLVED type-7 sobject_message record (claims/sobject-carrier.md; the decoder
 * cluster decompiles in RE_output/content/lane_sobject_ghidra{,2,3,4}.txt).
 *
 * Wire grammar, MSB-first (the fork's encoding::bits::Writer = the client's
 * FUN_1403513B0 stream order), read by the receive cluster in this exact order:
 *
 * 1. FUN_141718510 (bulk receive) preamble -- 2 bits:
 *      bit A = 0 (an entity loop follows), bit B = 1 (no message-level anchor index).
 *      (lane_sobject_ghidra4.txt lines 70-83: A/B read first; both 0 would read an
 *      "anchor-index" entity_index property before the loop.)
 * 2. entity-index property -- 17 bits: 13-bit handle + 4-bit salt (FUN_1404C16C0,
 *    phase9/decompiles.txt lines 92-115; the A-variant's 2-bit extra comes from the
 *    client global DAT_141F91300, not the wire). Written into record + 8, the index the
 *    lease/type checks in FUN_141718080 use.
 * 3. FUN_141717EB0 header:
 *      outer flag = 0 (the 5-flag path) -- 1 bit;
 *      mask bits create=1, update=0, destroy=0, bit3=0, anchor=0 -- 5 bits
 *      (lane_sobject_ghidra2.txt lines 144-185; bit0 create, bit1 update, bit2 destroy,
 *      bit3 spare, bit6 anchor);
 *      (anchor bit clear -> no anchor-entity-index property, record + 0xc stays -1);
 *      entity-index header: present=1, second=1, 8-bit local index -- 10 bits
 *      (lines 191-200: present -> second bit; 0 -> 0xffff sentinel; else 8 bits).
 * 4. FUN_141718080 create path:
 *      8 bits -> record + 0x44 (streamByte);
 *      2 bits -> record + 0 (codecType);
 *      then the per-type codec body (vtable + 0x60): u32 schemaTagHash, then the
 *      schema walker (FUN_1404B9200) field stream (entity-archetypes.md F1/F2).
 *      Destroy bit (bit2 clear -> no 1-bit read at the end).
 * 5. Loop termination -- 1 bit = 1 (FUN_141718510's post-entity read; 1 stops).
 * 6. Zero padding to the fixed 136-byte body.
 *
 * The 0x84-byte entity record is the client-side materialization (kind 0xff @0, id @4,
 * entity-index @8, anchor @0xc, header index @0x10, flags @0x40, ...) -- the stream above
 * is its wire form; it is not itself on the wire.
 */

/** Preamble: bit A = 0 (entity loop follows). */
constexpr std::uint64_t kPreambleA = 0;
/** Preamble: bit B = 1 (no message-level anchor). */
constexpr std::uint64_t kPreambleB = 1;
/** The create-path 5-flag mask: create=1, update=0, destroy=0, bit3=0, anchor=0. */
constexpr std::uint64_t kHeaderMask = 0b10000U;
/** Outer flag: 0 = the explicit 5-flag path (vs the implicit update-only path). */
constexpr std::uint64_t kHeaderOuterFlag = 0;
/** Entity-index header: present = 1, second bit = 1, then 8 value bits. */
constexpr std::uint64_t kHeaderIndexPresent = 1;
constexpr std::uint64_t kHeaderIndexSecond = 1;
constexpr std::uint8_t kHeaderIndexWidth = 8;

/** entity_index property widths (FUN_1404C16C0): 13-bit handle, 4-bit salt. */
constexpr std::uint8_t kEntityIndexHandleWidth = 13;
constexpr std::uint8_t kEntityIndexSaltWidth = 4;
/** Create-path 8-bit stream byte width (record + 0x44). */
constexpr std::uint8_t kStreamByteWidth = 8;
/** Create-path 2-bit codec type width (record + 0). */
constexpr std::uint8_t kCodecTypeWidth = 2;
/** Schema tag hash width: the codec body's first field (u32, MSB-first). */
constexpr std::uint8_t kSchemaHashWidth = 32;

/**
 * The archetype tree's present-flagged entry count (the wire present-bit count the
 * schema walker reads, entity-archetypes F1). The n1019 census reports 153 fields
 * (s2v0-carrier-spawn 2.1, schema-hash-mine 2.1). The runtime tree is rebuilt per boot,
 * so this is a probe constant: the boot's first job is to confirm the client's tree
 * count against the decode (Hook B + fail-arm log; see the claim).
 */
constexpr std::size_t kTreeFieldCount = 153;
/**
 * The F3-core fields the baseline populates, in the corpus property-vocabulary order
 * (entity-archetypes F3: identity indices -> movement -> vitality). All remaining tree
 * fields are emitted present=0 (wire 0 = skip, client keeps defaults).
 */
constexpr std::size_t kCoreFieldCount = 8;

/** F3 identity: three entity_index properties (anchor-entity-index, anchor-index,
 *  entity-index), each 1 present bit + 13-bit handle + 4-bit salt. The same slot names
 *  all three in v0 (the per-point mapping is open). */
constexpr std::uint8_t kIdentityFieldCount = 3;
/** F3 movement: vector3d present bit + 19-bit direction + 16-bit magnitude. The
 *  direction width is VERIFIED (FUN_1403516D0's 0x13 read); the magnitude width 16 and
 *  step 0.01 come from the vector3d descriptor 0x141BA5F90, whose contents are undumped
 *  (INFERRED probe constants, centralized here). */
constexpr std::uint8_t kVectorDirectionWidth = 19;
constexpr std::uint8_t kVectorMagnitudeWidth = 16;
/** F3 forward_and_up: present bit + 19-bit axis + 8-bit facing angle. Axis width
 *  VERIFIED (FUN_1409F4A60); angle width from DAT_141BA1780 (undumped, INFERRED). */
constexpr std::uint8_t kAxisWidth = 19;
constexpr std::uint8_t kFacingAngleWidth = 8;
/** F3 vitality: reader 11 real32 has a VERIFIED raw 32-bit branch. */
constexpr std::uint8_t kRawFloatWidth = 32;

/** Magnitude wire quantization step for the v0 probe (see kVectorMagnitudeWidth). */
constexpr float kVectorStep = 0.01F;
/** Magnitude wire floor for the v0 probe. */
constexpr float kVectorMinimum = 0.0F;
/** Facing-angle scale for the v0 probe (DAT_141BA1780 content unknown). */
constexpr float kFacingScale = 0.01F;
/** Direction index for position/velocity: 0 = the probe default (the direction table
 *  FUN_1403830E0 is undumped, so the decoded axis for index 0 is unknown). */
constexpr std::uint64_t kProbeDirectionIndex = 0;
/** Axis index for forward_and_up: 0 = the probe default (the 19-entry axis enum at
 *  0x141BF5B2C is undumped). */
constexpr std::uint64_t kProbeAxisIndex = 0;

/** Quantizes one nonnegative scalar to its wire value: (value - min) / step. */
[[nodiscard]] std::uint64_t quantize(float value, float minimum, float step) noexcept {
    const float scaled = (value - minimum) / step;
    return scaled <= 0.0F ? 0U : static_cast<std::uint64_t>(scaled);
}

/** Writes one F3 identity field: present bit + 13-bit handle + 4-bit salt. */
[[nodiscard]] bool write_identity(encoding::bits::Writer& writer, std::uint16_t slot) noexcept {
    return writer.write(1, 1) && writer.write(slot & 0x1FFFU, kEntityIndexHandleWidth)
           && writer.write(0, kEntityIndexSaltWidth);
}

/** Writes one F3 movement field: present bit + direction + magnitude. */
[[nodiscard]] bool write_vector3d(encoding::bits::Writer& writer,
                                  std::array<float, 3> value) noexcept {
    if (!writer.write(1, 1) || !writer.write(kProbeDirectionIndex, kVectorDirectionWidth)) {
        return false;
    }
    const float squared =
        value[0] * value[0] + value[1] * value[1] + value[2] * value[2];
    const float length = std::sqrt(squared);
    return writer.write(quantize(length, kVectorMinimum, kVectorStep),
                        kVectorMagnitudeWidth);
}

/** Writes one F3 vitality field: present bit + 32 raw float bits (VERIFIED branch). */
[[nodiscard]] bool write_vitality(encoding::bits::Writer& writer, float value) noexcept {
    const std::uint32_t raw = std::bit_cast<std::uint32_t>(value);
    return writer.write(1, 1) && writer.write(raw, kRawFloatWidth);
}

} // namespace

/** Encodes one type-7 sobject_message record (probe shape; every width cited above). */
bool encode_entity_baseline(const Baseline& baseline,
                            std::span<std::byte> output,
                            std::size_t& written) noexcept {
    written = 0;
    if (output.size() < kSobjectMessageSize) {
        return false;
    }
    // Byte 0: the kind byte the type-7 decoder gates on (VERIFIED: *param_2 == 2).
    output[0] = static_cast<std::byte>(kSobjectMessageKind);
    encoding::bits::Writer writer(output.subspan(1, kSobjectMessageBodySize));

    // 1. Preamble (FUN_141718510): A = 0 (entity loop), B = 1 (no anchor).
    if (!writer.write(kPreambleA, 1) || !writer.write(kPreambleB, 1)) {
        return false;
    }
    // 2. entity-index property: 13-bit handle (the global slot) + 4-bit salt 0.
    if (!writer.write(baseline.globalSlot & 0x1FFFU, kEntityIndexHandleWidth)
        || !writer.write(0, kEntityIndexSaltWidth)) {
        return false;
    }
    // 3. Header (FUN_141717EB0): outer flag 0 + the 5 mask bits (create only), then the
    //    entity-index header (present + second + 8-bit local index). The anchor flag is
    //    clear, so no anchor-entity-index property follows.
    if (!writer.write(kHeaderOuterFlag, 1) || !writer.write(kHeaderMask, 5)
        || !writer.write(kHeaderIndexPresent, 1) || !writer.write(kHeaderIndexSecond, 1)
        || !writer.write(baseline.localIndex & 0xFFU, kHeaderIndexWidth)) {
        return false;
    }
    // 4. Create path (FUN_141718080): 8-bit stream byte + 2-bit codec type.
    if (!writer.write(baseline.streamByte & 0xFFU, kStreamByteWidth)
        || !writer.write(baseline.codecType & 0x3U, kCodecTypeWidth)) {
        return false;
    }
    // The codec body: the u32 schemaTagHash, then the schema walker's field stream.
    if (!writer.write(baseline.schemaHash, kSchemaHashWidth)) {
        return false;
    }
    // F3-core fields 0..7 (present=1 + value), then the remaining tree fields present=0.
    const std::uint64_t slot = baseline.globalSlot & 0x1FFFU;
    if (!write_identity(writer, static_cast<std::uint16_t>(slot))
        || !write_identity(writer, static_cast<std::uint16_t>(slot))
        || !write_identity(writer, static_cast<std::uint16_t>(slot))
        || !write_vector3d(writer, baseline.position)
        || !write_vector3d(writer, {0.0F, 0.0F, 0.0F})) {
        return false;
    }
    // forward_and_up: present + probe axis 0 + facing angle. Axis 0 with angle 0 decodes
    // to forward = axis * sin(0) = 0, up = cos(0) = 1 -- a standing replica (INFERRED).
    if (!writer.write(1, 1) || !writer.write(kProbeAxisIndex, kAxisWidth)
        || !writer.write(quantize(baseline.facingRadians, 0.0F, kFacingScale),
                         kFacingAngleWidth)) {
        return false;
    }
    if (!write_vitality(writer, baseline.bodyVitality)
        || !write_vitality(writer, baseline.shieldVitality)) {
        return false;
    }
    // The remaining tree fields: one present bit = 0 each (client keeps defaults).
    for (std::size_t field = kCoreFieldCount; field < kTreeFieldCount; ++field) {
        if (!writer.write(0, 1)) {
            return false;
        }
    }
    // 5. Loop termination bit: 1 = no more entities (FUN_141718510's post-entity read).
    if (!writer.write(1, 1)) {
        return false;
    }
    // 6. Zero-pad the partial final byte; the rest of the 136-byte body stays zero.
    std::size_t produced = 0;
    if (!writer.finish(produced) || produced > kSobjectMessageBodySize) {
        return false;
    }
    written = kSobjectMessageSize;
    return true;
}

} // namespace sunrise::middleware::bap::activity_message::entity_baseline
