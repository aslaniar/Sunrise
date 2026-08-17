#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace sunrise::middleware::bap::activity_message::entity_baseline {

/**
 * The RESOLVED entity carrier (claims/sobject-carrier.md): the sim-event type 7
 * sobject_message record. The type-7 decoder FUN_140E739D0 (destiny2 + 0xE739D0) gates on
 * an exact 0x89-byte payload with kind byte @0 == 2, then copies the whole record
 * opaquely into the decode scratch (lane_sobject_ghidra3.txt lines 44-154).
 */
inline constexpr std::size_t kSobjectMessageSize = 0x89;
/** Kind byte the type-7 decoder accepts (@0 of the 0x89-byte record). */
inline constexpr std::uint8_t kSobjectMessageKind = 2;
/** The 136-byte body after the kind byte (the entity-replication bitstream). */
inline constexpr std::size_t kSobjectMessageBodySize = kSobjectMessageSize - 1;

/**
 * One static vendor baseline for the S2-0 one-point smoke (the vendor-first directive).
 * The encoder produces the full 0x89-byte type-7 record: kind byte, then the MSB-first
 * bitstream the sobject receive cluster consumes (FUN_141718510 -> FUN_141717EB0 ->
 * FUN_141718080 -> per-type codec body). Every field below is cited in the encoder body.
 */
struct Baseline final {
    /**
     * Archetype schemaTagHash the client resolves against the runtime schema table
     * (FUN_1404C74D0: bucket = (hash >> 13) & 0x3FF, row = hash & 0x1FFF). The verified
     * default = 0x80806AC0 = the hash the CLIENT ITSELF passes for the player baseline
     * at destination load (schema_capture hook observation, 2026-08-16:
     * `ev=schema_capture ... hash=0x80806AC0 bucket=3 row=2752 codec=0`; the player
     * renders with codec 0) -- a tag handle of package 3, entry 0xAC0. This SUPERSEDES
     * the earlier 0x7F6000 (bucket 1019, row 0) probe: schema-hash-mine.md 2.3 verified
     * row 0 of bucket 1019 is a garbage record, so that hash sent the walker over
     * garbage tree entries -- the black-screen poison. The settings knob carries the
     * live value (claims/refined-payload.md).
     */
    std::uint32_t schemaHash{};
    /**
     * Global entity slot: the 13-bit handle of the entity-index property (FUN_1404C16C0,
     * A-variant: 13-bit handle + 4-bit salt, the 2-bit extra from a client global). The
     * lease check in FUN_141718080 reads bit (handle & 0x1FFF) of the world's lease mask,
     * which the join's type-0 push grants fully (O1, spec 3.3). Slot 8191 is the SPEC
     * convention for server entities (s2-world-population-spec 3.3/7.1: server entities
     * take the top of the mask, 8191 downward, so the client's low-prefix grants can
     * never overlap; the fork's select_free also grants ascending -- the player lives in
     * the low prefix). A high slot's type-table entry is unregistered, so the
     * FUN_141718080 typeId match fails and the create runs the ordinary from-scratch
     * path (plVar7 = 0), which is the correct path for a create. Claims/refined-payload.md
     * 2 documents the reasoning.
     */
    std::uint16_t globalSlot{};
    /**
     * Local entity registry index: the header parser's u16 at record + 2 (1 present bit +
     * 1 second bit + 8 value bits, FUN_141717EB0). An 8-bit value, so it is a different
     * space from the 13-bit global slot; feeds the FUN_1416BAB50 registry lookup.
     */
    std::uint8_t localIndex{};
    /**
     * 2-bit codec type read by the create path (FUN_141718080) before the codec body. The
     * codec object (registry at world + 0x10) decodes the body. The type numbers are
     * runtime-built (DAT_1430B0440); 0 is the probe default.
     */
    std::uint8_t codecType{};
    /**
     * 8-bit field the create path reads into record + 0x44 (FUN_141718080). The encode
     * side (FUN_14171E240) writes the world type-table entry's +4 byte here; unknown
     * offline, so the probe default is 0.
     */
    std::uint8_t streamByte{};
    /**
     * Spawn-point FNV-1 name hash (the placement identity). The internal vendor-point
     * name is not corpus-resolvable; the point's own nameHash from spawn_sets_full.json
     * is used (position matters most for the first gate). The wire home of the name is
     * one of the archetype tree's non-core fields (unknown position) or client-side
     * content resolution -- see the claim's risk list.
     */
    std::uint32_t nameHash{};
    /** World position, engine units. */
    std::array<float, 3> position{};
    /** Facing yaw, radians. */
    float facingRadians{};
    /** 0..1 vitality fractions. */
    float bodyVitality{};
    float shieldVitality{};
};

/**
 * Encodes one type-7 sobject_message record (0x89 bytes, kind byte 2, then the
 * entity-replication bitstream: preamble, entity-index property, 5-flag header, entity
 * index, create-path reads, the codec body = schema hash + the F3-core field stream,
 * termination bit, zero padding). The header structure and the payload total size are
 * corpus-VERIFIED; the codec body's field stream is the best corpus layout (F3 order),
 * with every width that the corpus does not pin named as a probe constant in the body.
 * @param baseline Values to encode.
 * @param output Caller-owned storage, unchanged on failure.
 * @param written Receives 0x89 on success, zero on failure.
 * @return True when the whole record fit.
 */
[[nodiscard]] bool encode_entity_baseline(const Baseline& baseline,
                                          std::span<std::byte> output,
                                          std::size_t& written) noexcept;

} // namespace sunrise::middleware::bap::activity_message::entity_baseline
