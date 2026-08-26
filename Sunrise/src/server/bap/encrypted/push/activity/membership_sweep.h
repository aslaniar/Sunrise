#pragma once

#include <cstdint>

namespace sunrise::server::bap::encrypted::push::activity {

/**
 * INSTRUMENT: the readings of the FOUR trailing 32-bit fields, swept.
 *
 * WHY THIS IS THE VARIABLE NOW. The row SHAPE was swept first and made no difference at all
 * (FINDINGS 20.51): key_only and full_mirror behaved identically, which says the row is not
 * being read. And 20.62 read the client's own schema and found the roster ALREADY matches our
 * encoder exactly - 32 slots, a member row costing 3 presence bits. The row was never it.
 *
 * The gap the schema did find is here. Type 12 declares FOUR presence-flagged 32-bit fields
 * at presence indices 996-999 and we shipped TWO until p2(47). Lane M's parsed-struct field
 * registry names exactly four in that order:
 *
 *     [4] peer_and_player_counts   [5] peer_updates   [6] player_updates   [7] player_seq_number
 *
 * With ONE member every reading of every one of them is the number 1: mask 0b1 == count 1.
 * That is why months of solo bodies could never distinguish them, and why p2(47)'s solo boot
 * (20.63) could confirm the SHAPE while testing no semantics at all. With TWO members they
 * diverge for the first time - a mask is 0b11 (3), a count is 2 - and every peer-bearing body
 * we have ever shipped put 3 in a field named `counts`.
 *
 * That is the freeze hypothesis in one line: if the client reads [4] as a count, we told it
 * THREE members while the roster held two, and it walked into an absent slot.
 *
 * The client's own failure vocabulary contains `player-count-zero`, so counts are load-bearing
 * to this client.
 *
 * ORDER MATTERS AND IT IS NOT THE OBVIOUS ONE. A peer row has hard-frozen the client well
 * inside six bodies, so a sweep can run out of client before it reaches a late reading. The
 * readings are therefore ordered MOST-LIKELY-CORRECT FIRST, and the historical
 * all-masks reading - the one already known to freeze - sits near the END rather than at the
 * front where a control would normally go. `solo` stays last regardless: an acknowledgement
 * ends the republish loop, so the known-good body must not be tried before the candidates.
 *
 * NOTE FOR ANY NEW READING: zero is not expressible. The encoder treats a zero override as
 * "keep the historical value", so a reading that wants to send 0 silently sends the mask
 * instead. `run_membership_sweep_test` asserts no peer-bearing reading carries a zero.
 */
enum class TrailingVariant : std::uint8_t {
    /** 0x00020002 / 3 / 3 / 1 - counts packed as 16-bit halves, both update masks. LIKELIEST. */
    packedMasks,
    /** 2 / 3 / 3 / 1 - counts as one plain member count, both update masks. */
    countMasks,
    /** 0x00020002 / 3 / 3 / 3 - as packedMasks, with the sequence field also a mask. */
    packedMasksSeq,
    /** 2 / 3 / 3 / 3 - as countMasks, with the sequence field also a mask. */
    countMasksSeq,
    /** 3 / 3 / 3 / 3 - every field a slot mask. The historical reading, and it froze. */
    allMask,
    /** No peer row. Known ACCEPTED - the terminal positive control. */
    solo,
};

/** Readings in the sweep. Beside the enum because both must move together. */
inline constexpr std::uint64_t kTrailingVariantCount = 6;
/** Peer-bearing bodies one reading carries before the sweep may advance. */
inline constexpr std::uint64_t kDefaultSweepBodies = 4;
/** Milliseconds one reading must also hold, so a burst cannot skip readings. */
inline constexpr std::uint64_t kDefaultSweepFloorMs = 10'000;

/**
 * The four 32-bit values one reading publishes.
 *
 * Named for the schema positions they occupy, not for what we believe they mean - the
 * belief is Lane M's field-registry inference and it is what the peer boot tests.
 */
struct TrailingValues final {
    /** Presence index 996; `peer_and_player_counts`. Zero keeps the historical value. */
    std::uint32_t first{};
    /** Presence index 997; `peer_updates`. Zero keeps the historical value. */
    std::uint32_t second{};
    /** Presence index 998; `player_updates`. Never sent at all before p2(47). */
    std::uint32_t third{};
    /** Presence index 999; `player_seq_number`. Never sent at all before p2(47). */
    std::uint32_t fourth{};
    /** False for `solo`, which publishes no peer row at all. */
    bool peerPresent{true};
};

/** @return The four field values one reading publishes. */
[[nodiscard]] TrailingValues trailing_values(TrailingVariant variant) noexcept;

/** One session's place in the sweep. Sessions advance independently. */
struct SweepSlot final {
    /** Readings retired so far. The live one is `step % kTrailingVariantCount`. */
    std::uint64_t step{};
    /** Peer-bearing bodies the live reading has carried. */
    std::uint64_t bodiesThisStep{};
    /** Tick the live reading became live. */
    std::uint64_t lastAdvanceMs{};
    /**
     * Peer-bearing bodies published since the client last acknowledged one.
     *
     * Without a cap the server republishes a refused body every ~5 s forever - 127 of them
     * in one observed run - which starves the client and blocks its destination load. A
     * refusal must cost a clean negative, never a hung client.
     */
    std::uint64_t unackedPeerBodies{};
    /**
     * Set once the cap trips and the peer row is withdrawn for this session.
     * STICKY for the session's lifetime: withdrawing publishes a solo body, the client
     * acknowledges that, and clearing the flag on an acknowledgement would immediately
     * re-add the peer and start the storm again.
     */
    bool peerWithdrawn{};
};

/** What one peer-bearing body publishes, and what happens after it. */
struct SweepDecision final {
    /** Reading THIS body carries. */
    TrailingVariant variant{TrailingVariant::packedMasks};
    /**
     * True when the sweep retires this reading after this body.
     *
     * The caller must then advance the published revision. The client applies one update per
     * revision and DROPS every repeat (Lane M, opencode's p2(39)), so a change that reuses
     * a revision is discarded unread - which is exactly how the shape sweep's first run
     * measured nothing after its opening reading.
     */
    bool advance{};
};

/**
 * Decides one body's reading without mutating anything.
 * @param slot This session's current place in the sweep.
 * @param nowMs Monotonic tick.
 * @param bodiesNeeded Bodies one reading must carry. Zero takes the default.
 * @param floorMs Milliseconds one reading must hold. Zero takes the default.
 * @return The reading to publish and whether it is retired afterwards.
 */
[[nodiscard]] SweepDecision sweep_decide(const SweepSlot& slot,
                                         std::uint64_t nowMs,
                                         std::uint64_t bodiesNeeded,
                                         std::uint64_t floorMs) noexcept;

/**
 * Records one published body against the slot.
 * @param slot Receives the body count, and the next reading when this one is retired.
 * @param decision The decision that produced the body just published.
 * @param nowMs Monotonic tick, stored as the new reading's start.
 */
void sweep_apply(SweepSlot& slot, const SweepDecision& decision, std::uint64_t nowMs) noexcept;

/** @return Human-readable reading name, for the boot record. */
[[nodiscard]] const char* variant_name(TrailingVariant variant) noexcept;

/**
 * Drives the sweep through a full pass and checks its invariants.
 * Exists because the shape sweep's first run tested ONE reading and looked like two - the
 * failure was invisible in a boot record and trivially visible here.
 * @return Zero when every invariant holds.
 */
[[nodiscard]] int run_membership_sweep_test() noexcept;

/**
 * Encodes real bodies and reads their top-level trailer back out of the bits.
 *
 * WHY THIS GATE EXISTS. p2(47) changed the wire: the client's schema declares FOUR flagged
 * 32-bit fields after the region block and we shipped two (FINDINGS 20.62). Everything that
 * could have caught a mistake in that change was a constant compared against another constant
 * - `static_assert(kMeaningfulBitCount == kEncodedSize * 8)` passes just as happily for a
 * wrong pair as a right one. This reads the ACTUAL emitted buffer at the ACTUAL trailer
 * offset and checks each field came back with the distinct value it went in with, so a
 * dropped field, a swapped pair, or an off-by-one presence bit fails the deploy instead of
 * a boot. The pre-boot checklist's provenance rule, applied to a wire format.
 *
 * @return Zero when solo and peer bodies both round-trip at their declared sizes.
 */
[[nodiscard]] int run_membership_wire_test() noexcept;

} // namespace sunrise::server::bap::encrypted::push::activity
