#pragma once

#include <cstdint>

namespace sunrise::server::bap::encrypted::push::activity {

/**
 * INSTRUMENT: the readings of the two trailing 32-bit fields, swept.
 *
 * WHY THIS IS THE VARIABLE NOW. The row SHAPE was swept first and made no difference at all
 * (FINDINGS 20.51): key_only and full_mirror behaved identically, which says the row is not
 * being read. Lane M's field registry names `peer_and_player_counts` AHEAD of `peer_updates`
 * and `player_updates`, and its section 4 records U2 - whether those trailing fields carry
 * COUNTS or BITMASKS - as an open question.
 *
 * With ONE member the two readings are the same number: mask 0b1 == count 1. That is exactly
 * why months of solo bodies could never distinguish them. With TWO members they diverge for
 * the first time - a mask is 0b11 (3), a count is 2 - and we have been shipping 3.
 *
 * The client's own failure vocabulary contains `player-count-zero`, so counts are load-bearing
 * to this client.
 *
 * `solo` stays LAST for the same reason as the shape sweep: an acknowledgement ends the
 * republish loop, so the known-good body must not be tried before the candidates.
 */
enum class TrailingVariant : std::uint8_t {
    /** 3 / 3 - both fields as slot masks. Every body ever shipped. The control. */
    maskMask,
    /** 2 / 3 - first field a plain member count, second still a mask. */
    countMask,
    /** 0x00020002 / 3 - first field two packed 16-bit counts (peers, players). */
    packedMask,
    /** 2 / 2 - both fields plain counts. */
    countCount,
    /** 0x00020002 / 0x00020002 - both fields packed counts. */
    packedPacked,
    /** No peer row. Known ACCEPTED - the terminal positive control. */
    solo,
};

/** Readings in the sweep. Beside the enum because both must move together. */
inline constexpr std::uint64_t kTrailingVariantCount = 6;
/** Peer-bearing bodies one reading carries before the sweep may advance. */
inline constexpr std::uint64_t kDefaultSweepBodies = 4;
/** Milliseconds one reading must also hold, so a burst cannot skip readings. */
inline constexpr std::uint64_t kDefaultSweepFloorMs = 10'000;

/** The two 32-bit values one reading publishes. */
struct TrailingValues final {
    /** First trailing field. Zero tells the encoder to keep its historical value. */
    std::uint32_t first{};
    /** Second trailing field. Zero tells the encoder to keep its historical value. */
    std::uint32_t second{};
    /** False for `solo`, which publishes no peer row at all. */
    bool peerPresent{true};
};

/** @return The two field values one reading publishes. */
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
    TrailingVariant variant{TrailingVariant::maskMask};
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

} // namespace sunrise::server::bap::encrypted::push::activity
