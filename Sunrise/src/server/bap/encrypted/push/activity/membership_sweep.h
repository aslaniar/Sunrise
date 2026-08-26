#pragma once

#include <cstdint>

namespace sunrise::server::bap::encrypted::push::activity {

/**
 * INSTRUMENT: the shapes member slot 1 is swept through.
 *
 * The known-ACCEPTED artifact is our own solo body; the known-REJECTED one is the full
 * mirrored row (FINDINGS 20.48). Everything between is a cumulative build-up, so the first
 * shape the client applies names the field that was breaking it.
 *
 * ORDER IS DELIBERATE. `solo` sits LAST: an acknowledgement stops the republish loop and ends
 * the sweep, so the known-good shape first would close the harness before any peer-bearing
 * shape was tried.
 */
enum class PeerVariant : std::uint8_t {
    /** memberKey alone. Tests whether ANY second row is structurally acceptable. */
    keyOnly,
    /** + accountSoid. */
    keyAccount,
    /** + joinIdentity. */
    keyAccountJoin,
    /** + the two int32 opaques. */
    keyAccountJoinOpaque,
    /** Every field, byte-identical to p2(35). Known REJECTED - the negative control. */
    fullMirror,
    /** No peer row at all. Known ACCEPTED - the terminal positive control. */
    solo,
};

/** Shapes in the sweep. Beside the enum because both must move together. */
inline constexpr std::uint64_t kPeerVariantCount = 6;
/** Peer-bearing bodies one shape carries before the sweep may advance. */
inline constexpr std::uint64_t kDefaultSweepBodies = 4;
/** Milliseconds one shape must also hold, so a burst cannot skip shapes. */
inline constexpr std::uint64_t kDefaultSweepFloorMs = 10'000;

/** One session's place in the sweep. Sessions advance independently. */
struct SweepSlot final {
    /** Shapes retired so far. The live shape is `step % kPeerVariantCount`. */
    std::uint64_t step{};
    /** Peer-bearing bodies the live shape has carried. */
    std::uint64_t bodiesThisStep{};
    /** Tick the live shape became live. */
    std::uint64_t lastAdvanceMs{};
};

/** What one peer-bearing body publishes, and what happens after it. */
struct SweepDecision final {
    /** Shape THIS body carries. */
    PeerVariant variant{PeerVariant::keyOnly};
    /**
     * True when the sweep retires this shape after this body.
     *
     * The caller must then advance the published revision. The client applies one update per
     * revision and DROPS every repeat (Lane M, opencode's p2(39)), so a shape change that
     * reuses a revision is discarded unread - which is exactly how the first sweep run
     * measured nothing after its opening shape.
     */
    bool advance{};
};

/**
 * Decides one body's shape without mutating anything.
 * @param slot This session's current place in the sweep.
 * @param nowMs Monotonic tick.
 * @param bodiesNeeded Bodies one shape must carry. Zero takes the default.
 * @param floorMs Milliseconds one shape must hold. Zero takes the default.
 * @return The shape to publish and whether it is retired afterwards.
 */
[[nodiscard]] SweepDecision sweep_decide(const SweepSlot& slot,
                                         std::uint64_t nowMs,
                                         std::uint64_t bodiesNeeded,
                                         std::uint64_t floorMs) noexcept;

/**
 * Records one published body against the slot.
 * @param slot Receives the body count, and the next shape when the decision retires this one.
 * @param decision The decision that produced the body just published.
 * @param nowMs Monotonic tick, stored as the new shape's start.
 */
void sweep_apply(SweepSlot& slot, const SweepDecision& decision, std::uint64_t nowMs) noexcept;

/** @return Human-readable shape name, for the boot record. */
[[nodiscard]] const char* variant_name(PeerVariant variant) noexcept;

/**
 * Drives the sweep through a full pass and checks its invariants.
 * Exists because the first live run tested ONE shape and looked like it had tested two - the
 * failure was invisible in a boot record and trivially visible here.
 * @return Zero when every invariant holds.
 */
[[nodiscard]] int run_membership_sweep_test() noexcept;

} // namespace sunrise::server::bap::encrypted::push::activity
