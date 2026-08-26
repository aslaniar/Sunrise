#include "membership_sweep.h"

#include <cstdio>

namespace sunrise::server::bap::encrypted::push::activity {

/** Decides one body's shape without mutating anything. */
SweepDecision sweep_decide(const SweepSlot& slot,
                           const std::uint64_t nowMs,
                           const std::uint64_t bodiesNeeded,
                           const std::uint64_t floorMs) noexcept {
    const std::uint64_t needed = bodiesNeeded == 0 ? kDefaultSweepBodies : bodiesNeeded;
    const std::uint64_t floor = floorMs == 0 ? kDefaultSweepFloorMs : floorMs;
    SweepDecision decision{};
    decision.variant = static_cast<TrailingVariant>(slot.step % kTrailingVariantCount);
    // Counted with THIS body included: the shape is retired once it has carried `needed`
    // bodies and held for `floor`. Both, not either - bodies arrive in bursts (three inside
    // one second, observed), so a count alone skips shapes the client never saw settle, and a
    // clock alone retires a shape that barely shipped.
    decision.advance = (slot.bodiesThisStep + 1) >= needed && (nowMs - slot.lastAdvanceMs) >= floor;
    return decision;
}

/** Records one published body against the slot. */
void sweep_apply(SweepSlot& slot, const SweepDecision& decision, const std::uint64_t nowMs) noexcept {
    ++slot.bodiesThisStep;
    if (!decision.advance) {
        return;
    }
    ++slot.step;
    slot.bodiesThisStep = 0;
    slot.lastAdvanceMs = nowMs;
}

/** @return Human-readable reading name, for the boot record. */
const char* variant_name(const TrailingVariant variant) noexcept {
    switch (variant) {
    case TrailingVariant::maskMask:
        return "mask_mask";
    case TrailingVariant::countMask:
        return "count_mask";
    case TrailingVariant::packedMask:
        return "packed_mask";
    case TrailingVariant::countCount:
        return "count_count";
    case TrailingVariant::packedPacked:
        return "packed_packed";
    case TrailingVariant::solo:
        return "solo";
    }
    return "unknown";
}

/** Two members as a slot mask: bits 0 and 1 set. */
constexpr std::uint32_t kTwoMemberMask = 0b11;
/** Two members as a plain count. */
constexpr std::uint32_t kTwoMemberCount = 2;
/** Two peers and two players, packed as 16-bit halves - the name says "counts", plural. */
constexpr std::uint32_t kTwoPackedCounts = (kTwoMemberCount << 16) | kTwoMemberCount;

/** @return The two field values one reading publishes. */
TrailingValues trailing_values(const TrailingVariant variant) noexcept {
    switch (variant) {
    case TrailingVariant::maskMask:
        return {kTwoMemberMask, kTwoMemberMask, true};
    case TrailingVariant::countMask:
        return {kTwoMemberCount, kTwoMemberMask, true};
    case TrailingVariant::packedMask:
        return {kTwoPackedCounts, kTwoMemberMask, true};
    case TrailingVariant::countCount:
        return {kTwoMemberCount, kTwoMemberCount, true};
    case TrailingVariant::packedPacked:
        return {kTwoPackedCounts, kTwoPackedCounts, true};
    case TrailingVariant::solo:
        // Zeroes tell the encoder to keep its historical single-member value.
        return {0, 0, false};
    }
    return {kTwoMemberMask, kTwoMemberMask, true};
}

namespace {

/** Reports one failed invariant. */
void fail(const char* what, const std::uint64_t detail) noexcept {
    std::printf("ev=sweep_test stage=check result=fail what=%s detail=%llu\n",
                what,
                static_cast<unsigned long long>(detail));
}

} // namespace

/** Drives the sweep through a full pass and checks its invariants. */
int run_membership_sweep_test() noexcept {
    constexpr std::uint64_t kBodies = 4;
    constexpr std::uint64_t kFloorMs = 10'000;
    // One body every 5 s, the observed keepalive cadence.
    constexpr std::uint64_t kBodyIntervalMs = 5'000;

    SweepSlot slot{};
    std::uint64_t nowMs = 0;
    std::uint64_t failures = 0;

    std::uint64_t bodiesFor[kTrailingVariantCount] = {};
    std::uint64_t advancesSeen = 0;
    TrailingVariant lastVariant = TrailingVariant::maskMask;
    bool sawVariant[kTrailingVariantCount] = {};

    // Enough bodies to retire all six shapes at this cadence, with headroom.
    for (std::uint64_t body = 0; body < 200 && slot.step < kTrailingVariantCount; ++body) {
        const SweepDecision decision = sweep_decide(slot, nowMs, kBodies, kFloorMs);
        const auto index = static_cast<std::uint64_t>(decision.variant);

        // INVARIANT 1: readings are visited in order, each exactly once. The shape sweep's
        // first live run OPENED on index 4 because its phase was anchored to the wrong event.
        if (body == 0 && decision.variant != TrailingVariant::maskMask) {
            fail("opens_on_mask_mask", index);
            ++failures;
        }
        if (index != static_cast<std::uint64_t>(lastVariant)
            && index != static_cast<std::uint64_t>(lastVariant) + 1) {
            fail("variant_skipped", index);
            ++failures;
        }
        sawVariant[index] = true;
        ++bodiesFor[index];
        lastVariant = decision.variant;

        // INVARIANT 2: a retired shape carried at least `kBodies` bodies AND held `kFloorMs`.
        if (decision.advance) {
            ++advancesSeen;
            if (bodiesFor[index] < kBodies) {
                fail("retired_too_few_bodies", bodiesFor[index]);
                ++failures;
            }
            if ((nowMs - slot.lastAdvanceMs) < kFloorMs) {
                fail("retired_below_floor", nowMs - slot.lastAdvanceMs);
                ++failures;
            }
        }

        sweep_apply(slot, decision, nowMs);
        nowMs += kBodyIntervalMs;
    }

    // INVARIANT 3: every reading actually shipped. The shape sweep shipped two of six.
    for (std::uint64_t index = 0; index < kTrailingVariantCount; ++index) {
        if (!sawVariant[index]) {
            fail("variant_never_shipped", index);
            ++failures;
        }
    }
    // INVARIANT 4: one advance retires one reading, so a full pass advances six times.
    if (advancesSeen != kTrailingVariantCount) {
        fail("advance_count", advancesSeen);
        ++failures;
    }

    for (std::uint64_t index = 0; index < kTrailingVariantCount; ++index) {
        std::printf("ev=sweep_test stage=reading variant=%s bodies=%llu\n",
                    variant_name(static_cast<TrailingVariant>(index)),
                    static_cast<unsigned long long>(bodiesFor[index]));
    }
    std::printf("ev=sweep_test stage=done result=%s failures=%llu advances=%llu\n",
                failures == 0 ? "ok" : "fail",
                static_cast<unsigned long long>(failures),
                static_cast<unsigned long long>(advancesSeen));
    return failures == 0 ? 0 : 1;
}

} // namespace sunrise::server::bap::encrypted::push::activity
