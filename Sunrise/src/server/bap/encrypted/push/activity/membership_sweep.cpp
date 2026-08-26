#include "membership_sweep.h"

#include <array>
#include <cstdio>

#include "../../../../../middleware/bap/activity_message/replicate_membership.h"
#include "../../../../../middleware/encoding/bit_reader.h"

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
    case TrailingVariant::packedMasks:
        return "packed_masks";
    case TrailingVariant::countMasks:
        return "count_masks";
    case TrailingVariant::packedMasksSeq:
        return "packed_masks_seq";
    case TrailingVariant::countMasksSeq:
        return "count_masks_seq";
    case TrailingVariant::allMask:
        return "all_mask";
    case TrailingVariant::solo:
        return "solo";
    }
    return "unknown";
}

/** Two members as a slot mask: bits 0 and 1 set. */
constexpr std::uint32_t kTwoMemberMask = 0b11;
/** Two members as a plain count. */
constexpr std::uint32_t kTwoMemberCount = 2;
/**
 * Two peers and two players, packed as 16-bit halves - the name says "counts", plural.
 *
 * Which half is peers and which is players is UNKNOWN, and this value deliberately does not
 * depend on the answer: with two of each it is 0x00020002 either way. The ambiguity only bites
 * when the counts differ, which is not this boot.
 */
constexpr std::uint32_t kTwoPackedCounts = (kTwoMemberCount << 16) | kTwoMemberCount;
/**
 * A sequence field's least surprising non-zero value.
 * Zero is not expressible - the encoder reads it as "keep the historical value".
 */
constexpr std::uint32_t kSequenceOne = 1;

/** @return The four field values one reading publishes. */
TrailingValues trailing_values(const TrailingVariant variant) noexcept {
    switch (variant) {
    case TrailingVariant::packedMasks:
        return {kTwoPackedCounts, kTwoMemberMask, kTwoMemberMask, kSequenceOne, true};
    case TrailingVariant::countMasks:
        return {kTwoMemberCount, kTwoMemberMask, kTwoMemberMask, kSequenceOne, true};
    case TrailingVariant::packedMasksSeq:
        return {kTwoPackedCounts, kTwoMemberMask, kTwoMemberMask, kTwoMemberMask, true};
    case TrailingVariant::countMasksSeq:
        return {kTwoMemberCount, kTwoMemberMask, kTwoMemberMask, kTwoMemberMask, true};
    case TrailingVariant::allMask:
        return {kTwoMemberMask, kTwoMemberMask, kTwoMemberMask, kTwoMemberMask, true};
    case TrailingVariant::solo:
        // Zeroes tell the encoder to keep its historical single-member value.
        return {0, 0, 0, 0, false};
    }
    return {kTwoMemberMask, kTwoMemberMask, kTwoMemberMask, kTwoMemberMask, true};
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
    TrailingVariant lastVariant = TrailingVariant::packedMasks;
    bool sawVariant[kTrailingVariantCount] = {};

    // Enough bodies to retire all six shapes at this cadence, with headroom.
    for (std::uint64_t body = 0; body < 200 && slot.step < kTrailingVariantCount; ++body) {
        const SweepDecision decision = sweep_decide(slot, nowMs, kBodies, kFloorMs);
        const auto index = static_cast<std::uint64_t>(decision.variant);

        // INVARIANT 1: readings are visited in order, each exactly once. The shape sweep's
        // first live run OPENED on index 4 because its phase was anchored to the wrong event.
        // The opening reading is the LIKELIEST one, not the control - a peer row can freeze
        // the client before a late reading is ever reached (see the header's ORDER note).
        if (body == 0 && decision.variant != TrailingVariant::packedMasks) {
            fail("opens_on_packed_masks", index);
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

    // INVARIANT 5: no peer-bearing reading may carry a zero in any of the four fields. The
    // encoder reads a zero override as "keep the historical value", so such a reading would
    // silently publish the mask it was written to replace - a sweep step that measures the
    // control while reporting its own name. Cheap to assert, invisible in a boot record.
    for (std::uint64_t index = 0; index < kTrailingVariantCount; ++index) {
        const TrailingValues values = trailing_values(static_cast<TrailingVariant>(index));
        if (!values.peerPresent) {
            continue;
        }
        if (values.first == 0 || values.second == 0 || values.third == 0
            || values.fourth == 0) {
            fail("zero_is_not_expressible", index);
            ++failures;
        }
    }

    for (std::uint64_t index = 0; index < kTrailingVariantCount; ++index) {
        const TrailingValues values = trailing_values(static_cast<TrailingVariant>(index));
        std::printf("ev=sweep_test stage=reading variant=%s bodies=%llu "
                    "fields=0x%08X/0x%08X/0x%08X/0x%08X peer=%d\n",
                    variant_name(static_cast<TrailingVariant>(index)),
                    static_cast<unsigned long long>(bodiesFor[index]),
                    values.first,
                    values.second,
                    values.third,
                    values.fourth,
                    values.peerPresent ? 1 : 0);
    }
    std::printf("ev=sweep_test stage=done result=%s failures=%llu advances=%llu\n",
                failures == 0 ? "ok" : "fail",
                static_cast<unsigned long long>(failures),
                static_cast<unsigned long long>(advancesSeen));
    return failures == 0 ? 0 : 1;
}

namespace {

namespace message = middleware::bap::activity_message::replicate_membership;

/** Storage for one encoded body, with room for the peer row and a citizen descriptor. */
std::array<std::byte, message::kCitizenEncodedSize + 256> gWireBuffer{};

/**
 * Encodes one body and checks its size and its four trailing fields.
 * @param label Reported name of the case.
 * @param peerPresent Whether the body carries a peer row.
 * @return Number of failures found.
 */
std::uint64_t check_wire_case(const char* label, const bool peerPresent) noexcept {
    namespace bits = middleware::encoding::bits;

    // Distinct values, so a dropped, duplicated or swapped field is visible as a WRONG value
    // rather than merely a missing one. Non-zero matters: zero means "keep the historical
    // value" to the encoder, which would silently turn this into a test of the old behaviour.
    constexpr std::uint32_t kValues[4] = {0x11111111U, 0x22222222U, 0x33333333U, 0x44444444U};

    message::MembershipSnapshot snapshot{};
    snapshot.revision = 7;
    snapshot.epoch = 9;
    snapshot.peerPresent = peerPresent;
    snapshot.identity.memberKey = 0xAAAA'0000'0000'0001ULL;
    snapshot.peer.memberKey = 0xBBBB'0000'0000'0002ULL;
    snapshot.trailingFirst = kValues[0];
    snapshot.trailingSecond = kValues[1];
    snapshot.trailingThird = kValues[2];
    snapshot.trailingFourth = kValues[3];

    std::uint64_t failures = 0;
    const std::size_t expected = message::encoded_size(snapshot);
    std::size_t written = 0;
    if (!message::encode_replicate_membership(snapshot, gWireBuffer, written)) {
        std::printf("ev=wire_test stage=check result=fail case=%s what=encode_refused\n", label);
        return 1;
    }
    if (written != expected) {
        std::printf("ev=wire_test stage=check result=fail case=%s what=size got=%llu want=%llu\n",
                    label,
                    static_cast<unsigned long long>(written),
                    static_cast<unsigned long long>(expected));
        ++failures;
    }

    // Read the trailer back from where the region block ends.
    bits::Reader reader{std::span<const std::byte>(gWireBuffer).first(written)};
    if (!reader.skip(message::region_block_end_bit(snapshot))) {
        std::printf("ev=wire_test stage=check result=fail case=%s what=skip_to_trailer\n", label);
        return failures + 1;
    }
    for (std::size_t field = 0; field < 4; ++field) {
        std::uint64_t present = 0;
        std::uint64_t value = 0;
        if (!reader.read(1, present) || !reader.read(32, value)) {
            std::printf("ev=wire_test stage=check result=fail case=%s what=truncated field=%llu\n",
                        label,
                        static_cast<unsigned long long>(field));
            return failures + 1;
        }
        if (present != 1 || value != kValues[field]) {
            std::printf("ev=wire_test stage=check result=fail case=%s what=field field=%llu "
                        "present=%llu got=0x%08llX want=0x%08llX\n",
                        label,
                        static_cast<unsigned long long>(field),
                        static_cast<unsigned long long>(present),
                        static_cast<unsigned long long>(value),
                        static_cast<unsigned long long>(kValues[field]));
            ++failures;
        }
    }
    // The body must end exactly on the final absent-bit and its byte padding - no more.
    std::uint64_t tail = 0;
    if (!reader.read(1, tail) || tail != 0) {
        std::printf("ev=wire_test stage=check result=fail case=%s what=tail_bit got=%llu\n",
                    label,
                    static_cast<unsigned long long>(tail));
        ++failures;
    }
    if (reader.remaining_bits() >= 8) {
        std::printf("ev=wire_test stage=check result=fail case=%s what=trailing_slack bits=%llu\n",
                    label,
                    static_cast<unsigned long long>(reader.remaining_bits()));
        ++failures;
    }
    std::printf("ev=wire_test stage=case case=%s bytes=%llu trailer_bit=%llu failures=%llu\n",
                label,
                static_cast<unsigned long long>(written),
                static_cast<unsigned long long>(message::region_block_end_bit(snapshot)),
                static_cast<unsigned long long>(failures));
    return failures;
}

} // namespace

/** Encodes real bodies and reads their top-level trailer back out of the bits. */
int run_membership_wire_test() noexcept {
    std::uint64_t failures = check_wire_case("solo", false);
    failures += check_wire_case("peer", true);
    std::printf("ev=wire_test stage=done result=%s failures=%llu declared_bits=%llu "
                "declared_bytes=%llu\n",
                failures == 0 ? "ok" : "fail",
                static_cast<unsigned long long>(failures),
                static_cast<unsigned long long>(message::kMeaningfulBitCount),
                static_cast<unsigned long long>(message::kEncodedSize));
    return failures == 0 ? 0 : 1;
}

} // namespace sunrise::server::bap::encrypted::push::activity
