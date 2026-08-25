#pragma once

#include <cstdint>

#include "../../middleware/bap/activity_message/replicate_membership.h"
#include "../../state/activity/definition.h"

namespace sunrise::server::gameplay {

/** Where an advertised region index came from. Reported so a stand-in cannot look like a report. */
enum class RegionSource : std::uint8_t {
    /** The client reported the region it is in. */
    reported,
    /** No report has arrived, so the destination's arrival slice set stood in. */
    arrival,
};

/** Whether one exact source binding's advertisement can be built now. */
enum class AdvertisementState : std::uint8_t {
    /** It builds, so a push carries the descriptor and the host session. */
    ready,
    /** Only the source-bound target is missing, and the next service slice fills it. */
    pending,
    /** The channel advertises nothing at all. */
    absent,
};

/**
 * Builds a citizen advertisement from one exact source activity generation.
 * A successful call retains the returned host generation until the publisher releases it with
 * `group::release_host_session`.
 * @param source Exact source record whose destination the target must copy.
 * @param regionIndex Concrete region the roster publishes for this session.
 * @param regionSource Where that index came from.
 * @param localMemberSlot Member slot of the joining client.
 * @param output Cleared, then filled when the whole channel can be advertised.
 * @param hostGeneration Cleared, then receives the retained row generation on success.
 */
void build_advertisement(
    const state::activity::SessionBinding& source,
    std::int32_t regionIndex,
    RegionSource regionSource,
    std::uint8_t localMemberSlot,
    middleware::bap::activity_message::replicate_membership::CitizenAdvertisement& output,
    std::uint64_t& hostGeneration) noexcept;

/** Claims a missing host row and reports whether its advertisement is ready. */
[[nodiscard]] AdvertisementState advertisement_state(const state::activity::SessionBinding& source,
                                                     std::int32_t regionIndex) noexcept;

// The source-LESS overloads upstream ships here are DELETED in this fork. They are fail-closed
// stubs ("TODO: no caller yet") that clear the output and report `reason=no_source`, and because
// they are a valid overload our BAP publishers bound to them by accident when this subtree was
// adopted - silencing the citizen advertisement for three commits with a clean build and no
// warning (FINDINGS 20.31). Deleting them makes that mistake a COMPILE ERROR, which is the same
// treatment the defaulted AccountKey got in 20.22 and for the same reason.

} // namespace sunrise::server::gameplay
