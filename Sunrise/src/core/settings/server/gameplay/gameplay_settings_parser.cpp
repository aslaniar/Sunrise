#include <cstddef>
#include <cstdint>
#include <limits>
#include <string_view>

#include "../../address_text.h"
#include "../../parser.h"

namespace sunrise::core::settings::parser {
namespace {

namespace gameplay = server::gameplay;

/**
 * Turns one topology token into its enum value.
 * @param name Borrowed JSON token.
 * @param output Receives the topology only for a known token.
 * @return True when the token names a supported topology.
 */
[[nodiscard]] bool topology_value(std::string_view name, gameplay::Topology& output) noexcept {
    if (name == "disabled") {
        output = gameplay::Topology::disabled;
        return true;
    }
    if (name == "embedded") {
        output = gameplay::Topology::embedded;
        return true;
    }
    if (name == "external") {
        output = gameplay::Topology::external;
        return true;
    }
    return false;
}

} // namespace

/** Parses the gameplay endpoint block on top of the fixed defaults. */
bool Parser::gameplay_settings(gameplay::Settings& output) noexcept {
    if (!consume('{')) {
        return false;
    }
    gameplay::Settings candidate = output;
    if (consume('}')) {
        return gameplay::valid(candidate);
    }
    bool hasTopology = false;
    bool hasBind = false;
    bool hasAdvertised = false;
    bool hasTransport = false;
    bool hasPort = false;
    bool hasReserve = false;
    bool hasJoinGrant = false;
    bool hasEntityIndexAllocation = false;
    bool hasEntityIndexGrant = false;
    bool hasEntityIndexGrantFlat = false;
    bool hasEntityIndexAssignment = false;
    bool hasPoolC4MarkPush = false;
    bool hasSearchSelfHost = false;
    bool hasPublishJoinMachineIds = false;
    bool hasRelayPeerJoin = false;
    bool hasRelayJoinTargetIdentity = false;
    bool hasRelayJoinEngineChannel = false;
    bool hasActivityHostRegionBound = false;
    bool hasMembershipPeerSameRegionAdvert = false;
    bool hasActivityRegionSurvivesChurn = false;
    bool hasActivityMemberSetupFlags = false;
    bool hasActivitySliceSetFollowsRegion = false;
    bool hasPublicRowMembershipBodies = false;
    for (;;) {
        std::string_view key;
        if (!string(key) || !consume(':')) {
            return false;
        }
        if (key == "topology") {
            std::string_view name;
            if (hasTopology || !string(name) || !topology_value(name, candidate.topology)) {
                return false;
            }
            hasTopology = true;
        } else if (key == "bind_address") {
            std::string_view text;
            if (hasBind || !string(text) || !address::parse_ipv4(text, candidate.bindAddress)) {
                return false;
            }
            hasBind = true;
        } else if (key == "advertised_address") {
            std::string_view text;
            if (hasAdvertised || !string(text)
                || !address::parse_ipv4(text, candidate.advertisedAddress)) {
                return false;
            }
            hasAdvertised = true;
        } else if (key == "transport_address") {
            std::string_view text;
            if (hasTransport || !string(text)
                || !address::parse_ipv4(text, candidate.transportAddress)) {
                return false;
            }
            hasTransport = true;
        } else if (key == "port") {
            std::uint64_t value = 0;
            if (hasPort || !unsigned_integer(value)
                || value > (std::numeric_limits<std::uint16_t>::max)()) {
                return false;
            }
            candidate.port = static_cast<std::uint16_t>(value);
            hasPort = true;
        } else if (key == "server_reserve_count") {
            std::uint64_t value = 0;
            if (hasReserve || !unsigned_integer(value)
                || value > (std::numeric_limits<std::uint16_t>::max)()) {
                return false;
            }
            candidate.serverReserveCount = static_cast<std::uint16_t>(value);
            hasReserve = true;
        } else if (key == "entity_index_allocation") {
            if (hasEntityIndexAllocation || !boolean(candidate.entityIndexAllocation)) {
                return false;
            }
            hasEntityIndexAllocation = true;
        } else if (key == "entity_index_grant") {
            if (hasEntityIndexGrant || !boolean(candidate.entityIndexGrant)) {
                return false;
            }
            hasEntityIndexGrant = true;
        } else if (key == "entity_index_grant_flat") {
            if (hasEntityIndexGrantFlat || !boolean(candidate.entityIndexGrantFlat)) {
                return false;
            }
            hasEntityIndexGrantFlat = true;
        } else if (key == "entity_index_assignment") {
            if (hasEntityIndexAssignment || !boolean(candidate.entityIndexAssignment)) {
                return false;
            }
            hasEntityIndexAssignment = true;
        } else if (key == "pool_c4_mark_push") {
            if (hasPoolC4MarkPush || !boolean(candidate.poolC4MarkPush)) {
                return false;
            }
            hasPoolC4MarkPush = true;
        } else if (key == "client_join_grant_count") {
            std::uint64_t value = 0;
            if (hasJoinGrant || !unsigned_integer(value)
                || value > (std::numeric_limits<std::uint16_t>::max)()) {
                return false;
            }
            candidate.clientJoinGrantCount = static_cast<std::uint16_t>(value);
            hasJoinGrant = true;
        } else if (key == "search_self_host") {
            if (hasSearchSelfHost || !boolean(candidate.searchSelfHost)) {
                return false;
            }
            hasSearchSelfHost = true;
        } else if (key == "publish_join_machine_ids") {
            if (hasPublishJoinMachineIds || !boolean(candidate.publishJoinMachineIds)) {
                return false;
            }
            hasPublishJoinMachineIds = true;
        } else if (key == "relay_peer_join") {
            if (hasRelayPeerJoin || !boolean(candidate.relayPeerJoin)) {
                return false;
            }
            hasRelayPeerJoin = true;
        } else if (key == "relay_join_target_identity") {
            if (hasRelayJoinTargetIdentity || !boolean(candidate.relayJoinTargetIdentity)) {
                return false;
            }
            hasRelayJoinTargetIdentity = true;
        } else if (key == "relay_join_engine_channel") {
            if (hasRelayJoinEngineChannel || !boolean(candidate.relayJoinEngineChannel)) {
                return false;
            }
            hasRelayJoinEngineChannel = true;
        } else if (key == "activity_host_region_bound") {
            if (hasActivityHostRegionBound || !boolean(candidate.activityHostRegionBound)) {
                return false;
            }
            hasActivityHostRegionBound = true;
        } else if (key == "membership_peer_same_region_advert") {
            if (hasMembershipPeerSameRegionAdvert || !boolean(candidate.membershipPeerSameRegionAdvert)) {
                return false;
            }
            hasMembershipPeerSameRegionAdvert = true;
        } else if (key == "activity_region_survives_churn") {
            if (hasActivityRegionSurvivesChurn || !boolean(candidate.activityRegionSurvivesChurn)) {
                return false;
            }
            hasActivityRegionSurvivesChurn = true;
        } else if (key == "activity_member_setup_flags") {
            if (hasActivityMemberSetupFlags || !boolean(candidate.activityMemberSetupFlags)) {
                return false;
            }
            hasActivityMemberSetupFlags = true;
        } else if (key == "activity_slice_set_follows_region") {
            if (hasActivitySliceSetFollowsRegion
                || !boolean(candidate.activitySliceSetFollowsRegion)) {
                return false;
            }
            hasActivitySliceSetFollowsRegion = true;
        } else if (key == "activity_public_row_membership_bodies") {
            std::uint64_t value = 0;
            if (hasPublicRowMembershipBodies || !unsigned_integer(value)
                || value > (std::numeric_limits<std::uint16_t>::max)()) {
                return false;
            }
            candidate.activityPublicRowMembershipBodies = static_cast<std::uint16_t>(value);
            hasPublicRowMembershipBodies = true;
        } else if (!skip_value(0)) {
            return false;
        }
        if (consume('}')) {
            // The block is rejected as a whole so a half-applied topology never binds.
            if (!gameplay::valid(candidate)) {
                return false;
            }
            output = candidate;
            return true;
        }
        if (!consume(',')) {
            return false;
        }
    }
}

} // namespace sunrise::core::settings::parser
