#include "../parser.h"

namespace sunrise::core::settings::parser {

/** Parses Client-owned configuration over deterministic defaults. */
bool Parser::client_settings(client::Settings& output) noexcept {
    if (!consume('{')) {
        return false;
    }
    client::Settings candidate = output;
    bool hasUserInterface = false;
    bool hasExternalServer = false;
    bool hasFadeRelease = false;
    bool hasJoinRosterObserver = false;
    bool hasAdmissionCensus = false;
    bool hasAdmissionInject = false;
    bool hasProfileHarvest = false;
    bool hasProfileIngress = false;
    bool hasDecoderTrace = false;
    bool hasStagingPopulate = false;
    bool hasWorldTrace = false;
    bool hasStateDiff = false;
    bool hasMilestoneTrace = false;
    bool hasGatePoke = false;
    bool hasNotifierHook = false;
    bool hasAdmissionMemberIndex = false;
    bool hasAdmissionXuid = false;
    bool hasAdmissionPeerSteamId = false;
    bool hasAdmissionPeerMachine = false;
    bool hasAdmissionA7 = false;
    bool hasForceJoinRequestReady = false;
    bool hasRegionPrivate = false;
    bool hasRegionPublic = false;
    bool hasRegionPublicSliceSet = false;
    bool hasPinReplicatedRecord = false;
    bool hasGraphicsProbe = false;
    bool hasGraphicsProbeWarp = false;
    bool hasRendererHudAlways = false;
    bool hasRendererEnabled = false;
    bool hasHoldSpawn = false;
    bool hasSpawnHoldMs = false;
    if (consume('}')) {
        return true;
    }
    for (;;) {
        std::string_view key;
        if (!string(key) || !consume(':')) {
            return false;
        }
        if (key == "ui") {
            if (hasUserInterface || !client_ui_settings(candidate.userInterface)) {
                return false;
            }
            hasUserInterface = true;
        } else if (key == "external_server") {
            if (hasExternalServer || !client_external_settings(candidate.externalServer)) {
                return false;
            }
            hasExternalServer = true;
        } else if (key == "fade_release") {
            if (hasFadeRelease || !boolean(candidate.fadeRelease)) {
                return false;
            }
            hasFadeRelease = true;
        } else if (key == "join_roster_observer") {
            if (hasJoinRosterObserver || !boolean(candidate.joinRosterObserver)) {
                return false;
            }
        } else if (key == "admission_census") {
            if (hasAdmissionCensus || !boolean(candidate.admissionCensus)) {
                return false;
            }
            hasAdmissionCensus = true;
        } else if (key == "profile_ingress") {
            if (hasProfileIngress || !boolean(candidate.profileIngress)) {
                return false;
            }
            hasProfileIngress = true;
        } else if (key == "decoder_trace") {
            if (hasDecoderTrace || !boolean(candidate.decoderTrace)) {
                return false;
            }
            hasDecoderTrace = true;
        } else if (key == "milestone_trace") {
            if (hasMilestoneTrace || !boolean(candidate.milestoneTrace)) {
                return false;
            }
            hasMilestoneTrace = true;
        } else if (key == "gate_poke") {
            std::uint64_t value = 0;
            // Two groups defined; a wider value is a typo, not an intention.
            if (hasGatePoke || !unsigned_integer(value) || value > 0x3ULL) {
                return false;
            }
            candidate.gatePoke = static_cast<std::uint32_t>(value);
            hasGatePoke = true;
        } else if (key == "notifier_hook") {
            if (hasNotifierHook || !boolean(candidate.notifierHook)) {
                return false;
            }
            hasNotifierHook = true;
        } else if (key == "state_diff") {
            if (hasStateDiff || !boolean(candidate.stateDiff)) {
                return false;
            }
            hasStateDiff = true;
        } else if (key == "world_trace") {
            if (hasWorldTrace || !boolean(candidate.worldTrace)) {
                return false;
            }
            hasWorldTrace = true;
        } else if (key == "staging_populate") {
            if (hasStagingPopulate || !boolean(candidate.stagingPopulate)) {
                return false;
            }
            hasStagingPopulate = true;
        } else if (key == "profile_harvest") {
            if (hasProfileHarvest || !boolean(candidate.profileHarvest)) {
                return false;
            }
            hasProfileHarvest = true;
        } else if (key == "admission_inject") {
            if (hasAdmissionInject || !boolean(candidate.admissionInject)) {
                return false;
            }
            hasAdmissionInject = true;
        } else if (key == "admission_member_index") {
            std::uint64_t value = 0;
            if (hasAdmissionMemberIndex || !unsigned_integer(value)
                || value > (std::numeric_limits<std::uint32_t>::max)()) {
                return false;
            }
            candidate.admissionMemberIndex = static_cast<std::uint32_t>(value);
            hasAdmissionMemberIndex = true;
        } else if (key == "admission_xuid") {
            if (hasAdmissionXuid || !unsigned_integer(candidate.admissionXuid)) {
                return false;
            }
            hasAdmissionXuid = true;
        } else if (key == "admission_peer_steam_id") {
            if (hasAdmissionPeerSteamId || !unsigned_integer(candidate.admissionPeerSteamId)) {
                return false;
            }
            hasAdmissionPeerSteamId = true;
        } else if (key == "admission_peer_machine") {
            if (hasAdmissionPeerMachine || !unsigned_integer(candidate.admissionPeerMachine)) {
                return false;
            }
            hasAdmissionPeerMachine = true;
        } else if (key == "admission_a7") {
            if (hasAdmissionA7 || !unsigned_integer(candidate.admissionA7)) {
                return false;
            }
            hasAdmissionA7 = true;
            hasJoinRosterObserver = true;
        } else if (key == "force_join_request_ready") {
            if (hasForceJoinRequestReady || !boolean(candidate.forceJoinRequestReady)) {
                return false;
            }
            hasForceJoinRequestReady = true;
        } else if (key == "region_public_slice_set") {
            std::int64_t value = 0;
            if (hasRegionPublicSliceSet || !signed_integer(value)
                || value < -1 || value > (std::numeric_limits<std::int32_t>::max)()) {
                return false;
            }
            candidate.regionPublicSliceSet = static_cast<std::int32_t>(value);
            hasRegionPublicSliceSet = true;
        } else if (key == "region_public") {
            if (hasRegionPublic || !boolean(candidate.regionPublic)) {
                return false;
            }
            hasRegionPublic = true;
        } else if (key == "region_private") {
            if (hasRegionPrivate || !boolean(candidate.regionPrivate)) {
                return false;
            }
            hasRegionPrivate = true;
        } else if (key == "pin_replicated_record") {
            if (hasPinReplicatedRecord || !boolean(candidate.pinReplicatedRecord)) {
                return false;
            }
            hasPinReplicatedRecord = true;
        } else if (key == "graphics_probe") {
            if (hasGraphicsProbe || !boolean(candidate.graphicsProbe)) {
                return false;
            }
            hasGraphicsProbe = true;
        } else if (key == "graphics_probe_warp") {
            if (hasGraphicsProbeWarp || !boolean(candidate.graphicsProbeWarp)) {
                return false;
            }
            hasGraphicsProbeWarp = true;
        } else if (key == "renderer_hud_always") {
            if (hasRendererHudAlways || !boolean(candidate.rendererHudAlways)) {
                return false;
            }
            hasRendererHudAlways = true;
        } else if (key == "renderer_enabled") {
            if (hasRendererEnabled || !boolean(candidate.rendererEnabled)) {
                return false;
            }
            hasRendererEnabled = true;
        } else if (key == "hold_spawn") {
            if (hasHoldSpawn || !boolean(candidate.holdSpawn)) {
                return false;
            }
            hasHoldSpawn = true;
        } else if (key == "spawn_hold_ms") {
            std::uint64_t value = 0;
            if (hasSpawnHoldMs || !unsigned_integer(value) || value == 0
                || value > client::kMaximumSpawnHoldMs) {
                return false;
            }
            candidate.spawnHoldMs = value;
            hasSpawnHoldMs = true;
        } else if (!skip_value(0)) {
            return false;
        }
        if (consume('}')) {
            output = candidate;
            return true;
        }
        if (!consume(',')) {
            return false;
        }
    }
}

} // namespace sunrise::core::settings::parser
