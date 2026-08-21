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
    bool hasForceJoinRequestReady = false;
    bool hasRegionPrivate = false;
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
        } else if (key == "force_join_request_ready") {
            if (hasForceJoinRequestReady || !boolean(candidate.forceJoinRequestReady)) {
                return false;
            }
            hasForceJoinRequestReady = true;
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
