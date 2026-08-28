#pragma once

#include <cstdint>

#include "../../ui/runtime/settings.h"
#include "external/definition.h"

namespace sunrise::core::settings::client {

/** A load this long has stopped making progress, so the spawn stops waiting for it. */
inline constexpr std::uint64_t kDefaultSpawnHoldMs = 30'000;
/** A load past this is a hang, not a slow machine, and holding the spawn would never end. */
inline constexpr std::uint64_t kMaximumSpawnHoldMs = 600'000;

/** Read-only Client settings parsed by Core. */
struct Settings {
    /** In-game UI visibility and input policy. */
    ui::runtime::Settings userInterface;
    /** Points the Client at a server outside this process. Off answers everything in process. */
    external::Settings externalServer;
    /**
     * Releases the world-transition fade channel at the in-world step.
     * The client only releases it on the player spawn, so this covers a spawn that never runs
     * and leaves the world black. On by default.
     */
    bool fadeRelease{true};
    /**
     * Installs the join-roster observation detours (FINDINGS 20.109 option C):
     * five log-only pass-through hooks on the host-side join gate. Logging
     * changes no behavior; this switch exists so the detours themselves can be
     * removed by a settings edit plus restart, without a rebuild.
     */
    bool joinRosterObserver{true};
    /**
     * Forces the activity session's status 5-to-6 ready check.
     * Two of its five terms are client flags no host message reaches, so the host cannot open it.
     */
    bool forceJoinRequestReady{true};
    /**
     * Reports a public region as private to the region transition.
     * On, a public region loads solo. Off, it waits for a public activity host, which is the
     * route to the citizen join. A forced destination loads solo either way.
     */
    bool regionPrivate{false};
    /**
     * Forces the region transition's public-flag input to PUBLIC at the native decision point.
     *
     * The community handbook 15.3 records this as the change that started the citizen and search
     * path on a route that had stayed private: "Changing the region transition input to public
     * started the citizen and search path. The change occurred at the transition-starter call...
     * Change the input at the exact native decision point. Do not force a downstream result
     * globally."
     *
     * The starter's own call site is the only one the hook answers for, so this is that exact
     * point and not a global override. `region_private` still wins if both are set, and a forced
     * destination still loads solo - no public host serves one.
     */
    bool regionPublic{false};
    /**
     * Runs the graphics target-discovery probe at attach (a real D3D11 device +
     * swapchain created purely to read the swapchain vtable). The probe's costs
     * are throwaway on a native driver but NOT on a translation layer (DXMT on
     * macOS shares process-wide Metal state with the game); skip it there.
     */
    bool graphicsProbe{true};
    /**
     * Runs the target-discovery probe on the WARP (software) driver instead of the
     * hardware adapter. Same attach timing, no hardware/translation-layer state
     * touched - the discriminator for DXMT-churn crashes, and a safe permanent
     * fallback where the swapchain trio is unused (no overlay rendering wanted).
     */
    bool graphicsProbeWarp{false};
    /**
     * Draws the always-on HUD overlays (logo, status lines) even while the Core
     * surface is closed. Off, the surfaces draw only while the menu is open or
     * a busy/notice overlay is active - the discriminator for renderer-frame
     * interference with the game's per-frame world draws.
     */
    bool rendererHudAlways{true};
    /**
     * Initializes the overlay renderer at all (ImGui backends, render target,
     * window input). Off, the swapchain trio installs but no renderer state
     * is ever created - the discriminator for init-time resource churn racing
     * the game's first world-frame pipelines.
     */
    bool rendererEnabled{true};
    /**
     * Pins the participation record to the replicated snapshot at `comp + 496`.
     * Off, the record is the local one at `comp + 1256`, whose spawn-gate byte no wire field
     * reaches.
     */
    bool pinReplicatedRecord{true};
    /**
     * Runs the player spawn after the world-transition fade is armed.
     * A spawn before the arm releases nothing, so the screen stays black. Settable because it is
     * the only thing that can turn an allowed spawn into a refusal.
     */
    bool holdSpawn{true};
    /** How long the spawn waits for a load. `hold_spawn` decides whether it waits at all. */
    std::uint64_t spawnHoldMs{kDefaultSpawnHoldMs};
};

} // namespace sunrise::core::settings::client
