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
     * Logs the peer slots, states, machine ids and member lists the peer-adoption path
     * walks (FINDINGS 20.157). Observation only. True by default: it is the runtime
     * verification of a geometry that is currently a STATIC reading by the roster-caller
     * lane, whose reserve->admit trigger chain that lane itself labels INFERRED.
     */
    bool admissionCensus{true};
    /**
     * Injects the member record the peer-adoption path needs - the three fields ADMIT
     * (0x141777EC0) writes and the adoption arm reads. FALSE by default and deliberately
     * so: this writes into live netmgr state, and p2(62) changed six bindings, froze, and
     * its cause is now unknowable. Flip only after a census boot has confirmed the
     * geometry AND shown `admission_member_index` to be an unused record.
     */
    bool admissionInject{};
    /**
     * Harvests a real ~260B profile blob (marker + region A + header + tail) from the
     * registry commit wrapper 0x1417a6040, whose arguments carry all of it at ENTRY
     * (claims/profile-builder.md CLAIM 2/4, and see the observer header for why the
     * other two anchors were declined). OBSERVATION ONLY - it writes nothing.
     * FALSE by default anyway: it is a detour on an INTERNAL function, which is the
     * mechanism that poisoned the mac across p2(102)-p2(109) when it was used to WRITE.
     * Read-only makes that safe, but shipping it disarmed keeps the arm/disarm free.
     */
    bool profileHarvest{};
    /**
     * The RECEIVE side of the appearance question: observes 0x1417AF360, the region-A/
     * header/tail apply helper, which the apply 0x141781800 calls ONLY when a player
     * row's profile-present flag is set. Its firing answers "does a profile block ever
     * reach this client, from any source"; its arguments carry the decoded bytes, which
     * is the only grounded input for a server-side encoder (the wire->delta decoder was
     * never located). OBSERVATION ONLY. FALSE by default, like every internal detour.
     */
    bool profileIngress{};
    /**
     * The p2(115) WEDGE BISECTION (FINDINGS 20.178-20.182): the flag-on membership body
     * is delivered and acked but never applied - the row never materializes and the
     * profile helper never fires. This traces the two points between delivery and the
     * helper: the wire->delta DECODER 0x14173BFC0 (id-30 handler +0x28) and the APPLY
     * 0x141781800. Entry-log only, pass-through, capped. The three log shapes bisect:
     * decoder silent = dispatch refuses; decoder logged + apply silent = the decode or
     * the pipeline between them fails; both logged with helper silent = the apply's row
     * loop saw gate=0 or another struct. OBSERVATION ONLY. FALSE by default.
     */
    bool decoderTrace{};
    /**
     * THE FIRST WRITE DETOUR THIS PROJECT HAS SHIPPED (p2(116)). Every internal detour
     * before it was read-only; the p2(102)-p2(109) admission poisonings were write
     * detours done carelessly and they invalidated eight boots by corrupting the mac's
     * OWN structures (20.170). This one is deliberately shaped so that failure mode is
     * unreachable: it NEVER writes through a client pointer. The apply 0x141781800 takes
     * its profile content from a STAGING OBJECT passed in r8 (20.183 R2), and at stage 2
     * that pointer is read from session slot [+0x1af60], which no readable code writes
     * (20.185 R2) - the values observed were TLS tick counts, not addresses (20.184 R2).
     * Writing through them would be a wild write to an arbitrary address. Instead the
     * detour SUBSTITUTES a buffer we own, populated with the fields the apply reads, and
     * hands that to the original as r8. The incoming pointer is logged and discarded.
     * Armed only when the decoded update actually carries a player row, so the
     * members-only applies keep their original argument and their original behaviour.
     * FALSE by default; flipping it needs no rebuild. Requires decoderTrace (the hook
     * this rides on). OBSERVATION+WRITE - read the boot brief before arming.
     */
    bool stagingPopulate{};
    /**
     * THE PEER-VISIBILITY ENTITY FRONT'S INSTRUMENTS (p2(129)). Three read-only
     * observers in one hook unit: the roster-change manifest emitter 0x1417607B0
     * (the live chunk-2 identity column the client assembles - hunt item 1), the
     * entity create/decode path 0x141718080 whose RETURN VALUE is the decode
     * verdict the world-population front lacked (0 ok / 1,2 codec-body fail /
     * 3 mask fail), and a one-shot schema-registry dump (the live player-archetype
     * tree 0x80806AC0 + the chunk-8 power key - both runtime-built, neither
     * statically dumpable). OBSERVATION ONLY, every read SEH-guarded, capped.
     * FALSE by default.
     */
    bool worldTrace{};
    /**
     * THE CHECKSUM HUNT (p2(130)). Detours the client's membership checksum
     * verifier 0x141772100 (.pdata start) - the function that copies the client's
     * 28,768-byte replica from holder+8 and hashes it (lookup3, init 0xDEAE2F4E).
     * Logs our own hash of the captured bytes (pairs with the client's printed
     * "checksum failed" line, validating the capture) and fully dumps the replica
     * on the first two calls. The desk-side diff against build_session_state names
     * every differing region, which turns the state-hash disagreement into an
     * exact fix. OBSERVATION ONLY. FALSE by default.
     */
    bool stateDiff{};
    /**
     * THE MILESTONE TRACER: a table-driven census of the entity/render path. Logs each
     * traced function's CALLER - the only way to name a runtime-dispatched invoker, since
     * the entity receive chain has zero static references anywhere in the image
     * (FINDINGS 20.209) - and heartbeats every hook's call count, ZEROS INCLUDED. Built
     * after p2(130)/p2(133)/p2(136) each lost their answer to a silence that could not be
     * told apart from "never installed".
     */
    bool milestoneTrace{};

    /** Member-record index the injection writes. Must be unused - the census names one. */
    std::uint32_t admissionMemberIndex{};
    /** Peer xuid the injection publishes. Zero disables the injection outright. */
    std::uint64_t admissionXuid{};
    /**
     * The PEER's steam id, decimal, as it appears in the identity string the slot
     * creator is handed (FINDINGS 20.162: a5 is "steamid:<id>#<16 hex>"). The injection
     * copies the LOCAL string captured at the real kind=5 call and substitutes these
     * digits, so the shape stays byte-faithful and only the identity changes.
     */
    std::uint64_t admissionPeerSteamId{};
    /**
     * The PEER's machine id in the SESSION-STRING form (20.153), little-endian as the
     * bytes appear at the head of a6 - mac DC0FA61D6307F015 -> 0x15F007631DA60FDC,
     * rig E622D0F738836C84 -> 0x846C8338F7D022E6. Stable across every boot on record,
     * unlike a7.
     */
    std::uint64_t admissionPeerMachine{};
    /**
     * The a7 the injection registers as the peer's per-session machine id (lands at
     * slot+0xC8). 20.162: this value is per-boot, per-machine, and our server has never
     * seen it, so the first test FABRICATES one. If the roster then names the peer, a
     * local key suffices; if it does not, the real value must be obtained and this
     * setting is where it goes. Flagged against p2(63) - fabricated ids in client
     * enumeration loops have burned this project before.
     */
    std::uint64_t admissionA7{};
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
     * Slice set whose region transition is forced PUBLIC, or -1 for none.
     *
     * p2(76) proved `region_public` is too broad: the starter's decision point is reached for the
     * ORBIT transition first, and an orbit forced public sits in "PUBLIC but not yet connected"
     * forever - the client never even allocates an activity host, so the whole boot stalls before
     * the work we want to test. Naming ONE slice set keeps the handbook's rule (change the input
     * at the exact native decision point) without changing every other transition.
     *
     * Takes precedence over `region_public` when set: -1 means "use region_public".
     */
    std::int32_t regionPublicSliceSet{-1};
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
