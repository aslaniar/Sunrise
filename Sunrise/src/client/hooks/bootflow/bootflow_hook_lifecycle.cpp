#include "bootflow_hook_lifecycle.h"

#include <atomic>

#include "internal.h"

namespace sunrise::client::hooks::bootflow {
namespace {

std::atomic_bool g_installed{false};

} // namespace

/**
 * Attaches the boot-step fixes that carry sign-in through to orbit.
 * Each fix stands alone at one site, so a miss on one is reported and the others still attach.
 * @return True when every fix attached.
 */
bool install() noexcept {
    const bool hold = install_character_select_hold();
    const bool sliceSet = install_orbit_slice_set();
    const bool skip = install_profile_setup_skip();
    const bool composition = install_composition_check();
    const bool handoff = install_orbit_handoff();
    const bool joinReady = install_join_request_ready();
    const bool ownerSlot = install_owner_activity_slot();
    const bool regionPrivate = install_region_private();
    const bool worldStep = install_world_step();
    const bool spawn = install_spawn_hold();
    const bool fade = install_fade_release();
    const bool peerReason = install_peer_reason();
    // INCIDENT_2026-08-26_p2-59-freeze bisect step: seeker_rx DISABLED under BOTH
    // mechanisms so far (p2(59) code detours, p2(60) vtable swaps - each froze at
    // bootflow bap_signin/package_registration with zero rows completed). This
    // build isolates the OTHER variable (sv-43 relabel / everything else).
    const bool seekerRx = false;
    const bool anyFix = hold || sliceSet || skip || composition || handoff || joinReady || ownerSlot
                        || regionPrivate || worldStep || spawn || fade || peerReason || seekerRx;
    g_installed.store(anyFix, std::memory_order_release);
    return hold && sliceSet && skip && composition && handoff && joinReady && ownerSlot
           && regionPrivate && worldStep && spawn && fade && peerReason && seekerRx;
}

/** Detaches every boot-step fix, in the reverse order of install. */
void uninstall() noexcept {
    uninstall_seeker_rx();
    uninstall_peer_reason();
    uninstall_fade_release();
    uninstall_spawn_hold();
    uninstall_world_step();
    uninstall_region_private();
    uninstall_owner_activity_slot();
    uninstall_join_request_ready();
    uninstall_orbit_handoff();
    uninstall_composition_check();
    uninstall_profile_setup_skip();
    uninstall_orbit_slice_set();
    uninstall_character_select_hold();
    g_installed.store(false, std::memory_order_release);
}

/** @return True while at least one boot-step fix is attached. */
bool is_installed() noexcept {
    return g_installed.load(std::memory_order_acquire);
}

} // namespace sunrise::client::hooks::bootflow
