#include "client_ui_module_runtime.h"

#include <string_view>

#include "../../../core/ui/modules/registry/ui_module_registry.h"
#include "../../../core/ui/modules/ui_module_descriptor.h"
#include "../sword_skate/sword_skate_panel.h"
#include "../teleport/teleport_panel.h"

namespace sunrise::client::ui::runtime {
namespace {

/** Namespaced stable ID prevents Client modules from colliding with Server modules. */
constexpr std::string_view kTeleportStableId = "client.teleport";
/** Short menu label for the shared teleport and noclip page. */
constexpr std::string_view kTeleportDisplayName = "Movement";
/** Namespaced stable ID for the sword-skate page. */
constexpr std::string_view kSwordSkateStableId = "client.sword_skate";
/** Short menu label for the sword-skate page. */
constexpr std::string_view kSwordSkateDisplayName = "Sword Skate";

core::ui::modules::registry::PageRegistration g_teleportPage;
core::ui::modules::registry::PageRegistration g_swordSkatePage;

} // namespace

/** @return True when the Client module owns its Core UI registry slot. */
bool initialize() noexcept {
    const bool teleportPage = g_teleportPage.acquire(
        core::ui::modules::Owner::client, kTeleportStableId, kTeleportDisplayName, &teleport::draw);
    const bool swordSkatePage = g_swordSkatePage.acquire(core::ui::modules::Owner::client,
                                                         kSwordSkateStableId,
                                                         kSwordSkateDisplayName,
                                                         &sword_skate::draw);
    return teleportPage && swordSkatePage;
}

/** Removes the Client module from the Core UI registry. */
void shutdown() noexcept {
    g_teleportPage.release();
    g_swordSkatePage.release();
}

} // namespace sunrise::client::ui::runtime
