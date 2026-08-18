#include <Windows.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string_view>

#include "../../core/logging/log.h"
#include "../../core/ui/busy/busy.h"
#include "../../core/ui/notice/ui_notice_overlay.h"
#include "../content/bootstrap/bootstrap_token_publish.h"
#include "../content/investment/worker.h"
#include "../executable/image.h"
#include "../hooks/assert_handler/assert_handler_lifecycle.h"
#include "../hooks/banner/banner_hook_lifecycle.h"
#include "../hooks/bitmap/bitmap_hook_lifecycle.h"
#include "../hooks/bootflow/bootflow_hook_lifecycle.h"
#include "../hooks/config_getter/config_getter_lifecycle.h"
#include "../hooks/cursor/runtime.h"
#include "../hooks/package_validator/package_validator_iv.h"
#include "../hooks/graphics/graphics_hook_lifecycle.h"
#include "../hooks/ability_gate/ability_gate_observer.h"
#include "../hooks/gate_trace/gate_trace_observer.h"
#include "../hooks/handle_message/handle_message_observer.h"
#include "../hooks/schema_capture/schema_capture_observer.h"
#include "../hooks/network/runtime.h"
#include "../hooks/package_trust/package_trust_bypass.h"
#include "../hooks/noclip/runtime.h"
#include "../hooks/polled_input/runtime.h"
#include "../hooks/queuez/queuez_hook_lifecycle.h"
#include "../hooks/retail_log/retail_log_lifecycle.h"
#include "../hooks/teleport/runtime.h"
#include "../patterns/registry.h"
#include "../targets/game.h"
#include "internal.h"
#include "runtime.h"

namespace sunrise::client::runtime {

SRWLOCK g_lock{SRWLOCK_INIT};
StageState g_mainStage{StageState::pending};
StageState g_graphicsStage{StageState::pending};
StageState g_platformStage{StageState::pending};
HMODULE g_platformModule{};

namespace {

/** Main-image executable ranges remain valid while the process is loaded. */
struct GameImageRanges {
    executable::ExecutableImage executable;
    std::array<patterns::ImageRange, executable::kPeSectionLimit> ranges{};
};

/**
 * Inspects the main image and maps its executable sections to scanner ranges.
 * @param output Receives the inspected image and matching scanner ranges.
 * @return True when the main PE image has at least one valid executable range.
 */
[[nodiscard]] bool inspect_game_image(GameImageRanges& output) noexcept {
    output = {};
    if (!executable::inspect_main_module(output.executable)) {
        return false;
    }
    for (std::size_t index = 0; index < output.executable.count; ++index) {
        output.ranges[index] = patterns::ImageRange{output.executable.sections[index]};
    }
    return true;
}

/** @param image Inspected main image. @return Populated executable scanner ranges. */
[[nodiscard]] std::span<patterns::ImageRange> ranges(GameImageRanges& image) noexcept {
    return std::span(image.ranges.data(), image.executable.count);
}

/** Reports which resolve stage rejected the sweep, naming a missed signature. */
void report_resolve_failure() noexcept {
    const auto failure = targets::game::resolution::last_failure();
    if (failure == targets::game::resolution::Failure::networkDerive) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::error,
                         "ev=activate stage=game_targets reason=network_derive result=fail");
        return;
    }
    if (failure == targets::game::resolution::Failure::contentDerive) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::error,
                         "ev=activate stage=game_targets reason=content_derive result=fail");
        return;
    }
    const std::string_view name = targets::game::resolution::last_failed_signature();
    std::array<char, 128> line{};
    const int written = std::snprintf(line.data(),
                                      line.size(),
                                      "ev=activate stage=game_targets reason=signature name=%.*s "
                                      "result=fail",
                                      static_cast<int>(name.size()),
                                      name.data());
    if (written <= 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::error,
                         "ev=activate stage=game_targets reason=signature result=fail");
        return;
    }
    const auto length = static_cast<std::size_t>(written) < line.size()
                            ? static_cast<std::size_t>(written)
                            : line.size() - 1;
    core::log::write(
        core::log::Channel::client, core::log::Level::error, std::string_view(line.data(), length));
}

/**
 * Reports how long main activation took, for the debug channel only.
 * Timing is diagnostic, so it never appears at the levels a normal run uses.
 * @param event Event and phase text the duration is appended to.
 * @param startedTick Tick count taken when activation began.
 * @param result Outcome text for the log line.
 */
void report_elapsed(const char* event, std::uint64_t startedTick, const char* result) noexcept {
    const std::uint64_t elapsed = GetTickCount64() - startedTick;
    std::array<char, 96> line{};
    const int written = std::snprintf(line.data(),
                                      line.size(),
                                      "%s ms=%llu result=%s",
                                      event,
                                      static_cast<unsigned long long>(elapsed),
                                      result);
    if (written <= 0) {
        return;
    }
    const auto length = static_cast<std::size_t>(written) < line.size()
                            ? static_cast<std::size_t>(written)
                            : line.size() - 1;
    core::log::write(core::log::Channel::client, core::log::Level::debug, {line.data(), length});
}

/** Clears both main-image target groups while no game hook owns their entries. */
void clear_game_targets() noexcept {
    targets::game::content::clear();
    targets::game::network::clear();
}

/**
 * Resolves both main-image target groups from one inspection, then installs game hooks.
 * @return True when every required main-image target and game hook is ready.
 */
[[nodiscard]] bool activate_required_main_locked() noexcept {
    GameImageRanges gameImage;
    if (!inspect_game_image(gameImage)) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::error,
                         "ev=activate stage=game_image result=fail");
        clear_game_targets();
        return false;
    }
    const std::span<patterns::ImageRange> imageRanges = ranges(gameImage);
    if (!targets::game::resolution::resolve(imageRanges)) {
        report_resolve_failure();
        return false;
    }
    // Steam initialization installs package trust before base-package registration. Keep this
    // idempotent check beside the other main-image hooks so activation also verifies ownership.
    if (!hooks::package_trust::install()) {
        clear_game_targets();
        return false;
    }
    // The SignOn config blob carries this token. It must reach State before any hook owns the
    // resolved targets: extraction cannot recover from a missing bootstrap token.
    if (!content::bootstrap::publish_token()) {
        (void)hooks::package_trust::uninstall();
        clear_game_targets();
        return false;
    }
    if (!hooks::network::install_game()) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::error,
                         "ev=activate stage=game_network result=fail");
        if (!hooks::network::has_game_ownership()) {
            (void)hooks::package_trust::uninstall();
            clear_game_targets();
        }
        return false;
    }

    core::log::write(core::log::Channel::client,
                     core::log::Level::info,
                     "ev=activate stage=game_network result=ok");
    const bool packageKeys = targets::game::packages::is_resolved();
    core::log::write(core::log::Channel::client,
                     packageKeys ? core::log::Level::info : core::log::Level::warn,
                     packageKeys ? "ev=activate stage=package_keys result=ok"
                                 : "ev=activate stage=package_keys result=fail");
    // Diagnostic capture reports its own outcome and never demotes this stage.
    (void)hooks::retail_log::install();
    (void)hooks::assert_handler::install();
    (void)hooks::config_getter::install();
    // The external-server fix for the -87 registration failure: re-assert the healthy kind0
    // IV at every package-validator entry. Internal no-op while externalServer is disabled.
    (void)hooks::package_validator::install();
    // The S2-0 acceptance oracle: log-only observer on the per-type push apply dispatcher,
    // so every server push the client decodes is named. Internal no-op while externalServer
    // is disabled.
    (void)hooks::handle_message::install();
    // The inventory gate observers: log-only detours on the acquiredFlags byte test, the
    // opcode-2100 ability emitter, and the 702 sync-header serializer, capturing the
    // caller RVAs that name the un-analyzed CUI gate chain and the definition-hash slots
    // for the mode-pair diff. They attach in BOTH modes (in-process and external).
    (void)hooks::ability_gate::install();
    // The round-2 gate-trace observers: log-only detours on the character-bank byte test,
    // the family-4 kind-0 diff-apply (the rollback executor), and the acquire-flag writer
    // — the flag-map campaign's runtime foundation (the per-scope census + the swap's
    // gate-check footprint). Attach in BOTH modes, like the ability_gate family.
    (void)hooks::gate_trace::install();
    // The R1 schema-hash close: log-only observer on the schema-decode entry, so the
    // client's own player-baseline decode prints the real schemaTagHash (the
    // world_population_schema_hash knob value). Internal no-op while externalServer is
    // disabled.
    (void)hooks::schema_capture::install();
    // Boot-step fixes scan for their own single-site targets; each reports its own outcome.
    (void)hooks::bootflow::install();
    // The teleport hooks attach whether or not the feature is on, so the interface can enable it
    // without a restart. Both replacements return immediately while nothing is requested.
    (void)hooks::teleport::install();
    // Noclip owns its Havok-step target, so a patch-specific miss cannot disable teleport.
    (void)hooks::noclip::install();
    (void)hooks::queuez::install();
    // The bitmap reference guard puts the none sentinel in place of a reference outside tag
    // space. Without it the widget's stored-reference reader faults.
    (void)hooks::bitmap::install();
    // The orbit banner component ships unbound, so its update body never runs and it draws the
    // constructor's values.
    (void)hooks::banner::install();
    content::investment::worker::activate();
    return true;
}

} // namespace

} // namespace sunrise::client::runtime

namespace sunrise::client {

/** Resolves main-image targets and installs required game hooks once. */
bool activate_main_once() noexcept {
    AcquireSRWLockExclusive(&runtime::g_lock);
    if (runtime::g_mainStage != runtime::StageState::pending) {
        const bool active = runtime::g_mainStage == runtime::StageState::active;
        ReleaseSRWLockExclusive(&runtime::g_lock);
        return active;
    }
    // The image sweep dominates this call, so the pair of debug markers around it is what a
    // boot-time measurement reads. Both are diagnostic and stay off at the usual levels.
    core::log::write(
        core::log::Channel::client, core::log::Level::debug, "ev=activate stage=main phase=begin");
    // The sweep stalls whichever thread calls it, so the overlay says what is happening. It
    // only reaches the screen once the presentation hooks are installed.
    core::ui::busy::begin(core::ui::busy::Task::initialization);
    // Started after the overlay is up, because begin blocks for up to half a second waiting on
    // presents. That wait belongs to the overlay, not to the work being measured.
    const std::uint64_t startedTick = GetTickCount64();
    const bool active = runtime::activate_required_main_locked();
    runtime::report_elapsed(
        "ev=activate stage=main phase=complete", startedTick, active ? "ok" : "fail");
    core::ui::busy::end(core::ui::busy::Task::initialization);
    if (!active) {
        // A failed sweep latches too: repeating it stalls the frame loop for nothing.
        runtime::g_mainStage = runtime::StageState::failed;
        core::log::write(core::log::Channel::client,
                         core::log::Level::error,
                         "ev=activate stage=main result=fail");
        // The boot cannot reach orbit after this, so the user is told rather than left waiting.
        core::ui::notice::raise("Sunrise could not attach to the game. The boot will not finish.");
        ReleaseSRWLockExclusive(&runtime::g_lock);
        return false;
    }

    runtime::g_mainStage = runtime::StageState::active;
    core::log::write(
        core::log::Channel::client, core::log::Level::info, "ev=activate stage=main result=ok");
    ReleaseSRWLockExclusive(&runtime::g_lock);
    return true;
}

/** Installs the presentation hooks once, independently of the game image sweep. */
bool activate_graphics_once() noexcept {
    AcquireSRWLockExclusive(&runtime::g_lock);
    if (runtime::g_graphicsStage != runtime::StageState::pending) {
        const bool active = runtime::g_graphicsStage == runtime::StageState::active;
        ReleaseSRWLockExclusive(&runtime::g_lock);
        return active;
    }
    if (!hooks::graphics::install()) {
        runtime::g_graphicsStage = runtime::StageState::failed;
        core::log::write(core::log::Channel::client,
                         core::log::Level::error,
                         "ev=activate stage=graphics_hooks result=fail");
        ReleaseSRWLockExclusive(&runtime::g_lock);
        return false;
    }

    runtime::g_graphicsStage = runtime::StageState::active;
    // The cursor guards only matter once the interface can be shown. A miss must not demote
    // presentation readiness, so it is logged and not propagated.
    (void)hooks::cursor::install();
    // The game reads its action keys by scanning GetKeyState every frame, which no window
    // procedure sees, so the polled guards carry the same terms as the cursor guards.
    (void)hooks::polled_input::install();
    core::log::write(
        core::log::Channel::client, core::log::Level::info, "ev=activate stage=graphics result=ok");
    ReleaseSRWLockExclusive(&runtime::g_lock);
    return true;
}

} // namespace sunrise::client
