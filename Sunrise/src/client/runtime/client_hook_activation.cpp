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
#include "../hooks/join_roster/join_roster_observer.h"
#include "../hooks/ability_gate/ability_gate_observer.h"
#include "../hooks/gate_trace/gate_trace_observer.h"
#include "../hooks/admission/admission_observer.h"
#include "../hooks/nat_probe/nat_probe_observer.h"
#include "../hooks/profile_harvest/profile_harvest_observer.h"
#include "../hooks/profile_ingress/profile_ingress_observer.h"
#include "../hooks/decoder_trace/decoder_trace_observer.h"
#include "../hooks/world_trace/world_trace_observer.h"
#include "../hooks/phase_probe/phase_probe_observer.h"
#include "../hooks/item_gate/item_gate_observer.h"
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
    // The inventory gate observers (ability_gate) and the round-2 gate-trace observers
    // (gate_trace): log-only research instrumentation for the flag-map/veteran-hunt
    // investigation, no gameplay effect. Left uninstalled by default (2026-08-21) - they
    // fire on hot per-tick engine paths and logged 20k+ lines a boot, which was the
    // dominant cost in several multi-second launch stalls once file_sink was on. Re-enable
    // (uncomment both installs) only when actually resuming that investigation.
    // (void)hooks::ability_gate::install();
    // (void)hooks::gate_trace::install();
    // (phase_probe, FINDINGS 20.154/20.155): ACTIVE. Log-only observer on the slice-set
    // transition phase query (0xE22C70). It reads the two bytes that gate a PUBLIC
    // transition's switch-now - [obj+0x2bc] (wants 1) and [obj+0x2c1] (wants 2) - which
    // static analysis cannot resolve: +0x2c1 has no disp32 writer in .text and the
    // predicate behind +0x2bc calls into a non-exported function of our own DLL.
    // Unlike the two observers above this one is SAFE ON A HOT PATH BY CONSTRUCTION: it
    // logs only when the answer tuple CHANGES and stops at 64 lines, so the per-frame
    // cost is one compare. Remove it once the phase question is closed.
    (void)hooks::phase_probe::install();
    // (admission, FINDINGS 20.157): the peer-adoption observer. Its CENSUS half is
    // observation and defaults on; its INJECT half writes live netmgr state and defaults
    // OFF, gated by client.admission_inject. Attaching here is safe either way - with
    // inject off this is a read-only walk on a tick, rate-limited like the phase probe.
    (void)hooks::admission::install();
    // (nat_probe, FINDINGS 20.168): the bdNAT dial-site argument dump. The wedge at
    // setup:orbit is a NAT-traversal retry loop dialing identity-string bytes as
    // sockaddr endpoints; this pass-through on the bdNAT logging shim (0x9E3230) dumps
    // the dial arguments (client object, payload pointer) under SEH so the endpoint
    // array's container is named. Log-only, first 8 calls, no settings switch.
    (void)hooks::nat_probe::install();
    // (profile_harvest, FINDINGS 20.145 + claims/profile-builder.md): harvests a real
    // ~260B profile blob (marker + region A + header + tail) from the registry commit
    // wrapper 0x1417a6040, which carries every piece as an ENTRY argument - including
    // the blob's own expected lookup3 hash, so the dump has an offline oracle. p2(110)
    // showed every group_target row at pc=0 (no profile, nothing to draw) while the
    // fireteam self-row is pc=1, so a real blob exists locally to harvest. Read-only,
    // SEH-guarded, capped, and gated by client.profile_harvest (DEFAULT FALSE).
    (void)hooks::profile_harvest::install();
    // (profile_ingress, FINDINGS 20.174): the RECEIVE side. 0x1417AF360 runs only when a
    // player row carries a profile block, so its firing answers "does one ever arrive"
    // and its arguments carry the decoded bytes. Caller RVA separates the wire apply from
    // the local registry commit. Read-only, SEH-guarded, capped, gated by
    // client.profile_ingress (DEFAULT FALSE). NOTE: 0x1417AF2D0 (region B) is NOT hooked -
    // pdata_bounds proves it is not a function start.
    (void)hooks::profile_ingress::install();
    // (decoder_trace, FINDINGS 20.182 R3): the p2(115) WEDGE BISECTION. The flag-on
    // membership body is delivered and acked but never applied; this traces the decoder
    // 0x14173BFC0 and the apply 0x141781800 entries to name the failing layer. Read-only,
    // pass-through, capped, gated by client.decoder_trace (DEFAULT FALSE).
    (void)hooks::decoder_trace::install();
    // (world_trace, p2(129)): the peer-visibility entity front's instruments. The
    // manifest emitter 0x1417607B0 (live chunk-2 identity column), the entity
    // create/decode 0x141718080 (its return value is the decode verdict), and a
    // one-shot schema-registry dump (player archetype 0x80806AC0 + chunk-8 power
    // key). Read-only, pass-through, capped, gated by client.world_trace
    // (DEFAULT FALSE).
    (void)hooks::world_trace::install();
    // The weapon/armor validation-chain observers (item_gate, FINDINGS 14.23): log-only
    // research instrumentation for the two-bugs front, which CLOSED at 15.9. Left
    // uninstalled by default (2026-08-22) - the "cool path" note above was wrong: it
    // emitted 114,126 of 114,671 client lines in one boot (98.6%), which buried the
    // retail narration and the protocol tape in an 14 MB log. Re-enable (uncomment the
    // install) only when actually resuming that investigation.
    // (void)hooks::item_gate::install();
    // The R1 schema-hash close: log-only observer on the schema-decode entry, so the
    // client's own player-baseline decode prints the real schemaTagHash (the
    // world_population_schema_hash knob value). Internal no-op while externalServer is
    // disabled.
    (void)hooks::schema_capture::install();
    // The join-roster observers (FINDINGS 20.109 option C): five log-only pass-through
    // detours on the host-side join gate (join request, processor, reserve, admit,
    // add-candidates) plus a read-only poll of the join-candidate table count. The
    // candidate-table poll rides this activation's funnel period from retail_log.
    // Prologue bytes are verified before each attach; the group installs only while
    // client.join_roster_observer is true (settings.json, restart to re-arm).
    (void)hooks::join_roster::install();
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
