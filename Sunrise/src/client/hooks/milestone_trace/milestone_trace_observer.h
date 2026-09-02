#pragma once

namespace sunrise::client::hooks::milestone_trace {

/**
 * THE MILESTONE TRACER - a table-driven census of the entity/render path.
 *
 * Built because one-off hooks kept costing whole boots to answer one question and then
 * dying (p2(130) hooked a verifier that never runs; p2(136) hooked a create that never
 * runs). This traces EVERY function on the path in one pass, and - the part that matters -
 * a heartbeat thread prints the call count of every hook every few seconds INCLUDING THE
 * ZEROS. A function that never fires says so out loud instead of leaving an ambiguous
 * silence, which is the failure mode that made two boots unreadable.
 *
 * Each hook logs its CALLER's return address, which is what actually names an unknown
 * dispatch: the entity receive chain has no static references anywhere in the image
 * (FINDINGS 20.209), so the only way to learn who invokes it is to ask at runtime.
 *
 * Adding a function later is one line in kTargets.
 * Gated by client.milestone_trace (DEFAULT FALSE).
 */
[[nodiscard]] bool install() noexcept;

/** Removes every installed detour. */
[[nodiscard]] bool uninstall() noexcept;

/** @return True when at least one detour is attached. */
[[nodiscard]] bool is_installed() noexcept;

} // namespace sunrise::client::hooks::milestone_trace
