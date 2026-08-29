/**
 * Log-only observer on the slice-set transition PHASE query (FINDINGS 20.154/20.155).
 *
 * WHAT IT ANSWERS. Both clients precache PUB56.56 and then never take the
 * slice-set-switch task. fn 0x140E22C70 is the phase query: it returns 4
 * ('switch-now') on three simulator paths and 2 or 3 on its fall-through, and a
 * PUBLIC transition reaches 4 only when BOTH of these hold (0x140e22ff5, and again
 * in the consumer at 0x140e26d8a):
 *     cmp byte [obj + 0x2bc], 1      ; is this a public/shared region?
 *     cmp byte [obj + 0x2c1], 2      ; the second gate
 * Static analysis cannot say which half fails: +0x2c1 has no disp32 writer anywhere
 * in .text, and the predicate behind +0x2bc calls into a NON-EXPORTED function of our
 * own steam_api64.dll (20.155 - which also means the unpacked exe carries our hook
 * bytes at that call site, so it cannot be trusted there). This reads both bytes at
 * runtime instead, and the answer forks cleanly:
 *   +0x2bc != 1              -> the client does not classify PUB56 as public, and the
 *                               deciding predicate is our own code.
 *   +0x2bc == 1, +0x2c1 != 2 -> that byte's real value, against the disc/ctng/cntd
 *                               ladder the region lines already print.
 *
 * HOT-PATH DISCIPLINE (client_hook_activation.cpp's standing warning, earned twice:
 * the ws_wire observer re-triggered the tower stall, and item_gate emitted 98.6% of
 * one boot's lines). A phase query runs per frame while a transition is live, so this
 * observer LOGS ONLY WHEN THE ANSWER CHANGES and stops after a hard line cap. Steady
 * state is: call the original, three guarded byte reads, one 64-bit compare, return.
 * Nothing is formatted and nothing is written on the unchanged path.
 *
 * Changes nothing. The original runs first and its result is returned untouched.
 */
#pragma once

namespace sunrise::client::hooks::phase_probe {

/** Attaches the phase-query observer. */
bool install() noexcept;

/** Detaches the observer and drops its trampoline. */
bool uninstall() noexcept;

/** @return True while the observer is attached. */
bool is_installed() noexcept;

} // namespace sunrise::client::hooks::phase_probe
