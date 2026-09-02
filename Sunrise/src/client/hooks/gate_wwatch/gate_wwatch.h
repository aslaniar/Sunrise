#pragma once

#include <cstdint>

namespace sunrise::client::hooks::gate_wwatch {

/**
 * THE cond5 WIRE-WATCH (20.251 follow-up). The construction gate's blocker is bit 4 of
 * participant record+0x38; static analysis is exhausted (20.246) and 20.251 proved the
 * cond5-gated receiver is the REQUIRED path to a rendered peer. This instrument watches
 * the gate bytes with HARDWARE debug registers (DR0-3, write-only, exact) - not detours:
 * nothing in the game is patched, nothing is dereferenced that the game itself does not
 * already dereference, and every capture path is lock-free, so the worst the instrument
 * can do is miss an event, never change the game's behaviour.
 *
 * install() adds a first-chance vectored exception handler and starts one watchdog
 * thread. arm_table() is called from the ptable probe (which already runs per lifecycle
 * tick and has proven, guarded reads) the moment a participant table with a resolved
 * self/peer split is seen - the watch addresses are computed, never dereferenced, there.
 */
bool install() noexcept;

/**
 * Arm (or re-arm) the record watches for one participant table. Called on every ptable
 * probe invocation; the fast path is two atomic loads. selfIdx/peerIdx come from the
 * same maskB walk 0x1404DD640 performs; peerIdx < 0 means solo (only self present).
 */
void arm_table(std::uintptr_t table, int selfIdx, int peerIdx) noexcept;

} // namespace sunrise::client::hooks::gate_wwatch
