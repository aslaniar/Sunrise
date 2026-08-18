/**
 * Log-only observers on the round-2 gate-trace surface (the flag-map campaign's runtime
 * foundation). Every detour calls the original first, then logs one line — nothing is
 * changed, so the hooks are safe on every path. The pass-2 lesson holds: no observer
 * dereferences an assumed register shape; only decompile-verified entry ABIs are read.
 *
 * 1. FUN_140E06090 (destiny2 + 0xE06090, 31 B): the character-object acquiredFlags byte
 *    test — `FUN_140be1cb0() + 0x9348 + idx == 2` (bool). The sibling of the ability_gate
 *    observer's FUN_140E06070 (the account bank). Logs the raw RCX/RDX, the result and the
 *    caller — the character bank's per-index read census (the orbit/guided-state gate's
 *    family) with the caller RVAs that name the CUI-region readers.
 * 2. FUN_140E078F0 (destiny2 + 0xE078F0, 505 B): the family-4 kind-0 diff-apply — THE
 *    ROLLBACK EXECUTOR (`void(longlong desired, longlong store)`, the consumer-trace's
 *    named decision point). Logs the raw record pointers + the caller: a marker line per
 *    diff-apply fire — the swap-window anchor (every push's apply is stamped).
 * 3. FUN_140FA8FD0 (destiny2 + 0xFA8FD0, 235 B): the acquire-flag writer
 *    (`void(char* record, short itemIndex, uint32 value)`) — matches the item index
 *    against the UI's equipped/featured selections and sets the acquire flag. Logs the
 *    raw record pointer, the item index (RDX lo16, decompile-verified), the value, and
 *    the caller — the swap's per-item gate-check footprint.
 *
 * All three attach in BOTH modes (in-process and external), like the ability_gate family.
 */
#pragma once

namespace sunrise::client::hooks::gate_trace {

/** Attaches the three observers in either server mode. */
bool install() noexcept;

/** Detaches all three observers and drops their trampolines. */
bool uninstall() noexcept;

/** @return True while any observer is attached. */
bool is_installed() noexcept;

} // namespace sunrise::client::hooks::gate_trace
