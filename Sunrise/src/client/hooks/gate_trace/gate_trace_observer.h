/**
 * Log-only observers on the round-2 gate-trace surface (the flag-map campaign's runtime
 * foundation). Every detour calls the original first, then logs one line — nothing is
 * changed, so the hooks are safe on every path. The pass-2 lesson holds: no observer
 * dereferences an assumed register shape; only decompile-verified entry ABIs are read.
 *
 * The twelve deployed observers (install count=12):
 * 1. FUN_140E06090 (destiny2 + 0xE06090): the character-object acquiredFlags byte test —
 *    `FUN_140be1cb0() + 0x9348 + idx == 2` (bool). The sibling of the ability_gate
 *    observer's FUN_140E06070 (the account bank). The character bank's per-index read
 *    census with the caller RVAs that name the CUI-region readers.
 * 2. FUN_140E078F0 (+0xE078F0): the family-4 kind-0 diff-apply — THE ROLLBACK EXECUTOR
 *    (`void(longlong desired, longlong store)`). A marker line per diff-apply fire.
 * 3. FUN_140FA8FD0 (+0xFA8FD0): the acquire-flag writer (`void(char* record, short
 *    itemIndex, uint32 value)`) — the swap's per-item gate-check footprint.
 * 4. FUN_140BA3E70 (+0xBA3E70): the per-item marker-bit poll (`ulonglong(int*
 *    itemHashRecord)`) — raw pointer, no deref.
 * 5. FUN_1405084C0 (+0x5084C0): the character-level requirement session — the evaluator's
 *    caller names the UI context that triggered an evaluation.
 * 6. FUN_140548D80 (+0x548D80): the session wrapper.
 * 7. FUN_140C8F1C0 (+0xC8F1C0): the shared per-index marker-bit poll primitive — THE
 *    MARKER_POLL surface (the census hook spec's 1.4): every informative marker-bit read
 *    funnels through it, the index in RDX (a register read).
 * 8. FUN_14050F4C0 (+0x50F4C0): the item-service vtable+0x6F8 hash->index resolver —
 *    THE CORRESPONDENCE INSTRUMENT: hash in R8, index written to RDX (0xFFFF = miss).
 * 9. FUN_140548E00 (+0x548E00): the requirement-expression evaluator (7 args; the
 *    completion marker byte at outEval+0x14dfc).
 * 10. FUN_140A42FD0 (+0xA42FD0): the stamp-table flag consume (AL = consumed).
 * 11. FUN_140E82AB0 (+0xE82AB0): the stamp-chain consume gate (the record key in RDX,
 *     logged raw).
 * 12. FUN_140E80FC0 (+0xE80FC0): the 5-byte UI-refresh thunk (the record key in RDX, the
 *     out buffer in R8 — raw, no post-read).
 *
 * All twelve attach in BOTH modes (in-process and external), like the ability_gate family.
 * The expr_vm hook (FUN_140540320) = OPTIONAL and NOT attached by default.
 */
#pragma once

namespace sunrise::client::hooks::gate_trace {

/** Attaches the twelve observers in either server mode. */
bool install() noexcept;

/** Detaches all twelve observers and drops their trampolines. */
bool uninstall() noexcept;

/** @return True while any observer is attached. */
bool is_installed() noexcept;

} // namespace sunrise::client::hooks::gate_trace
