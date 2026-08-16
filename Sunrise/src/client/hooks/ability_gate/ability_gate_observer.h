/**
 * Log-only observers on the gate-side primitives the inventory campaign watches:
 *
 * 1. FUN_140E06070 (destiny2 + 0xE06070, 31 B): the acquiredFlags byte test —
 *    `FUN_140be1b00() + 0x742C + idx == 2` (bool). Logs the raw RCX/RDX, the result and the
 *    caller. The caller address is the prize: it names the un-analyzed CUI-region function
 *    that drives the ability gate (inventory-l3-delta-encoder.md, the gate claim).
 * 2. FUN_140F2B690 (destiny2 + 0xF2B690, 65 B): the opcode-2100 ability-change emitter
 *    (payload = u32 definition hash, defaults to kNoDefinitionHash). Logs whether it ever
 *    fires and the hash it carries — the negative watch on the "no live caller" finding.
 * 3. FUN_1405308C0 (destiny2 + 0x5308C0, 61 B): the opcode-702 sync serializer — copies the
 *    8-u32 dynamic-state header (u32 0 + two kNoDefinitionHash definition-hash slots + the
 *    post-sync dynamic hashes) into the caller's output buffer. Logs the 8 header u32s the
 *    original just wrote — the definition-slot sampler for the mode-pair diff.
 *
 * All three run the original untouched and only log. They attach in BOTH modes (in-process
 * and external) — the mode-pair diff needs the same instruments on each side. The pass-2
 * lesson holds: no observer dereferences an assumed register shape; the 702 sampler reads
 * only the output buffer the original itself just wrote (a decompile-verified pointer pair).
 */
#pragma once

namespace sunrise::client::hooks::ability_gate {

/** Attaches the three observers in either server mode. */
bool install() noexcept;

/** Detaches all three observers and drops their trampolines. */
bool uninstall() noexcept;

/** @return True while any observer is attached. */
bool is_installed() noexcept;

} // namespace sunrise::client::hooks::ability_gate
