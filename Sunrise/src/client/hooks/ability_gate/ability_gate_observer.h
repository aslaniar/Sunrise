/**
 * Log-only observers on the two gate-side primitives the inventory campaign watches:
 *
 * 1. FUN_140E06070 (destiny2 + 0xE06070, 31 B): the acquiredFlags byte test —
 *    `FUN_140be1b00() + 0x742C + idx == 2` (bool). Logs {idx, byte, result, caller}.
 *    The caller address is the prize: it names the un-analyzed CUI-region function
 *    that drives the ability gate (inventory-l3-delta-encoder.md, the gate claim).
 * 2. FUN_140F2B690 (destiny2 + 0xF2B690, 65 B): the opcode-2100 ability-change emitter
 *    (payload = u32 definition hash, defaults to kNoDefinitionHash). Logs whether it ever
 *    fires and the hash it carries — the negative watch on the "no live caller" finding.
 *
 * Both run the original untouched and only log. Attach only while
 * client.externalServer.enabled is true (the handle_message pattern).
 */
#pragma once

namespace sunrise::client::hooks::ability_gate {

/** Attaches both observers when the external-server switch is on. */
bool install() noexcept;

/** Detaches both observers and drops their trampolines. */
bool uninstall() noexcept;

/** @return True while either observer is attached. */
bool is_installed() noexcept;

} // namespace sunrise::client::hooks::ability_gate
