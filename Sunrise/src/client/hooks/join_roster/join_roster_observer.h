#pragma once

namespace sunrise::client::hooks::join_roster {

/**
 * Log-only observers on the host-side join gate (FINDINGS 20.108/20.109 option C).
 *
 * Five pass-through detours, each one per-tick-or-per-message checkpoint between
 * "a machine asks to join" and "the peer reaches the roster's candidate array":
 *
 *   join_request    +0x16E0460  inbound connection-layer type 0x0A handler
 *   join_process    +0x17806C0  join-request processor (candidate-table feeder)
 *   reserve         +0x17692E0  machine registration (the reservation gate)
 *   admit           +0x1777EC0  member record fill (host-side accept)
 *   add_candidates  +0x1792080  the sustained writer of session candidates +0xC8
 *
 * Every body calls the original and passes its return through unchanged; the only
 * side effect is a rate-limited log line. Callers of all five are censused
 * (20.109): E8/jmp reachability is fully enumerated, no function-pointer refs.
 * Installs only while client.join_roster_observer is true (settings.json, restart
 * to re-arm). Prologue bytes are verified before each attach; a mismatch fails
 * loud and attaches nothing.
 */

/** Attaches all five observers when the settings switch allows it. */
bool install() noexcept;

/** Detaches every observer and drops the trampolines. */
bool uninstall() noexcept;

/** @return True while every observer is attached. */
bool is_installed() noexcept;

/**
 * Read-only poll of the join-candidate table count (global +0x1431E1118).
 * Emits one line per CHANGE of the count, so silence means it stayed zero.
 * No-op until install() has resolved the game image base. Called from the
 * retail-log observer's periodic re-assert block (a game thread, every 2 s).
 */
void poll_candidate_table() noexcept;

} // namespace sunrise::client::hooks::join_roster
