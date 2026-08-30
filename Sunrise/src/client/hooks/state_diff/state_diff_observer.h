/**
 * STATE DIFF - capture the client's membership replica for the checksum hunt (p2(130)).
 *
 * WHY. The client rejects our membership bodies ("session membership checksum failed,
 * <client_hash> != <our_hash>") chronically, escalating to force-disconnect at peer
 * arrival - the black-screen mechanism. The l9-profile-layout ADDENDUM's 8-byte player-
 * table shift (shipped as session_state_client_base) did NOT reconcile the hash, so the
 * client's 28,768-byte replica differs from our built state in CONTENT we have never
 * seen. This hook captures those bytes.
 *
 * THE SITE. 0x141772100 (fn 0x141772100..0x1417722F8, .pdata START) is the checksum
 * verifier, read from its own body this session:
 *   - rcx = a session-state holder;
 *   - it copies [rcx+8 .. rcx+8+0x7060)  (0x7060 = 28768 = kSessionStateSize EXACTLY)
 *     to a scratch at [rcx+0x7068];
 *   - then hashes the copy with lookup3, initial 0xDEAE2F4E (the immediate sits at
 *     0x141772176, offset 0x76).
 * So [rcx+8] IS the client's replica at compare time.
 *
 * WHAT IT LOGS. Per call: our own lookup3 over the replica (must equal the client's
 * printed hash in the following "checksum failed" line - that pair VALIDATES the
 * capture), the holder pointer, and the original's return (pass/fail). The first two
 * calls additionally dump the replica in full (28768 B = 113 lines of 0x100 B).
 * Desk-side then byte-diffs the validated dump against build_session_state for the
 * body whose sent hash equals the line's expected value.
 *
 * SAFETY. Pass-through, log-only, reads SEH-guarded, streams capped. Gated by
 * `state_diff`, DEFAULT FALSE.
 */
#pragma once

namespace sunrise::client::hooks::state_diff {

/** Attaches the checksum-verifier detour. No-op unless `state_diff` is set. */
bool install() noexcept;

/** Detaches it. */
bool uninstall() noexcept;

/** @return True while the detour is attached. */
bool is_installed() noexcept;

} // namespace sunrise::client::hooks::state_diff
