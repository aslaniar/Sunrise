/**
 * PROFILE HARVEST (FINDINGS 20.145 + claims/profile-builder.md CLAIM 2/4).
 *
 * WHY. p2(110) proved the whole networking chain is finished: both clients reach
 * `[AC PUBLIC TARGET CON-Y EST-Y AH->9eaa300100200003 MEM-5]`, hold `peers 0x7 /
 * players 0x3` at real endpoints, and land in one instance. What is missing is the
 * APPEARANCE: in the shared `group_target` session EVERY row reports `pc=0` - host,
 * peer, and the local player alike - while the fireteam self-row reports `pc=1`.
 * `pc` is the profile-present flag (20.145). No profile, no body to draw.
 *
 * The blob is opaque and self-hashed, so it must be REPLAYED, never synthesized
 * (20.145). This observer harvests a real one. IT WRITES NOTHING.
 *
 * WHERE, AND WHY NOT THE OTHER TWO ANCHORS.
 *  - The apply 0x141781800 (L9's anchor) holds all 396B, but PHASE 5 established
 *    region B is written ONLY from a WIRE delta and PHASE 6 established no profile
 *    is ever on our wire (the fork publishes kPlayerProfileAbsent=0). Hooking the
 *    apply would capture nothing in this topology.
 *  - The registry committer 0x1417664C0 (CLAIM 4's anchor) is correct in principle,
 *    but its entry base settles in r15 only at 0x141766502, AFTER an obfuscated
 *    singleton call (0x14174f4d0). Reading it needs either a mid-function detour or
 *    calling that accessor ourselves - the p2(99) class of risk, declined.
 *  - THIS ANCHOR, 0x1417a6040 (the decision/apply wrapper it calls), receives every
 *    piece as an ordinary argument at ENTRY, verified from the call site at
 *    0x14176681a:
 *        rcx = this,  edx = index,  r8d = header(4B),  r9d = "+28" marker(4B),
 *        arg5 [rsp+0x20] = mask,        arg6 [rsp+0x28] = region A (232B) pointer,
 *        arg7 [rsp+0x30] = valid flag,  arg8 [rsp+0x38] = expected lookup3 hash,
 *        arg9 [rsp+0x40] = tail (20B) pointer.
 *    That is the full 260B window (marker 4 + region A 232 + header 4 + tail 20)
 *    with NO obfuscated call and NO mid-function patch - plus arg8, which is the
 *    blob's own expected hash and therefore an ORACLE the dump can be checked against
 *    offline (lookup3, init 0xdeadbfd6).
 *
 * HONEST LIMIT (do not overstate the harvest): this yields 260 of the 396 bytes.
 * Region B (136B) is wire-fed only; its local assembly point was NOT found in the
 * PROFILE-BUILDER lane's budget (raw PHASE 5/7, OPEN). A replay needing region B is
 * NOT unblocked by this boot.
 *
 * SAFETY. Pass-through detour, log-only, no writes of any kind. Only two pointers are
 * dereferenced (region A, tail) and both under SEH. Dumps are emitted in 64-byte
 * chunks so no line can overrun the log capacity, and are capped; every call is
 * counted so the true call rate is visible even after the cap. Gated by the client
 * setting `profile_harvest`, DEFAULT FALSE - it ships disarmed and arms with no
 * rebuild, and disarms the same way if it misbehaves.
 */
#pragma once

namespace sunrise::client::hooks::profile_harvest {

/** Attaches the profile-commit argument harvest. No-op unless `profile_harvest` is set. */
bool install() noexcept;

/** Detaches the observer. */
bool uninstall() noexcept;

/** @return True while the observer is attached. */
bool is_installed() noexcept;

} // namespace sunrise::client::hooks::profile_harvest
