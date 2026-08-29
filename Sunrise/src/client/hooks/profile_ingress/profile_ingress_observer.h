/**
 * PROFILE INGRESS - the receive side of the appearance question (FINDINGS 20.173/20.174).
 *
 * WHY. p2(110) proved the whole networking chain works; the only thing missing is the
 * profile block. Our server hardcodes `kPlayerProfileAbsent = 0`, so every
 * group_target row is `pc=0`. Before writing an encoder we must know (a) whether a
 * profile block EVER reaches this client from any source, and (b) what the decoded
 * bytes look like, because the wire->delta DECODER was never located (l9-profile-layout
 * OPEN ITEMS) and guessing the encoding is the error class that lane exists to prevent.
 *
 * WHERE, AND WHY THIS EXACT ADDRESS.
 * The apply 0x141781800 gates BOTH profile helpers behind one flag:
 *     0x14178241b  cmp byte [rbx+0x19], 0     ; rbx = delta+8, so delta+0x21
 *     0x14178241f  je  <skip both>
 *     0x141782458  call 0x1417af360           ; region A + both headers + tail
 *     0x141782469  call 0x1417af2d0           ; region B
 * So 0x1417af360 runs ONLY when a profile is actually present, from ANY path - the
 * wire apply AND the local registry commit (0x1417a6040 calls it too). Its firing is
 * therefore the direct answer to (a), and its arguments are the answer to (b).
 *
 * ARGUMENT MAP, verified from the call site at 0x141782450 and from the frame
 * arithmetic (8 pushes + `lea rbp,[rsp-0x758]` puts arg5 at rbp+0x7c0):
 *     rcx = state object      rdx = player index
 *     r8d = header1 (delta+0x24)      r9d = header2 / "+28 marker" (delta+0x28)
 *     arg5 = mask (0x1FF from the wire path = all 9 sub-chunks)
 *     arg6 = REGION A source, 232B    arg7 = verify flag    arg8 = expected hash
 *     arg9 = TAIL source, 20B
 * REGION B is NOT an argument here - the apply passes it separately to 0x1417af2d0,
 * which `pdata_bounds` proves is NOT a function start (it sits in a .pdata gap and
 * chains to 0x1417AE4B0). Detouring it would repeat p2(112)'s mistake as a
 * MID-FUNCTION patch, so it is deliberately NOT hooked. On the wire path region B is
 * at delta+0x118 and region A at delta+0x30, so it is reachable as regionA + 0xE8;
 * that arithmetic holds ONLY for the wire caller, which is why every line carries the
 * caller RVA (LESSONS 18c) and region B is labelled by it rather than trusted blindly.
 *
 * WHAT THIS SETTLES BESIDES (a)/(b): the wire path passes verify=0 and a dummy hash
 * (0xFFFFFFFF), and 0x1417af6d3 `je` skips the ENTIRE lookup3 when verify==0 - so an
 * authored block needs no correct hash. Logging arg7/arg8 confirms that at runtime
 * instead of on my reading alone.
 *
 * SAFETY. Pass-through detour, log-only, no writes. Only two pointers are dereferenced
 * (region A and tail, plus regionA+0xE8) and all under SEH. Dumps are 64-byte chunks so
 * no line can overrun the log, capped, and every call is counted so the true rate stays
 * visible past the cap. Gated by `profile_ingress`, DEFAULT FALSE.
 */
#pragma once

namespace sunrise::client::hooks::profile_ingress {

/** Attaches the profile-apply observer. No-op unless `profile_ingress` is set. */
bool install() noexcept;

/** Detaches the observer. */
bool uninstall() noexcept;

/** @return True while the observer is attached. */
bool is_installed() noexcept;

} // namespace sunrise::client::hooks::profile_ingress
