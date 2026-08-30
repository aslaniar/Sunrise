/**
 * DECODER TRACE - the bisection instrument for the p2(115) wedge (FINDINGS 20.178-20.182).
 *
 * WHY. With publish_player_profile on, the server's membership body is DELIVERED and
 * ACKED (20.182 R1: sendqueue cleared lines follow every enqueue) but the player row
 * never materializes: pc stays 0, no ingress apply ever fires from the wire. The body
 * dies somewhere between delivery and the apply's helper call - and the remaining
 * suspects are the DISPATCH GATE (0x1416E0460: a 16-bit compare, a session lookup, a
 * stage range 6..9), the DECODER itself (0x14173BFC0), and the apply's own entry.
 *
 * WHAT THIS HOOKS - two entry points, entry-log only, pass-through:
 *     0x14173BFC0  the wire->delta DECODER (id-30 handler +0x28; FINDINGS 20.176 R2)
 *     0x141781800  the APPLY (delta->state; l9-profile-layout CLAIM 1)
 * Three log shapes fully bisect the space:
 *     decoder never logged                      -> the dispatch/gate refuses upstream
 *     decoder logged, apply never logged        -> the decode fails or the pipeline
 *                                                  between them drops the update
 *     both logged, helper (profile_ingress)     -> the apply ran but its row loop saw
 *        silent                                    gate=0 or a different struct - the
 *                                                  three-structure selector diverged
 * The struct POINTER each call carries (r8 for the decoder, r8 for the apply) correlates
 * the two: if the apply's struct differs from the decoder's, the selector picked another
 * copy, and the decoder's work was applied to the wrong buffer or none.
 *
 * ARGUMENT MAP (decoder head 0x14173BFC0: r14=r8 struct base, rbx=rcx reader, first
 * read_wide 64 bits -> [struct+0]; apply head 0x141781800: rdi=rcx object, r15=rdx,
 * rbx=r8 struct selector input):
 *     decoder: rcx = reader        rdx = unknown (overwritten early)  r8 = struct
 *     apply:   rcx = state object  rdx = unknown                      r8 = struct in
 *
 * SAFETY. Pass-through detours, log-only, no writes, no dereference beyond the pointer
 * VALUES logged. Capped at 16 reports each (counters keep the rate visible). Gated by
 * `decoder_trace`, DEFAULT FALSE.
 */
#pragma once

namespace sunrise::client::hooks::decoder_trace {

/** Attaches both trace detours. No-op unless `decoder_trace` is set. */
bool install() noexcept;

/** Detaches both. */
bool uninstall() noexcept;

/** @return True while both detours are attached. */
bool is_installed() noexcept;

} // namespace sunrise::client::hooks::decoder_trace
