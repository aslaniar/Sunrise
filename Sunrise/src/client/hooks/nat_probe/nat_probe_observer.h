/**
 * bdNAT WEDGE PROBE (FINDINGS 20.168): the dial-site argument dump.
 *
 * 20.168 caught the setup:orbit wedge mechanism: ~3 s before the stall the client runs
 * Demonware NAT traversal (bdNATTravClient) and dials SIX INTRO REQs whose "addresses"
 * are ASCII windows (stride exactly 6 = sockaddr-shaped) over the INJECTED PEER IDENTITY
 * STRING "steamid:...#...". The client-internal wait is that retry loop against garbage
 * endpoints: the adopted forged record feeds a connection path that needs the peer's
 * REAL transport endpoint and gets identity-string bytes.
 *
 * p2(107) named the logging shim every bdNAT line emits through: fn 0x1409E3230
 * (950 B; all three funnel targets - "Request timed out", "Public Addr", "sent INTRO
 * REQ" - resolve to the same return address inside it). The shim is a message-type
 * dispatcher that decrypts an obfuscated format string and formats its 4th register
 * argument (r9 -> rdi) as the %s payload; the dialing logic and the endpoint array live
 * in its (indirect) CALLERS, so this probe hooks the SHIM and dumps what arrives:
 *   rcx - the bdNAT client/transport object (candidate array pointer likely inside)
 *   rdx - the message-type selector (1..3)
 *   r8  - unknown; dumped
 *   r9  - the endpoint payload the shim formats (the dial target)
 * Each pointer target is hexdumped 0x80 bytes under SEH; NO argument is dereferenced
 * without the guard. If the identity-string bytes appear inside one of the dumps, the
 * array is found and its container's field offset feeds field_xref next.
 *
 * PRE-ATTACH VERIFICATION (LESSONS 18 corollary 2): the shim reads only its own stack
 * args (deepest = slot 6, rbp+0x260) and its cookie at rbp+0x210 - nothing in the
 * caller's frame beyond the arg area. The pass-through forwards 4 registers + 16 stack
 * slots bit-exact, which covers every caller on record and is harmless for shallower
 * ABIs. Log-only: the first 8 calls dump, later calls only count. The shim fires at
 * NAT-traversal cadence (per-retry), not per-frame, so the cost is negligible.
 */
#pragma once

namespace sunrise::client::hooks::nat_probe {

/** Attaches the dial-site argument dump. */
bool install() noexcept;

/** Detaches the probe. */
bool uninstall() noexcept;

/** @return True while the probe is attached. */
bool is_installed() noexcept;

} // namespace sunrise::client::hooks::nat_probe
