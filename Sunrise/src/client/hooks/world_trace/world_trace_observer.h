/**
 * WORLD TRACE - the peer-visibility entity front's paired instruments (p2(129)).
 *
 * WHY. The Tower guardians live in the ACTIVITY/ENTITY layer (the client's own
 * activity-message names: replicate_membership, allocate/free_entity_indices,
 * client_authoritative_data_update), not in any lobby-layer route - every one of
 * which is closed by measurement (HANDOFF_2026-08-30, hunts 1-3). Three read-only
 * instruments, one hook unit:
 *
 * 1. THE MANIFEST EMITTER, 0x1417607B0 (fn 0x1417607B0..0x1417607E0, .pdata start).
 *    The event-router emit wrapper the roster-change handler 0x140D47D00 feeds with
 *    every player's chunk-2 identity (48-byte records) plus a match flag
 *    (entry+0xe8 byte vs manager+0x2055). ABI (from the 12-instruction body):
 *      rcx = const dword* eventid source, edx = record count,
 *      r8 = records (count x 48B, chunk-2 region: 8-byte id + 40 zero bytes),
 *      r9 = flags (count dwords).
 *    Our server publishes chunk 2 ABSENT, so the peer's record arrives as ZERO - the
 *    live values this logs are what the client computes for its own row, which is
 *    hunt item 1's answer and the prerequisite for authoring the field.
 *    FIRST CALL ALSO FIRES THE SCHEMA DUMP (3), because a session is by then live.
 *
 * 2. THE ENTITY CREATE/DECODE PATH, 0x141718080 (fn 0x141718080..0x1417183B2,
 *    .pdata start). The sobject-creation reader the world-population entity record
 *    lands in (peer-visibility-codec-findings.md "the observer hook the front
 *    actually needs"). Its own RETURN VALUE is the oracle the front lacked:
 *      ret 0 = success, 1/2 = the codec body decode FAILED (vtable+0x60 false),
 *      3 = update-mask walker failure. One detour, no inner hooks.
 *    ABI (lane_sobject_ghidra.txt decompile): rcx = world, rdx = bit reader,
 *    r8 = record out (flags byte at +0x40 pre-set by the caller; codecType lands at
 *    [0], size at +0x2c, streamByte at +0x44, body buffer at +0x30), r9 = unused,
 *    stack[0] = param_5 int.
 *
 * 3. THE SCHEMA-REGISTRY DUMP (one-shot). Walks *DAT_142439C70 with the documented
 *    resolver (character-record-mapping.md CLAIM 2, dialect A) for TWO keys:
 *      - 0x80806AC0, the client's own player archetype (the world_population
 *        entity emission's schema): its true field count and reader types are the
 *        front's riskiest unknown (codec-findings F2).
 *      - the CHUNK-8 schema id, read live as *(int32*)(*(void**)0x14209ED00):
 *        the power chunk's wire form is the one thing the static dump cannot give
 *        (the table is runtime-built; femu confirmed by execution). With this tree
 *        the server-side power writer is derivable offline.
 *    The traversal arithmetic is INFERRED (documented, not re-derived here); every
 *    row/slot/node is ALSO dumped raw, so a traversal slip is recoverable desk-side.
 *
 * SAFETY. All three are pass-through, log-only, no writes through any client
 * pointer; every client-memory read is SEH-guarded; every stream is capped.
 * Gated by `world_trace`, DEFAULT FALSE.
 */
#pragma once

namespace sunrise::client::hooks::world_trace {

/** Attaches all three detours. No-op unless `world_trace` is set. */
bool install() noexcept;

/** Detaches all three. */
bool uninstall() noexcept;

/** @return True while the detours are attached. */
bool is_installed() noexcept;

} // namespace sunrise::client::hooks::world_trace
