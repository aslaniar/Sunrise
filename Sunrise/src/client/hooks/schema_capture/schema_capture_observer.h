#pragma once

namespace sunrise::client::hooks::schema_capture {

/**
 * Log-only observer on FUN_1404C74D0 (destiny2 + 0x4C74D0), the schema-decode entry
 * point (entity-archetypes.md FINAL F1 layer 2). The client resolves every quantized
 * property stream through this function: param_1 (RCX) is the u32 schemaTagHash whose
 * bucket/row select the archetype's schema tree in the runtime table *DAT_142439C70
 * (bucket = (hash >> 13) & 0x3FF, row = hash & 0x1FFF -- schema-hash-mine.md). The
 * client's own player-baseline decode passes the EXACT combatant-baseline hash, so this
 * hook closes the R1 row question with one log line: the hash it prints IS the value
 * the world_population_schema_hash knob needs (claims/schema-hash-mine.md section 4).
 * Attaches only while client.externalServer.enabled is true, mirroring the
 * package-validator hook. It changes nothing; log-only.
 */

/** Attaches the observer when the external-server switch is on. */
bool install() noexcept;

/** Detaches the observer and drops its trampoline. */
bool uninstall() noexcept;

/** @return True while the observer is attached. */
bool is_installed() noexcept;

} // namespace sunrise::client::hooks::schema_capture
