#pragma once

namespace sunrise::client::hooks::handle_message {

/**
 * Log-only observer on FUN_140E0F000 ("handle_message_internal", destiny2 + 0xE0F000),
 * the per-type server-push apply dispatcher (entity-combatants.md FINAL R1 / Hook B).
 * Every decoded server push arrives here named, so this hook is the S2-0 acceptance
 * oracle: it prints the message name, wire type, id, payload length and the first
 * payload bytes for every push the client applies. Attaches only while
 * client.externalServer.enabled is true, mirroring the package-validator hook.
 */

/** Attaches the observer when the external-server switch is on. */
bool install() noexcept;

/** Detaches the observer and drops its trampoline. */
bool uninstall() noexcept;

/** @return True while the observer is attached. */
bool is_installed() noexcept;

} // namespace sunrise::client::hooks::handle_message
