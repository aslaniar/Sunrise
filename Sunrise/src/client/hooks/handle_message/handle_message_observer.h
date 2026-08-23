#pragma once

namespace sunrise::client::hooks::handle_message {

/**
 * Log-only protocol tape on FUN_140E0F000 ("handle_message_internal",
 * destiny2 + 0xE0F000), the per-type server-push apply dispatcher
 * (entity-combatants.md FINAL R1 / Hook B). Every decoded server push arrives
 * here named, so this hook is the S2-0 acceptance oracle: it emits ONE
 * structured tape row per applied push - direction, named BAP service
 * (protocol_table.h, handbook pp15-17), envelope kind when decodable (pp46-47),
 * session id, size, result, elapsed, account handle, connection label. Rows
 * carry tape=1 for dashboards; the event name stays ev=handle_message for the
 * live tail tooling. Attaches only while client.externalServer.enabled is
 * true, mirroring the package-validator hook. Observe only: the original runs
 * first, unconditionally, with the same arguments.
 */

/** Attaches the observer when the external-server switch is on. */
bool install() noexcept;

/** Detaches the observer and drops its trampoline. */
bool uninstall() noexcept;

/** @return True while the observer is attached. */
bool is_installed() noexcept;

} // namespace sunrise::client::hooks::handle_message
