#pragma once

namespace sunrise::server::admin {

/**
 * Starts the loopback admin HTTP listener (the Layer-2 surface): the read verbs
 * (/state, /ladder, /flags, /journal) and the write verbs (/suppress, /restore,
 * /restamp, /repush), every write journaled.
 * @return True when the listener thread starts.
 */
[[nodiscard]] bool initialize() noexcept;

/** Stops the admin listener and joins its thread. */
void shutdown() noexcept;

} // namespace sunrise::server::admin
