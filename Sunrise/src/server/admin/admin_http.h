#pragma once

namespace sunrise::server::admin {

/**
 * Starts the admin HTTP listener (the Layer-2 surface): the read verbs
 * (/state, /ladder, /flags, /journal, /events, and the dashboard at /) and
 * the write verbs (/suppress, /restore, /restamp, /repush), every write
 * journaled. The listener binds the configured server.bind_address (loopback
 * by default) on port 8099; the worker thread carries an 8 MiB stack for the
 * events route's ~4 MiB value-owned snapshot.
 * @return True when the listener thread starts.
 */
[[nodiscard]] bool initialize() noexcept;

/** Stops the admin listener and joins its thread. */
void shutdown() noexcept;

} // namespace sunrise::server::admin
