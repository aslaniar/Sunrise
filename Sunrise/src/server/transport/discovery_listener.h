#pragma once

namespace sunrise::server::transport::discovery {

/**
 * Starts the loopback UDP discovery listener thread on ports 3074 and 3075.
 * In external-server mode the game disables its in-process discovery responder
 * (egress_discovery_responder.cpp:158-161) and expects the external server to own the
 * bdNet listener; this standalone listener answers the same NatProbe / IpDiscovery
 * datagrams the client-side responder would have answered in-process.
 * @return True when both sockets are bound and the worker thread is running.
 */
[[nodiscard]] bool initialize() noexcept;

/** Stops the worker thread and closes every discovery socket. */
void shutdown() noexcept;

} // namespace sunrise::server::transport::discovery
