#pragma once

#include <string_view>

namespace sunrise::server::https {

/**
 * Starts the HTTPS listener thread on the configured loopback port.
 * The SignOn POST and the config-manifest GET share one SChannel listener.
 * @return True when the TLS credentials, the bind, and the worker thread are ready.
 */
[[nodiscard]] bool initialize() noexcept;

/** Stops the worker thread and releases every socket and credential. */
void shutdown() noexcept;

/** @return True when the text is a canonical ContentConfig fetch id. */
[[nodiscard]] bool valid_config_guid(std::string_view guid) noexcept;

} // namespace sunrise::server::https
