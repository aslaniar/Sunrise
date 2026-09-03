#pragma once

namespace sunrise::middleware::bap::activity_message::sensor_auth_update {

/**
 * The peer-participation encoder test: the W1 off-path must stay bit-identical to the
 * pre-peer encoder, and the on-path must carry the local key, then the peer's, one whole
 * object block apart (FINDINGS 20.269 R5, the NST gate before any deploy).
 * Needs no state, no settings and no network: safe to run before any startup stage.
 * @return Zero when every assertion holds; one otherwise, with the failure printed.
 */
int run_sensor_auth_peer_test() noexcept;

} // namespace sunrise::middleware::bap::activity_message::sensor_auth_update
