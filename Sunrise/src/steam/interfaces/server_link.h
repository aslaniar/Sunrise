#pragma once

#include <cstddef>
#include <string_view>

namespace sunrise::steam::interfaces {

/**
 * One plaintext HTTP/1.1 exchange with the standalone server's admin listener (8099).
 *
 * This is the ONLY way shim code reaches the server. client::network::consume_http does
 * NOT work for this: the one in-process consumer the Client DLL registers answers
 * "/SignOn" and returns false for everything else, so p2(64)'s relay silently dropped
 * every request (FINDINGS 20.99). 8443 is not usable either - its handshake fails with
 * SEC_E_UNSUPPORTED_FUNCTION.
 *
 * CALL THIS FROM A WORKER THREAD ONLY. It blocks on connect/recv.
 *
 * @param verb "GET" or "POST".
 * @param target Absolute path plus query, e.g. "/presence".
 * @param body Response body written here, null terminated. May be null.
 * @param capacity Bytes available at @p body.
 * @return HTTP status code, or zero when the exchange did not complete.
 */
unsigned http_exchange(const char* verb,
                       const char* target,
                       char* body,
                       std::size_t capacity) noexcept;

} // namespace sunrise::steam::interfaces
