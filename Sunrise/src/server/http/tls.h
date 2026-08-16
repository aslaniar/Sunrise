#pragma once

// sspi.h refuses to declare the Win32 security entry points without this selector.
#define SECURITY_WIN32

#include <Windows.h>
#include <WinSock2.h>
#include <schannel.h>
#include <security.h>
#include <wincrypt.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace sunrise::server::tls {

/** Largest plaintext payload one TLS record can carry. */
inline constexpr std::size_t kRecordPlaintextCapacity = 16384;
/** Receive window sized for two full TLS records plus handshake slack. */
inline constexpr std::size_t kIoCapacity = 2 * kRecordPlaintextCapacity + 1024;

/**
 * Process-owned SChannel server credentials and their self-signed certificate.
 * The certificate is generated at boot, so no key material ships in the tree.
 */
struct Context {
    CredHandle credentials{};
    PCCERT_CONTEXT certificate{};
    HCRYPTPROV provider{};
    bool active{};
};

/** One TLS connection: the security context and the pending record window. */
struct Connection {
    CtxtHandle context{};
    SOCKET socket{INVALID_SOCKET};
    std::array<std::byte, kIoCapacity> input{};
    std::size_t inputOffset{};
    std::size_t inputSize{};
    bool contextActive{};
    bool established{};
};

/** Generates one self-signed certificate and acquires the inbound credential handle. */
[[nodiscard]] bool initialize(Context& context) noexcept;

/** Releases the credential handle, the certificate, and the key provider. */
void shutdown(Context& context) noexcept;

/**
 * Runs the blocking server TLS handshake over one accepted socket.
 * @param context Process credentials.
 * @param connection Receives the established security context and any buffered record bytes.
 * @param socket Accepted socket. Stays owned by the caller.
 * @return True when the handshake completes and the connection can exchange application data.
 */
[[nodiscard]] bool accept_connection(Context& context,
                                     Connection& connection,
                                     SOCKET socket) noexcept;

/**
 * Reads decrypted application bytes.
 * @param connection Established connection.
 * @param output Caller storage of at least kRecordPlaintextCapacity bytes.
 * @return Bytes copied, 0 for a clean close, or -1 on failure.
 */
[[nodiscard]] std::int64_t read_application(Connection& connection,
                                            std::span<std::byte> output) noexcept;

/** Writes one whole application payload, split across TLS records as needed. */
[[nodiscard]] bool write_application(Connection& connection,
                                     std::span<const std::byte> data) noexcept;

/** Releases one connection's security context. */
void close_connection(Connection& connection) noexcept;

} // namespace sunrise::server::tls
