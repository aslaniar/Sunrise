#include "tls.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <limits>

#include "../../core/logging/log.h"

namespace sunrise::server::tls {
namespace {

/** Per-user key container that owns the self-signed server key. */
constexpr wchar_t kKeyContainerName[] = L"SunriseStandaloneServer";
/** The subject names the address the Client always connects to. */
constexpr wchar_t kCertificateSubject[] = L"CN=127.0.0.1";
/** Server-authentication usage satisfies every TLS client stack. */
constexpr char kServerAuthenticationOid[] = szOID_PKIX_KP_SERVER_AUTH;
/**
 * Success-severity handshake status the SDK no longer names: one more record fragment is
 * required before the security package can continue. Documented value 0x00090313.
 */
constexpr SECURITY_STATUS kIncompleteMessage = static_cast<SECURITY_STATUS>(0x00090313L);

/**
 * Sends one whole payload, retrying short sends until it is fully written.
 * @param socket Blocking socket.
 * @param bytes Remaining payload.
 * @return True when every byte is sent.
 */
[[nodiscard]] bool send_all(SOCKET socket, const std::byte* bytes, std::size_t size) noexcept {
    while (size != 0) {
        const int chunk = static_cast<int>(
            (std::min)(size, static_cast<std::size_t>((std::numeric_limits<int>::max)())));
        const int sent = send(socket, reinterpret_cast<const char*>(bytes), chunk, 0);
        if (sent <= 0) {
            return false;
        }
        bytes += sent;
        size -= static_cast<std::size_t>(sent);
    }
    return true;
}

/**
 * Fetches more TLS bytes into the connection window.
 * @param connection Connection with a full unread region.
 * @return 1 with new bytes, 0 at a clean close, or -1 on failure.
 */
[[nodiscard]] int fetch_bytes(Connection& connection) noexcept {
    if (connection.inputOffset != 0) {
        if (connection.inputOffset != connection.inputSize) {
            std::memmove(connection.input.data(),
                         connection.input.data() + connection.inputOffset,
                         connection.inputSize - connection.inputOffset);
        }
        connection.inputSize -= connection.inputOffset;
        connection.inputOffset = 0;
    }
    if (connection.inputSize == connection.input.size()) {
        return -1;
    }
    const int received =
        recv(connection.socket,
             reinterpret_cast<char*>(connection.input.data() + connection.inputSize),
             static_cast<int>(connection.input.size() - connection.inputSize),
             0);
    if (received > 0) {
        connection.inputSize += static_cast<std::size_t>(received);
        return 1;
    }
    return received == 0 ? 0 : -1;
}

} // namespace

/** Generates one self-signed certificate and acquires the inbound credential handle. */
bool initialize(Context& context) noexcept {
    // The key container is per-user, so booting the listener needs no elevation.
    HCRYPTPROV provider = 0;
    if (!CryptAcquireContextW(&provider, kKeyContainerName, nullptr, PROV_RSA_FULL, CRYPT_NEWKEYSET)) {
        if (GetLastError() != NTE_EXISTS
            || !CryptAcquireContextW(&provider, kKeyContainerName, nullptr, PROV_RSA_FULL, 0)) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::error,
                             "ev=https stage=tls result=fail reason=provider");
            return false;
        }
    }
    HCRYPTKEY key = 0;
    if (!CryptGenKey(provider, AT_SIGNATURE, CRYPT_EXPORTABLE, &key)) {
        CryptReleaseContext(provider, 0);
        core::log::write(core::log::Channel::server,
                         core::log::Level::error,
                         "ev=https stage=tls result=fail reason=key");
        return false;
    }

    std::array<BYTE, 512> encodedSubject{};
    DWORD encodedSubjectSize = static_cast<DWORD>(encodedSubject.size());
    if (CertStrToNameW(X509_ASN_ENCODING,
                       kCertificateSubject,
                       CERT_X500_NAME_STR,
                       nullptr,
                       encodedSubject.data(),
                       &encodedSubjectSize,
                       nullptr)
        == FALSE) {
        CryptReleaseContext(provider, 0);
        core::log::write(core::log::Channel::server,
                         core::log::Level::error,
                         "ev=https stage=tls result=fail reason=subject");
        return false;
    }
    CERT_NAME_BLOB subject{encodedSubjectSize, encodedSubject.data()};

    std::array<BYTE, 128> encodedUsage{};
    DWORD encodedUsageSize = static_cast<DWORD>(encodedUsage.size());
    LPSTR usageIdentifiers[]{const_cast<LPSTR>(kServerAuthenticationOid)};
    const CERT_ENHKEY_USAGE usage{1, usageIdentifiers};
    if (CryptEncodeObject(X509_ASN_ENCODING,
                          X509_ENHANCED_KEY_USAGE,
                          &usage,
                          encodedUsage.data(),
                          &encodedUsageSize)
        == FALSE) {
        CryptReleaseContext(provider, 0);
        core::log::write(core::log::Channel::server,
                         core::log::Level::error,
                         "ev=https stage=tls result=fail reason=usage");
        return false;
    }
    CERT_EXTENSION extension{
        const_cast<char*>(szOID_ENHANCED_KEY_USAGE), FALSE, {encodedUsageSize, encodedUsage.data()}};
    CERT_EXTENSIONS extensions{1, &extension};

    PCCERT_CONTEXT certificate = CertCreateSelfSignCertificate(provider,
                                                               &subject,
                                                               0,
                                                               nullptr,
                                                               nullptr,
                                                               nullptr,
                                                               nullptr,
                                                               &extensions);
    if (certificate == nullptr) {
        CryptReleaseContext(provider, 0);
        core::log::write(core::log::Channel::server,
                         core::log::Level::error,
                         "ev=https stage=tls result=fail reason=cert");
        return false;
    }

    SCHANNEL_CRED credential{};
    credential.dwVersion = SCHANNEL_CRED_VERSION;
    credential.cCreds = 1;
    credential.paCred = &certificate;
    // Old curl builds may only speak TLS 1.0, so the whole server range is offered.
    credential.grbitEnabledProtocols =
        SP_PROT_TLS1_0_SERVER | SP_PROT_TLS1_1_SERVER | SP_PROT_TLS1_2_SERVER;
    credential.dwFlags = SCH_CRED_NO_DEFAULT_CREDS;
    const SECURITY_STATUS status =
        AcquireCredentialsHandleW(nullptr,
                                  const_cast<SEC_WCHAR*>(UNISP_NAME_W),
                                  SECPKG_CRED_INBOUND,
                                  nullptr,
                                  &credential,
                                  nullptr,
                                  nullptr,
                                  &context.credentials,
                                  nullptr);
    if (status != SEC_E_OK) {
        CertFreeCertificateContext(certificate);
        CryptReleaseContext(provider, 0);
        core::log::write(core::log::Channel::server,
                         core::log::Level::error,
                         "ev=https stage=tls result=fail reason=credentials");
        return false;
    }
    context.certificate = certificate;
    context.provider = provider;
    context.active = true;
    return true;
}

/** Releases the credential handle, the certificate, and the key provider. */
void shutdown(Context& context) noexcept {
    if (context.active) {
        FreeCredentialsHandle(&context.credentials);
        context.active = false;
    }
    if (context.certificate != nullptr) {
        CertFreeCertificateContext(context.certificate);
        context.certificate = nullptr;
    }
    if (context.provider != 0) {
        CryptReleaseContext(context.provider, 0);
        context.provider = 0;
    }
}

/** Runs the blocking server TLS handshake over one accepted socket. */
bool accept_connection(Context& context, Connection& connection, SOCKET socket) noexcept {
    connection = {};
    connection.socket = socket;
    for (;;) {
        if (connection.inputOffset == connection.inputSize && fetch_bytes(connection) <= 0) {
            return false;
        }
        SecBuffer inputBuffer{};
        inputBuffer.BufferType = SECBUFFER_TOKEN;
        inputBuffer.pvBuffer = connection.input.data() + connection.inputOffset;
        inputBuffer.cbBuffer =
            static_cast<ULONG>(connection.inputSize - connection.inputOffset);
        SecBufferDesc inputDesc{SECBUFFER_VERSION, 1, &inputBuffer};

        std::array<std::byte, kIoCapacity> output{};
        SecBuffer outputBuffer{};
        outputBuffer.BufferType = SECBUFFER_TOKEN;
        outputBuffer.pvBuffer = output.data();
        outputBuffer.cbBuffer = static_cast<ULONG>(output.size());
        SecBufferDesc outputDesc{SECBUFFER_VERSION, 1, &outputBuffer};

        ULONG attributes = 0;
        SECURITY_STATUS status = kIncompleteMessage;
        if (!connection.contextActive) {
            // The caller provides the token storage, so SChannel must not allocate its own.
            status = AcceptSecurityContext(&context.credentials,
                                           nullptr,
                                           &inputDesc,
                                           ASC_REQ_STREAM,
                                           0,
                                           &connection.context,
                                           &outputDesc,
                                           &attributes,
                                           nullptr);
            connection.contextActive = status != kIncompleteMessage;
        } else {
            status = AcceptSecurityContext(&context.credentials,
                                           &connection.context,
                                           &inputDesc,
                                           ASC_REQ_STREAM,
                                           0,
                                           nullptr,
                                           &outputDesc,
                                           &attributes,
                                           nullptr);
        }
        if (outputBuffer.cbBuffer != 0
            && !send_all(socket, output.data(), static_cast<std::size_t>(outputBuffer.cbBuffer))) {
            return false;
        }
        if (status == kIncompleteMessage) {
            // Nothing was consumed; one more TLS record fragment is needed.
            if (fetch_bytes(connection) <= 0) {
                return false;
            }
            continue;
        }
        if (status == SEC_E_OK || status == SEC_I_CONTINUE_NEEDED) {
            // The token input reports exactly the bytes the handshake consumed.
            connection.inputOffset += static_cast<std::size_t>(inputBuffer.cbBuffer);
        }
        if (status == SEC_E_OK) {
            connection.established = true;
            return true;
        }
        if (status == SEC_I_CONTINUE_NEEDED) {
            continue;
        }
        return false;
    }
}

/** Reads decrypted application bytes. */
std::int64_t read_application(Connection& connection, std::span<std::byte> output) noexcept {
    if (output.size() < kRecordPlaintextCapacity) {
        return -1;
    }
    for (;;) {
        if (connection.inputOffset == connection.inputSize) {
            const int fetched = fetch_bytes(connection);
            if (fetched <= 0) {
                return fetched;
            }
        }
        std::array<SecBuffer, 4> buffers{};
        buffers[0].BufferType = SECBUFFER_DATA;
        buffers[0].pvBuffer = connection.input.data() + connection.inputOffset;
        buffers[0].cbBuffer =
            static_cast<ULONG>(connection.inputSize - connection.inputOffset);
        SecBufferDesc descriptor{
            SECBUFFER_VERSION, static_cast<ULONG>(buffers.size()), buffers.data()};
        const SECURITY_STATUS status = DecryptMessage(&connection.context, &descriptor, 0, nullptr);
        if (status == SEC_E_INCOMPLETE_MESSAGE) {
            const int fetched = fetch_bytes(connection);
            if (fetched <= 0) {
                return fetched;
            }
            continue;
        }
        if (status == SEC_I_CONTEXT_EXPIRED) {
            connection.inputOffset = connection.inputSize;
            return 0;
        }
        if (status != SEC_E_OK) {
            return -1;
        }
        const SecBuffer* data = nullptr;
        const SecBuffer* extra = nullptr;
        for (const SecBuffer& buffer : buffers) {
            if (buffer.BufferType == SECBUFFER_DATA) {
                data = &buffer;
            } else if (buffer.BufferType == SECBUFFER_EXTRA) {
                extra = &buffer;
            }
        }
        if (data == nullptr || data->cbBuffer > output.size()) {
            return -1;
        }
        const std::size_t decrypted = static_cast<std::size_t>(data->cbBuffer);
        if (decrypted != 0) {
            std::memcpy(output.data(), data->pvBuffer, decrypted);
        }
        // Bytes past the consumed record stay buffered for the next call.
        const std::size_t extraBytes =
            extra != nullptr ? static_cast<std::size_t>(extra->cbBuffer) : 0;
        const std::size_t consumed = (connection.inputSize - connection.inputOffset) - extraBytes;
        connection.inputOffset += consumed;
        if (extraBytes != 0) {
            std::memmove(connection.input.data(), extra->pvBuffer, extraBytes);
            connection.inputOffset = 0;
            connection.inputSize = extraBytes;
        } else {
            connection.inputOffset = connection.inputSize;
        }
        if (decrypted != 0) {
            return static_cast<std::int64_t>(decrypted);
        }
        // Empty records carry no application bytes; loop for the next record.
    }
}

/** Writes one whole application payload, split across TLS records as needed. */
bool write_application(Connection& connection, std::span<const std::byte> data) noexcept {
    SecPkgContext_StreamSizes sizes{};
    if (QueryContextAttributes(&connection.context, SECPKG_ATTR_STREAM_SIZES, &sizes) != SEC_E_OK) {
        return false;
    }
    const std::size_t headerSize = static_cast<std::size_t>(sizes.cbHeader);
    const std::size_t trailerSize = static_cast<std::size_t>(sizes.cbTrailer);
    std::array<std::byte, kRecordPlaintextCapacity + 1024> record{};
    while (!data.empty()) {
        const std::size_t chunk = (std::min)(data.size(), kRecordPlaintextCapacity);
        if (headerSize + chunk + trailerSize > record.size()) {
            return false;
        }
        std::memcpy(record.data() + headerSize, data.data(), chunk);

        std::array<SecBuffer, 4> buffers{};
        buffers[0].BufferType = SECBUFFER_STREAM_HEADER;
        buffers[0].pvBuffer = record.data();
        buffers[0].cbBuffer = sizes.cbHeader;
        buffers[1].BufferType = SECBUFFER_DATA;
        buffers[1].pvBuffer = record.data() + headerSize;
        buffers[1].cbBuffer = static_cast<ULONG>(chunk);
        buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
        buffers[2].pvBuffer = record.data() + headerSize + chunk;
        buffers[2].cbBuffer = sizes.cbTrailer;
        buffers[3].BufferType = SECBUFFER_EMPTY;
        buffers[3].pvBuffer = nullptr;
        buffers[3].cbBuffer = 0;
        SecBufferDesc descriptor{
            SECBUFFER_VERSION, static_cast<ULONG>(buffers.size()), buffers.data()};
        if (EncryptMessage(&connection.context, 0, &descriptor, 0) != SEC_E_OK) {
            return false;
        }
        const std::size_t total =
            headerSize + static_cast<std::size_t>(buffers[1].cbBuffer) + trailerSize;
        if (!send_all(connection.socket, record.data(), total)) {
            return false;
        }
        data = data.subspan(chunk);
    }
    return true;
}

/** Releases one connection's security context. */
void close_connection(Connection& connection) noexcept {
    if (connection.contextActive) {
        DeleteSecurityContext(&connection.context);
        connection.contextActive = false;
    }
    connection.established = false;
    connection.inputOffset = 0;
    connection.inputSize = 0;
    connection.socket = INVALID_SOCKET;
}

} // namespace sunrise::server::tls
