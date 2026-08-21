#include <array>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include "../../../../core/logging/log.h"
#include "internal.h"

namespace sunrise::client::hooks::network::http {
namespace {

/** Operation 2 selects the direct-buffer POST path. */
constexpr std::uint32_t kPostOperation = 2;
/** Returning 5 makes the worker skip the native external operation. */
constexpr std::int64_t kSkipNativeOperation = 5;
/** HTTP 200 with no body finishes a route this server does not map. */
constexpr std::uint32_t kHttpOk = 200;
/** The executor takes a direct response size of at most a signed 32-bit value. */
constexpr std::int64_t kMaximumResponseCapacity = INT_MAX;
/** The descriptor owns a fixed 512-byte inline URL. */
constexpr std::size_t kUrlCapacity = 512;
/** The descriptor owns a fixed 64-byte inline content type. */
constexpr std::size_t kContentTypeCapacity = 64;

/** ABI offset of the executor operation selector. */
constexpr std::size_t kOperationOffset = 0x08;
/** ABI offset of the direct request buffer. */
constexpr std::size_t kRequestBodyOffset = 0x10;
/** ABI offset of the request size in bytes. */
constexpr std::size_t kRequestSizeOffset = 0x18;
/** ABI offset of the direct response buffer. */
constexpr std::size_t kResponseBodyOffset = 0x20;
/** ABI offset of the direct response size, or of the other handler. */
constexpr std::size_t kResponseCapacityOffset = 0x28;
/** ABI offset of the inline request URL. */
constexpr std::size_t kUrlOffset = 0x40;
/** ABI offset of the inline request content type. */
constexpr std::size_t kContentTypeOffset = 0x240;
/** Native executor descriptors are 640 bytes. */
constexpr std::size_t kDescriptorSize = 0x280;
/** The direct-buffer request descriptor the shared HTTP executor reads. */
struct HttpRequestDescriptor final {
    void* result{};
    std::uint32_t operation{};
    std::uint8_t option{};
    std::uint8_t useTls{};
    std::array<std::byte, 2> operationPadding{};
    const void* requestBody{};
    std::uint32_t requestSize{};
    std::array<std::byte, 4> requestSizePadding{};
    void* responseBody{};
    std::int64_t responseCapacity{};
    const void* headers{};
    std::uint32_t headerCount{};
    std::array<std::byte, 4> headerCountPadding{};
    std::array<char, kUrlCapacity> url{};
    std::array<char, kContentTypeCapacity> contentType{};
};

static_assert(offsetof(HttpRequestDescriptor, operation) == kOperationOffset);
static_assert(offsetof(HttpRequestDescriptor, requestBody) == kRequestBodyOffset);
static_assert(offsetof(HttpRequestDescriptor, requestSize) == kRequestSizeOffset);
static_assert(offsetof(HttpRequestDescriptor, responseBody) == kResponseBodyOffset);
static_assert(offsetof(HttpRequestDescriptor, responseCapacity) == kResponseCapacityOffset);
static_assert(offsetof(HttpRequestDescriptor, url) == kUrlOffset);
static_assert(offsetof(HttpRequestDescriptor, contentType) == kContentTypeOffset);
static_assert(sizeof(HttpRequestDescriptor) == kDescriptorSize);

/** @param value Inline fixed-size string. @return Borrowed text, capped at the array size. */
template <std::size_t Capacity>
[[nodiscard]] std::string_view bounded_string(const std::array<char, Capacity>& value) noexcept {
    return {value.data(), strnlen_s(value.data(), value.size())};
}

/** @return True when the descriptor's direct request and response spans are valid. */
[[nodiscard]] bool valid_direct_buffers(const HttpRequestDescriptor& descriptor) noexcept {
    return (descriptor.requestSize == 0 || descriptor.requestBody != nullptr)
           && descriptor.responseCapacity >= 0
           && descriptor.responseCapacity <= kMaximumResponseCapacity
           && (descriptor.responseCapacity == 0 || descriptor.responseBody != nullptr);
}

/**
 * Finishes an unmapped route here with an empty success.
 * @param wrapper Game-owned HTTP wrapper.
 * @return The value that makes the worker skip the external HTTP operation.
 */
[[nodiscard]] std::int64_t unmapped_route(void* wrapper) noexcept {
    core::log::write(
        core::log::Channel::client, core::log::Level::debug, "ev=http stage=route result=unmapped");
    publish_completion(wrapper, 0, kHttpOk);
    return kSkipNativeOperation;
}

} // namespace

/** Routes one game-owned HTTP descriptor without calling the native transport. */
std::int64_t route_descriptor(const coordinator::CallLease& lease,
                              void* wrapperValue,
                              std::byte* descriptorValue) noexcept {
    // Hybrid mode: this executor never opens a TLS socket, in external mode or not. SignOn
    // (and every other route reaching this generic descriptor path) is answered by the same
    // in-process consumer embedded mode uses (http::consume, registered unconditionally by
    // server::initialize()); a route it does not recognize (the SignOn-sourced content GETs)
    // finishes as an unmapped 200-empty below so the Client proceeds on local packages. BAP
    // is the only traffic that still leaves this process, over its own transport.
    if (wrapperValue == nullptr) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::warn,
                         "ev=http stage=wrapper result=blocked");
        return kSkipNativeOperation;
    }

    if (descriptorValue == nullptr) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::warn,
                         "ev=http stage=descriptor result=blocked");
        return block_request(wrapperValue);
    }

    auto& descriptor = *reinterpret_cast<HttpRequestDescriptor*>(descriptorValue);
    if (descriptor.result == nullptr) {
        descriptor.result = discard_result();
        core::log::write(core::log::Channel::client,
                         core::log::Level::warn,
                         "ev=http stage=result result=blocked");
        return block_request(wrapperValue);
    }
    if (!lease.accepting || lease.httpConsumer == nullptr) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::warn,
                         "ev=http stage=consumer result=blocked");
        return block_request(wrapperValue);
    }
    if (!valid_direct_buffers(descriptor)) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::warn,
                         "ev=http stage=buffer result=blocked");
        return block_request(wrapperValue);
    }
    if (descriptor.operation != kPostOperation) {
        return unmapped_route(wrapperValue);
    }

    const auto responseCapacity = static_cast<std::size_t>(descriptor.responseCapacity);
    const sunrise::client::network::HttpRequest request{
        bounded_string(descriptor.url),
        bounded_string(descriptor.contentType),
        {static_cast<const std::byte*>(descriptor.requestBody), descriptor.requestSize},
        {static_cast<std::byte*>(descriptor.responseBody), responseCapacity},
    };
    sunrise::client::network::HttpResponse response;
    if (!lease.httpConsumer(request, response)) {
        return unmapped_route(wrapperValue);
    }
    // The consumer writes into the response span, so the size cannot pass the buffer size.
    publish_completion(
        wrapperValue, static_cast<std::uint32_t>(response.size), response.statusCode);
    return kSkipNativeOperation;
}

} // namespace sunrise::client::hooks::network::http
