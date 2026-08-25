#include "matchmaking_dynamic_response.h"

#include "../../../protobuf/codec.h"
#include "../definition.h"

namespace sunrise::middleware::bap::matchmaking::response {
namespace {

using protobuf::Writer;

/** Field 1 reports that kind 2 assigned an advertisement id. */
constexpr std::uint32_t kAssignmentResultField = 1;
/** Result 2 tells the client to use the nested advertisement id. */
constexpr std::uint64_t kAssignmentResultValue = 2;
/** Assigned and rejoin advertisement ids use service-43 field 5. */
constexpr std::uint32_t kAdvertisementField = 5;
/** Locate-session results use service-43 field 7. */
constexpr std::uint32_t kLocateResultField = 7;
/** Advertisement and locate-result messages carry their id in field 1. */
constexpr std::uint32_t kAdvertisementIdField = 1;
/** Locate-result field 2 wraps the whole descriptor message. */
constexpr std::uint32_t kLocateDescriptorField = 2;
/** Search results live in service-43 field 3, which is a CONTAINER message. */
constexpr std::uint32_t kSearchResultsField = 3;
/** Container field 1 is the repeated SearchResult element (client table cap: 50). */
constexpr std::uint32_t kSearchResultElementField = 1;
/** Element field 6 is the IdPair the client uses to name what a result points at. */
constexpr std::uint32_t kSearchResultIdPairField = 6;
/** IdPair fields 1 and 2, both uint64 varints (client table 0x141C38D40). */
constexpr std::uint32_t kIdPairFirstField = 1;
constexpr std::uint32_t kIdPairSecondField = 2;
/** Element field 1 wraps the descriptor, using the same table as the locate result. */
constexpr std::uint32_t kSearchDescriptorField = 1;
/** Descriptor-message field 1 carries the opaque descriptor bytes. */
constexpr std::uint32_t kDescriptorBytesField = 1;
/** Zero is never a valid assigned advertisement id. */
constexpr std::uint64_t kInvalidAdvertisementId = 0;

} // namespace

/** Encodes kind 2 or 5 around one nested advertisement id. */
bool encode_advertisement_id(bool includeAssignmentResult,
                             std::uint64_t advertisementId,
                             std::span<std::byte> output,
                             std::size_t& written) noexcept {
    written = 0;
    if (advertisementId == kInvalidAdvertisementId) {
        return false;
    }

    std::size_t resultSize = 0;
    std::size_t advertisementPayloadSize = 0;
    std::size_t encodedAdvertisementSize = 0;
    if ((includeAssignmentResult
         && !protobuf::measure_varint_field(
             kAssignmentResultField, kAssignmentResultValue, resultSize))
        || !protobuf::measure_varint_field(
            kAdvertisementIdField, advertisementId, advertisementPayloadSize)
        || !protobuf::measure_length_delimited_field(
            kAdvertisementField, advertisementPayloadSize, encodedAdvertisementSize)) {
        return false;
    }
    const std::size_t required = resultSize + encodedAdvertisementSize;
    if (output.size() < required) {
        return false;
    }

    // The size checks above make every write below fit. Build the child id at its final offset,
    // then wrap it in the advertisement field.
    if (includeAssignmentResult) {
        Writer resultWriter(output.first(resultSize));
        if (!resultWriter.write_varint(kAssignmentResultField, kAssignmentResultValue)) {
            return false;
        }
    }

    const std::size_t advertisementPrefixSize = encodedAdvertisementSize - advertisementPayloadSize;
    const std::size_t idOffset = resultSize + advertisementPrefixSize;
    Writer idWriter(output.subspan(idOffset, advertisementPayloadSize));
    if (!idWriter.write_varint(kAdvertisementIdField, advertisementId)) {
        return false;
    }
    Writer advertisementWriter(output.subspan(resultSize, encodedAdvertisementSize));
    if (!advertisementWriter.write_length_delimited(
            kAdvertisementField, output.subspan(idOffset, advertisementPayloadSize))) {
        return false;
    }
    written = required;
    return true;
}

/** Encodes one locate-session result with its id and descriptor. */
bool encode_locate_result(std::uint64_t advertisementId,
                          std::span<const std::byte> descriptor,
                          std::span<std::byte> output,
                          std::size_t& written) noexcept {
    written = 0;
    if (advertisementId == kInvalidAdvertisementId || descriptor.size() != kJoinDescriptorSize) {
        return false;
    }

    std::size_t descriptorMessagePayloadSize = 0;
    std::size_t encodedResultDescriptorSize = 0;
    std::size_t advertisementIdFieldSize = 0;
    if (!protobuf::measure_length_delimited_field(
            kDescriptorBytesField, descriptor.size(), descriptorMessagePayloadSize)
        || !protobuf::measure_length_delimited_field(
            kLocateDescriptorField, descriptorMessagePayloadSize, encodedResultDescriptorSize)
        || !protobuf::measure_varint_field(
            kAdvertisementIdField, advertisementId, advertisementIdFieldSize)) {
        return false;
    }
    const std::size_t resultSize = advertisementIdFieldSize + encodedResultDescriptorSize;
    std::size_t required = 0;
    if (!protobuf::measure_length_delimited_field(kLocateResultField, resultSize, required)
        || required > kMaximumResponseBodySize || output.size() < required) {
        return false;
    }

    // Lay out the nested messages innermost first, then outward. Each wrapper moves its already
    // encoded child into the same final payload range.
    const std::size_t resultOffset = required - resultSize;
    const std::size_t resultDescriptorOffset = resultOffset + advertisementIdFieldSize;
    const std::size_t descriptorMessageOffset =
        resultDescriptorOffset + encodedResultDescriptorSize - descriptorMessagePayloadSize;

    Writer descriptorWriter(output.subspan(descriptorMessageOffset, descriptorMessagePayloadSize));
    if (!descriptorWriter.write_length_delimited(kDescriptorBytesField, descriptor)) {
        return false;
    }
    Writer idWriter(output.subspan(resultOffset, advertisementIdFieldSize));
    if (!idWriter.write_varint(kAdvertisementIdField, advertisementId)) {
        return false;
    }
    Writer resultDescriptorWriter(
        output.subspan(resultDescriptorOffset, encodedResultDescriptorSize));
    if (!resultDescriptorWriter.write_length_delimited(
            kLocateDescriptorField,
            output.subspan(descriptorMessageOffset, descriptorMessagePayloadSize))) {
        return false;
    }
    Writer outerWriter(output.first(required));
    if (!outerWriter.write_length_delimited(kLocateResultField,
                                            output.subspan(resultOffset, resultSize))) {
        return false;
    }
    written = required;
    return true;
}


/** Encodes one search result carrying a single join descriptor. */
bool encode_search_results(std::uint64_t advertisementId,
                           std::span<const std::byte> descriptor,
                           std::span<std::byte> output,
                           std::size_t& written) noexcept {
    written = 0;
    if (descriptor.size() != kJoinDescriptorSize
        || advertisementId == kInvalidAdvertisementId) {
        return false;
    }

    // Measured innermost first, exactly like encode_locate_result: each wrapper needs its
    // child's encoded size before its own tag and length can be sized.
    std::size_t bytesFieldSize = 0;      // 1: bytes[128]        inside DescriptorWrapper
    std::size_t wrapperFieldSize = 0;    // 1: DescriptorWrapper inside SearchResult
    std::size_t idFirstSize = 0;         // 1: uint64            inside IdPair
    std::size_t idSecondSize = 0;        // 2: uint64            inside IdPair
    std::size_t idPairFieldSize = 0;     // 6: IdPair            inside SearchResult
    std::size_t elementPayloadSize = 0;  // wrapper + idPair
    std::size_t elementFieldSize = 0;    // 1: SearchResult      inside SearchResults
    std::size_t required = 0;            // 3: SearchResults     inside the body
    if (!protobuf::measure_length_delimited_field(
            kDescriptorBytesField, descriptor.size(), bytesFieldSize)
        || !protobuf::measure_length_delimited_field(
            kSearchDescriptorField, bytesFieldSize, wrapperFieldSize)
        || !protobuf::measure_varint_field(kIdPairFirstField, advertisementId, idFirstSize)
        || !protobuf::measure_varint_field(kIdPairSecondField, advertisementId, idSecondSize)) {
        return false;
    }
    idPairFieldSize = 0;
    if (!protobuf::measure_length_delimited_field(
            kSearchResultIdPairField, idFirstSize + idSecondSize, idPairFieldSize)) {
        return false;
    }
    elementPayloadSize = wrapperFieldSize + idPairFieldSize;
    if (!protobuf::measure_length_delimited_field(
            kSearchResultElementField, elementPayloadSize, elementFieldSize)
        || !protobuf::measure_length_delimited_field(
            kSearchResultsField, elementFieldSize, required)) {
        return false;
    }
    if (required > kMaximumSearchResponseBodySize || output.size() < required) {
        return false;
    }

    // Lay the nested messages out innermost first, then wrap outward, each wrapper moving its
    // already encoded child into the same final payload range.
    const std::size_t elementOffset = required - elementFieldSize;
    // Element payload order: the descriptor wrapper, then the IdPair naming what it points at.
    const std::size_t payloadOffset = elementOffset + elementFieldSize - elementPayloadSize;
    const std::size_t wrapperOffset = payloadOffset;
    const std::size_t bytesOffset = wrapperOffset + wrapperFieldSize - bytesFieldSize;
    const std::size_t idPairOffset = payloadOffset + wrapperFieldSize;
    const std::size_t idPayloadOffset = idPairOffset + idPairFieldSize - (idFirstSize + idSecondSize);

    Writer bytesWriter(output.subspan(bytesOffset, bytesFieldSize));
    if (!bytesWriter.write_length_delimited(kDescriptorBytesField, descriptor)) {
        return false;
    }
    Writer wrapperWriter(output.subspan(wrapperOffset, wrapperFieldSize));
    if (!wrapperWriter.write_length_delimited(kSearchDescriptorField,
                                              output.subspan(bytesOffset, bytesFieldSize))) {
        return false;
    }
    Writer idWriter(output.subspan(idPayloadOffset, idFirstSize + idSecondSize));
    if (!idWriter.write_varint(kIdPairFirstField, advertisementId)
        || !idWriter.write_varint(kIdPairSecondField, advertisementId)) {
        return false;
    }
    Writer idPairWriter(output.subspan(idPairOffset, idPairFieldSize));
    if (!idPairWriter.write_length_delimited(
            kSearchResultIdPairField,
            output.subspan(idPayloadOffset, idFirstSize + idSecondSize))) {
        return false;
    }
    Writer elementWriter(output.subspan(elementOffset, elementFieldSize));
    if (!elementWriter.write_length_delimited(kSearchResultElementField,
                                              output.subspan(payloadOffset, elementPayloadSize))) {
        return false;
    }
    Writer outerWriter(output.first(required));
    if (!outerWriter.write_length_delimited(kSearchResultsField,
                                            output.subspan(elementOffset, elementFieldSize))) {
        return false;
    }
    written = required;
    return true;
}

} // namespace sunrise::middleware::bap::matchmaking::response
