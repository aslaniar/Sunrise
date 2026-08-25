#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace sunrise::middleware::bap::matchmaking::response {

/**
 * Encodes kind 2 or 5 around one nested advertisement id.
 * @param includeAssignmentResult True only when kind 2 needs field 1 value 2.
 * @param advertisementId Nonzero id returned to the client.
 * @param output Caller-owned response storage, left unchanged on failure.
 * @param written Receives the whole response size or zero on failure.
 * @return True when the id is valid and the response fits.
 */
[[nodiscard]] bool encode_advertisement_id(bool includeAssignmentResult,
                                           std::uint64_t advertisementId,
                                           std::span<std::byte> output,
                                           std::size_t& written) noexcept;

/**
 * Encodes one search result carrying a single join descriptor.
 *
 * SHAPE, read out of the CLIENT'S OWN schema tables (claims/lane-svc43-field3.md):
 * service-43 field 3 is a CONTAINER message, not a bare repeated field - the naive
 * symmetry guess was wrong by one nesting level.
 *     3: SearchResults { 1: repeated SearchResult { 1: DescriptorWrapper {
 *                                                     1: bytes[128] } } }
 * The DescriptorWrapper table (0x141C38BE0) is the SAME one used by the locate
 * result's field 2 and by svc-42's advertisementUpdate, so the innermost two levels
 * are wire-proven by two independent production paths.
 *
 * @param advertisementId Nonzero id of the advertisement this result points at; the element's
 *        field-6 IdPair names it, so the client can associate the descriptor with a session.
 * @param descriptor Exactly 128 bytes; the join descriptor a searcher should reach.
 * @param output Caller-owned response storage, left unchanged on failure.
 * @param written Receives the whole response size or zero on failure.
 * @return True when the descriptor is the right size and the response fits.
 */
[[nodiscard]] bool encode_search_results(std::uint64_t advertisementId,
                                         std::span<const std::byte> descriptor,
                                         std::span<std::byte> output,
                                         std::size_t& written) noexcept;

/**
 * Encodes one locate-session result with its id and descriptor.
 * @param advertisementId Nonzero id of the latest advertisement.
 * @param descriptor Exactly 128 bytes, borrowed from runtime State.
 * @param output Caller-owned response storage, left unchanged on failure.
 * @param written Receives the whole response size or zero on failure.
 * @return True when the inputs are valid and the response fits.
 */
[[nodiscard]] bool encode_locate_result(std::uint64_t advertisementId,
                                        std::span<const std::byte> descriptor,
                                        std::span<std::byte> output,
                                        std::size_t& written) noexcept;

} // namespace sunrise::middleware::bap::matchmaking::response
