#pragma once

#include <cstddef>
#include <cstdint>

#include "../../encoding/bit_reader.h"
#include "../../encoding/bit_writer.h"

namespace sunrise::middleware::gameplay::peer {

/** Registry ids of the group-session join messages. */
enum class JoinId : std::uint8_t {
    request = 10,
    refuse = 14,
};

/** Declared decoded sizes the registry holds for those ids. */
inline constexpr std::uint32_t kJoinRequestSize = 6144;
/** See kJoinRequestSize. */
inline constexpr std::uint32_t kJoinRefuseSize = 24;

/** Protocol version the host requires. A mismatch is dropped with no reply at all. */
inline constexpr std::uint16_t kProtocolVersion = 0xA4F8;
/** Build the host reports. The request's build interval has to contain it. */
inline constexpr std::uint32_t kHostBuild = 86657;
/** Executable type the host requires. */
inline constexpr std::uint8_t kExecutableType = 5;

/** Refusal reasons this host emits, by their registry order. */
enum class RefuseReason : std::uint8_t {
    notFound = 4,
    peerVersionTooLow = 27,
    hostVersionTooLow = 28,
    executableTypeMismatch = 29,
};

/**
 * Leading fixed fields of a join request.
 * Everything after the join id is address and player tables. Admission does not read them.
 */
struct JoinRequest {
    std::uint16_t protocolVersion{};
    std::uint32_t minimumBuild{};
    std::uint32_t maximumBuild{};
    std::uint8_t executableType{};
    std::uint64_t sessionId{};
    /** Identifies this join attempt, not the machine. It changes on every retry, and the peer
     *  refuses a membership update that does not echo it. */
    std::uint64_t joinId{};
};

/** Body of a join refusal. The host echoes the request's join id. */
struct JoinRefuse {
    std::uint64_t sessionId{};
    std::uint64_t joinId{};
    RefuseReason reason{RefuseReason::notFound};
};

/**
 * Reads the admission prefix of a join request.
 * @param reader Reader positioned at the body.
 * @param output Receives the fields admission checks.
 * @return True when every admission field was present.
 */
[[nodiscard]] bool read_join_request(encoding::bits::Reader& reader, JoinRequest& output) noexcept;

/**
 * One machine identity as the join request's identity table carries it.
 * MEASURED (p2-85 captures, FINDINGS 20.128): behind the admission prefix (211 bits
 * from the BODY start, 237 from the container start) the table holds, in this order,
 * an 8-bit entry tag (0x08 observed on both machines), a NetAddr pair (32-bit address
 * in network order, 16-bit port low byte first - the descriptor's own grammar), four
 * 6-byte placeholder groups, a SECOND NetAddr pair, and a machine identity blob whose
 * first qword differs per machine and is stable for the whole boot.
 *
 * The TWO PAIRS LEGITIMATELY DIVERGE (p2-188, both machines' captures decoded
 * offline): the mac's first pair names 192.168.1.164 - its address BEFORE the
 * 2026-09-05 network move - while the second names the current 192.168.1.7; the
 * rig's pairs agree because its address never changed. The client caches the
 * address across network changes in the first pair. Requiring the pairs to be
 * identical (the old rule) refused the mac's identity in TWO consecutive boots
 * and starved the relay retarget of the mac's machine id. The decoder now returns
 * both pairs; the consumer's self-check accepts EITHER pair matching the
 * datagram's source.
 */
struct JoinMachineIdentity {
    /** First entry's tag byte. 0x08 on every capture so far. */
    std::uint8_t entryTag{};
    /** First entry's address, network order (comparable to Endpoint::address). */
    std::uint32_t address{};
    /** First entry's port, decoded low byte first (the descriptor's port grammar). */
    std::uint16_t port{};
    /** The second pair's address. May differ from the first (p2-188: the mac's
     *  cached pre-move address vs the current one). */
    std::uint32_t address2{};
    /** The second pair's port, same grammar as the first. */
    std::uint16_t port2{};
    /** The identity blob's first qword, read low byte first like the descriptor's machineId. */
    std::uint64_t machineId{};
    /** The same 8 wire bytes read big-endian first, kept so a boot can disambiguate the order
     *  the consumer compares against without another capture run. Logging-only. */
    std::uint64_t machineIdReversed{};
};

/**
 * Reads the machine identity table behind one admission prefix.
 * @param reader Reader positioned directly behind `read_join_request`'s prefix.
 * @param output Receives the decoded identity.
 * @return True when the tag, both NetAddr pairs, and the identity qword were present.
 *         The pairs are NOT required to be equal (p2-188: the first pair may carry a
 *         stale cached address); the consumer decides which pair is authoritative.
 */
[[nodiscard]] bool read_join_machine_identity(encoding::bits::Reader& reader,
                                              JoinMachineIdentity& output) noexcept;

/** Writes a join refusal body. @return True when every field fit. */
[[nodiscard]] bool write_join_refuse(encoding::bits::Writer& writer,
                                     const JoinRefuse& body) noexcept;

/**
 * Applies the host's admission rules in their exact order.
 * @param request Decoded admission prefix.
 * @param hostSessionId Session id this host advertises.
 * @param reason Receives the refusal reason when admission fails.
 * @return True when the request is admitted. A protocol mismatch also returns false and leaves
 *         the reason at its default. Drop such a request without a reply.
 */
[[nodiscard]] bool
admit(const JoinRequest& request, std::uint64_t hostSessionId, RefuseReason& reason) noexcept;

/** @return True when the request may be answered at all. A protocol mismatch may not. */
[[nodiscard]] bool answerable(const JoinRequest& request) noexcept;

} // namespace sunrise::middleware::gameplay::peer
