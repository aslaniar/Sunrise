#include "join_messages.h"

#include "../../encoding/bit_raw.h"

namespace sunrise::middleware::gameplay::peer {

namespace {

namespace bits = encoding::bits;

/** The protocol version is a 16-bit value field. */
constexpr std::uint8_t kProtocolWidth = 16;
/** Both build fields are 32-bit value fields. */
constexpr std::uint8_t kBuildWidth = 32;
/** The executable type is three bits. */
constexpr std::uint8_t kExecutableWidth = 3;
/** The refusal reason is six bits. */
constexpr std::uint8_t kReasonWidth = 6;
} // namespace

/** Reads the admission prefix of a join request. */
bool read_join_request(bits::Reader& reader, JoinRequest& output) noexcept {
    std::uint64_t protocol = 0;
    std::uint64_t minimum = 0;
    std::uint64_t maximum = 0;
    std::uint64_t executable = 0;
    JoinRequest candidate{};
    if (!reader.read(kProtocolWidth, protocol) || !reader.read(kBuildWidth, minimum)
        || !reader.read(kBuildWidth, maximum) || !reader.read(kExecutableWidth, executable)
        || !bits::read_raw_u64(reader, candidate.sessionId)
        || !bits::read_raw_u64(reader, candidate.joinId)) {
        return false;
    }
    candidate.protocolVersion = static_cast<std::uint16_t>(protocol);
    candidate.minimumBuild = static_cast<std::uint32_t>(minimum);
    candidate.maximumBuild = static_cast<std::uint32_t>(maximum);
    candidate.executableType = static_cast<std::uint8_t>(executable);
    output = candidate;
    return true;
}

/** Reads the machine identity table behind one admission prefix (p2-85 measured layout). */
bool read_join_machine_identity(bits::Reader& reader, JoinMachineIdentity& output) noexcept {
    JoinMachineIdentity candidate{};
    std::uint64_t tag = 0;
    std::uint64_t address = 0;
    std::uint64_t port = 0;
    if (!reader.read(8, tag) || !reader.read(32, address) || !reader.read(16, port)) {
        return false;
    }
    candidate.entryTag = static_cast<std::uint8_t>(tag);
    candidate.address = static_cast<std::uint32_t>(address);
    // The port rides low byte first (the descriptor's memory order), so the 16 bits the reader
    // assembled most-significant-first swap into the host value here.
    candidate.port = static_cast<std::uint16_t>(((port & 0xFFU) << 8) | ((port >> 8) & 0xFFU));
    // Four placeholder groups of six bytes each sit between the two NetAddr pairs. Identical on
    // every capture so far; skipped without validation so an unrelated filler change cannot
    // wedge admission (the identity is a bonus, never a gate).
    if (!reader.skip(4 * 6 * 8)) {
        return false;
    }
    std::uint64_t address2 = 0;
    std::uint64_t port2 = 0;
    if (!reader.read(32, address2) || !reader.read(16, port2)) {
        return false;
    }
    // The second pair is NOT required to equal the first (p2-188: the mac's first pair
    // carries its cached pre-network-move address while the second names the current
    // one; the rig's pairs agree). Both are returned; the consumer's self-check picks
    // whichever matches the datagram's source.
    candidate.address2 = static_cast<std::uint32_t>(address2);
    candidate.port2 = static_cast<std::uint16_t>(((port2 & 0xFFU) << 8) | ((port2 >> 8) & 0xFFU));
    if (candidate.entryTag != 0x08) {
        return false;
    }
    // The identity qword rides low byte first, like the descriptor's machineId field and the
    // port above. The reversed read is kept logging-only (INFERRED order - one boot settles it).
    for (unsigned index = 0; index < 8; ++index) {
        std::uint64_t byte = 0;
        if (!reader.read(8, byte)) {
            return false;
        }
        candidate.machineId |= byte << (index * 8);
        candidate.machineIdReversed =
            (candidate.machineIdReversed << 8) | byte;
    }
    if (candidate.machineId == 0) {
        return false;
    }
    output = candidate;
    return true;
}

/** Writes a join refusal body. */
bool write_join_refuse(bits::Writer& writer, const JoinRefuse& body) noexcept {
    return bits::write_raw_u64(writer, body.sessionId) && bits::write_raw_u64(writer, body.joinId)
           && writer.write(static_cast<std::uint64_t>(body.reason), kReasonWidth);
}

/** Reports whether a request may be answered at all. */
bool answerable(const JoinRequest& request) noexcept {
    return request.protocolVersion == kProtocolVersion;
}

/** Applies the host's admission rules in their exact order. */
bool admit(const JoinRequest& request, std::uint64_t hostSessionId, RefuseReason& reason) noexcept {
    if (!answerable(request)) {
        return false;
    }
    // This host holds one group session, so the request's session id needs no lookup.
    (void)hostSessionId;
    if (request.maximumBuild < kHostBuild) {
        reason = RefuseReason::peerVersionTooLow;
        return false;
    }
    if (request.minimumBuild > kHostBuild) {
        reason = RefuseReason::hostVersionTooLow;
        return false;
    }
    if (request.executableType != kExecutableType) {
        reason = RefuseReason::executableTypeMismatch;
        return false;
    }
    return true;
}

} // namespace sunrise::middleware::gameplay::peer
