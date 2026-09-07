#include "external_send.h"

#include <cstring>

namespace sunrise::server::gameplay::peer::external_send {
namespace {

namespace external = ::sunrise::middleware::gameplay::external;
namespace bits = ::sunrise::middleware::encoding::bits;

using external::EntityRecord;
using external::EntityToken;
using external::EntityType;
using external::ExternalEntityFrame;
using external::TypePayload;
using external::TypePayloadPart;

/**
 * The kind-2 payload writer. A playerBroadcast baseline is RAW 8 BYTES on the wire
 * (femu-validated contract, ent-receive-contract.md sections 4 and 7) - no presence
 * bits, no transforms, bytes in order. Everything else fails closed: this probe has
 * no body for any other type or part, and a silent empty body would be a wrong answer.
 */
[[nodiscard]] bool write_payload(const void* /*context*/,
                                 const EntityToken& /*token*/,
                                 EntityType type,
                                 TypePayloadPart part,
                                 const TypePayload& payload,
                                 bits::Writer& writer) noexcept {
    if (type != EntityType::playerBroadcast || part != TypePayloadPart::baseline) {
        return false;
    }
    if (payload.byteCount != kPeerBaselineBytes.size()
        || payload.byteCount > payload.state.size()) {
        return false;
    }
    for (std::size_t index = 0; index < payload.byteCount; ++index) {
        const auto value = std::to_integer<std::uint64_t>(payload.state[index]);
        if (!writer.write(value, 8)) {
            return false;
        }
    }
    return true;
}

/** The matching reader, for the round-trip self test only. */
[[nodiscard]] bool read_payload(const void* /*context*/,
                                const EntityToken& /*token*/,
                                EntityType type,
                                TypePayloadPart part,
                                bits::Reader& reader,
                                TypePayload& output) noexcept {
    if (type != EntityType::playerBroadcast || part != TypePayloadPart::baseline) {
        return false;
    }
    for (std::size_t index = 0; index < kPeerBaselineBytes.size(); ++index) {
        std::uint64_t value = 0;
        if (!reader.read(8, value)) {
            return false;
        }
        output.state[index] = static_cast<std::byte>(value);
    }
    output.byteCount = kPeerBaselineBytes.size();
    return true;
}

/** The probe's codec: no resolve callback (creates carry their type), strict limits. */
[[nodiscard]] external::TypePayloadCodec probe_codec() noexcept {
    external::TypePayloadCodec codec{};
    codec.write = &write_payload;
    codec.read = &read_payload;
    codec.maximumBaselineBits = kPeerBaselineBytes.size() * 8;
    codec.maximumUpdateBits = 0;
    return codec;
}

} // namespace

bool build_peer_create_frame(ExternalEntityFrame& frame) noexcept {
    frame = {};
    // The common root stays absent in the probe: the client's own empty frames prove the
    // channels tolerate absence, and a fabricated epoch would be a guess (U17: nothing
    // optional ships - if the client requires the common root, the readout shows it and
    // the follow-up mirrors the client's own root instead of inventing one).
    frame.commonPresent = false;

    EntityRecord& record = frame.entities.record;
    record.token.slot = kPeerEntitySlot;
    record.token.incarnation = kPeerEntityIncarnation;
    record.type = EntityType::playerBroadcast;
    record.flags = external::entityCreate;
    record.lifecycleRevision = 0;
    record.rawBubble = external::kNoRawBubble;
    record.anchorPresent = false;
    record.trailingState = false;
    for (std::size_t index = 0; index < kPeerBaselineBytes.size(); ++index) {
        record.baseline.state[index] = static_cast<std::byte>(kPeerBaselineBytes[index]);
    }
    record.baseline.byteCount = kPeerBaselineBytes.size();
    record.update.byteCount = 0;
    frame.entities.recordPresent = true;
    frame.entities.defaultRawBubble = external::kNoRawBubble;
    return true;
}

bool encode_frame(const ExternalEntityFrame& frame, EncodedFrame& output) noexcept {
    output = {};
    bits::Writer writer(output.bytes);
    const external::TypePayloadCodec codec = probe_codec();
    if (!external::write_external_entity_frame(writer, codec, frame)) {
        return false;
    }
    // finish() reports WHOLE BYTES; bitCount is the exact BIT count the tail writer copies.
    std::size_t wholeBytes = 0;
    if (!writer.finish(wholeBytes) || wholeBytes > output.bytes.size()
        || writer.bit_count() > wholeBytes * 8) {
        return false;
    }
    output.bitCount = writer.bit_count();
    return true;
}

bool build_and_encode(EncodedFrame& output) noexcept {
    ExternalEntityFrame frame{};
    if (!build_peer_create_frame(frame)) {
        return false;
    }
    return encode_frame(frame, output);
}

bool self_test() noexcept {
    // Negative arm FIRST (09-05 rule: the guard must be shown to fail pre-fix): a remove
    // record carrying a baseline must be rejected by the codec's own preflight.
    {
        ExternalEntityFrame bad{};
        bad.entities.recordPresent = true;
        bad.entities.record.token = EntityToken{kPeerEntitySlot, kPeerEntityIncarnation};
        bad.entities.record.flags = external::entityRemove;
        bad.entities.record.baseline.byteCount = kPeerBaselineBytes.size();
        bad.entities.record.baseline.state[0] = static_cast<std::byte>(0xFD);
        EncodedFrame ignored{};
        if (encode_frame(bad, ignored)) {
            return false;
        }
    }

    // Positive arm: build, encode, decode back, compare, re-encode.
    EncodedFrame encoded{};
    if (!build_and_encode(encoded)) {
        return false;
    }
    const external::TypePayloadCodec codec = probe_codec();
    bits::Reader reader(encoded.bytes);
    ExternalEntityFrame decoded{};
    if (!external::read_external_entity_frame(reader, codec, decoded)) {
        return false;
    }
    const EntityRecord& record = decoded.entities.record;
    if (!decoded.entities.recordPresent || record.token.slot != kPeerEntitySlot
        || record.token.incarnation != kPeerEntityIncarnation
        || record.type != EntityType::playerBroadcast
        || record.flags != external::entityCreate
        || record.baseline.byteCount != kPeerBaselineBytes.size()
        || std::memcmp(record.baseline.state.data(), kPeerBaselineBytes.data(),
                       kPeerBaselineBytes.size()) != 0
        || decoded.commonPresent) {
        return false;
    }
    EncodedFrame reencoded{};
    if (!encode_frame(decoded, reencoded) || reencoded.bitCount != encoded.bitCount
        || std::memcmp(reencoded.bytes.data(), encoded.bytes.data(), encoded.bytes.size())
               != 0) {
        return false;
    }
    // The frame is NOT byte-padded (the packet tail pads after it). The reader spans the
    // whole 32-byte buffer, so the decode must have consumed exactly the frame's bits -
    // the buffer size minus the frame bit count. Anything else is a mis-framed decode.
    return reader.remaining_bits() == encoded.bytes.size() * 8 - encoded.bitCount;
}

} // namespace sunrise::server::gameplay::peer::external_send
