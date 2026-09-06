#include "peer_transport.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdio>

#include "../../../middleware/crypto/random_bytes.h"
#include "../../../middleware/encoding/bit_reader.h"
#include "../../../middleware/encoding/bit_writer.h"
#include "../../../middleware/gameplay/descriptor/join_descriptor.h"
#include "../../../middleware/gameplay/peer/connect_messages.h"
#include "../../../middleware/gameplay/peer/established_packet.h"
#include "../../../middleware/gameplay/peer/join_messages.h"
#include "../../../middleware/gameplay/peer/peer_container.h"
#include "../../../middleware/gameplay/peer/reliable_assembly.h"
#include "../association/association_host.h"
#include "../dtls/dtls_host.h"
#include "../endpoint/gameplay_endpoint.h"
#include "../gameplay_log.h"
#include "../group/group_host.h"
#include "../../../core/settings/settings.h"

namespace sunrise::server::gameplay::peer {

namespace {

namespace gp = state::gameplay;
namespace wire = middleware::gameplay::peer;
namespace bits = middleware::encoding::bits;

/**
 * Sends one payload over whichever transport the peer arrived on.
 * Records go first. The engine association answers only when no record association exists.
 * @param to Peer endpoint.
 * @param payload Payload bytes.
 * @return True when one of the two carried it.
 */
[[nodiscard]] bool send_transport(const gp::Endpoint& to,
                                  std::span<const std::byte> payload) noexcept {
    return dtls::send_payload(to, payload) || association::send_payload(to, payload);
}

/** One out-of-band reply fits well inside a single unfragmented payload. */
constexpr std::size_t kReplyCapacity = 1024;
/** Bit position of the payload marker inside its first byte. */
constexpr unsigned kMarkerShift = 7;
/** Bits in one byte. */
constexpr unsigned kByteBits = 8;
/** Mask of one byte. */
constexpr std::uint32_t kByteMask = 0xFF;
/** Delay sentinel used until a round trip has been measured. */
constexpr std::uint16_t kDelaySentinel = 1023;
/** Packet sequences are published as ten bits. */
constexpr std::uint16_t kPacketSequenceModulus = gp::kPacketSequenceModulus;
/** Sequence the first packet to a peer carries, because the head advances before it is written. */
constexpr std::uint16_t kFirstPacketSequence = 1;
/** Smallest head-minus-cursor the peer accepts. This host keeps at most one packet in flight. */
constexpr std::uint8_t kMinimumHeadCursor = 1;
/** One packet cannot report more delivered messages than this. */
constexpr std::size_t kMessageReportCapacity = 8;
/**
 * Milliseconds between two resends of the same queue. The peer discards a packet more than 128
 * sequences ahead of its window, so this host must not send faster than the peer does.
 */
constexpr std::uint64_t kResendInterval = 250;
/**
 * Milliseconds of silence before this host sends an empty established packet.
 *
 * FINDINGS 20.119: once a join settles, `service` had nothing owed and nothing to resend, so this
 * host sent NOTHING and the peer sent nothing back. The link then idled out and the peer rebuilt
 * its channel every ~21.5 s (`connect result=ok rebuilt=1`), tearing down and redoing a join that
 * had completed cleanly. A real host emits a continuous packet stream; this is the minimum that
 * keeps the link alive. Well under the observed timeout, and one packet per second costs one
 * sequence out of a 1024 modulus.
 */
constexpr std::uint64_t kKeepaliveInterval = 1000;

SRWLOCK g_lock{SRWLOCK_INIT};
std::array<gp::PeerLink, gp::kAssociationCapacity> g_peers;
/** Channel ids this host hands out. The peer refuses one that does not increase. */
std::uint32_t g_channelId{0};

/**
 * The join identity each connected peer's own join decoded, endpoint-keyed.
 *
 * The join lookup retarget (relayJoinTargetIdentity) retargets the relayed join's
 * sessionId at a value the RECIPIENT's gate can match. Every client sends the fork
 * its own type-0x0A join, so answer_join records the join's identity halves here;
 * a peer that has not joined yet has no entry and its relayed copy stays verbatim.
 * Entries are overwritten per endpoint on every re-join, so a stale row cannot
 * survive a reconnect.
 *
 * ARM HISTORY (measured, p2-188b + p2-189):
 * - arm 1, the join machine id (field6=0 activity identity): REFUTED - the gate's
 *   6-slot lookup refused it and the join processor never ran.
 * - arm 2, the recipient's real account key (field6!=0): the FALLBACK, not the
 *   next move - the walked slots are not proven to hold it.
 * - arm 3 (CURRENT): the recipient's CURRENT JOINID - the value under which its
 *   own client binds its session. PROVEN inside the gate's walked records on
 *   both machines (p2-189: binder2's stack args = the machine's own joinId,
 *   binder ctx pointers = the walked slots, cof_soid granted that key index 2;
 *   p2-187 census: key=joinId vs blob=joinId, match=1).
 *
 * The per-caller sesscmp triples at a refusal decide the next arm, not this
 * table's contents; see the setting's comment for the full arm history.
 */
struct PeerJoinIdentity {
    gp::Endpoint endpoint{};
    std::uint64_t machineId{};
    /** The joinId the peer's OWN join request carried - arm 3's retarget value. */
    std::uint64_t joinId{};
    bool present{};
};
std::array<PeerJoinIdentity, gp::kAssociationCapacity> g_peerJoinIdentities;

/** @return True when both endpoints name the same address and port. */
[[nodiscard]] bool same_endpoint(const gp::Endpoint& left, const gp::Endpoint& right) noexcept {
    return left.address == right.address && left.port == right.port;
}

/** Records one peer's decoded join identity (machine id + its own joinId). Callers hold no lock. */
void remember_join_identity(const gp::Endpoint& from, std::uint64_t machineId,
                            std::uint64_t joinId) noexcept {
    if (machineId == 0 && joinId == 0) {
        return;
    }
    AcquireSRWLockExclusive(&g_lock);
    for (PeerJoinIdentity& entry : g_peerJoinIdentities) {
        if (!entry.present || same_endpoint(entry.endpoint, from)) {
            entry.endpoint = from;
            entry.machineId = machineId;
            entry.joinId = joinId;
            entry.present = true;
            break;
        }
    }
    ReleaseSRWLockExclusive(&g_lock);
}

/**
 * @return The joinId one endpoint's OWN join request carried (arm 3's retarget
 * value - the value under which that recipient's client binds its session), or
 * zero when the peer has not joined. Callers hold no lock.
 */
[[nodiscard]] std::uint64_t peer_join_id(const gp::Endpoint& endpoint) noexcept {
    AcquireSRWLockShared(&g_lock);
    std::uint64_t joinId = 0;
    for (const PeerJoinIdentity& entry : g_peerJoinIdentities) {
        if (entry.present && same_endpoint(entry.endpoint, endpoint)) {
            joinId = entry.joinId;
            break;
        }
    }
    ReleaseSRWLockShared(&g_lock);
    return joinId;
}

/** @return Peer for one endpoint, or null. Callers already hold the lock. */
[[nodiscard]] gp::PeerLink* find_locked(const gp::Endpoint& from) noexcept {
    for (gp::PeerLink& peer : g_peers) {
        if (peer.stage != gp::PeerStage::absent && same_endpoint(peer.endpoint, from)) {
            return &peer;
        }
    }
    return nullptr;
}

/** @return True when the link carries one group session. Callers hold the lock. */
[[nodiscard]] bool carries_locked(const gp::PeerLink& peer, std::uint64_t sessionId) noexcept {
    for (const std::uint64_t held : peer.sessions) {
        if (held == sessionId) {
            return true;
        }
    }
    return false;
}

/**
 * @return The link at one endpoint that carries one group session, or null.
 * Two peers can hold one session, so the endpoint is what disambiguates them. A link that does
 * not carry the session is never chosen: delivering to it would hand one peer's records to
 * another. Callers hold the lock.
 */
[[nodiscard]] gp::PeerLink* find_session_at_locked(const gp::Endpoint& endpoint,
                                                   std::uint64_t sessionId) noexcept {
    if (sessionId == 0) {
        return nullptr;
    }
    gp::PeerLink* peer = find_locked(endpoint);
    return peer != nullptr && carries_locked(*peer, sessionId) ? peer : nullptr;
}

/** @return Link carrying one group session, or null. Callers hold the lock. */
[[nodiscard]] gp::PeerLink* find_session_locked(std::uint64_t sessionId) noexcept {
    if (sessionId == 0) {
        return nullptr;
    }
    for (gp::PeerLink& peer : g_peers) {
        if (peer.stage != gp::PeerStage::absent && carries_locked(peer, sessionId)) {
            return &peer;
        }
    }
    return nullptr;
}

/**
 * Resolves the session a message that does not name one belongs to.
 * A link carrying more than one session leaves it unresolved rather than guessing.
 * @param peer Link the message arrived on.
 * @return The session id, or zero when the link carries none or several.
 */
[[nodiscard]] std::uint64_t sole_session_locked(const gp::PeerLink& peer) noexcept {
    std::uint64_t only = 0;
    for (const std::uint64_t held : peer.sessions) {
        if (held == 0) {
            continue;
        }
        if (only != 0) {
            return 0;
        }
        only = held;
    }
    return only;
}

/**
 * Resolves the session an out-of-band message at one endpoint belongs to.
 * @param from Peer endpoint.
 * @return The session id, or zero when it cannot be resolved.
 */
[[nodiscard]] std::uint64_t session_for_endpoint(const gp::Endpoint& from) noexcept {
    AcquireSRWLockShared(&g_lock);
    const gp::PeerLink* const peer = find_locked(from);
    const std::uint64_t only = peer == nullptr ? 0 : sole_session_locked(*peer);
    ReleaseSRWLockShared(&g_lock);
    return only;
}

/** @return A free peer slot, or null. Callers already hold the lock. */
[[nodiscard]] gp::PeerLink* allocate_locked() noexcept {
    for (gp::PeerLink& peer : g_peers) {
        if (peer.stage == gp::PeerStage::absent) {
            return &peer;
        }
    }
    return nullptr;
}

/** Fills the address blob that names this host on the direct path. */
void local_address(std::array<std::byte, wire::kAddressBlobSize>& output) noexcept {
    const gp::Endpoint advertised = endpoint::advertised();
    middleware::gameplay::descriptor::write_net_addr(advertised.address, advertised.port, output);
}

/** @return A random 32-bit sequence, or zero when Windows refused. */
[[nodiscard]] std::uint32_t random_sequence() noexcept {
    std::array<std::byte, sizeof(std::uint32_t)> bytes{};
    if (!middleware::crypto::random::fill(bytes)) {
        return 0;
    }
    std::uint32_t value = 0;
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        value |= std::to_integer<std::uint32_t>(bytes[index]) << (index * kByteBits);
    }
    return value;
}

/**
 * Answers the peer's connect establish with this host's own.
 * It goes on the reliable queue because that is where the peer sends its own.
 * @param to Peer endpoint.
 * @param remoteChannelId Channel id the request carried. The link must still hold it.
 * @param body Both channel ids.
 */
void answer_establish(const gp::Endpoint& to,
                      std::uint32_t remoteChannelId,
                      const wire::ConnectEstablish& body) noexcept {
    std::array<std::byte, kReplyCapacity> buffer{};
    bits::Writer writer(buffer);
    std::size_t size = 0;
    if (!wire::write_establish(writer, body) || !writer.finish(size)) {
        report(core::log::Level::warn, "ev=gameplay stage=establish result=fail reason=encode");
        return;
    }
    AcquireSRWLockExclusive(&g_lock);
    // The endpoint's link. A channel the peer has retired has no link of its own to answer on.
    gp::PeerLink* peer = find_locked(to);
    const bool queued =
        peer != nullptr && peer->remoteConnectionSequence == remoteChannelId
        && wire::enqueue_message(peer->outbound,
                                 static_cast<std::uint8_t>(wire::ConnectId::establish),
                                 wire::kEstablishSize,
                                 {buffer.data(), size},
                                 writer.bit_count());
    if (queued) {
        peer->acknowledgementOwed = true;
        peer->outbound.awaitingAcknowledgement = false;
    }
    ReleaseSRWLockExclusive(&g_lock);
    report(core::log::Level::info,
           "ev=gameplay stage=establish result=%s local=0x%08X remote=0x%08X",
           queued ? "queued" : "fail",
           body.channelId,
           body.remoteChannelId);
}

/**
 * Answers one connect request with a connect response.
 * @param from Requesting endpoint.
 * @param request Decoded request body.
 * @param now Monotonic tick count.
 */
void answer_connect(const gp::Endpoint& from,
                    const wire::ConnectRequest& request,
                    std::uint64_t now) noexcept {
    wire::ConnectResponse response{};
    // The peer checks both echoed fields and closes the connection on a wrong sequence.
    response.remoteChannelId = request.channelId;
    response.remoteSequence = request.sequence;
    local_address(response.address);

    AcquireSRWLockExclusive(&g_lock);
    // Keyed by endpoint. The client holds one channel per host peer, so a second link would stamp
    // packets with a channel id the client has already retired.
    gp::PeerLink* peer = find_locked(from);
    // A repeat of the same request is a retransmission and leaves the link alone. A different
    // channel or sequence is a new incarnation the peer built without announcing the teardown.
    const bool rebuilt = peer != nullptr
                         && (peer->remoteConnectionSequence != request.channelId
                             || peer->remoteTransportSequence != request.sequence);
    if (peer == nullptr) {
        peer = allocate_locked();
    }
    const bool fresh = peer != nullptr && (peer->stage == gp::PeerStage::absent || rebuilt);
    if (fresh) {
        // The sessions outlive the channel. The client rebuilds one channel under every group
        // session it holds and rejoins none of them, so dropping them here strands each one.
        const std::array<std::uint64_t, gp::kSessionsPerLink> held =
            peer->stage == gp::PeerStage::absent ? std::array<std::uint64_t, gp::kSessionsPerLink>{}
                                                 : peer->sessions;
        *peer = {};
        peer->sessions = held;
        peer->endpoint = from;
        // The channel id is an incarnation counter: the peer refuses one that does not
        // increase, and reads all ones as unset.
        peer->localConnectionSequence = ++g_channelId;
        // The peer builds its receive window from the announced sequence and expects the first
        // packet one past it. This announces the sequence before the first packet, not the first
        // packet itself.
        peer->localTransportSequence =
            (random_sequence() & ~static_cast<std::uint32_t>(kPacketSequenceModulus - 1))
            | static_cast<std::uint32_t>(kFirstPacketSequence - 1);
    }
    if (peer != nullptr) {
        peer->remoteConnectionSequence = request.channelId;
        peer->remoteTransportSequence = request.sequence;
        // The membership update must name the peer's own address, so its own blob is kept.
        peer->remoteAddress = request.address;
        peer->remoteAddressPresent = true;
        // A retransmission must not move an established link back a stage.
        if (fresh) {
            peer->stage = gp::PeerStage::connecting;
        }
        peer->lastTick = now;
        response.channelId = peer->localConnectionSequence;
        response.sequence = peer->localTransportSequence;
    }
    ReleaseSRWLockExclusive(&g_lock);
    if (peer == nullptr) {
        report(core::log::Level::warn, "ev=gameplay stage=connect result=fail reason=capacity");
        return;
    }

    std::array<std::byte, kReplyCapacity> buffer{};
    bits::Writer writer(buffer);
    wire::MessageHeader header{static_cast<std::uint8_t>(wire::ConnectId::response),
                               wire::kResponseSize};
    std::size_t size = 0;
    if (!wire::open_container(writer) || !wire::write_header(writer, header)
        || !wire::write_response(writer, response) || !wire::close_container(writer)
        || !writer.finish(size) || !send_transport(from, {buffer.data(), size})) {
        report(core::log::Level::warn, "ev=gameplay stage=connect result=fail reason=send");
        return;
    }
    // A rebuilt link is invisible otherwise: the peer closes the old one silently.
    report(core::log::Level::info,
           "ev=gameplay stage=connect result=ok peer=%u local=0x%08X remote=0x%08X rebuilt=%u",
           from.port,
           response.channelId,
           request.channelId,
           rebuilt ? 1U : 0U);
    // The peer refuses any first reliable record that is not a connect establish, so this must be
    // enqueued before anything else the join produces.
    wire::ConnectEstablish establish{};
    establish.remoteChannelId = response.remoteChannelId;
    establish.channelId = response.channelId;
    answer_establish(from, request.channelId, establish);
}

/**
 * Binds one group session to the link the peer opened for it.
 * @param from Peer endpoint.
 * @param sessionId Session the join request named.
 * @return True when a link now carries that session.
 */
[[nodiscard]] bool bind_session(const gp::Endpoint& from, std::uint64_t sessionId) noexcept {
    if (sessionId == 0) {
        return false;
    }
    AcquireSRWLockExclusive(&g_lock);
    // The endpoint's link, whatever it already carries. A join for a second region arrives on the
    // same channel as the first, and out of band when that channel is still being rebuilt.
    gp::PeerLink* const peer = find_locked(from);
    const char* result = "nolink";
    bool bound = false;
    std::uint32_t channel = 0;
    if (peer != nullptr) {
        channel = peer->localConnectionSequence;
        result = "full";
        for (std::uint64_t& slot : peer->sessions) {
            if (slot == sessionId) {
                result = "held";
                bound = true;
                break;
            }
            if (slot == 0) {
                slot = sessionId;
                result = "bound";
                bound = true;
                break;
            }
        }
    }
    ReleaseSRWLockExclusive(&g_lock);
    report(bound ? core::log::Level::info : core::log::Level::warn,
           "ev=gameplay stage=link result=%s session=0x%016llX peer=%u local=0x%08X",
           result,
           static_cast<unsigned long long>(sessionId),
           from.port,
           channel);
    return bound;
}

/**
 * Applies the admission rules to one join request and answers it.
 * A protocol mismatch is dropped with no reply.
 * @param from Requesting endpoint.
 * @param request Decoded admission prefix.
 * @param machineId Machine identity the request's identity table carried, or zero when it did
 *                  not decode (the snapshot then falls back to the joinId stand-in).
 */
void answer_join(const gp::Endpoint& from,
                 const wire::JoinRequest& request,
                 std::uint64_t machineId) noexcept {
    // Record the sender's own join identity for the relay's lookup retarget before any
    // admission decision: the identity is the peer's, not the admission's. The joinId
    // half is arm 3's retarget value - the value under which the SENDER's client binds
    // its own session (the value the sender's gate walk must match when a PEER's join
    // is relayed back to it).
    remember_join_identity(from, machineId, request.joinId);
    const std::uint64_t hostSession = endpoint::identity().onlineSessionId;
    wire::RefuseReason reason = wire::RefuseReason::notFound;
    if (wire::admit(request, hostSession, reason)) {
        // The join is the first thing on this link that names the session. A link already
        // carrying it is a retry.
        const bool bound = bind_session(from, request.sessionId);
        const bool published =
            bound && group::publish_membership(from, request.joinId, machineId, request.sessionId);
        // The peer needs both before it finishes: the snapshot names it, and the parameter update
        // releases the latch its own tick waits on.
        const bool parameters =
            bound && group::publish_join_parameters(request.sessionId, from);
        // Nothing else names what the peer thinks it is joining.
        report(core::log::Level::info,
               "ev=gameplay stage=join result=admit build=%u..%u exe=%u session=0x%016llX "
               "host=0x%016llX join=0x%016llX machine=0x%016llX membership=%s parameters=%s",
               request.minimumBuild,
               request.maximumBuild,
               static_cast<unsigned>(request.executableType),
               static_cast<unsigned long long>(request.sessionId),
               static_cast<unsigned long long>(hostSession),
               static_cast<unsigned long long>(request.joinId),
               static_cast<unsigned long long>(machineId),
               published ? "queued" : "fail",
               parameters ? "queued" : "fail");
        return;
    }
    if (!wire::answerable(request)) {
        report(core::log::Level::warn,
               "ev=gameplay stage=join result=drop reason=protocol value=0x%04X",
               static_cast<unsigned>(request.protocolVersion));
        return;
    }
    report(core::log::Level::warn,
           "ev=gameplay stage=join result=refuse reason=%u build=%u..%u exe=%u session=0x%016llX "
           "host=0x%016llX",
           static_cast<unsigned>(reason),
           request.minimumBuild,
           request.maximumBuild,
           static_cast<unsigned>(request.executableType),
           static_cast<unsigned long long>(request.sessionId),
           static_cast<unsigned long long>(hostSession));
    wire::JoinRefuse refusal{};
    refusal.sessionId = request.sessionId;
    refusal.joinId = request.joinId;
    refusal.reason = reason;

    std::array<std::byte, kReplyCapacity> buffer{};
    bits::Writer writer(buffer);
    const wire::MessageHeader header{static_cast<std::uint8_t>(wire::JoinId::refuse),
                                     wire::kJoinRefuseSize};
    std::size_t size = 0;
    if (!wire::open_container(writer) || !wire::write_header(writer, header)
        || !wire::write_join_refuse(writer, refusal) || !wire::close_container(writer)
        || !writer.finish(size) || !send_transport(from, {buffer.data(), size})) {
        report(core::log::Level::warn, "ev=gameplay stage=join result=fail reason=send");
        return;
    }
    report(core::log::Level::info,
           "ev=gameplay stage=join result=refuse reason=%u",
           static_cast<unsigned>(refusal.reason));
}

/**
 * Answers one ping with the pong that echoes it.
 * The pair is mandatory: a peer that pings and is never answered treats the link as unreachable.
 * @param from Peer endpoint.
 * @param reader Reader positioned at the ping body.
 * @return True when the body read, whether or not the reply left the endpoint.
 */
[[nodiscard]] bool answer_ping(const gp::Endpoint& from, bits::Reader& reader) noexcept {
    wire::PingBody ping{};
    if (!wire::read_ping(reader, ping)) {
        return false;
    }
    wire::PongBody pong{};
    pong.sequence = ping.sequence;
    pong.timestamp = ping.timestamp;
    const bool sent = send_out_of_band(
        from,
        static_cast<std::uint8_t>(wire::ConnectId::pong),
        wire::kPongSize,
        [&pong](bits::Writer& writer) noexcept { return wire::write_pong(writer, pong); });
    report(sent ? core::log::Level::debug : core::log::Level::warn,
           "ev=gameplay stage=ping result=%s sequence=%u",
           sent ? "answered" : "fail",
           static_cast<unsigned>(ping.sequence));
    return true;
}

/** Payload bytes logged per join-capture line; 512 hex characters fit kLineCapacity. */
constexpr std::size_t kJoinCaptureChunk = 256;
/** Upper bound of the join-request container capture. */
constexpr std::size_t kJoinCaptureBytes = 1536;

/**
 * INSTRUMENT (p2(85)): dumps the whole join-request container payload as hex.
 * Behind the admission prefix this host reads (protocol, build interval, executable
 * type, session, join id - 211 bits in), the client's type-0x0A join request carries
 * an address and machine-id table this host has never decoded. group_host publishes
 * each peer's join id as its machineId stand-in, and the consumer drops the rows that
 * stand-in cannot match - the deterministic symmetric row drop (FINDINGS 20.127
 * addendum 3). The table starts mid-byte, so the whole container is captured
 * bit-faithfully: `tail_bits` is the reader's remaining bit count right behind the
 * decoded prefix, which locates the table's first bit inside the dump. Decoding
 * happens offline (U2: instrument before intervention). This fires per join request -
 * a handful of lines per boot, no flood.
 * @param from Peer endpoint the container arrived from.
 * @param payload Whole decrypted container payload.
 * @param reader Copy of the container reader positioned behind the decoded prefix.
 */
void capture_join_container(const gp::Endpoint& from,
                            std::span<const std::byte> payload,
                            const bits::Reader& reader) noexcept {
    const std::size_t bytes =
        payload.size() < kJoinCaptureBytes ? payload.size() : kJoinCaptureBytes;
    report(core::log::Level::info,
           "ev=gameplay stage=joincapture result=begin peer=%u bytes=%zu tail_bits=%zu",
           static_cast<unsigned>(from.port),
           payload.size(),
           reader.remaining_bits());
    static constexpr char kDigits[] = "0123456789ABCDEF";
    for (std::size_t offset = 0; offset < bytes; offset += kJoinCaptureChunk) {
        const std::size_t count = bytes - offset < kJoinCaptureChunk ? bytes - offset
                                                                     : kJoinCaptureChunk;
        std::array<char, 2 * kJoinCaptureChunk + 1> hex{};
        for (std::size_t index = 0; index < count; ++index) {
            const auto value = std::to_integer<unsigned>(payload[offset + index]);
            hex[index * 2] = kDigits[(value >> 4) & 0xF];
            hex[(index * 2) + 1] = kDigits[value & 0xF];
        }
        hex[2 * count] = '\0';
        report(core::log::Level::info,
               "ev=gameplay stage=joincapture result=data peer=%u off=%zu hex=%s",
               static_cast<unsigned>(from.port),
               offset,
               hex.data());
    }
}

/**
 * Rewrites one relayed join container's sessionId field to the retarget value.
 *
 * Wire layout (peer_container.cpp + join_messages.cpp, all fixed widths):
 *   marker(1) + header [follows(1) + id(6) + declaredSize(18)] = 26 bits, then the
 *   admission prefix protocolVersion(16) + minimumBuild(32) + maximumBuild(32) +
 *   executableType(3) = 83 bits, then the sessionId as eight 8-bit groups assembled
 *   low byte first (read_raw_u64) - so the field's first bit sits at absolute bit 109.
 * VERIFIED against the p2-182 capture: the fork's own admit decode of that container
 * (session=0x7F7EAE4DD8A942DB join=0x338F19050FD86611) re-derives bit-exact from
 * exactly this offset, and the prefix fields match line-for-line.
 * Everything around the field is copied bit-exact; the value replaces the sender's
 * session id, so the receiving client's join gate lookup can match a session its
 * slots hold (see relayJoinTargetIdentity's comment for the arm the value comes from).
 * @param containerPayload Whole decrypted container payload (marker .. terminator).
 * @param machineId Retarget value, written low byte first like read_raw_u64 reads.
 * @param output Buffer receiving the rewritten container.
 * @return True when the container parsed and was rewritten. False leaves the output
 *         untouched and the caller falls back to the verbatim forward.
 */
[[nodiscard]] bool rewrite_join_session_id(std::span<const std::byte> containerPayload,
                                           std::uint64_t machineId,
                                           std::span<std::byte> output) noexcept {
    static constexpr std::uint8_t kMarkerWidth = 1;
    static constexpr std::uint64_t kContainerMarker = 1;
    static constexpr std::uint8_t kFollowsWidth = 1;
    static constexpr std::uint8_t kIdWidth = 6;
    static constexpr std::uint8_t kSizeWidth = 18;
    static constexpr std::uint8_t kProtocolWidth = 16;
    static constexpr std::uint8_t kBuildWidth = 32;
    static constexpr std::uint8_t kExecutableWidth = 3;
    static constexpr std::size_t kSessionIdBitOffset =
        kMarkerWidth + kFollowsWidth + kIdWidth + kSizeWidth
        + kProtocolWidth + 2 * kBuildWidth + kExecutableWidth;

    bits::Reader reader(containerPayload);
    std::uint64_t marker = 0;
    std::uint64_t follows = 0;
    std::uint64_t id = 0;
    std::uint64_t declaredSize = 0;
    if (!reader.read(kMarkerWidth, marker) || marker != kContainerMarker || !reader.read(kFollowsWidth, follows)
        || follows == 0 || !reader.read(kIdWidth, id)
        || id != static_cast<std::uint64_t>(wire::JoinId::request)
        || !reader.read(kSizeWidth, declaredSize)
        || !reader.skip(kProtocolWidth) || !reader.skip(kBuildWidth) || !reader.skip(kBuildWidth)
        || !reader.skip(kExecutableWidth)) {
        return false;
    }

    if (containerPayload.size() > output.size()) {
        return false;
    }
    std::copy(containerPayload.begin(), containerPayload.end(), output.begin());
    // The 64 sessionId bits ride low byte first (read_raw_u64's order), each byte
    // most-significant-bit first in the stream - write_raw_u64's exact inverse.
    for (std::size_t index = 0; index < 8; ++index) {
        const unsigned char group = static_cast<unsigned char>((machineId >> (index * 8)) & 0xFFU);
        for (std::size_t bit = 0; bit < 8; ++bit) {
            const std::size_t position = kSessionIdBitOffset + index * 8 + bit;
            const std::size_t byteIndex = position / 8;
            const unsigned char mask = static_cast<unsigned char>(0x80U >> (position % 8));
            const unsigned char byteValue = std::to_integer<unsigned char>(output[byteIndex]);
            const unsigned char replacement = ((group >> (7 - bit)) & 1U) != 0
                                                  ? static_cast<unsigned char>(byteValue | mask)
                                                  : static_cast<unsigned char>(byteValue & ~mask);
            output[byteIndex] = std::byte{replacement};
        }
    }
    return true;
}

/**
 * THE JOIN RELAY, re-targeted (p2-183; RE_output/claims/connection-layer-join-delivery.md):
 * forwards one client's whole OOB join container to every OTHER connected peer as a
 * STANDALONE CONTAINER DATAGRAM - the channel the join lives on in both directions.
 * The client sends its own joins as OOB containers (this host receives them in
 * consume_container as whole payloads), and the client's connection-layer switch
 * 0x1416E0940 is reachable ONLY from the OOB container consumer 0x1416E2A90 - so the
 * p2-181 reliable-queue delivery could never reach the join gate. Two defects, both
 * fixed here: the channel (OOB datagram via send_transport, like connect-responses)
 * and the declared size (the client's own header carries 1536; the old relay declared
 * 6144, outside any registry range check).
 *
 * The sender's container is forwarded BYTE-VERBATIM: marker, message header
 * (id 10, declared size 0x600), body and terminator are a client-authored join - the
 * receiving client's OOB parse rebuilds its packet record from the same wire fields
 * the original sender produced (instance nonce, the +0x10 session key the join gate
 * 0x1416E0460 looks sessions up by). The per-link transport envelope (channel id,
 * sequences, encryption) is added by send_transport, exactly as for the
 * connect-responses this host already delivers and clients accept.
 * @param from Peer endpoint the join arrived from (excluded from the relay).
 * @param containerPayload Whole decrypted OOB container payload (marker .. terminator).
 */
void relay_join_body(const gp::Endpoint& from,
                     std::span<const std::byte> containerPayload) noexcept {
    if (containerPayload.empty()) {
        report(core::log::Level::warn,
               "ev=gameplay stage=join_relay result=skip reason=empty");
        return;
    }
    /** The OOB gateway caps one container at 5120 bytes (peer_container.h); the observed
     *  join container is ~149. Bound the relay at the capture bound - any join that fits
     *  the client's own framing fits this. */
    static constexpr std::size_t kRelayMaxBytes = kJoinCaptureBytes;
    if (containerPayload.size() > kRelayMaxBytes) {
        report(core::log::Level::warn,
               "ev=gameplay stage=join_relay result=skip reason=size bytes=%zu",
               containerPayload.size());
        return;
    }

    // Collect targets under the lock; send outside it (send_transport writes and the
    // 09-05 lesson keeps blocking calls out of held locks).
    std::array<gp::Endpoint, gp::kAssociationCapacity> targets{};
    std::size_t targetCount = 0;
    {
        AcquireSRWLockExclusive(&g_lock);
        for (const gp::PeerLink& peer : g_peers) {
            if (peer.stage == gp::PeerStage::absent || same_endpoint(peer.endpoint, from)) {
                continue;
            }
            targets[targetCount++] = peer.endpoint;
        }
        ReleaseSRWLockExclusive(&g_lock);
    }

    unsigned sentPeers = 0;
    unsigned retargeted = 0;
    // THE RELAY CHANNEL (relayJoinEngineChannel, p2-191): the join gate walks the
    // container of the packet's OWN connection ([ctx+0x28], disasm-verified). The
    // dtls association's client-side container is nearly empty (p2-190f: one slot,
    // blob 0 - every key value refused there); the rich container (the client's own
    // landing bindings, forkSession blob matching) lives on the ENGINE association.
    // False (default) = the old dtls-first path; true = engine association first,
    // dtls fallback.
    const bool retarget = core::settings::get().server.gameplay.relayJoinTargetIdentity;
    const bool engineChannel = core::settings::get().server.gameplay.relayJoinEngineChannel;
    // Channel-selected send: engine-first when the container fix is on, else the
    // legacy order. Same payload either way - only the carrier association changes.
    const auto send_relay = [engineChannel](const gp::Endpoint& to,
                                             std::span<const std::byte> payload) {
        return engineChannel
                   ? (association::send_payload(to, payload) || dtls::send_payload(to, payload))
                   : send_transport(to, payload);
    };
    for (std::size_t i = 0; i < targetCount; ++i) {
        // One datagram per peer, no retry here: the OOB channel is best-effort and the
        // peer re-joins on any silence (FINDINGS 20.119), so a lost relay re-arms within
        // the channel's own rebuild cycle.
        std::uint64_t retargetValue = 0;
        if (retarget) {
            retargetValue = peer_join_id(targets[i]);
        }
        if (retargetValue != 0) {
            std::array<std::byte, kJoinCaptureBytes> rewritten{};
            if (rewrite_join_session_id(containerPayload, retargetValue, rewritten)) {
                const bool sent = send_relay(
                    targets[i],
                    std::span<const std::byte>(rewritten.data(), containerPayload.size()));
                if (sent) {
                    ++sentPeers;
                    ++retargeted;
                }
                report(core::log::Level::info,
                       "ev=gameplay stage=join_relay_target result=%s peer=%u "
                       "retarget=0x%016llX bytes=%zu",
                       sent ? "sent" : "fail",
                       static_cast<unsigned>(targets[i].port),
                       static_cast<unsigned long long>(retargetValue),
                       containerPayload.size());
                continue;
            }
            report(core::log::Level::warn,
                   "ev=gameplay stage=join_relay_target result=verbatim reason=parse peer=%u",
                   static_cast<unsigned>(targets[i].port));
        }
        if (send_relay(targets[i], containerPayload)) {
            ++sentPeers;
        }
    }
    report(core::log::Level::info,
           "ev=gameplay stage=join_relay result=%s peers=%u retargeted=%u bytes=%zu channel=%s",
           sentPeers != 0 ? "sent" : "none",
           sentPeers,
           retargeted,
           containerPayload.size(),
           engineChannel ? "engine" : "dtls");
}

/**
 * Consumes one out-of-band message container.
 * @param from Peer endpoint.
 * @param payload Whole decrypted payload.
 * @param now Monotonic tick count.
 */
void consume_container(const gp::Endpoint& from,
                       std::span<const std::byte> payload,
                       std::uint64_t now) noexcept {
    bits::Reader reader(payload);
    if (!wire::read_marker(reader)) {
        return;
    }
    for (;;) {
        wire::MessageHeader header{};
        bool present = false;
        if (!wire::read_header(reader, header, present)) {
            report(core::log::Level::debug, "ev=gameplay stage=oob result=drop reason=header");
            return;
        }
        if (!present) {
            return;
        }
        // The join relay (FINDINGS 20.309) forwards the join message's own bits - from
        // the end of this header to the end of the container - so the whole chain below
        // is captured BEFORE any body decode moves the reader.
        bits::Reader bodyReader = reader;
        if (header.id == static_cast<std::uint8_t>(wire::ConnectId::ping)) {
            if (!answer_ping(from, reader)) {
                return;
            }
            continue;
        }
        if (header.id == static_cast<std::uint8_t>(wire::ConnectId::packetsDiscarded)) {
            std::uint8_t discarded = 0;
            if (!wire::read_packets_discarded(reader, discarded)) {
                return;
            }
            report(core::log::Level::debug,
                   "ev=gameplay stage=discarded result=read packets=%u",
                   static_cast<unsigned>(discarded));
            continue;
        }
        if (header.id == static_cast<std::uint8_t>(wire::ConnectId::mayday)) {
            wire::MaydayBody mayday{};
            if (!wire::read_mayday(reader, mayday)) {
                return;
            }
            report(core::log::Level::warn,
                   "ev=gameplay stage=mayday result=read session=0x%016llX code=%u",
                   static_cast<unsigned long long>(mayday.sessionId),
                   static_cast<unsigned>(mayday.code));
            continue;
        }
        if (header.id == static_cast<std::uint8_t>(wire::ConnectId::request)) {
            wire::ConnectRequest request{};
            if (!wire::read_request(reader, request)) {
                return;
            }
            answer_connect(from, request, now);
            continue;
        }
        if (header.id == static_cast<std::uint8_t>(wire::JoinId::request)) {
            wire::JoinRequest request{};
            if (wire::read_join_request(reader, request)) {
                // The identity table sits directly behind the admission prefix. Its first entry
                // names the sender's own address, so a decode that disagrees with the datagram's
                // source is a wrong parse and publishes nothing (fail-safe to the stand-in).
                wire::JoinMachineIdentity identity{};
                const bool identified = wire::read_join_machine_identity(reader, identity);
                // The self-check accepts EITHER NetAddr pair: the first may carry the
                // machine's cached pre-network-move address while the second names the
                // current one (p2-188: mac .164 stale / .7 current; the rig's agree).
                const bool firstPair = identity.address == from.address
                                       && identity.port == from.port;
                const bool secondPair = identity.address2 == from.address
                                        && identity.port2 == from.port;
                const bool selfcheck = identified && (firstPair || secondPair);
                report(core::log::Level::info,
                       "ev=gameplay stage=identity result=%s tag=%u addr=0x%08X port=%u "
                       "addr2=0x%08X port2=%u "
                       "machine=0x%016llX machine_rev=0x%016llX selfcheck=%s",
                       !identified ? "absent"
                       : selfcheck ? "ok"
                                   : "mismatch",
                       static_cast<unsigned>(identity.entryTag),
                       identity.address,
                       static_cast<unsigned>(identity.port),
                       identity.address2,
                       static_cast<unsigned>(identity.port2),
                       static_cast<unsigned long long>(identity.machineId),
                       static_cast<unsigned long long>(identity.machineIdReversed),
                       selfcheck ? "ok" : "fail");
                answer_join(from, request,
                            identified && selfcheck ? identity.machineId : 0);
                // THE JOIN RELAY (FINDINGS 20.309, settings-gated, default off = the off
                // path is byte-identical): forward the WHOLE join body - the admission
                // prefix, the identity table and the address/player tables - to every
                // other connected peer's reliable outbound queue. The receiving client's
                // host-side join gate then processes the peer's join and creates the
                // peer's reservation record inside a proper container, which stamps the
                // record's participant-mask bit from the container's field (0/1 -> bits
                // 6/7) instead of the containerless birth (field -1 -> bit 5) that every
                // boot measures and the guard can never match.
                if (core::settings::get().server.gameplay.relayPeerJoin) {
                    // p2-183: the WHOLE container payload (marker .. terminator) goes out
                    // verbatim on the OOB datagram channel - see relay_join_body.
                    relay_join_body(from, payload);
                }
            }
            // The rest of the request is address and player tables this host does not decode,
            // so no later message in this container can be located.
            capture_join_container(from, payload, reader);
            return;
        }
        if (header.id == static_cast<std::uint8_t>(wire::ConnectId::closed)) {
            wire::ConnectEnd closed{};
            if (!wire::read_closed(reader, closed)) {
                return;
            }
            // The link goes, the sessions stay. The client rebuilds the channel and rejoins none
            // of them, so releasing their activity host sessions here strands every one.
            drop_endpoint(from);
            report(core::log::Level::info,
                   "ev=gameplay stage=peer result=closed reason=%u",
                   static_cast<unsigned>(closed.reason));
            return;
        }
        if (group::consume(from, session_for_endpoint(from), header.id, reader, now)) {
            continue;
        }
        // A message this host does not decode ends the chain: its body width is unknown, so
        // every message behind it would be read at the wrong offset.
        report(core::log::Level::debug, "ev=gameplay stage=oob result=stop id=%u", header.id);
        return;
    }
}

/**
 * Records one received packet sequence in the acknowledgement history.
 * @param peer Peer receiving the packet.
 * @param sequence Sequence the packet published.
 */
void record_sequence(gp::PeerLink& peer, std::uint16_t sequence) noexcept {
    if (!peer.ringInitialized) {
        peer.ringInitialized = true;
        peer.receiveHead = sequence;
        peer.received = {};
        return;
    }
    // Add the modulus before subtracting. A bare difference is signed and goes negative on a wrap.
    const std::uint16_t advance = static_cast<std::uint16_t>(
        (sequence + gp::kPacketSequenceModulus - peer.receiveHead) % gp::kPacketSequenceModulus);
    if (advance == 0 || advance >= gp::kPacketSequenceHalf) {
        // A repeat or an older packet leaves the published history alone.
        return;
    }
    std::array<bool, gp::kAckHistory> shifted{};
    for (std::size_t index = 0; index < shifted.size(); ++index) {
        // Entry `index` is the packet `index + 1` before the new head, so the old head lands at
        // `advance - 1`. Anything newer than the old head and older than this packet was skipped.
        if (index + 1 < advance) {
            continue;
        }
        if (index + 1 == advance) {
            shifted[index] = true;
            continue;
        }
        const std::size_t source = index - advance;
        shifted[index] = source < peer.received.size() && peer.received[source];
    }
    peer.received = shifted;
    peer.receiveHead = sequence;
}

/**
 * Applies one reassembled reliable message.
 * @param peer Peer that sent it, held under the lock.
 * @param message Reassembled message and its inner header.
 */
void apply_message(gp::PeerLink& peer, const wire::AssembledMessage& message) noexcept {
    if (message.id == static_cast<std::uint8_t>(wire::ConnectId::establish)
        && peer.stage == gp::PeerStage::connecting) {
        // The reliable establish is what moves a connected peer past the out-of-band pair.
        peer.stage = gp::PeerStage::connected;
    }
}

/**
 * Clears the send queue once the peer acknowledges the packet that carried it.
 * @param peer Peer whose acknowledgement arrived, held under the lock.
 * @param ack Acknowledgement state the packet published.
 * @return True when this acknowledgement emptied the queue.
 */
bool apply_acknowledgement(gp::PeerLink& peer, const wire::AckState& ack) noexcept {
    if (!peer.outbound.awaitingAcknowledgement
        || !wire::acknowledgement_covers(ack, peer.outbound.sentInPacket)) {
        return false;
    }
    // The peer has the packet, so every fragment in it is delivered. The next sequence is kept
    // because message sequences continue across messages.
    for (gp::OutboundFragment& fragment : peer.outbound.fragments) {
        fragment = {};
    }
    peer.outbound.count = 0;
    peer.outbound.awaitingAcknowledgement = false;
    return true;
}

/**
 * Dumps one undecoded assembled message's identity and the first 48 body bytes as hex.
 * The dump starts at the body's CONTAINING byte; the message's bit offset is logged so
 * the reader can shift. Body bytes past the assembled window are skipped, not wrapped.
 * @param body The assembled message the group layer could not decode.
 */
void dump_body(const wire::AssembledMessage& body) noexcept {
    constexpr std::size_t kDumpBytes = 48;
    constexpr char kHexDigits[] = "0123456789abcdef";
    const std::size_t bodyByte = body.bodyBitOffset / 8;
    std::size_t dumpLen = kDumpBytes;
    if (bodyByte >= gp::kReassemblyCapacity) {
        dumpLen = 0;
    } else if (bodyByte + dumpLen > gp::kReassemblyCapacity) {
        dumpLen = gp::kReassemblyCapacity - bodyByte;
    }
    std::array<char, 64 + kDumpBytes * 2> text{};
    const int written = std::snprintf(text.data(), text.size(),
                                      "ev=gameplay stage=body id=%u declared=%u bits=%zu "
                                      "body_bit=%zu hex=",
                                      static_cast<unsigned>(body.id),
                                      body.declaredSize, body.bitCount, body.bodyBitOffset);
    if (written <= 0 || static_cast<std::size_t>(written) >= text.size()) {
        return;
    }
    for (std::size_t index = 0; index < dumpLen; ++index) {
        const unsigned value = std::to_integer<unsigned>(body.bytes[bodyByte + index]);
        text[static_cast<std::size_t>(written) + index * 2] = kHexDigits[value >> 4];
        text[static_cast<std::size_t>(written) + index * 2 + 1] = kHexDigits[value & 0xF];
    }
    const std::size_t hexEnd = static_cast<std::size_t>(written) + dumpLen * 2;
    report(core::log::Level::debug, "%.*s", static_cast<int>(hexEnd), text.data());
}

/**
 * Consumes one established packet.
 * @param from Peer endpoint.
 * @param payload Whole decrypted payload.
 * @param now Monotonic tick count.
 */
void consume_established(const gp::Endpoint& from,
                         std::span<const std::byte> payload,
                         std::uint64_t now) noexcept {
    wire::EstablishedPacket packet{};
    if (!wire::decode_established(payload, false, packet)) {
        report(core::log::Level::debug, "ev=gameplay stage=packet result=drop reason=grammar");
        return;
    }
    std::array<std::uint8_t, kMessageReportCapacity> delivered{};
    std::size_t deliveredCount = 0;
    unsigned stage = 0;
    bool queueCleared = false;
    std::uint16_t clearedPacket = 0;
    std::uint64_t sessionId = 0;
    // The reliable window never resynchronises, so a stalled queue is only visible as a refused
    // record against the sequence it is still waiting for.
    std::size_t largeDropped = 0;
    std::uint16_t largeNext = 0;
    std::uint16_t largeFirst = 0;
    bool peerFound = false;
    bool guardAccepted = false;
    std::uint8_t expectedGuard = 0;
    AcquireSRWLockExclusive(&g_lock);
    gp::PeerLink* peer = find_locked(from);
    std::array<wire::AssembledMessage, kMessageReportCapacity> bodies{};
    if (peer != nullptr) {
        peerFound = true;
        expectedGuard = wire::connection_sequence_low2(peer->remoteConnectionSequence);
        guardAccepted = packet.connectionSequenceLow2 == expectedGuard;
    }
    if (guardAccepted) {
        sessionId = sole_session_locked(*peer);
        if (packet.ack.outboundHeadPresent) {
            record_sequence(*peer, packet.ack.outboundHead);
        }
        // THE APPLICATION-READY BOUNDARY. Reaching here with an accepted channel guard IS the
        // "normal connected packet" the boundary requires: this body is an established packet,
        // not an out-of-band one, and it passed the peer's own connection-sequence check.
        peer->applicationReady = true;
        clearedPacket = peer->outbound.sentInPacket;
        queueCleared = apply_acknowledgement(*peer, packet.ack);
        peer->acknowledgementOwed = true;
        peer->lastTick = now;
        largeDropped = wire::accept_records(packet.large, peer->large);
        largeNext = peer->large.nextSequence;
        largeFirst = packet.large.count == 0 ? 0 : packet.large.records[0].sequence;
        wire::accept_records(packet.small, peer->small);
        wire::AssembledMessage message{};
        while (wire::drain_message(peer->large, message)) {
            apply_message(*peer, message);
            if (deliveredCount < delivered.size()) {
                delivered[deliveredCount] = message.id;
                bodies[deliveredCount] = message;
                ++deliveredCount;
            }
        }
        while (wire::drain_message(peer->small, message)) {
            apply_message(*peer, message);
            if (deliveredCount < delivered.size()) {
                delivered[deliveredCount] = message.id;
                bodies[deliveredCount] = message;
                ++deliveredCount;
            }
        }
        stage = static_cast<unsigned>(peer->stage);
    }
    ReleaseSRWLockExclusive(&g_lock);
    if (!peerFound) {
        return;
    }
    if (!guardAccepted) {
        report(core::log::Level::debug,
               "ev=gameplay stage=packet result=drop reason=channel_low2 got=%u expect=%u",
               static_cast<unsigned>(packet.connectionSequenceLow2),
               static_cast<unsigned>(expectedGuard));
        return;
    }
    for (std::size_t index = 0; index < deliveredCount; ++index) {
        report(core::log::Level::info,
               "ev=gameplay stage=message result=ok id=%u peerstage=%u",
               static_cast<unsigned>(delivered[index]),
               stage);
        // The connect establish belongs to this layer and apply_message already took it, so
        // handing it to the group layer would only report it as undecoded on every connection.
        const wire::AssembledMessage& body = bodies[index];
        if (body.id == static_cast<std::uint8_t>(wire::ConnectId::establish)) {
            continue;
        }
        // Group handling runs outside the lock because answering takes it again.
        bits::Reader reader({body.bytes.data(), gp::kReassemblyCapacity});
        if (reader.skip(body.bodyBitOffset)
            && !group::consume(from, sessionId, body.id, reader, now)) {
            report(core::log::Level::debug,
                   "ev=gameplay stage=message result=undecoded id=%u",
                   static_cast<unsigned>(body.id));
            // The undecoded BODY dump. The established-plane census left exactly one
            // unidentified id (37, post-join + periodic); its body shape - a 4-byte
            // count versus a 1024-byte bitmap - is what discriminates "37 is the
            // entity-index pool request" from "37 is housekeeping" without a pcap.
            // The dump starts at the body's CONTAINING byte; body_bit carries the
            // sub-byte offset for exact alignment.
            dump_body(body);
        }
    }
    if (queueCleared) {
        report(core::log::Level::info,
               "ev=gameplay stage=sendqueue result=cleared packet=%u base=%u entries=%u",
               static_cast<unsigned>(clearedPacket),
               static_cast<unsigned>(packet.ack.receiveHead),
               static_cast<unsigned>(packet.ack.reportedCount));
    }
    report(core::log::Level::debug,
           "ev=gameplay stage=packet result=ok seq=%u base=%u entries=%u large=%u small=%u "
           "first=%u next=%u drop=%zu",
           static_cast<unsigned>(packet.ack.outboundHead),
           static_cast<unsigned>(packet.ack.receiveHead),
           static_cast<unsigned>(packet.ack.reportedCount),
           static_cast<unsigned>(packet.large.count),
           static_cast<unsigned>(packet.small.count),
           static_cast<unsigned>(largeFirst),
           static_cast<unsigned>(largeNext),
           largeDropped);
}

/**
 * Builds and sends one acknowledgement-only packet.
 * @param peer Peer state copied under the lock before the send.
 * @return True when the packet left the endpoint.
 */
[[nodiscard]] bool send_acknowledgement(const gp::PeerLink& peer) noexcept {
    wire::AckState ack{};
    ack.outboundHead = peer.outboundHead;
    ack.outboundHeadPresent = peer.outboundHeadPresent;
    // The peer subtracts this from the decoded sequence to place its receive window. A zero
    // collapses that window and the peer discards every packet.
    ack.headMinusCursor = kMinimumHeadCursor;
    ack.receiveHead = peer.receiveHead;
    ack.ringInitialized = peer.ringInitialized;
    ack.received = peer.received;
    // No round trip is timed, so the delay field carries its sentinel.
    ack.delay = kDelaySentinel;

    std::array<std::byte, kReplyCapacity> buffer{};
    bits::Writer writer(buffer);
    const std::uint8_t guard = wire::connection_sequence_low2(peer.localConnectionSequence);
    std::size_t size = 0;
    // Only the 32-byte queue carries this host's messages; the 6-byte queue stays empty.
    if (!wire::write_head_and_ack(writer, guard, ack) || !wire::write_queue(writer, peer.outbound)
        || !wire::write_empty_queue(writer) || !wire::write_absent_filler(writer)
        || !writer.finish(size)) {
        return false;
    }
    return send_transport(peer.endpoint, {buffer.data(), size});
}

} // namespace

/** Consumes one decrypted transport payload. */
void deliver(const gp::Endpoint& from,
             std::span<const std::byte> payload,
             std::uint64_t now) noexcept {
    if (payload.empty()) {
        return;
    }
    if ((std::to_integer<unsigned>(payload[0]) >> kMarkerShift) != 0) {
        consume_container(from, payload, now);
        return;
    }
    consume_established(from, payload, now);
}

/** Sends one already-encoded out-of-band body in its own container. */
bool send_container(const gp::Endpoint& to,
                    std::uint8_t id,
                    std::uint32_t declaredSize,
                    std::span<const std::byte> body,
                    std::size_t bodyBits) noexcept {
    std::array<std::byte, kReplyCapacity> buffer{};
    bits::Writer writer(buffer);
    const wire::MessageHeader header{id, declaredSize};
    if (!wire::open_container(writer) || !wire::write_header(writer, header)) {
        return false;
    }
    bits::Reader reader(body);
    std::size_t remaining = bodyBits;
    while (remaining != 0) {
        const auto width = static_cast<std::uint8_t>(remaining < kByteBits ? remaining : kByteBits);
        std::uint64_t value = 0;
        if (!reader.read(width, value) || !writer.write(value, width)) {
            return false;
        }
        remaining -= width;
    }
    std::size_t size = 0;
    if (!wire::close_container(writer) || !writer.finish(size)) {
        return false;
    }
    return send_transport(to, {buffer.data(), size});
}

/** Queues one reliable message for a peer. */
bool enqueue_reliable(std::uint64_t sessionId,
                      const gp::Endpoint& endpoint,
                      std::uint8_t id,
                      std::uint32_t declaredSize,
                      std::span<const std::byte> body,
                      std::size_t bodyBits) noexcept {
    AcquireSRWLockExclusive(&g_lock);
    gp::PeerLink* peer = find_session_at_locked(endpoint, sessionId);
    const bool queued =
        peer != nullptr && wire::enqueue_message(peer->outbound, id, declaredSize, body, bodyBits);
    if (queued) {
        // The next service slice carries it, so the acknowledgement path also flushes sends.
        peer->acknowledgementOwed = true;
        // The queue changed, so the packet it was stamped against no longer carries all of it.
        peer->outbound.awaitingAcknowledgement = false;
    }
    ReleaseSRWLockExclusive(&g_lock);
    return queued;
}

/** Reports the NetAddr one peer sent in its own connect request. */
bool remote_address(std::uint64_t sessionId,
                    const gp::Endpoint& endpoint,
                    std::array<std::byte, gp::kNetAddrBlobSize>& output) noexcept {
    AcquireSRWLockShared(&g_lock);
    const gp::PeerLink* peer = find_session_at_locked(endpoint, sessionId);
    const bool present = peer != nullptr && peer->remoteAddressPresent;
    if (present) {
        output = peer->remoteAddress;
    }
    ReleaseSRWLockShared(&g_lock);
    return present;
}

/** Reports whether one endpoint holds a live link at all. */
bool linked(const gp::Endpoint& endpoint) noexcept {
    AcquireSRWLockShared(&g_lock);
    const gp::PeerLink* peer = find_locked(endpoint);
    const bool present = peer != nullptr;
    ReleaseSRWLockShared(&g_lock);
    return present;
}

/** Binds one peer's view signature. */
void bind_view(const gp::Endpoint& from, const gp::ViewSignature& signature) noexcept {
    AcquireSRWLockExclusive(&g_lock);
    // Keyed by endpoint, not by session: the view body carries no session id, and a link holding
    // both a current and a target region resolves no sole session to key it by.
    gp::PeerLink* peer = find_locked(from);
    if (peer != nullptr) {
        peer->view = signature;
    }
    ReleaseSRWLockExclusive(&g_lock);
}

/**
 * Reports whether the peer carrying one session has crossed the application-ready boundary.
 * Mirrors `view_bound`: the link must also be past its connect exchange, or the readiness belongs
 * to a channel the peer has already rebuilt.
 */
bool application_ready(std::uint64_t sessionId, const gp::Endpoint& endpoint) noexcept {
    AcquireSRWLockShared(&g_lock);
    const gp::PeerLink* peer = find_session_at_locked(endpoint, sessionId);
    const bool ready =
        peer != nullptr && peer->applicationReady && peer->stage == gp::PeerStage::connected;
    ReleaseSRWLockShared(&g_lock);
    return ready;
}

/** Reports how far the link carrying one group session has got. */
bool link_stage(std::uint64_t sessionId, gp::PeerStage& stage) noexcept {
    stage = gp::PeerStage::absent;
    AcquireSRWLockShared(&g_lock);
    const gp::PeerLink* peer = find_session_locked(sessionId);
    const bool present = peer != nullptr;
    if (present) {
        stage = peer->stage;
    }
    ReleaseSRWLockShared(&g_lock);
    return present;
}

/** Copies the connect sequences of the link carrying one group session at one endpoint. */
bool link_identity(std::uint64_t sessionId,
                   const gp::Endpoint& endpoint,
                   LinkIdentity& output) noexcept {
    output = {};
    AcquireSRWLockShared(&g_lock);
    const gp::PeerLink* peer = find_session_at_locked(endpoint, sessionId);
    const bool present = peer != nullptr;
    if (present) {
        output.localConnectionSequence = peer->localConnectionSequence;
        output.remoteConnectionSequence = peer->remoteConnectionSequence;
    }
    ReleaseSRWLockShared(&g_lock);
    return present;
}

/** Sends any owed acknowledgement. */
void service(std::uint64_t now) noexcept {
    std::array<gp::PeerLink, gp::kAssociationCapacity> owed{};
    std::size_t count = 0;
    AcquireSRWLockExclusive(&g_lock);
    for (gp::PeerLink& peer : g_peers) {
        // An unacknowledged send queue keeps the packet going out until the peer confirms it.
        // Every packet burns one sequence, so the resend is paced.
        const bool resendDue = peer.outbound.count != 0 && now - peer.lastSend >= kResendInterval;
        // An established link that owes nothing still has to be heard from, or the peer treats it
        // as dead and rebuilds (20.119). Only connected links: anything earlier is still in its
        // connect exchange and has its own retries.
        const bool keepaliveDue =
            peer.stage == gp::PeerStage::connected && now - peer.lastSend >= kKeepaliveInterval;
        const bool due = peer.acknowledgementOwed || resendDue || keepaliveDue;
        const bool keepaliveOnly = keepaliveDue && !peer.acknowledgementOwed && !resendDue;
        if (peer.stage == gp::PeerStage::absent || !due) {
            // INSTRUMENT (p2-115 wedge): the client's packets are consumed but nothing is sent
            // back, so this branch is where the send is being skipped. Log the skip whenever the
            // queue holds fragments or an ack is owed - the two states that must produce a send.
            if (peer.stage != gp::PeerStage::absent
                && (peer.outbound.count != 0 || peer.acknowledgementOwed)) {
                report(core::log::Level::debug,
                       "ev=gameplay stage=svc result=skip count=%zu stage=%d owed=%d "
                       "ready=%d lastSend=%llu now=%llu",
                       peer.outbound.count,
                       static_cast<int>(peer.stage),
                       peer.acknowledgementOwed ? 1 : 0,
                       peer.applicationReady ? 1 : 0,
                       static_cast<unsigned long long>(peer.lastSend),
                       static_cast<unsigned long long>(now));
            }
            continue;
        }
        peer.acknowledgementOwed = false;
        peer.lastSend = now;
        // Only the first send of the current contents is stamped. A resend carries the same
        // fragments, so re-stamping would move the target past what the peer can acknowledge.
        if (peer.outbound.count != 0 && !peer.outbound.awaitingAcknowledgement) {
            peer.outbound.sentInPacket =
                static_cast<std::uint16_t>((peer.outboundHead + 1) % kPacketSequenceModulus);
            peer.outbound.awaitingAcknowledgement = true;
        }
        // The packet sequence advances here so the copy carries the value it will publish.
        peer.outboundHead =
            static_cast<std::uint16_t>((peer.outboundHead + 1) % kPacketSequenceModulus);
        peer.outboundHeadPresent = true;
        peer.lastTick = now;
        if (keepaliveOnly) {
            // Debug, and one per second per peer: it is the only evidence the link is being held
            // open rather than merely quiet, and those two look identical from outside (L13).
            report(core::log::Level::debug,
                   "ev=gameplay stage=keepalive result=sent peer=%u sequence=%u",
                   static_cast<unsigned>(peer.endpoint.port),
                   static_cast<unsigned>(peer.outboundHead));
        }
        owed[count] = peer;
        ++count;
    }
    ReleaseSRWLockExclusive(&g_lock);
    for (std::size_t index = 0; index < count; ++index) {
        if (!send_acknowledgement(owed[index])) {
            report(core::log::Level::debug, "ev=gameplay stage=ack result=fail");
        }
    }
}

/** Unbinds one group session from one endpoint's link. */
void drop(std::uint64_t sessionId, const gp::Endpoint& endpoint) noexcept {
    AcquireSRWLockExclusive(&g_lock);
    gp::PeerLink* const peer = find_session_at_locked(endpoint, sessionId);
    if (peer != nullptr) {
        // The channel outlives the session. A leave names one region, and the client keeps playing
        // the other over the same channel.
        for (std::uint64_t& slot : peer->sessions) {
            if (slot == sessionId) {
                slot = 0;
            }
        }
    }
    ReleaseSRWLockExclusive(&g_lock);
}

/** Drops every link at one endpoint, which is what a connect-closed names. */
void drop_endpoint(const gp::Endpoint& endpoint) noexcept {
    AcquireSRWLockExclusive(&g_lock);
    for (gp::PeerLink& peer : g_peers) {
        if (peer.stage != gp::PeerStage::absent && same_endpoint(peer.endpoint, endpoint)) {
            peer = {};
        }
    }
    ReleaseSRWLockExclusive(&g_lock);
}

/** Drops every peer. */
void reset() noexcept {
    AcquireSRWLockExclusive(&g_lock);
    for (gp::PeerLink& peer : g_peers) {
        peer = {};
    }
    ReleaseSRWLockExclusive(&g_lock);
}

} // namespace sunrise::server::gameplay::peer
