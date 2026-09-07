#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "../../../middleware/gameplay/external/external_entity_codec.h"

namespace sunrise::server::gameplay::peer::external_send {

/**
 * The external-body dispatch probe (the peer-render front's step 5c).
 *
 * Builds the fixed four-channel external frame carrying exactly ONE channel-2 entity
 * record: a strict CREATE of the peer's player entity. This is the minimal send that can
 * reach the client's ent_recv interface through the established packet's external body -
 * it is NOT the shipping replication path (the WorldCoordinator owns relevance, deltas,
 * and settle semantics; this probe deliberately bypasses all of it so the first boot
 * answers one question: does the client's receive side dispatch on our body).
 *
 * The record's identity and payload come from the paired-tower dump's descriptor 0
 * (kind 2 = playerBroadcast): payload size 8, baseline bytes fd 87 97 50 21 0f 02 21.
 * The token slot starts at 7 - the first id outside the live 0..6 lease set - pending
 * the femu ent_create fresh-id verdict (the arm decides whether a lease/descriptor must
 * precede this send).
 */

/** The dump's descriptor-0 kind-2 baseline: the local player entity's own create body. */
inline constexpr std::array<std::uint8_t, 8> kPeerBaselineBytes{0xFD, 0x87, 0x97, 0x50,
                                                                0x21, 0x0F, 0x02, 0x21};
/** First entity id outside the six the client already leases (0..6). */
inline constexpr std::uint16_t kPeerEntitySlot = 7;
/** A fresh id carries incarnation 0. */
inline constexpr std::uint8_t kPeerEntityIncarnation = 0;
/** The encoded four-channel wrapper with one create record fits this easily. */
inline constexpr std::size_t kEncodedFrameCapacity = 32;

/** One encoded external body: whole bytes plus the exact trailing bit count. */
struct EncodedFrame {
    std::array<std::byte, kEncodedFrameCapacity> bytes{};
    std::size_t bitCount{};
};

/** Builds the one-record peer-create frame. Fail-closed: never writes partial output. */
[[nodiscard]] bool build_peer_create_frame(
    middleware::gameplay::external::ExternalEntityFrame& frame) noexcept;

/** Encodes the frame to wire bits (the fixed four-channel wrapper). */
[[nodiscard]] bool encode_frame(
    const middleware::gameplay::external::ExternalEntityFrame& frame,
    EncodedFrame& output) noexcept;

/** Builds and encodes in one step. */
[[nodiscard]] bool build_and_encode(EncodedFrame& output) noexcept;

/**
 * Round-trip self test, negative-first: (a) a malformed record (remove flags carrying a
 * baseline) must FAIL the codec's preflight; (b) the real frame must encode, decode back
 * bit-identically, and re-encode to the same bits. Run once before the first send.
 */
[[nodiscard]] bool self_test() noexcept;

} // namespace sunrise::server::gameplay::peer::external_send
