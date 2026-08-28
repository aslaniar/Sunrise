#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "../../encoding/bit_reader.h"
#include "../descriptor/join_descriptor.h"
#include "session_messages.h"

namespace sunrise::middleware::gameplay::group {

/**
 * Peers one composed snapshot can name beyond the host.
 * MEASURED BOUND (RE_output/scratch/l8_regression/test_sizes.cpp): the worst-case body — every
 * peer carrying a player row — is 988 bytes at 7 members (host + 6), the last size that fits the
 * reliable path's kReassemblyCapacity staging buffer (1024). 8 members measure 1128 and would be
 * refused mid-transport, so the composer refuses them first and the bound is provable at compile
 * time against the host's own record capacity.
 */
inline constexpr std::size_t kSnapshotPeerCapacity = 6;

/**
 * One admitted peer as the snapshot builder receives it.
 * The caller resolves every identity against the transport before calling; nothing here talks
 * to it, which is what keeps the composition pure and testable.
 */
struct SnapshotPeer {
    /** Join id the peer's own join request carried. Its entry echoes it, and so does the host's. */
    std::uint64_t joinId{};
    /** Machine identity the peer's join request carried (FINDINGS 20.128). The caller decides
     *  what this publishes - the real id, or the joinId stand-in it replaces - so the composer
     *  writes it verbatim. */
    std::uint64_t machineId{};
    /** Player identity the owning member sent in its player-add. Valid when `hasPlayer`. */
    std::uint64_t playerId{};
    bool hasPlayer{};
    /** Set once the peer reported its join finished. Its entry and the host's move to the top
     *  of the ladder with it; the other entries keep their own states. */
    bool joinComplete{};
    /** Player slot assigned to this peer's player while it holds one. */
    std::uint32_t playerSlot{};
    /** Session player-add counter at the time of the add. The first player of a session gets 0. */
    std::uint32_t addSequence{};
    /** The peer's own NetAddr blob, byte exact as it reached this host. The consumer finds the
     *  peer by address, so a rebuilt blob is not the same bytes. */
    std::array<std::byte, descriptor::kNetAddrSize> address{};
};

/** One composed snapshot and the storage its spans point into. */
struct SnapshotComposition {
    MembershipUpdate update{};
    std::array<MembershipMember, kSnapshotPeerCapacity + 1> members{};
    std::array<MembershipPlayer, kSnapshotPeerCapacity> players{};
};

/**
 * Builds the complete membership snapshot one recipient peer receives.
 * The consumer clears its own table and rebuilds it from this snapshot, finding itself by
 * NetAddr, so the composition names EVERY member of the session, not just the recipient.
 *
 * Member 0 is the host. The host entry echoes the RECIPIENT's join id and takes the recipient's
 * state, which is what the single-peer host published and what ends the recipient's own join:
 * a table that names the recipient's id on exactly two entries, both at the same rung, tells it
 * the join is over once that rung is `established`. Every peer entry carries its own join id,
 * its own byte-exact address blob, and its own ladder rung.
 *
 * @param hostMachineId Machine identity the host publishes (the session's per-region id).
 * @param revision Snapshot revision. Must be at least 1 and strictly increase per publish.
 * @param hostAddress The host's own NetAddr blob, byte exact as it was advertised.
 * @param recipientIndex Index into `peers` of the peer this snapshot is built for.
 * @param peers Every admitted peer of the session, in member-index order.
 * @param output Cleared first, then filled. Its spans point into `output`'s own storage.
 * @return True when the snapshot was composed. False when the recipient index is out of range
 *         or the session outgrows the schema bound.
 */
[[nodiscard]] bool compose_membership_snapshot(
    std::uint64_t hostMachineId,
    std::uint32_t revision,
    const std::array<std::byte, descriptor::kNetAddrSize>& hostAddress,
    std::size_t recipientIndex,
    std::span<const SnapshotPeer> peers,
    SnapshotComposition& output) noexcept;

} // namespace sunrise::middleware::gameplay::group
