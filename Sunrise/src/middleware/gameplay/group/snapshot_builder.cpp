#include "snapshot_builder.h"

namespace sunrise::middleware::gameplay::group {

namespace {

/** Builds one member row with the connection block the consumer resolves peer links through. */
void fill_member(MembershipMember& member,
                 const std::array<std::byte, descriptor::kNetAddrSize>& address,
                 std::uint64_t machineId,
                 std::uint64_t joinId,
                 MemberState state) noexcept {
    member = {};
    member.address = address;
    member.machineId = machineId;
    member.joinId = joinId;
    member.state = state;
    // The connection group is what makes the consumer resolve the member's peer link. This host
    // has no value for join compatibility or the join timestamp, so both stay cleared.
    member.connectionPresent = true;
}

/** @return The state one admitted peer's entries publish. */
[[nodiscard]] MemberState peer_state(bool joinComplete) noexcept {
    return joinComplete ? MemberState::established : MemberState::ready;
}

} // namespace

/** Builds the complete membership snapshot one recipient peer receives. */
bool compose_membership_snapshot(
    std::uint64_t hostMachineId,
    std::uint32_t revision,
    const std::array<std::byte, descriptor::kNetAddrSize>& hostAddress,
    std::size_t recipientIndex,
    std::span<const SnapshotPeer> peers,
    SnapshotComposition& output) noexcept {
    if (recipientIndex >= peers.size() || peers.size() > kSnapshotPeerCapacity
        || peers.size() + 1 > kMemberCapacity || revision == 0) {
        return false;
    }
    const SnapshotPeer& recipient = peers[recipientIndex];
    const MemberState recipientState = peer_state(recipient.joinComplete);

    // Cleared whole, so no span from a previous composition survives a refused rebuild.
    output = {};

    std::size_t playerCount = 0;

    // The host entry. Its join id and state are the recipient's, so the recipient's id appears
    // on exactly two entries and both move up the ladder with it. Once the recipient's own join
    // finished, both read `established`, which is what stops it re-sending that report.
    fill_member(
        output.members[0], hostAddress, hostMachineId, recipient.joinId, recipientState);

    for (std::size_t index = 0; index < peers.size(); ++index) {
        const SnapshotPeer& peer = peers[index];
        MembershipMember& member = output.members[index + 1];
        // The peer's own machine id - real or stand-in, the caller's decision - now that the
        // join-request identity table names it (FINDINGS 20.128).
        fill_member(member, peer.address, peer.machineId, peer.joinId, peer_state(peer.joinComplete));
        if (peer.hasPlayer) {
            member.ownsPlayerSlot = true;
            member.playerSlot = peer.playerSlot;
            MembershipPlayer& player = output.players[playerCount];
            player.slot = peer.playerSlot;
            player.playerId = peer.playerId;
            // The member index of this peer in THIS snapshot. The consumer resolves a player to
            // its owning member through it.
            player.memberIndex = static_cast<std::uint32_t>(index + 1);
            player.addSequence = peer.addSequence;
            ++playerCount;
        }
    }

    output.update.hostMachineId = hostMachineId;
    output.update.revision = revision;
    output.update.hostMemberIndex = 0;
    output.update.successionIndex = 0;
    output.update.members = {output.members.data(), peers.size() + 1};
    output.update.players = {output.players.data(), playerCount};
    return true;
}

} // namespace sunrise::middleware::gameplay::group
