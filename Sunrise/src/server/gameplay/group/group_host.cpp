#include "group_host.h"

#include <Windows.h>

#include <array>
#include <atomic>

#include "../../../core/settings/settings.h"
#include "../../../state/runtime/runtime.h"
#include "../../../middleware/gameplay/descriptor/join_descriptor.h"
#include "../../../middleware/gameplay/group/member_messages.h"
#include "../../../middleware/gameplay/group/parameter_messages.h"
#include "../../../middleware/gameplay/group/parameter_registry.h"
#include "../../../middleware/gameplay/group/session_messages.h"
#include "../../../middleware/gameplay/group/snapshot_builder.h"
#include "../../../middleware/gameplay/group/session_state.h"
#include "../../../middleware/gameplay/group/view_message.h"
#include "../../../state/activity/runtime.h"
#include "../endpoint/gameplay_endpoint.h"
#include "../gameplay_log.h"
#include "../peer/peer_transport.h"
#include "group_host_sessions.h"
#include "group_migration_receipts.h"

namespace sunrise::server::gameplay::group {

namespace {

namespace wire = middleware::gameplay::group;
namespace bits = middleware::encoding::bits;
namespace descriptor = middleware::gameplay::descriptor;

/** One reliable body staged before it is split into fragments. */
constexpr std::size_t kBodyCapacity = 128;
/** A membership snapshot is far larger. The real bound is the reliable path's staging buffer,
 *  which enqueue_message stages every body into before fragmenting - a body past it fails there,
 *  so the buffer here must not be the thing that runs out first. MEASURED: the worst snapshot
 *  this host can compose (kSnapshotPeerCapacity peers, every one carrying a player) is 988 bytes
 *  (RE_output/scratch/l8_regression/test_sizes.cpp). */
constexpr std::size_t kMembershipBodyCapacity = state::gameplay::kReassemblyCapacity;
/** Only the low 25 bitmap bits name a registry parameter. */
constexpr std::uint64_t kParameterMaskBits = 0x1FFFFFF;
/** Hex characters of the captured parameter-request body, plus its terminator. */
constexpr std::size_t kRequestCaptureCapacity = 513;
/** Room for every registry name plus its separators. */
constexpr std::size_t kParameterNameCapacity = 640;
/** Member index this host takes, and the index it nominates to succeed it. */
constexpr std::uint32_t kHostMemberIndex = 0;
/** Registry index the join-latch update names. Any of the 25 would do; none is ever filled. */
constexpr std::uint8_t kJoinLatchParameter = 0;
/** Admitted (session, endpoint) records this host tracks at once. Two clients hold two
 *  public sessions each at most (four live records), and a rebuild rebinds its record rather
 *  than allocating. Capped at the snapshot composer's peer bound, so one session can never
 *  outgrow the membership body the transport can carry - proven by the static_assert below. */
constexpr std::size_t kAdmittedCapacity = 6;

static_assert(kAdmittedCapacity <= wire::kSnapshotPeerCapacity,
              "one session's records must all fit in one composed membership snapshot");
/** Loopback address the BAP listener binds, in host order. */
constexpr std::uint32_t kLoopbackAddress = 0x7F000001;
/** Every member index the `activity-host` parameter covers. The peer needs its own bit set. */
constexpr std::uint32_t kAllMembers = 0xFFFFFFFF;
/** Shortest gap between two retries of an owed publish. */
constexpr std::uint64_t kRetryInterval = 250;

/** One admitted peer and the player it asked this host to add. */
struct Admitted {
    state::gameplay::Endpoint endpoint{};
    std::uint64_t joinId{};
    /** Machine identity the peer's join request carried (FINDINGS 20.128). Stable for the
     *  peer's whole boot; zero when its identity table did not decode. */
    std::uint64_t machineId{};
    std::uint64_t playerId{};
    /** Group-session id the peer named in its join request, which its parameters must echo. */
    std::uint64_t sessionId{};
    bool occupied{};
    bool hasPlayer{};
    /** Set once the peer reports its join finished, which is what promotes it to `established`. */
    bool joinComplete{};
    /** Set once a snapshot carrying that promotion is on the peer's reliable channel. */
    bool joinPublished{};
    /** Set once the `activity-host` parameter is on the peer's reliable channel. */
    bool activityHostPublished{};
    /** Set once a snapshot naming the peer's player is on that channel. The queue can refuse it. */
    bool playerPublished{};
    /** Set when the session's composition changed after this record's last queued snapshot, so
     *  it is owed a fresh complete one. Another peer joining or leaving, or another peer's
     *  player changing, marks every record of the session. */
    bool snapshotOwed{};
    /** Player slot this record's player holds while `hasPlayer`. Assigned on the first add and
     *  kept, so a remove-and-re-add reuses the row the client's table already knows. */
    std::uint32_t playerSlot{};
    /** Session player-add counter at the time of the add. The first player of a session gets 0. */
    std::uint32_t addSequence{};
    /** Tick of the last retry, so a full queue is retried on a timer rather than every packet. */
    std::uint64_t lastRetry{};
    /** Set while a publish is being held for the application-ready boundary, so it logs once. */
    bool readyHeld{};
    /** Order in which the peer last named this session. The lowest is the least recently used. */
    std::uint64_t lastUse{};
};

/**
 * Public group sessions the peer holds at once: one current and one target.
 * The peer resolves a session through a two-element array, so a third is one it left.
 */
constexpr std::size_t kPublicSessionCapacity = 2;

/** Revision of the last published snapshot. The consumer refuses one that does not increase. */
std::atomic<std::uint32_t> g_membershipRevision{0};
/** Snapshots that may emit the full variant table. One is enough to read the answer; the cap
 *  exists because a rejected body republishes at kRetryInterval and would flood the log. */
constexpr std::uint32_t kVariantLogBudget = 2;
/** Snapshots that have emitted it. */
std::atomic<std::uint32_t> g_variantsLogged{0};
/** Stamps `Admitted::lastUse`. It only has to order the records, so it never has to be a clock. */
std::atomic<std::uint64_t> g_admitClock{0};
/** Guards the admitted table against the worker and the callback pump. */
SRWLOCK g_admittedLock{SRWLOCK_INIT};
/** Admitted peers. A join claims a slot and a leave never reclaims one in this POC. */
std::array<Admitted, kAdmittedCapacity> g_admitted{};

/** Member state this host publishes for every member carrying the join id. */
constexpr wire::MemberState kJoinMemberState = wire::MemberState::ready;

// Three peer checks pin this to exactly `ready`. The joining peer's entry must be at least
// `joined`, must not be `established`, and the request waits until every member carrying the
// join id reads `ready`.
static_assert(static_cast<std::uint8_t>(kJoinMemberState)
                  >= static_cast<std::uint8_t>(wire::MemberState::joined),
              "the published member state must clear the peer's own join bar");
static_assert(kJoinMemberState == wire::MemberState::ready,
              "the request advances only when every member carrying the join id reads ready");

/**
 * Sends one reliable group-session message.
 * @param sessionId Group session whose reliable channel carries it.
 * @param id Registry message id.
 * @param declaredSize Decoded structure size the registry declares.
 * @param write Callback that writes the body.
 * @return True when the message was queued.
 */
template <typename Body>
[[nodiscard]] bool send_reliable(std::uint64_t sessionId,
                                 const state::gameplay::Endpoint& endpoint,
                                 std::uint8_t id,
                                 std::uint32_t declaredSize,
                                 Body write) noexcept {
    std::array<std::byte, kBodyCapacity> body{};
    bits::Writer writer(body);
    std::size_t size = 0;
    if (!write(writer) || !writer.finish(size)) {
        return false;
    }
    return peer::enqueue_reliable(
        sessionId, endpoint, id, declaredSize, {body.data(), size}, writer.bit_count());
}

/** @return True when two endpoints name the same address and port. */
[[nodiscard]] bool same_endpoint(const state::gameplay::Endpoint& left,
                                 const state::gameplay::Endpoint& right) noexcept {
    return left.address == right.address && left.port == right.port;
}

/**
 * Finds or claims the record for one peer, and binds it to that peer's endpoint.
 * Admission is what establishes ownership, so this rebinds an existing record. A client that
 * rebuilds its channel arrives from a new port and joins the same session again.
 * @param peer Peer endpoint.
 * @param sessionId Group session the record is keyed by. Zero claims nothing.
 * @return Record for that session, or null when the table is full.
 */
[[nodiscard]] Admitted* claim(const state::gameplay::Endpoint& peer,
                              std::uint64_t sessionId) noexcept {
    if (sessionId == 0) {
        return nullptr;
    }
    // Keyed by session AND endpoint, because two peers can join one session and each keeps its
    // own record. A channel rebuild rebinds instead: it arrives from the SAME source port
    // (measured, p2(81): every rebuilt connect named the client's original port), so the
    // (session, endpoint) match finds it.
    const std::uint64_t use = g_admitClock.fetch_add(1) + 1;
    for (Admitted& entry : g_admitted) {
        if (entry.occupied && entry.sessionId == sessionId && same_endpoint(entry.endpoint, peer)) {
            entry.lastUse = use;
            return &entry;
        }
    }
    for (Admitted& entry : g_admitted) {
        if (entry.occupied && entry.sessionId == sessionId && !peer::linked(entry.endpoint)) {
            // A rebuild from a port this host never saw: the old link is gone, the session is the
            // same. Rebind the record so the session does not double-count the departed endpoint.
            entry.endpoint = peer;
            entry.lastUse = use;
            return &entry;
        }
    }
    for (Admitted& entry : g_admitted) {
        if (!entry.occupied) {
            entry.occupied = true;
            entry.endpoint = peer;
            entry.sessionId = sessionId;
            entry.lastUse = use;
            return &entry;
        }
    }
    return nullptr;
}

/**
 * Finds the record for one session and proves the sender owns it.
 * Every later message names its own session in its body, so without this a peer could name a
 * session another endpoint was admitted for and move that session's state.
 * @param peer Peer endpoint the message arrived from.
 * @param sessionId Group session the message named.
 * @return Record for that session, or null when it is absent or owned by another endpoint.
 */
[[nodiscard]] Admitted* claim_owned(const state::gameplay::Endpoint& peer,
                                    std::uint64_t sessionId) noexcept {
    if (sessionId == 0) {
        return nullptr;
    }
    const std::uint64_t use = g_admitClock.fetch_add(1) + 1;
    for (Admitted& entry : g_admitted) {
        // Scan every record: with two peers on one session the first session match can be the
        // other endpoint's, and returning null for this one would drop its whole join.
        if (entry.occupied && entry.sessionId == sessionId && same_endpoint(entry.endpoint, peer)) {
            entry.lastUse = use;
            return &entry;
        }
    }
    return nullptr;
}

/**
 * Tests whether one endpoint was admitted for one session.
 * With two peers on one session this is the ownership test: a session-scoped message only moves
 * the record of the endpoint that sent it, and an endpoint that holds no record for the session
 * it names has no business moving anyone's state.
 * @param peer Peer endpoint the message arrived from.
 * @param sessionId Group session the message named.
 * @return True when a record holds that session for this endpoint.
 */
[[nodiscard]] bool holds_session(const state::gameplay::Endpoint& peer,
                                 std::uint64_t sessionId) noexcept {
    AcquireSRWLockShared(&g_admittedLock);
    bool held = false;
    for (const Admitted& entry : g_admitted) {
        if (entry.occupied && entry.sessionId == sessionId && same_endpoint(entry.endpoint, peer)) {
            held = true;
            break;
        }
    }
    ReleaseSRWLockShared(&g_admittedLock);
    return held;
}

/**
 * Marks every record of one session as owed a fresh complete snapshot.
 * The consumer clears its own table and rebuilds it from each snapshot, so a composition change
 * (a peer joining, leaving, or changing its player) is only visible to the others once they
 * receive a snapshot naming it. The acting record is marked too: its next queued snapshot is
 * the same complete one it needs either way.
 * @param sessionId Group session whose records are marked. Caller holds the admitted lock.
 */
void mark_session_dirty(std::uint64_t sessionId) noexcept {
    for (Admitted& entry : g_admitted) {
        if (entry.occupied && entry.sessionId == sessionId) {
            entry.snapshotOwed = true;
        }
    }
}

/**
 * Publishes one snapshot naming this host, one admitted peer, and that peer's player if it has
 * one. The caller holds the admitted lock.
 * @param record Admitted peer the snapshot names.
 * @return True when the snapshot was queued on the peer's reliable channel.
 */
/**
 * Reports whether anything important may be published to one peer yet, logging each transition.
 *
 * THE APPLICATION-READY BOUNDARY (FINDINGS 20.118, handbook 18.5/18.6). The establish exchange
 * alone does not cross it: before the peer sends one normal connected packet, the transport
 * ACKNOWLEDGES reliable records without the application DISPATCHING their group messages. A
 * membership snapshot published early is therefore acked, never delivered, and the peer re-joins
 * on a timer having never seen it - measured as a ~21.7 s re-join cycle on a SINGLE client.
 * An acknowledgement is not proof of dispatch, so nothing here may rely on the queue accepting.
 *
 * Refusing leaves the publish owed, and `service` retries it on its own timer.
 * @param record Admitted peer whose publish is being considered. Caller holds the admitted lock.
 * @return True when the peer may receive membership and parameter records.
 */
[[nodiscard]] bool may_publish(Admitted& record) noexcept {
    if (peer::application_ready(record.sessionId, record.endpoint)) {
        if (record.readyHeld) {
            record.readyHeld = false;
            report(core::log::Level::info,
                   "ev=gameplay stage=publish result=released reason=application_ready "
                   "session=0x%016llX",
                   static_cast<unsigned long long>(record.sessionId));
        }
        return true;
    }
    if (!record.readyHeld) {
        record.readyHeld = true;
        report(core::log::Level::info,
               "ev=gameplay stage=publish result=held reason=not_application_ready "
               "session=0x%016llX",
               static_cast<unsigned long long>(record.sessionId));
    }
    return false;
}

[[nodiscard]] bool publish_snapshot(Admitted& record) noexcept {
    if (!may_publish(record)) {
        return false;
    }
    // Every admitted record of this session, in array order, which is the member-index order the
    // snapshot publishes. The recipient is one of them.
    std::array<wire::SnapshotPeer, kAdmittedCapacity> peers{};
    std::size_t peerCount = 0;
    std::size_t recipient = kAdmittedCapacity;
    for (const Admitted& entry : g_admitted) {
        if (!entry.occupied || entry.sessionId != record.sessionId) {
            continue;
        }
        wire::SnapshotPeer& peer = peers[peerCount];
        peer.joinId = entry.joinId;
        // The real machine id the peer's join request carried, behind the switch; the switch
        // off (or an undecoded identity) restores the joinId stand-in byte for byte.
        peer.machineId =
            core::settings::get().server.gameplay.publishJoinMachineIds && entry.machineId != 0
                ? entry.machineId
                : entry.joinId;
        peer.playerId = entry.playerId;
        peer.hasPlayer = entry.hasPlayer;
        peer.joinComplete = entry.joinComplete;
        peer.playerSlot = entry.playerSlot;
        peer.addSequence = entry.addSequence;
        // The peer's own blob is echoed byte exact. A blob rebuilt from the endpoint it arrived
        // from is not the same bytes.
        if (!peer::remote_address(record.sessionId, entry.endpoint, peer.address)) {
            descriptor::write_net_addr(entry.endpoint.address, entry.endpoint.port, peer.address);
        }
        if (&entry == &record) {
            recipient = peerCount;
        }
        ++peerCount;
    }
    if (recipient == kAdmittedCapacity) {
        return false;
    }

    const state::gameplay::Endpoint host = endpoint::advertised();
    std::array<std::byte, descriptor::kNetAddrSize> hostAddress{};
    descriptor::write_net_addr(host.address, host.port, hostAddress);
    wire::SnapshotComposition composition{};
    if (!wire::compose_membership_snapshot(record.sessionId,
                                           g_membershipRevision.fetch_add(1) + 1,
                                           hostAddress,
                                           recipient,
                                           {peers.data(), peerCount},
                                           composition)) {
        return false;
    }
    // FINDINGS 20.151/20.152 (ms-start-gate2/3): the client derives per-peer activity-
    // setup-complete from member-record flag bytes at record +181/+183 (the gate's +0xED/
    // +0xEF readers use a different base) - carried by member protobuf fields 11/12,
    // PROVEN the only 1-byte member fields by the client's own descriptor table
    // (0x141ca68e0). Value 1 on every row EXCEPT the recipient's own: the p2(91)
    // all-rows experiment broke the citizen join, and the recipient identifies its own
    // row by NetAddr (members[0] is the host, members[i+1] is peers[i]).
    if (core::settings::get().server.gameplay.activityMemberSetupFlags) {
        const std::size_t selfRow = recipient + 1;
        for (std::size_t index = 0; index < composition.update.members.size(); ++index) {
            if (index == selfRow) {
                continue;
            }
            composition.members[index].flagA = 1;
            composition.members[index].flagB = 1;
        }
    }

    // Region A chunk 7: give each player row a REAL account+character identity, so a peer's
    // row names somebody. TEST-RIG MAPPING (see the setting's doc): slot picks the account by
    // order, because no machineId->accountKey association exists yet. Both SOIDs come from
    // provisioned account state - nothing is fabricated, and an unprovisioned slot stays zero,
    // which leaves chunk 7 absent for that row rather than publishing a wrong identity.
    if (core::settings::get().server.profileIdentity) {
        for (std::size_t index = 0; index < composition.update.players.size(); ++index) {
            auto& player = composition.players[index];
            const auto key = static_cast<core::settings::AccountKey>(player.slot);
            const state::AccountState account = state::account_snapshot(key);
            if (account.primarySoid == 0) {
                continue;
            }
            std::uint64_t character = 0;
            for (const auto& entry : account.characters) {
                if (entry.soid != 0 && (entry.selected || character == 0)) {
                    character = entry.soid;
                    if (entry.selected) {
                        break;
                    }
                }
            }
            if (character == 0) {
                continue;
            }
            player.accountSoid = account.primarySoid;
            player.characterSoid = character;
        }
    }

    std::array<std::byte, kMembershipBodyCapacity> body{};
    bits::Writer writer(body);
    std::size_t size = 0;
    if (!wire::write_membership_update(writer,
                                       composition.update,
                                       core::settings::get().server.publishPlayerProfile,
                                       std::string_view{
                                           core::settings::get().server.profileName.data()},
                                       core::settings::get().server.sessionStateClientBase,
                                       core::settings::get().server.profileStateVariant)
        || !writer.finish(size)) {
        return false;
    }
    const bool clientBase = core::settings::get().server.sessionStateClientBase;
    const bool publishProfile = core::settings::get().server.publishPlayerProfile;
    const std::string_view profileName{core::settings::get().server.profileName.data()};
    wire::ProfileModel published{};
    published.publish = publishProfile;
    published.name = profileName;
    published.variant =
        wire::profile_variant(core::settings::get().server.profileStateVariant);
    // The peer logs the hash it wanted, so ours has to be logged next to it to read a mismatch.
    report(core::log::Level::info,
           "ev=gameplay stage=membership result=built revision=%u members=%zu players=%zu "
           "hash=0x%08X peer=%u client_base=%u profile=%u variant=%zu",
           composition.update.revision,
           composition.update.members.size(),
           composition.update.players.size(),
           wire::session_state_hash(composition.update, clientBase, published),
           record.endpoint.port,
           clientBase ? 1U : 0U,
           publishProfile ? 1U : 0U,
           core::settings::get().server.profileStateVariant);
    // THE DISCRIMINATOR (FINDINGS 20.205 / session-state-profile-image.md OPEN). Two things
    // in the stored image are enumerable rather than known: whether the name stores
    // obfuscated or plain, and where the tail's 5-bit field lands in its trailing 8 bytes.
    // Publishing one guess and rebuilding per hypothesis costs a boot each. Instead every
    // variant's hash is logged ONCE per session; the client prints the hash it computed, and
    // whichever variant reproduces it is the answer - after which `profile_state_variant`
    // makes it live as a SETTINGS FLIP, no rebuild. Capped so it cannot flood a republish loop.
    // BUDGET PER EVENT CLASS (STATE hard rule; p2(133) spent this budget on a players=0
    // snapshot where every variant is identical and learned nothing from half its own
    // instrument). Only a PLAYER-BEARING snapshot may spend it - a body with no player row
    // carries no profile, so its variants cannot differ.
    if (publishProfile && !composition.update.players.empty()
        && g_variantsLogged.fetch_add(1, std::memory_order_relaxed) < kVariantLogBudget) {
        for (std::size_t index = 0; index < wire::kProfileVariantCount; ++index) {
            wire::ProfileModel candidate{};
            candidate.publish = true;
            candidate.name = profileName;
            candidate.variant = wire::profile_variant(index);
            report(core::log::Level::info,
                   "ev=gameplay stage=membership result=variant revision=%u index=%zu "
                   "name_obfuscated=%u tail_field=%d hash=0x%08X",
                   composition.update.revision,
                   index,
                   candidate.variant.nameObfuscated ? 1U : 0U,
                   candidate.variant.tailFieldOffset == wire::kTailFieldAbsent
                       ? -1
                       : static_cast<int>(candidate.variant.tailFieldOffset),
                   wire::session_state_hash(composition.update, clientBase, candidate));
        }
        // The absent-model hash too, so a body that STILL fails can be told apart from one
        // whose failure is unrelated to the profile.
        wire::ProfileModel absent{};
        report(core::log::Level::info,
               "ev=gameplay stage=membership result=variant revision=%u index=absent "
               "hash=0x%08X",
               composition.update.revision,
               wire::session_state_hash(composition.update, clientBase, absent));
        // OUR HALF OF THE DIFF. p2(130)'s capture recipe was unrunnable because the server
        // never dumped the replica it built, so there was nothing to diff the client's
        // stored bytes against. One 424-byte player entry per published player row, hex,
        // keyed by revision and slot - small, and it makes the client-side capture usable
        // offline the moment it lands.
        static thread_local wire::SessionState built{};
        wire::build_session_state(composition.update, built, clientBase, published);
        for (const auto& player : composition.update.players) {
            const std::size_t entry = wire::kPlayerTableOffset + wire::kPlayerStride * player.slot;
            std::array<char, core::log::kLineCapacity> text{};
            int written = std::snprintf(text.data(), text.size(),
                                        "ev=gameplay stage=membership result=entry revision=%u "
                                        "slot=%u hex=",
                                        composition.update.revision, player.slot);
            for (std::size_t i = 0; i < wire::kPlayerStride && written > 0; ++i) {
                written += std::snprintf(text.data() + written,
                                         text.size() - static_cast<std::size_t>(written),
                                         "%02X",
                                         static_cast<unsigned>(built[entry + i]));
            }
            if (written > 0) {
                report(core::log::Level::info, "%s", text.data());
            }
        }
    }
    const bool queued = peer::enqueue_reliable(
        record.sessionId,
        record.endpoint,
        static_cast<std::uint8_t>(wire::SessionMessageId::membershipUpdate),
        wire::kMembershipUpdateSize,
        {body.data(), size},
        writer.bit_count());
    if (queued) {
        // The snapshot carried the record's whole current state, so it clears every publish this
        // record owed, not just the one that triggered it.
        record.joinPublished = record.joinComplete;
        record.playerPublished = record.hasPlayer;
        record.snapshotOwed = false;
    }
    return queued;
}
/**
 * Fills the `activity-host` body this host publishes.
 * The peer creates no activity client until it holds this parameter, and the public-region
 * slice-set switch waits behind that client.
 * @param body Cleared body to fill.
 * @param binding Retained host row used for this whole parameter body.
 */
void fill_activity_host(wire::ActivityHostParameter& body,
                        const HostSessionBinding& binding) noexcept {
    // The peer's `current-activity` carries this host's empty delta, so its nonce is the
    // descriptor default and the comparand is the empty id.
    body.selectionId = 0;
    // The peer addresses its activity join request to this id, and the activity route refuses one
    // that names no committed activity session. A gameplay identity is not one.
    body.hostId = binding.target.sessionId;
    // The peer tests only the bit for its own member index, and this host does not decode which
    // index that is, so every bit is set.
    body.memberMask = kAllMembers;
    body.address = kLoopbackAddress;
    body.port = core::settings::get().server.bapPort;
}

/**
 * Publishes the `activity-host` parameter for one admitted peer. The caller holds the lock.
 * @param record Admitted peer the parameter is published to.
 * @return True when the update was queued on the peer's reliable channel.
 */
[[nodiscard]] bool publish_activity_host(Admitted& record) noexcept {
    if (!may_publish(record)) {
        return false;
    }
    // The body is built from this copy, so no retain is needed: `host_session_for_group` already
    // returns only a ready row whose State bindings still match, and nothing below reads the table.
    HostSessionBinding binding{};
    if (!host_session_for_group(record.sessionId, binding)) {
        // Publishing a zero host id latches an unusable parameter on the peer, and the peer only
        // reads it once. The region's advertisement allocates and this retries.
        report(core::log::Level::debug, "ev=gameplay stage=activityhost result=nosession");
        return false;
    }
    wire::ParameterUpdate update{};
    update.sessionId = record.sessionId;
    // Both go in one update, so the peer never holds the host without the activity it belongs to.
    // `current-activity` carries an empty delta, which leaves the peer's own descriptor defaults.
    update.carriedMask =
        (std::uint64_t{1} << static_cast<std::uint8_t>(wire::Parameter::activityHost))
        | (std::uint64_t{1} << static_cast<std::uint8_t>(wire::Parameter::currentActivity));
    fill_activity_host(update.activityHost, binding);

    const bool sent = send_reliable(
        record.sessionId,
        record.endpoint,
        wire::kParameterUpdateId,
        wire::kParameterUpdateSize,
        [&update](bits::Writer& writer) { return wire::write_parameter_update(writer, update); });
    std::array<char, kParameterNameCapacity> names{};
    report(sent ? core::log::Level::info : core::log::Level::debug,
           "ev=gameplay stage=activityhost result=%s host=0x%llX address=0x%08X port=%u names=%s",
           sent ? "queued" : "deferred",
           static_cast<unsigned long long>(update.activityHost.hostId),
           update.activityHost.address,
           static_cast<unsigned>(update.activityHost.port),
           wire::parameter_names(update.carriedMask, names.data(), names.size()));
    return sent;
}

/**
 * Answers one view establishment by binding and echoing the peer's own signature.
 * What a host's own view should hold is unknown. Echoing is the only answer that cannot produce
 * a signature mismatch. The binding is keyed by the link, because the body names no session.
 * @param from Peer endpoint the view arrived from.
 * @param sessionId Session the reply rides back on, or zero when the link carries several.
 * @param view Decoded view body.
 */
void bind_view(const state::gameplay::Endpoint& from,
               std::uint64_t sessionId,
               const wire::ViewEstablishment& view) noexcept {
    state::gameplay::ViewSignature signature{};
    signature.token = view.sessionToken;
    signature.kind = view.kind;
    signature.listCount = view.listCount;
    signature.hasList = view.hasList;
    signature.list = view.list;
    // Kept unread. Its meaning is unrecovered, and dropping it would lose a field the peer sent.
    signature.optionalValue = view.optionalValue;
    signature.hasOptionalValue = view.hasOptionalValue;
    signature.bound = true;
    peer::bind_view(from, signature);

    const bool sent = send_reliable(
        sessionId,
        from,
        wire::kViewMessageId,
        wire::kViewMessageSize,
        [&view](bits::Writer& writer) noexcept { return wire::write_view(writer, view); });
    report(sent ? core::log::Level::info : core::log::Level::warn,
           "ev=gameplay stage=view result=%s kind=%u token=0x%llX list=%u",
           sent ? "bound" : "fail",
           static_cast<unsigned>(view.kind),
           static_cast<unsigned long long>(view.sessionToken),
           static_cast<unsigned>(view.listCount));
}

/**
 * Answers one parameter request with the parameters this host can encode.
 * An empty answer leaves the peer waiting, so the answer carries every requested parameter that
 * has an encoder and names the rest as unheld.
 * @param sessionId Session the request named, which is also the link it goes back on.
 * @param requested Requested parameter mask, already reduced to its meaningful bits.
 */
void answer_parameters(const state::gameplay::Endpoint& from,
                       std::uint64_t sessionId,
                       std::uint64_t requested) noexcept {
    std::uint64_t carried = requested & wire::kEncodableParameters;
    const std::uint64_t activityHostMask =
        std::uint64_t{1} << static_cast<std::uint8_t>(wire::Parameter::activityHost);
    // The body is built from this copy, so no retain is needed. See publish_activity_host.
    HostSessionBinding binding{};
    const bool hasHost =
        (carried & activityHostMask) != 0 && host_session_for_group(sessionId, binding);
    if ((carried & activityHostMask) != 0 && !hasHost) {
        // A zero host id is worse than no answer for this one.
        carried &= ~activityHostMask;
    }
    if (carried == 0) {
        report(core::log::Level::debug,
               "ev=gameplay stage=parameters result=unheld mask=0x%08X",
               static_cast<unsigned>(requested));
        return;
    }

    wire::ParameterUpdate update{};
    update.sessionId = sessionId;
    update.carriedMask = carried;
    // A zero host id latches an unusable parameter on the peer, so the answer carries the same
    // body the unsolicited publish does.
    if (hasHost) {
        fill_activity_host(update.activityHost, binding);
    }

    const bool sent = send_reliable(
        sessionId,
        from,
        wire::kParameterUpdateId,
        wire::kParameterUpdateSize,
        [&update](bits::Writer& writer) { return wire::write_parameter_update(writer, update); });
    std::array<char, kParameterNameCapacity> names{};
    report(sent ? core::log::Level::info : core::log::Level::warn,
           "ev=gameplay stage=parameters result=%s carried=0x%08X names=%s",
           sent ? "answered" : "fail",
           static_cast<unsigned>(carried),
           wire::parameter_names(carried, names.data(), names.size()));
}

/**
 * Answers one time-synchronize probe with the same form it arrived in.
 * @param from Peer endpoint.
 * @param probe Decoded probe.
 */
void answer_time(const state::gameplay::Endpoint& from,
                 const wire::TimeSynchronize& probe) noexcept {
    // The exchange must never block the event loop, so the samples are echoed unchanged.
    if (!peer::send_out_of_band(from,
                                static_cast<std::uint8_t>(wire::SessionMessageId::timeSynchronize),
                                wire::kTimeSynchronizeSize,
                                [&probe](bits::Writer& writer) noexcept {
                                    return wire::write_time_synchronize(writer, probe);
                                })) {
        report(core::log::Level::debug, "ev=gameplay stage=time result=fail");
    }
}

/**
 * Drops one session's link and its admitted record together.
 * A leave names one region's session, and the client's other region must keep its own link.
 * @param sessionId Session the peer is leaving.
 */
void release(const state::gameplay::Endpoint& from, std::uint64_t sessionId) noexcept {
    peer::drop(sessionId, from);
    // The region's activity host stays. A leave is also how the peer fast travels to the region it
    // is already in, and a fresh id there is `public_activity_host_mismatch`.
    AcquireSRWLockExclusive(&g_admittedLock);
    for (Admitted& entry : g_admitted) {
        if (entry.occupied && entry.sessionId == sessionId && same_endpoint(entry.endpoint, from)) {
            entry = {};
        }
    }
    // The leaver's row would otherwise live on as a ghost `established` member in every
    // survivor's table until that survivor's own next event healed it.
    mark_session_dirty(sessionId);
    ReleaseSRWLockExclusive(&g_admittedLock);
}

} // namespace

/** Frees every admitted record at one endpoint. */
void release_endpoint(const state::gameplay::Endpoint& endpoint) noexcept {
    std::size_t count = 0;
    AcquireSRWLockExclusive(&g_admittedLock);
    // Gathered under the lock: every session the dropped endpoint held lost a member, and the
    // survivors are owed a snapshot that no longer names it.
    std::uint64_t touched[kAdmittedCapacity] = {};
    std::size_t touchedCount = 0;
    for (Admitted& entry : g_admitted) {
        if (!entry.occupied || !same_endpoint(entry.endpoint, endpoint)) {
            continue;
        }
        ++count;
        const std::uint64_t sessionId = entry.sessionId;
        entry = {};
        bool seen = false;
        for (std::size_t index = 0; index < touchedCount; ++index) {
            seen = touched[index] == sessionId;
            if (seen) {
                break;
            }
        }
        if (!seen && touchedCount < std::size(touched)) {
            touched[touchedCount++] = sessionId;
        }
    }
    for (std::size_t index = 0; index < touchedCount; ++index) {
        mark_session_dirty(touched[index]);
    }
    ReleaseSRWLockExclusive(&g_admittedLock);
    if (count != 0) {
        report(core::log::Level::info,
               "ev=gameplay stage=admitted result=dropped endpoint=0x%08X:%u sessions=%zu",
               endpoint.address,
               static_cast<unsigned>(endpoint.port),
               count);
    }
}

/**
 * @param id Group-session message id as it arrived.
 * @return True when consume() below has an arm for it. Mirrors that dispatch by hand, so
 *         a new arm must be added here too - the census line is only worth reading if
 *         `dispatched=0` really means "fell through".
 */
[[nodiscard]] bool dispatched_id(std::uint8_t id) noexcept {
    switch (id) {
    case static_cast<std::uint8_t>(wire::SessionMessageId::timeSynchronize):
    case static_cast<std::uint8_t>(wire::SessionMessageId::leaveSession):
    case static_cast<std::uint8_t>(wire::SessionMessageId::peerEstablish):
    case static_cast<std::uint8_t>(wire::SessionMessageId::joinComplete):
    case static_cast<std::uint8_t>(wire::SessionMessageId::joinAbort):
    case wire::kViewMessageId:
    case wire::kParameterRequestId:
    case wire::kPeerPropertiesId:
    case wire::kPlayerAddId:
    case wire::kPlayerRemoveId:
    case wire::kPlayerPropertiesId:
        return true;
    default:
        return false;
    }
}

/** Consumes one group-session message. */
bool consume(const state::gameplay::Endpoint& from,
             std::uint64_t sessionId,
             std::uint8_t id,
             bits::Reader& reader,
             std::uint64_t now) noexcept {
    // MESSAGE-ID CENSUS (FINDINGS 20.156 / blockers-research #2+#5). The pump dispatches
    // eleven ids and lets EVERYTHING ELSE fall through to migration::consume, which handles
    // host-handoff ids only and drops the rest without a word - so we do not know what the
    // clients actually send us. The load-bearing unknown is the type-0x0A (10) ADMISSION
    // JOIN: it is absent from SessionMessageId entirely, and whether it reaches this pump
    // decides the whole admission route (server relay vs DLL-side reserve/admit injection),
    // which in turn gates the roster AND, on the current hypothesis, the public world swap.
    // `peerConnect` (11) is in the enum but NOT dispatched here either.
    // One line per distinct id, so a per-tick id cannot flood the log (the standing
    // hot-path rule); the counter keeps accumulating so the summary stays honest.
    {
        static bool s_idSeen[256]{};
        static std::uint32_t s_idCount[256]{};
        ++s_idCount[id];
        if (!s_idSeen[id]) {
            s_idSeen[id] = true;
            report(core::log::Level::info,
                   "ev=gameplay stage=msg_census id=%u dispatched=%u endpoint=0x%08X:%u "
                   "session=0x%llX",
                   static_cast<unsigned>(id),
                   dispatched_id(id) ? 1U : 0U,
                   from.address,
                   static_cast<unsigned>(from.port),
                   static_cast<unsigned long long>(sessionId));
        }
    }
    if (id == static_cast<std::uint8_t>(wire::SessionMessageId::timeSynchronize)) {
        wire::TimeSynchronize probe{};
        if (!wire::read_time_synchronize(reader, probe)) {
            return false;
        }
        answer_time(from, probe);
        return true;
    }
    if (id == wire::kViewMessageId) {
        wire::ViewEstablishment view{};
        if (!wire::read_view(reader, view)) {
            return false;
        }
        bind_view(from, sessionId, view);
        return true;
    }
    if (id == static_cast<std::uint8_t>(wire::SessionMessageId::leaveSession)) {
        std::uint64_t leaving = 0;
        if (!wire::read_session_only(reader, leaving)) {
            return false;
        }
        if (!holds_session(from, leaving)) {
            // A leave tears the sender's own record down. With two peers on one session a leave
            // from one endpoint must not touch the other's record, and an endpoint that holds no
            // record for the session it names moves nobody's state at all.
            report(core::log::Level::warn,
                   "ev=gameplay stage=leave result=unowned session=0x%016llX",
                   static_cast<unsigned long long>(leaving));
            return true;
        }
        const bool sent = peer::send_out_of_band(
            from,
            static_cast<std::uint8_t>(wire::SessionMessageId::leaveAcknowledge),
            wire::kLeaveAcknowledgeSize,
            [leaving](bits::Writer& writer) noexcept {
                return wire::write_session_only(writer, leaving);
            });
        report(core::log::Level::info,
               "ev=gameplay stage=leave result=%s session=0x%016llX",
               sent ? "acknowledged" : "fail",
               static_cast<unsigned long long>(leaving));
        release(from, leaving);
        return true;
    }
    if (id == static_cast<std::uint8_t>(wire::SessionMessageId::peerEstablish)) {
        std::uint64_t established = 0;
        if (!wire::read_session_only(reader, established)) {
            return false;
        }
        report(core::log::Level::info,
               "ev=gameplay stage=establish result=ok session=0x%016llX",
               static_cast<unsigned long long>(established));
        return true;
    }
    if (id == static_cast<std::uint8_t>(wire::SessionMessageId::joinComplete)) {
        wire::JoinComplete body{};
        if (!wire::read_join_complete(reader, body)) {
            return false;
        }
        // The peer repeats this until its membership shows every member of the join at
        // `established`, so the answer is a snapshot that promotes them. Keyed by the body's
        // session, not the link's: one link carries every region the client joined over it.
        AcquireSRWLockExclusive(&g_admittedLock);
        Admitted* const record = claim_owned(from, body.sessionId);
        bool queued = false;
        const bool owed = record != nullptr && !record->joinPublished;
        if (record != nullptr) {
            record->joinComplete = true;
            if (owed) {
                // This record's rung changed, so every record of the session is owed a snapshot
                // that carries it (the others see a member move to `established`). The
                // completing record's own publish clears its flags; the rest refresh on service.
                mark_session_dirty(body.sessionId);
                queued = publish_snapshot(*record);
            }
            // The peer only reads the parameter once its join is finished, and the queue is at its
            // fullest right here, so a refusal is expected and the service slice retries it.
            if (record->joinPublished && !record->activityHostPublished) {
                record->activityHostPublished = publish_activity_host(*record);
                record->lastRetry = now;
            }
        }
        ReleaseSRWLockExclusive(&g_admittedLock);
        report(queued ? core::log::Level::info : core::log::Level::debug,
               "ev=gameplay stage=join result=%s session=0x%llX machine=0x%llX update=%u",
               queued              ? "completed"
               : record == nullptr ? "fail"
               : owed              ? "deferred"
                                   : "repeat",
               static_cast<unsigned long long>(body.sessionId),
               static_cast<unsigned long long>(body.machineId),
               body.joinSequence);
        return true;
    }
    if (id == static_cast<std::uint8_t>(wire::SessionMessageId::joinAbort)) {
        wire::SessionNotice notice{};
        if (!wire::read_join_abort(reader, notice)) {
            return false;
        }
        if (!holds_session(from, notice.sessionId)) {
            report(core::log::Level::warn,
                   "ev=gameplay stage=join result=unowned_abort session=0x%016llX",
                   static_cast<unsigned long long>(notice.sessionId));
            return true;
        }
        report(core::log::Level::info,
               "ev=gameplay stage=join result=abort session=0x%016llX",
               static_cast<unsigned long long>(notice.sessionId));
        release(from, notice.sessionId);
        return true;
    }
    if (id == wire::kParameterRequestId) {
        wire::ParameterRequestHeader header{};
        if (!wire::read_parameter_request(reader, header)) {
            return false;
        }
        const std::uint64_t mask = header.requestedMask & kParameterMaskBits;
        std::array<char, kParameterNameCapacity> names{};
        report(core::log::Level::info,
               "ev=gameplay stage=parameters result=request mask=0x%08X mode=%u names=%s",
               static_cast<unsigned>(mask),
               static_cast<unsigned>(header.modeFlag ? 1U : 0U),
               wire::parameter_names(mask, names.data(), names.size()));
        // The selected bodies are walked before the answer goes out, so nothing is answered from
        // a request that was only read as far as its header.
        // INSTRUMENT (FINDINGS 20.121). Parameter 21 `publicSessionReservations` is where the
        // walk stops, and our ANSWER for it is a clear root bit - "no value, keep your own" -
        // because its body layout is unrecovered. The client then sets its public bubble
        // reservation to 0 slots and recycles the session every ~22.8 s. Inventing a body is the
        // policy-31 fatal-decode class the handbook warns about, so capture the peer's OWN bytes
        // instead and decode the layout offline (U2: instrument before intervention).
        {
            bits::Reader capture = reader;
            std::array<char, kRequestCaptureCapacity> hex{};
            std::size_t written = 0;
            std::uint64_t byte = 0;
            while (written + 2 < hex.size() && capture.read(8, byte)) {
                static constexpr char kDigits[] = "0123456789ABCDEF";
                hex[written++] = kDigits[(byte >> 4) & 0xF];
                hex[written++] = kDigits[byte & 0xF];
            }
            hex[written] = '\0';
            report(core::log::Level::info,
                   "ev=gameplay stage=parameters result=body_capture mask=0x%08X bytes=%zu hex=%s",
                   static_cast<unsigned>(mask),
                   written / 2,
                   hex.data());
        }
        wire::ParameterRequestWalk walk{};
        const bool intact = wire::walk_parameter_request(reader, mask, walk);
        report(walk.complete ? core::log::Level::debug : core::log::Level::info,
               "ev=gameplay stage=parameters result=%s walked=0x%08X stopped=%u tail=%u",
               walk.complete ? "framed"
               : intact      ? "ambiguous"
                             : "truncated",
               static_cast<unsigned>(walk.walkedMask),
               static_cast<unsigned>(walk.ambiguousParameter),
               walk.tailBits);
        // The peer builds no activity client until it holds the host parameter, so the answer goes
        // out even when a later body could not be located. The tail above is what is unread, not
        // the answer's own inputs. The request is answered only to an endpoint this host admitted
        // for the session it names; every other endpoint is left to that session's own holders.
        if (holds_session(from, header.sessionId)) {
            answer_parameters(from, header.sessionId, mask);
        } else {
            report(core::log::Level::debug,
                   "ev=gameplay stage=parameters result=unowned session=0x%016llX",
                   static_cast<unsigned long long>(header.sessionId));
        }
        // Only a fully located request leaves the container readable behind it.
        return walk.complete;
    }
    if (id == wire::kPeerPropertiesId) {
        wire::PeerPropertiesHeader header{};
        if (!wire::read_peer_properties_header(reader, header)) {
            return false;
        }
        // The 304-byte property block behind the address is not decoded, so the body is
        // reported and not consumed.
        report(core::log::Level::info,
               "ev=gameplay stage=properties result=read session=0x%llX method=%u",
               static_cast<unsigned long long>(header.sessionId),
               static_cast<unsigned>(header.addressMethod));
        return false;
    }
    if (id == wire::kPlayerAddId) {
        wire::PlayerAddRequest request{};
        if (!wire::read_player_add(reader, request)) {
            return false;
        }
        // The published row carries the identity group only. The profile block behind it has no
        // encoder here, and the peer's clear-flag arm accepts a row without one.
        AcquireSRWLockExclusive(&g_admittedLock);
        // The body's session, for the same reason join-complete uses its own.
        Admitted* const record = claim_owned(from, request.sessionId);
        bool published = false;
        if (record != nullptr) {
            if (!record->hasPlayer) {
                // A fresh player takes the lowest slot the session's other players do not hold,
                // and the next add sequence. The first player of a session gets 0, which is what
                // the consumer's own local add starts at too.
                std::uint32_t used = 0;
                std::uint32_t sequence = 0;
                for (const Admitted& entry : g_admitted) {
                    if (!entry.occupied || entry.sessionId != record->sessionId
                        || &entry == record) {
                        continue;
                    }
                    if (entry.hasPlayer) {
                        used |= 1U << entry.playerSlot;
                        if (entry.addSequence + 1 > sequence) {
                            sequence = entry.addSequence + 1;
                        }
                    }
                }
                std::uint32_t slot = 0;
                while (slot < 32 && (used & (1U << slot)) != 0) {
                    ++slot;
                }
                record->playerSlot = slot;
                record->addSequence = sequence;
            }
            record->hasPlayer = true;
            record->playerId = request.playerId;
            // The other peers are owed a snapshot naming this player; the adding peer's own copy
            // is what its player-add waits on.
            mark_session_dirty(request.sessionId);
            published = publish_snapshot(*record);
        }
        ReleaseSRWLockExclusive(&g_admittedLock);
        // The player block and its tail are not decoded, so the body is reported and not consumed.
        report(core::log::Level::info,
               "ev=gameplay stage=player result=%s session=0x%llX player=0x%llX seq=%u kind=%u",
               published ? "added" : "fail",
               static_cast<unsigned long long>(request.sessionId),
               static_cast<unsigned long long>(request.playerId),
               request.sequence,
               static_cast<unsigned>(request.kind));
        return false;
    }
    if (id == wire::kPlayerRemoveId) {
        wire::PlayerRemoveRequest request{};
        if (!wire::read_player_remove(reader, request)) {
            return false;
        }
        // The message names no player. The one to drop is the player the bound record holds.
        AcquireSRWLockExclusive(&g_admittedLock);
        Admitted* const record = claim_owned(from, request.sessionId);
        bool published = false;
        if (record != nullptr && record->hasPlayer) {
            record->hasPlayer = false;
            record->playerId = 0;
            // The slot stays with the record, so a re-add reuses the row the others already know.
            mark_session_dirty(request.sessionId);
            published = publish_snapshot(*record);
        }
        ReleaseSRWLockExclusive(&g_admittedLock);
        report(core::log::Level::info,
               "ev=gameplay stage=player result=%s session=0x%llX",
               published           ? "removed"
               : record == nullptr ? "fail"
                                   : "absent",
               static_cast<unsigned long long>(request.sessionId));
        // The whole body is two fields, so the container stays readable behind it.
        return true;
    }
    if (id == wire::kPlayerPropertiesId) {
        wire::PlayerPropertiesRequest request{};
        if (!wire::read_player_properties_header(reader, request)) {
            return false;
        }
        // The sparse record behind the header is not decoded, so nothing is merged from it. A
        // merge from the header alone would reset every field the record carries.
        report(core::log::Level::info,
               "ev=gameplay stage=player result=properties session=0x%llX seq=%u kind=%u",
               static_cast<unsigned long long>(request.sessionId),
               request.sequence,
               static_cast<unsigned>(request.kind));
        return false;
    }
    // Migration and election bodies are read and recorded. This host never starts a migration and
    // never answers one, but leaving them unread would end the container at the first of them.
    // The fallthrough, named. An id arriving here is one this host does not dispatch;
    // migration::consume answers only the host-handoff ids and returns false for the rest,
    // which is where a client message goes to die silently. One line per distinct id.
    {
        const bool consumed = migration::consume(id, reader);
        static bool s_fellSeen[256]{};
        if (!s_fellSeen[id]) {
            s_fellSeen[id] = true;
            report(core::log::Level::info,
                   "ev=gameplay stage=msg_unhandled id=%u migration_consumed=%u "
                   "endpoint=0x%08X:%u",
                   static_cast<unsigned>(id),
                   consumed ? 1U : 0U,
                   from.address,
                   static_cast<unsigned>(from.port));
        }
        return consumed;
    }
}

/** Publishes the membership snapshot that completes one peer's join. */
bool publish_membership(const state::gameplay::Endpoint& peer,
                        std::uint64_t peerJoinId,
                        std::uint64_t peerMachineId,
                        std::uint64_t sessionId) noexcept {
    AcquireSRWLockExclusive(&g_admittedLock);
    Admitted* const record = claim(peer, sessionId);
    bool published = false;
    if (record != nullptr) {
        // A fresh record joins the session the others already hold, and a retried one re-enters
        // it, so every record is owed a snapshot naming the new composition.
        mark_session_dirty(sessionId);
        // A retried join brings a new join id and drops any player the previous attempt added.
        // It also starts again at `ready`, so the previous attempt's completion does not carry.
        // The machine id is stable across the peer's retries (measured: 21 identical identity
        // tables in one boot), so it re-stamps harmlessly.
        record->joinId = peerJoinId;
        record->machineId = peerMachineId;
        record->sessionId = sessionId;
        record->hasPlayer = false;
        record->playerId = 0;
        record->joinComplete = false;
        record->joinPublished = false;
        record->activityHostPublished = false;
        record->playerPublished = false;
        record->lastRetry = 0;
        published = publish_snapshot(*record);
    }
    ReleaseSRWLockExclusive(&g_admittedLock);
    return published;
}

/** Retries any publish a full reliable queue refused. */
void service(std::uint64_t now) noexcept {
    // Outside any staged push, so the state revision it advances cannot fail a transaction guard.
    allocate_claimed_host_sessions();
    // A client holds at most two public sessions at once (one current, one target), and drops a
    // stale one locally with no leave. Such a record shows up only as the least recently named
    // one over that capacity AT ITS OWN ENDPOINT, so the eviction is per endpoint too: two
    // clients never evict each other's records.
    std::uint64_t retired = 0;
    state::gameplay::Endpoint retiredEndpoint{};
    AcquireSRWLockExclusive(&g_admittedLock);
    for (Admitted& pivot : g_admitted) {
        if (!pivot.occupied) {
            continue;
        }
        std::size_t held = 0;
        Admitted* oldest = nullptr;
        for (Admitted& record : g_admitted) {
            if (!record.occupied
                || record.endpoint.address != pivot.endpoint.address
                || record.endpoint.port != pivot.endpoint.port) {
                continue;
            }
            ++held;
            if (oldest == nullptr || record.lastUse < oldest->lastUse) {
                oldest = &record;
            }
        }
        if (held > kPublicSessionCapacity && oldest != nullptr) {
            retired = oldest->sessionId;
            retiredEndpoint = oldest->endpoint;
            *oldest = {};
            mark_session_dirty(retired);
            break;
        }
    }
    for (Admitted& record : g_admitted) {
        const bool owed =
            record.occupied
            && ((record.joinComplete && !record.joinPublished)
                || (record.joinPublished && !record.activityHostPublished)
                || (record.joinPublished && record.hasPlayer && !record.playerPublished)
                || record.snapshotOwed);
        if (!owed || now - record.lastRetry < kRetryInterval) {
            continue;
        }
        record.lastRetry = now;
        if (!record.joinPublished) {
            publish_snapshot(record);
            continue;
        }
        if (!record.activityHostPublished) {
            record.activityHostPublished = publish_activity_host(record);
            // A refusing activity-host publish must not starve the composition refresh behind
            // it: the join needs that order, but a session whose members changed cannot wait
            // on a parameter the host row may never satisfy.
            if (!record.snapshotOwed) {
                continue;
            }
        }
        // Last, so the order the join needs is unchanged. This also carries every refresh the
        // session composition owed: the snapshot is the complete current state.
        publish_snapshot(record);
    }
    ReleaseSRWLockExclusive(&g_admittedLock);
    // Outside the lock, in the order `release` already uses. The region's activity host stays: the
    // peer rotates back into a region it has not left, and a fresh id there is a hard error.
    if (retired != 0) {
        peer::drop(retired, retiredEndpoint);
        report(core::log::Level::info,
               "ev=gameplay stage=admitted result=retired session=0x%016llX peer=%u",
               static_cast<unsigned long long>(retired),
               retiredEndpoint.port);
    }
}

/** Publishes the parameter update a joining peer needs before it will finish its join. */
bool publish_join_parameters(std::uint64_t sessionId,
                             const state::gameplay::Endpoint& peer) noexcept {
    // A joining peer finishes only once it has applied one parameter update. Any update with a
    // named parameter and no body sets that latch. This host has no values, so it releases a slot
    // the peer never filled, which leaves the peer's state alone.
    wire::ParameterUpdate update{};
    update.sessionId = sessionId;
    update.releasedMask = std::uint64_t{1} << kJoinLatchParameter;

    const bool sent = send_reliable(
        sessionId,
        peer,
        wire::kParameterUpdateId,
        wire::kParameterUpdateSize,
        [&update](bits::Writer& writer) { return wire::write_parameter_update(writer, update); });
    std::array<char, kParameterNameCapacity> names{};
    report(sent ? core::log::Level::info : core::log::Level::warn,
           "ev=gameplay stage=parameters result=%s released=0x%08X names=%s",
           sent ? "queued" : "fail",
           static_cast<unsigned>(update.releasedMask),
           wire::parameter_names(update.releasedMask, names.data(), names.size()));
    return sent;
}

/** Copies every admitted group-session record. */
void snapshot_admitted(std::span<AdmittedRow> output, std::size_t& count) noexcept {
    count = 0;
    AcquireSRWLockShared(&g_admittedLock);
    for (const Admitted& entry : g_admitted) {
        if (!entry.occupied || count >= output.size()) {
            continue;
        }
        output[count] = {entry.sessionId,
                         entry.endpoint,
                         entry.joinComplete,
                         entry.activityHostPublished,
                         entry.hasPlayer,
                         entry.playerPublished,
                         entry.joinId};
        ++count;
    }
    ReleaseSRWLockShared(&g_admittedLock);
}

/** Reports the byte-exact NetAddr blob one member sent for itself. */
bool net_addr_for_member(std::uint64_t memberKey,
                         std::array<std::byte, state::gameplay::kNetAddrBlobSize>& output,
                         const char*& reason) noexcept {
    // The measured relation (p2-166 and p2-167, both machines, four samples): the low 24 bits
    // of the member key ARE the top 24 bits of the join request's machine id. The machine ids
    // changed between boots while those 24 bits did not, so the relation is real rather than
    // one boot's coincidence. Rows whose identity table never decoded carry machineId 0 and
    // are skipped rather than matched against a zero key.
    //
    // DELIBERATELY NOT WIDENED. p2-167 saw the activity layer publish the peer row keyed by
    // 0xD022E6013910CA03 - the rig's own MACHINE ID, not a member key - and this lookup
    // refused it six times running. Accepting that form was written and then reverted: the
    // shape appears in ONE boot only (p2-165/p2-166 show member keys exclusively) and only in
    // the 26 s window before that client's transport reset. It is a symptom of a session
    // already failing, so matching it would publish a peer card for a peer that is leaving.
    // The refusal is the CORRECT outcome here; the open question is why the identity changed
    // at all, and that is answered by reading the roster path, not by loosening this test.
    const std::uint64_t wanted = memberKey & 0xFFFFFFULL;
    std::size_t matches = 0;
    std::uint64_t sessionId = 0;
    state::gameplay::Endpoint endpoint{};
    if (wanted != 0) {
        AcquireSRWLockShared(&g_admittedLock);
        for (const Admitted& entry : g_admitted) {
            if (!entry.occupied || entry.machineId == 0
                || (entry.machineId >> 40) != wanted) {
                continue;
            }
            ++matches;
            sessionId = entry.sessionId;
            endpoint = entry.endpoint;
        }
        ReleaseSRWLockShared(&g_admittedLock);
    }
    if (matches != 1) {
        reason = matches == 0 ? "no_admitted_row" : "ambiguous_member_key";
        return false;
    }
    // The peer's own blob is echoed byte exact. A blob rebuilt from the endpoint it arrived from
    // is NOT the same bytes - the same rule publish_snapshot follows, and the reason the client's
    // 86-byte compare can match at all. The rebuild is the honest fallback, and it is named.
    if (peer::remote_address(sessionId, endpoint, output)) {
        reason = "echoed";
        return true;
    }
    descriptor::write_net_addr(endpoint.address, endpoint.port, output);
    reason = "rebuilt";
    return true;
}

/** Clears every group-session record. */
void reset() noexcept {
    g_membershipRevision.store(0);
    // Every host session goes back to State as well, or its records are stranded there.
    reset_host_sessions();
    AcquireSRWLockExclusive(&g_admittedLock);
    g_admitted = {};
    ReleaseSRWLockExclusive(&g_admittedLock);
}

} // namespace sunrise::server::gameplay::group
