#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace sunrise::core::settings::server::gameplay {

/** Process that owns the gameplay UDP endpoint for this run. */
enum class Topology : std::uint8_t {
    /** No endpoint is bound and no method-0 descriptor is advertised. */
    disabled,
    /** Sunrise binds the endpoint and hosts the peer protocol itself. */
    embedded,
    /** A configured process owns the endpoint. Sunrise binds nothing. */
    external,
};

/** Octets in one IPv4 address. */
inline constexpr std::size_t kAddressOctets = 4;
/** The join descriptor carries an even UDP port, so an odd port is refused at load. */
inline constexpr std::uint16_t kPortAlignment = 2;
/** Even, and clear of both discovery ports. */
inline constexpr std::uint16_t kDefaultPort = 30976;
/** Discovery owns 3074 and 3075, so the gameplay endpoint may take neither. */
inline constexpr std::uint16_t kDiscoveryPortLow = 3074;
/** Upper discovery port. See kDiscoveryPortLow. */
inline constexpr std::uint16_t kDiscoveryPortHigh = 3075;
/** One carrier, the live wave, and removal headroom fit in this many reserved slots. */
inline constexpr std::uint16_t kDefaultServerReserve = 256;
/** A smaller reserve cannot hold one carrier plus its removal and quarantine headroom. */
inline constexpr std::uint16_t kMinimumServerReserve = 8;
/** The client keeps at least this many lease bits after the reserve is subtracted. */
inline constexpr std::uint16_t kClientLeaseMinimum = 4096;
/**
 * Entity slots the join hands the client before it asks for any.
 * The whole slot space, capped at what the reserve leaves, which is the measured behaviour.
 */
inline constexpr std::uint16_t kDefaultClientJoinGrant = 8'192;
/** Below this a join cannot cover the client's own low water mark of 400. */
inline constexpr std::uint16_t kMinimumClientJoinGrant = 400;

/**
 * Gameplay endpoint topology and the entity-slot split it implies.
 * The advertised address is the one message 12 publishes. The transport address is where the
 * datagram lands after the Client's egress rewrite. Both carry the same port.
 */
struct Settings {
    /** Embedded by default. Public activities reach each other over the peer protocol. */
    Topology topology{Topology::embedded};
    /** Local interface the embedded endpoint binds. */
    std::array<unsigned char, kAddressOctets> bindAddress{127, 0, 0, 1};
    /** Address written into the published descriptor. */
    std::array<unsigned char, kAddressOctets> advertisedAddress{127, 0, 0, 1};
    /** Address the Client's egress rewrite produces. Must reach the bound endpoint. */
    std::array<unsigned char, kAddressOctets> transportAddress{127, 0, 0, 1};
    /** Even UDP port, shared by all three addresses because the egress hook keeps the port. */
    std::uint16_t port{kDefaultPort};
    /** Entity indices held back from the client lease for server-authored entities. */
    std::uint16_t serverReserveCount{kDefaultServerReserve};
    /** Entity indices the join grants. The rest stay free for the client to request. */
    std::uint16_t clientJoinGrantCount{kDefaultClientJoinGrant};
    /**
     * Answer a session search with THIS server's gameplay endpoint instead of relaying another
     * client's advertisement (FINDINGS 20.114).
     *
     * Under road C the server hosts every instance and both clients are its guests, so the
     * descriptor every searcher should receive is ours. The relay it replaces hands client A
     * client B's STEAM-IDENTITY blob, which names a Steam networking path this build stubs and
     * has never run - and it is order-dependent besides, because the first client to search
     * finds no foreign advertisement at all.
     *
     * False restores the relay behaviour without a rebuild, which is what makes any freeze this
     * causes bisectable (HARD RULES, p2(62)).
     */
    bool searchSelfHost{true};
    /**
     * Publish each peer's REAL machine id (decoded from its join request's identity table,
     * FINDINGS 20.128) in membership snapshots, instead of the joinId stand-in.
     *
     * The joinId stand-in is the prime suspect for the deterministic symmetric row drop
     * (20.127 addendum 3): the consumer rebuilds its member table from every snapshot and
     * drops the foreign member's row, and the stand-in matches nothing it holds. False
     * restores the stand-in without a rebuild, so the row-drop boot stays bisectable
     * (HARD RULES, p2(62)).
     */
    bool publishJoinMachineIds{false};
    /**
     * Bind the activity-host session to the (group session, region) instead of to whichever
     * client's activity source pushed last (FINDINGS 20.130).
     *
     * With two clients in one public region, every membership push from the other client used
     * to retire the shared host row and reallocate it under a NEW activity-session id - 118
     * allocations and 116 retires in one run - so the activity session both clients' activity
     * clients must join never outlived the next push, and co-location could never form. True
     * reuses the row when the (group session, region) matches and lets it outlive its first
     * source's own (recycling) session record. False restores the source-bound behaviour
     * without a rebuild (HARD RULES, p2(62)).
     */
    bool activityHostRegionBound{false};
    /**
     * Seeds a freshly committed activity-session record with the account's last
     * client-reported region (FINDINGS 20.147). True by default.
     *
     * MEASURED DEFECT: a client's reported region lives on its session record, and a
     * session re-creation (the client's re-target after a withdrawn membership) starts a
     * fresh record with no report, so `effective_region` falls back to the arrival slice
     * set forever. The client reports its desired public region once and never repeats it
     * after a re-target, so the churned session can never reach the public region: no
     * citizen join, no second BAP link, and the Tower load hangs at
     * `Waiting for managed-session-start for all peers`. The player did not move - only
     * the session id did - so the fresh record inherits the account's last reported
     * region. False restores the per-session behaviour without a rebuild (HARD RULES,
     * p2(62)).
     */
    bool activityRegionSurvivesChurn{true};
    /**
     * Publishes member protobuf fields 11/12 as 1 (instead of the cleared 0) in every
     * composed group-session membership snapshot (FINDINGS 20.151). True by default.
     *
     * MEASURED DEFECT: the client's world controller waits for per-peer
     * 'activity setup complete' (the managed-session-start gate, ms-start-gate.md).
     * The setup-complete flag is DERIVED client-locally (setter 0x1404F3870) from the
     * wire-fed state ladder (established=10, already satisfied) PLUS member-record flag
     * bytes @+0xED (reader 0x14177A080) and @+0xEF (reader 0x14177A060) - and this
     * encoder publishes fields 11/12 (and 8/9) as zero, so no peer ever reads as
     * setup-complete and the second client's Tower load hangs at a black screen.
     * Field 8 (idB) is deliberately NOT touched - it is an id, not a flag. The exact
     * wire-bit -> record-offset mapping is unproven (the client's message-30 bit-reader
     * is unmapped); this is the measured-best experiment, flippable without a rebuild
     * (HARD RULES, p2(62)).
     */
    bool activityMemberSetupFlags{true};
    /**
     * Makes the slice set this host PUBLISHES follow the region the client REPORTED,
     * instead of staying pinned to the destination's own arrival bubble (FINDINGS 20.153).
     * True by default.
     *
     * MEASURED DEFECT (p2(90) boot, both machines, symmetric): every keepalive read
     * `region=56 slice=48` for the whole run. `effective_region` already lets the reported
     * region win for `region.index`, and activity_membership_query.h says outright that a
     * reported region "beats the destination's own arrival slice set wherever the host must
     * say where the player is" - but `region.arrival` keeps the arrival bubble (48), and the
     * two consumers that name the slice set both read the arrival: the roster's spawn
     * override (activity_roster_snapshot.cpp) and the global-activity-state body's
     * sliceSetIndex (activity_global_state_push.cpp).
     *
     * CONSEQUENCE: the client precaches PUB56.56, finishes ('slice_set_loader: Successfully
     * loaded pending slice-set 56'), and then stalls forever because the authority still
     * says 48. A private or orbit slice-set transition self-simulates its phase
     * (':simulator: advancing simulated phase directly to switch-now'), so PRV24/PRV48
     * complete with no server agreement at all; a PUBLIC 'normal_z_leg' transition has no
     * simulator arm and never gets its slice-set-switch task. Neither client ever swaps out
     * of its private Tower.
     *
     * False restores the arrival-pinned behaviour without a rebuild (HARD RULES, p2(62)).
     */
    bool activitySliceSetFollowsRegion{true};
    /**
     * Membership bodies this host addresses to the SHARED activity-host session the client
     * joined as its public target (L8b, FINDINGS 20.132). Zero disables the whole path.
     *
     * MEASURED DEFECT: both clients' PUBLIC TARGET activity clients establish into the
     * region-bound host row (0x9EAA3001:00200003) and this host has never sent that session
     * one message - `stage=wire_snapshot` named only each client's own private activity
     * session - so the public activity client sits at `MEM-0`, the public bubble reserves
     * `0` peer slots 125/125, and the peer channel is dropped by the game for want of an
     * owner. The existing `publicTarget` publisher cannot reach it: its role is set only by
     * `bindsPublicTarget`, which requires the join to name a session OTHER than the handle
     * the envelope addresses, and a client always addresses the host it is joining.
     *
     * This path is additive: each body is appended ALONGSIDE everything the link already
     * sends, and the link's own `activitySessionId` is never reassigned, so the private
     * activity client's stream is byte-for-byte what it is today. The count is a settings
     * value rather than a bool because whether the client needs one body (the upstream
     * `publicTarget` contract) or a live stream is exactly what the boot decides - raising
     * it must not need a rebuild (HARD RULES, p2(62)).
     */
    std::uint16_t activityPublicRowMembershipBodies{0};
};

/**
 * Checks one gameplay block for internal consistency.
 * @param settings Parsed or default gameplay settings.
 * @return True when the topology, port, and reserve can be bound and advertised together.
 */
[[nodiscard]] bool valid(const Settings& settings) noexcept;

/**
 * Reports the slots actually held back from the client lease.
 * A disabled channel authors no entities, so it reserves nothing and the client keeps the
 * whole slot space.
 * @param settings Active gameplay settings.
 * @return Configured reserve, or zero while the channel is off.
 */
[[nodiscard]] std::uint16_t effective_reserve(const Settings& settings) noexcept;

/**
 * Reports the entity slots one join grants.
 * A disabled channel reserves nothing, so the grant is bounded by the whole slot space instead.
 * @param settings Active gameplay settings.
 * @return Configured grant, capped at what the reserve leaves free.
 */
[[nodiscard]] std::size_t join_grant(const Settings& settings) noexcept;

} // namespace sunrise::core::settings::server::gameplay
