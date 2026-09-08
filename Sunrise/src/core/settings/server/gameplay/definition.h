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
     * Push one type-20 (allocate_entity_indices) notification per join, naming the
     * joining member's index block. Off keeps the join burst byte-identical to the
     * pre-20.213 shape (FINDINGS 20.212/20.213, RE_output/claims/
     * entity-index-allocation-schema.md).
     */
    bool entityIndexAllocation{false};
    /**
     * Name EVERY joined machine in the type-20 allocation, not just the joiner.
     *
     * v1 shipped `{&member, 1}` with the call site's own note that "the cross-member
     * map is deferred until decode is confirmed" - so a peer's index block has never
     * been published, while the encoder has always accepted kParticipantSlots (64)
     * rows and the schema has always carried them (20.336 R6). Twelve lines above
     * that call site the fork already records the consequence: "without it the host
     * client's manager sync always skips and every player_broadcast creation returns
     * -1", and the client duly logs `failed to create 'player_broadcast' entity`
     * 17-80 times in every archived boot on both machines.
     *
     * Off publishes v1's single row, byte-identical, so the arm reverts with a
     * settings flip and no rebuild.
     */
    bool entityIndexAllocationCrossMember{false};
    /**
     * Initiate the view-establishment handshake: the host sends its own view (id 40)
     * once per admitted peer at the first publish. The fork has only ever answered;
     * a client that never receives a host view never establishes its own, and the
     * entity external body stays unregistered (the 20.323/20.324 arc).
     */
    bool activityViewInitiate{false};
    /**
     * Designate each client to START hosting its own activity session (activity
     * message type 9, body [mode 1][activity session id][value 4], once per join
     * burst). The client's apply runs its per-session host state-machine step -
     * the activity-plane lever for the receiver-object construction after the
     * group-plane view road closed (20.326: the client drops id 40 at the switch,
     * no consumer on any plane). An unknown session id is a client-side no-op.
     */
    bool activityStartHostPush{false};
    /**
     * Push the type-51 (bubble_host_startup_info) handshake per join burst,
     * echoing the recipient client's own SteamNetworkingIdentity (captured
     * from its matchmaking advertisement). The client's validator memcmps
     * the decoded field-2 against the client's own row byte-exact — the
     * token is per-session and must be captured, never derived. The femu-
     * validated wire form is in RE_output/claims/type51-bubble-startup-
     * startup-spec.md (W8); the apply-half semantics are the boot's question.
     */
    bool activityBubbleStartup{false};
    /**
     * Log the raw leading bytes of every UPSTREAM (svc8) activity message body -
     * the client's own activity-message serialization, the one source for the
     * object layout the DOWN dispatcher consumes (the 20.323 ingress arc). Off
     * keeps the accept/skip lines byte-count only.
     */
    bool activityUpstreamDump{false};
    /**
     * Push one type-21 (entity-index grant) notification per join, carrying the
     * joiner's lease as the 1024-byte free-slot mask the client's entity manager
     * feeds its index allocator from (claims K/M, RE_output/claims/
     * entity-index-allocation-schema.md). Independent of entity_index_allocation
     * so either push can be turned off without a rebuild.
     */
    bool entityIndexGrant{false};
    /**
     * Push one type-30 (entity-index pool ASSIGNMENT) notification per join: one u32
     * the client decodes into [pool+0x602b4]. Its -1 default blocks the entity
     * manager's post-init local-mask sync, leaving the host client's mask empty and
     * failing every peer/player_broadcast creation (FINDINGS 20.217). v1 value: 0.
     */
    bool entityIndexAssignment{false};
    /**
     * Push one type-45 (peer-contact) notification alongside every peer-bearing
     * membership body: a 6-bit count and the peer's machine id, which the client's
     * handler 0x1404F3870 turns into "this peer is CONTACTABLE" (pool+0x602C4 = 1).
     * That byte is the last missing input of the per-tick peer evaluator
     * 0x140C171F0 - p2-153 caught the evaluator running and aborting on it 6,293
     * times across the two clients without it ever going nonzero (FINDINGS 20.245),
     * and 20.246 R6 established the evaluator's remaining per-entry probes are
     * informational writes rather than gates. Default off so the push burst stays
     * byte-identical until the lane turns it on.
     */
    bool poolC4MarkPush{false};
    /**
     * Selects the flat type-21 body (256 mask words, each MSB-first — the client
     * pool sender's own serialization) instead of the raw struct shape
     * {reserved word, mask bytes, owner byte}. Flippable without a rebuild so
     * one boot can A/B the two framings.
     */
    bool entityIndexGrantFlat{false};
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
     * THE JOIN RELAY (FINDINGS 20.309, settings-gated, default off = the off path is
     * byte-identical): when a client's type-0x0A join request arrives, forward the
     * whole join body to every OTHER connected peer's reliable outbound queue, so
     * each client's host-side join gate (0x14178DE60) processes the peer's join and
     * creates the peer's reservation record inside a proper container - stamping the
     * record's participant-mask bit from the container's field (0/1 -> bits 6/7)
     * instead of the containerless birth (field -1 -> bit 5) every boot measures.
     */
    bool relayPeerJoin{false};
    /**
     * THE JOIN LOOKUP RETARGET (20.319 static arc, connection-layer-join-delivery.md):
     * when the relay forwards one client's join to another peer, rewrite the COPY's
     * sessionId field to a value the RECIPIENT's own join gate can match, instead of
     * forwarding the sender's copy verbatim.
     *
     * Measured basis (p2-187, sess_cmp on the lookup's equality helper 0x141A83C00):
     * the client's join gate looks the join's sessionId up against the sessions bound
     * to its receiving connection's contexts (walker 0x14177A0B0, six slots, each
     * [ctx+0x1C7C0]-bound), and a join naming any other value is refused "unknown
     * session" (greppable) before the join processor ever runs. The mac refused the
     * relayed join at exactly that gate.
     *
     * THE VALUE (arm history, measured - never by assumption, the 09-01 rule):
     * arm 1, the recipient's JOIN IDENTITY machine id (read_join_machine_identity's
     * qword, the field6=0 activity identity): REFUTED by measurement (p2-188b - the
     * gate's 6-slot lookup refused it; the join processor never ran; that value
     * appeared as a live session blob NOWHERE).
     *
     * arm 2, the recipient's REAL account key (the field6!=0 activity identity,
     * 0xD3DABDA3AF16F99E on the mac): the FALLBACK, not the next move - the walked
     * slots are not proven to hold it.
     *
     * arm 3 (CURRENT): the recipient's CURRENT JOINID - the value under which its own
     * client binds its session, the joinId its own join request carried. PROVEN inside
     * the gate's walked records on BOTH machines (p2-189: binder2's stack args = the
     * machine's own joinId; binder ctx pointers = the walked slots; cof_soid granted
     * that key index 2; walk_map {0,-1,1,-1,-1,2}; p2-187 census: key=joinId vs
     * blob=joinId, match=1). The fork holds it live on every admitted row (the
     * membership machinery refuses updates that do not echo it).
     *
     * If the retargeted join is still refused, the per-caller sesscmp triples AT the
     * refusal walk (the widened instrument) name the gate's walked container directly
     * and decide the next arm without another value-arming boot.
     *
     * A recipient with no decoded identity falls back to the verbatim forward. False
     * keeps the byte-verbatim relay (HARD RULES, p2(62) - bisectable without a
     * rebuild). Default off.
     */
    bool relayJoinTargetIdentity{false};
    /**
     * THE JOIN-RELAY CHANNEL (p2-191, the container fix): which OOB association
     * carries the RELAYED join to each peer. False (default, byte-identical) =
     * the old path: dtls records first, the engine association only as fallback.
     * True = the ENGINE association first, dtls fallback.
     *
     * WHY IT MATTERS (p2-190f's complete walk readout): the join gate walks the
     * container of the packet's OWN connection ([ctx+0x28], disasm-verified). The
     * fork's dtls association's client-side container is nearly empty (one slot,
     * blob 0) so every key value refused there; the rich container - the one the
     * client's own landing machinery binds (binder1/binder2) and whose
     * forkSession blob matched (p2-190f: key=blob match=1) - lives on the
     * ENGINE association, the client's native transport. Delivering the join
     * there walks the primed container.
     */
    bool relayJoinEngineChannel{false};
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
     * Publishes the PEER's citizen advertisement even when the peer stands in THIS
     * session's own region (the shared-bubble case), instead of skipping it (FINDINGS
     * 20.239; the deferred 20.79 gap-5 question resolved as: both advertisements point
     * at the SAME region-bound shared host session, which activityHostRegionBound
     * already makes safe - the second request returns the existing row instead of
     * retiring it, so the p2(54)-era collide-and-retire destruction is unreachable).
     *
     * MEASURED DEFECT (p2-150, both machines, verified by dump + logs): with both
     * clients in one Tower region the peer row went out WITHOUT its join endpoint
     (peer_citizen=0), and the client fixup-released exactly that row ("a peer with
     * no address is not joinable"): the peer's participant record never activated
     * (state dword 0 vs the local 5), no presence bit, and the construction gate
     * never evaluated the peer. False keeps the historical skip (HARD RULES, p2(62)).
     */
    bool membershipPeerSameRegionAdvert{false};
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
