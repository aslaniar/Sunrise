#include "activity_membership_push.h"

#include "activity_message_push.h"

#include <Windows.h>

#include <array>
#include <cstddef>
#include <cstdio>
#include <optional>
#include <string_view>

#include "../../../../../middleware/bap/activity_message/replicate_membership.h"
#include "../../../../../middleware/gameplay/descriptor/join_descriptor.h"
#include "../../../../../middleware/secure_channel/runtime.h"
#include "../../../../../core/logging/log.h"
#include "../../../../gameplay/gameplay_advertisement.h"
#include "../../../../../state/activity/runtime.h"
#include "../../../../../state/activity/membership/activity_membership_query.h"
#include "../../../../../state/runtime/runtime.h"
#include "../../../../../core/settings/settings.h"
#include "../../../../gameplay/group/group_host.h"
#include "../../../../gameplay/group/group_host_sessions.h"
#include "../snapshot/internal.h"
#include "activity_arrival.h"
#include "membership_sweep.h"
#include "activity_notification_frame.h"

namespace sunrise::server::bap::encrypted::push::activity {
namespace {

/**
 * Peer-bearing bodies that may go out while the peer's transport identity is still
 * unknowable before they start counting against the withdrawal cap.
 *
 * SIZED FROM MEASUREMENT, not picked: p2-166's bodies were ~5 s apart and the gameplay
 * admission landed 11 s after the first refusal, so three bodies would have covered that
 * race with no margin. Eight gives roughly 40 s - comfortably past the observed race - and
 * still terminates, which is the property the cap exists to preserve.
 */
constexpr std::uint64_t kPeerAddressWaitCap = 8;

namespace message = middleware::bap::activity_message::replicate_membership;
namespace descriptor = middleware::gameplay::descriptor;

/** The one published member always occupies slot zero of both top-level masks. */
constexpr std::uint8_t kLocalMemberSlot = 0;

/**
 * Per-session place in the shape sweep.
 *
 * PER SESSION, not process-wide. The revision that carries a shape is per session, and a shape
 * change is only seen if its own session's revision advances with it - a shared phase would
 * advance the shape for a session whose revision had not moved, and the client would drop that
 * body as a repeat (Lane M). Independent slots also give two independent trials.
 */
struct SweepEntry final {
    std::uint64_t sessionId;
    SweepSlot slot;
    bool occupied;
};

/** Sessions that may be sweeping at once. Matches the activity session table's practical width. */
constexpr std::size_t kSweepEntryCapacity = 8;
/** Sweep slots. Touched only from the push path. */
SweepEntry g_sweepEntries[kSweepEntryCapacity]{};

/** @return This session's slot, claiming a free one on first use, or nullptr when full. */
[[nodiscard]] SweepSlot* sweep_slot(std::uint64_t sessionId) noexcept {
    SweepEntry* free = nullptr;
    for (SweepEntry& entry : g_sweepEntries) {
        if (entry.occupied && entry.sessionId == sessionId) {
            return &entry.slot;
        }
        if (!entry.occupied && free == nullptr) {
            free = &entry;
        }
    }
    if (free == nullptr) {
        return nullptr;
    }
    free->sessionId = sessionId;
    free->slot = {};
    free->occupied = true;
    return &free->slot;
}

/** @return Name of one absent-peer reason, for the boot record. */
[[nodiscard]] const char* peer_reason_name(state::activity::ForeignPeerReason reason) noexcept {
    switch (reason) {
    case state::activity::ForeignPeerReason::found:
        return "found";
    case state::activity::ForeignPeerReason::identity_missing:
        return "identity_missing";
    case state::activity::ForeignPeerReason::destination_mismatch:
        return "destination_mismatch";
    case state::activity::ForeignPeerReason::same_client:
        return "same_client";
    case state::activity::ForeignPeerReason::same_account:
        return "same_account";
    case state::activity::ForeignPeerReason::none_joined:
        return "none_joined";
    }
    return "unknown";
}

/**
 * Writes the full mirrored peer row.
 *
 * The row shape is no longer a variable: it was swept across six shapes and made no
 * difference at all (FINDINGS 20.51), so the most complete row is published every time and
 * the sweep varies the trailing fields instead.
 *
 * @param peer The other joined session's identity.
 * @param wire Receives the peer row.
 */
void apply_peer_row(const state::activity::membership::Identity& peer,
                    message::MembershipSnapshot& wire) noexcept {
    wire.peer = {};
    wire.peer.memberKey = peer.memberKey;
    wire.peer.field1 = peer.smallOpaque;
    wire.peer.field2 = peer.signedOpaque;
    wire.peer.field3 = peer.joinIdentity;
    wire.peer.accountSoid = peer.accountSoid;
    wire.peer.field5 = peer.opaqueSoid;
    wire.peer.field6 = peer.secondaryOpaque;
}

/**
 * Maps a lock-consistent State snapshot into the fixed Middleware schema.
 * @param sessionId Joined activity session, used to resolve the advertised region.
 * @param mutation Prepared membership operation, whose region this body publishes.
 * @return Whole current membership encoder input.
 */
[[nodiscard]] message::MembershipSnapshot
make_wire_snapshot(std::uint64_t sessionId,
                   const state::activity::membership::PendingMutation& mutation) noexcept {
    const state::activity::membership::Snapshot& snapshot = mutation.snapshot;
    message::MembershipSnapshot wire{};
    wire.identity.memberKey = snapshot.identity.memberKey;
    wire.identity.field1 = snapshot.identity.smallOpaque;
    wire.identity.field2 = snapshot.identity.signedOpaque;
    wire.identity.field3 = snapshot.identity.joinIdentity;
    wire.identity.accountSoid = snapshot.identity.accountSoid;
    wire.identity.field5 = snapshot.identity.opaqueSoid;
    wire.identity.field6 = snapshot.identity.secondaryOpaque;
    wire.spawn.state = snapshot.spawn.state;
    wire.spawn.opaqueByte = snapshot.spawn.opaqueByte;
    wire.spawn.opaqueValue = snapshot.spawn.opaqueValue;
    wire.teleport.state = snapshot.teleport.state;
    wire.teleport.token = snapshot.teleport.token;
    wire.teleport.sliceSetIndex = snapshot.teleport.sliceSetIndex;
    wire.teleport.sliceSetHash = snapshot.teleport.sliceSetHash;
    wire.revision = snapshot.revision;
    wire.epoch = snapshot.epoch;
    wire.transitionToken = snapshot.transitionToken;
    // The region this body is about to commit, not the one State still holds. Staging runs before
    // the commit, so the region just left would leave the pending record empty for good.
    const EffectiveRegion region = planned_region(mutation, sessionId);
    // SOURCED, not source-less. The source-less overload is upstream's fail-closed stub - it
    // clears the output and reports `reason=no_source` - and binding to it by accident is what
    // silenced the citizen advertisement from f68f230 onward (FINDINGS 20.31). The source is
    // this session's own committed record, whose destination the advertised target must copy.
    state::activity::SessionBinding source{};
    std::uint64_t hostGeneration = 0;
    if (state::activity::snapshot_binding(sessionId, source)) {
        server::gameplay::build_advertisement(
            source,
            region.index,
            region.reported ? server::gameplay::RegionSource::reported
                            : server::gameplay::RegionSource::arrival,
            kLocalMemberSlot,
            wire.citizen,
            hostGeneration);
        // Released here rather than held on the Session: threading a generation through six
        // append_membership_notification call sites buys only eviction resistance, and the host
        // row is re-claimed by the next advertisement. The row stays claimed; only the retain
        // that pins it against LRU eviction is dropped. Every retain is balanced.
        if (hostGeneration != 0) {
            server::gameplay::group::release_host_session(hostGeneration);
        }
    } else {
        wire.citizen = {};
    }
    // FINDINGS 20.44: a second joined session in this destination publishes its identity as
    // member slot 1. Without it the client's peer table holds only the local player and no
    // contact attempt can ever name anyone.
    state::activity::membership::Identity peerIdentity{};
    state::activity::ForeignPeerReason peerReason{};
    const core::settings::server::Settings& pushSettings = core::settings::get().server;
    const bool craftedSelfPeer = pushSettings.membershipSelfPeerRow;
    bool havePeer = false;
    if (craftedSelfPeer) {
        // C3 (BOOT_BRIEF_p2-174, FINDINGS 20.294 R5): recreate the p2(42)/20.53 condition -
        // a full row naming the LOCAL player - on today's fork, settings-gated. The
        // same_client/same_account refusals are bypassed by construction: this row names self
        // on purpose, and the boot's question is what the client's body-builder does with a
        // row whose CHARACTER field is overridden (membership_row_character_override).
        peerIdentity.memberKey = snapshot.identity.memberKey;
        peerIdentity.smallOpaque = snapshot.identity.smallOpaque;
        peerIdentity.signedOpaque = snapshot.identity.signedOpaque;
        peerIdentity.joinIdentity = snapshot.identity.joinIdentity;
        peerIdentity.accountSoid = snapshot.identity.accountSoid;
        peerIdentity.opaqueSoid = snapshot.identity.opaqueSoid;
        peerIdentity.secondaryOpaque = snapshot.identity.secondaryOpaque;
        havePeer = true;
        std::array<char, core::log::kLineCapacity> craftedLine{};
        const int craftedWritten = std::snprintf(
            craftedLine.data(), craftedLine.size(),
            "ev=membership stage=crafted_peer result=ok key=0x%016llx acct=0x%016llx "
            "f3=0x%016llx f5=0x%016llx f6=0x%016llx",
            static_cast<unsigned long long>(peerIdentity.memberKey),
            static_cast<unsigned long long>(peerIdentity.accountSoid),
            static_cast<unsigned long long>(peerIdentity.joinIdentity),
            static_cast<unsigned long long>(peerIdentity.opaqueSoid),
            static_cast<unsigned long long>(peerIdentity.secondaryOpaque));
        if (craftedWritten > 0) {
            core::log::write(core::log::Channel::server, core::log::Level::info,
                             {craftedLine.data(), static_cast<std::size_t>(craftedWritten)});
        }
        if (pushSettings.membershipRowCharacterOverride != 0) {
            // The character field is KNOWN, not guessed: the fork's own membership route
            // maps parsed.field5 -> identity.opaqueSoid and logs it as character=
            // (activity_membership_route.cpp:33/77-83). Replace field5 directly, with a
            // sanity check against the account's FULL character list (not just the
            // selected one - the server's selection can diverge from the client's played
            // character, 20.64's lesson). A field5 outside the list is logged and the row
            // publishes unchanged - that is a locator-negative to record, not a C3
            // answer by itself.
            const core::settings::AccountKey accountKey = core::settings::local_account();
            const state::AccountState account = state::account_snapshot(accountKey);
            bool knownCharacter = false;
            for (std::size_t index = 0; index < account.characterCount; ++index) {
                if (account.characters[index].soid == peerIdentity.opaqueSoid) {
                    knownCharacter = true;
                    break;
                }
            }
            if (knownCharacter) {
                const std::uint64_t before = peerIdentity.opaqueSoid;
                peerIdentity.opaqueSoid = pushSettings.membershipRowCharacterOverride;
                std::array<char, core::log::kLineCapacity> overrideLine{};
                const int written = std::snprintf(
                    overrideLine.data(), overrideLine.size(),
                    "ev=membership stage=crafted_character result=ok field=field5 "
                    "pre=0x%016llx post=0x%016llx",
                    static_cast<unsigned long long>(before),
                    static_cast<unsigned long long>(peerIdentity.opaqueSoid));
                if (written > 0) {
                    core::log::write(core::log::Channel::server, core::log::Level::info,
                                     {overrideLine.data(), static_cast<std::size_t>(written)});
                }
            } else {
                std::array<char, core::log::kLineCapacity> missLine{};
                const int written = std::snprintf(
                    missLine.data(), missLine.size(),
                    "ev=membership stage=crafted_character result=field5_not_known_"
                    "character f5=0x%016llx accountChars=%u - row published UNCHANGED",
                    static_cast<unsigned long long>(peerIdentity.opaqueSoid),
                    static_cast<unsigned>(account.characterCount));
                if (written > 0) {
                    core::log::write(core::log::Channel::server, core::log::Level::warn,
                                     {missLine.data(), static_cast<std::size_t>(written)});
                }
            }
        }
    } else {
        havePeer =
            state::activity::foreign_member_identity(sessionId, peerIdentity, peerReason);
    }
    // 20.74.4 DELIVERY FIX: the foreign member row arrives at the other host only when THIS
    // body also carries THAT host's citizen advertisement - its join endpoint. Without it
    // every host fixup-releases the row (reason=1) because a peer with no address is not
    // joinable.
    //
    // THE PEER'S OWN REGION, not this session's. p2(54) passed `region.index` here, which is
    // the LOCAL session's region, and the consequences were both silent and destructive
    // (FINDINGS 20.78 defect 3): the two advertisements landed on one region record, and
    // because `region_machine_id` keys the host-session row by region index alone, the peer's
    // `request_host_session` call collided with the local one and RETIRED the row the local
    // call had just built. Every peer push cost the local host session and returned
    // `no_host_session`.
    //
    // The same-region case is skipped outright rather than resolved. A region record holds ONE
    // descriptor and the local advertisement owns the record for the local region, so a peer
    // standing in the same bubble has no record to occupy - and skipping makes the key
    // collision unreachable by construction instead of merely unlikely. Whose endpoint belongs
    // in a shared bubble is the host/guest question (protocol types 8 -> 9/10, FINDINGS 20.79
    // gap 5); it is not answerable here and must not be guessed at.
    message::CitizenAdvertisement peerCitizen{};
    constexpr std::uint8_t kPeerMemberSlot = 1;
    // THE DECISION, not the activity (lesson 5). THREE different causes leave a peer row with no
    // endpoint and TWO of them emit nothing at all: an unresolved binding is silent, and the
    // same-region skip does not even call `build_advertisement`, so its `result=skip` line never
    // appears either. A body carrying a peer but no peer endpoint would then be unattributable
    // among three causes. This line fires on EVERY peer-bearing body, including the boring one.
    const char* peerAdvertReason = "no_peer";
    std::int32_t peerRegionIndex = -1;
    if (havePeer) {
        peerAdvertReason = "no_binding";
        state::activity::SessionBinding peerBinding{};
        if (state::activity::session_binding_for_member(peerIdentity.memberKey, peerBinding)) {
            const EffectiveRegion peerRegion = effective_region(peerBinding.sessionId);
            peerRegionIndex = peerRegion.index;
            if (peerRegion.index < 0) {
                peerAdvertReason = "peer_region_unset";
            } else if (peerRegion.index == region.index
                       && !core::settings::get().server.gameplay.membershipPeerSameRegionAdvert) {
                // Shared bubble, switch OFF: the historical skip (FINDINGS 20.239 - the
                // peer row went out with no endpoint and both clients fixup-released it).
                peerAdvertReason = "same_region";
            } else {
                // With the switch ON this path also runs for the SHARED bubble: the peer's
                // advertisement is built against the peer's OWN region, which here equals
                // ours, and with activityHostRegionBound the second request on that region
                // key returns the EXISTING shared host row (no retire, no conflict) - so
                // both advertisements carry the same shared activity-host descriptor.
                std::uint64_t peerGeneration = 0;
                server::gameplay::build_advertisement(
                    peerBinding,
                    peerRegion.index,
                    peerRegion.reported ? server::gameplay::RegionSource::reported
                                        : server::gameplay::RegionSource::arrival,
                    kPeerMemberSlot,
                    peerCitizen,
                    peerGeneration);
                if (peerGeneration != 0) {
                    server::gameplay::group::release_host_session(peerGeneration);
                }
                peerAdvertReason = peerCitizen.present ? "built" : "build_failed";
            }
        }
    }
    if (havePeer) {
        std::array<char, 192> advertLine{};
        const int advertWritten =
            std::snprintf(advertLine.data(),
                          advertLine.size(),
                          "ev=activity stage=peer_advert result=%s own_region=%d peer_region=%d "
                          "own_citizen=%d peer_citizen=%d",
                          peerAdvertReason,
                          static_cast<int>(region.index),
                          static_cast<int>(peerRegionIndex),
                          wire.citizen.present ? 1 : 0,
                          peerCitizen.present ? 1 : 0);
        if (advertWritten > 0) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::info,
                             {advertLine.data(), static_cast<std::size_t>(advertWritten)});
        }
    }
    // Only a body that HAS a peer to publish advances the sweep - a solo body carries no shape
    // under test, and counting it would spend shapes on nothing.
    const core::settings::server::Settings& serverSettings = core::settings::get().server;
    TrailingVariant variant = TrailingVariant::packedMasks;
    SweepDecision decision{};
    SweepSlot* slot = nullptr;
    // A PINNED reading never advances: it is how a candidate the sweep implicated gets
    // confirmed on its own, one variable at a time, with no rebuild between rounds.
    const bool pinned = serverSettings.membershipSweepPin >= 0
                        && serverSettings.membershipSweepPin
                               < static_cast<std::int32_t>(kTrailingVariantCount);
    if (pinned) {
        variant = static_cast<TrailingVariant>(serverSettings.membershipSweepPin);
    }
    // The slot is claimed whenever there IS a peer, not only while sweeping: it now also
    // carries the retry counters, which apply to every peer body however the reading was
    // chosen.
    SweepSlot* retry = havePeer ? sweep_slot(sessionId) : nullptr;
    if (!pinned && havePeer && serverSettings.membershipSweep) {
        slot = retry;
    }
    if (slot != nullptr) {
        decision = sweep_decide(*slot,
                                GetTickCount64(),
                                serverSettings.membershipSweepBodies,
                                serverSettings.membershipSweepDwellMs);
        variant = decision.variant;
    }
    const TrailingValues values = trailing_values(variant);
    // An acknowledgement means the last body landed, so the retry budget starts over.
    //
    // The withdrawal flag is NOT cleared on a bare acknowledgement: after a withdrawal the
    // SOLO body is what gets acknowledged, and clearing on that would re-add the peer
    // immediately and restart the storm the cap exists to stop (p2(111) blocked a Tower
    // load that way). That is why "clear on ack" is the wrong fix.
    //
    // THE RATE-LIMITED RE-ARM (FINDINGS 20.298 R7 / 20.299, settings-gated, default OFF so
    // the off path is byte-identical): sticky-forever is wrong in the other direction. The
    // client never acknowledges a peer-bearing body (20.48), so the cap always trips and the
    // session then runs dry - 81% of p2-175's peer-available snapshots sent nothing, and
    // 20.297 R2's verdict was measured against that silence. With the knob set, N
    // acknowledged bodies re-arm the peer ONCE. Each re-arm still pays the full retry cap
    // before withdrawing again, so the storm ceiling is unchanged.
    if (retry != nullptr && state::activity::membership::acknowledged(sessionId)) {
        retry->unackedPeerBodies = 0;
        if (retry->peerWithdrawn && serverSettings.membershipPeerRearmAfterAcks != 0) {
            ++retry->acksSinceWithdrawal;
            if (retry->acksSinceWithdrawal >= serverSettings.membershipPeerRearmAfterAcks) {
                retry->peerWithdrawn = false;
                retry->acksSinceWithdrawal = 0;
                std::array<char, 192> rearm{};
                const int rearmLine =
                    std::snprintf(rearm.data(),
                                  rearm.size(),
                                  "ev=activity stage=membership_peer result=rearmed "
                                  "after_acks=%u session=%llu",
                                  serverSettings.membershipPeerRearmAfterAcks,
                                  static_cast<unsigned long long>(sessionId));
                if (rearmLine > 0) {
                    core::log::write(core::log::Channel::server,
                                     core::log::Level::warn,
                                     {rearm.data(), static_cast<std::size_t>(rearmLine)});
                }
            }
        }
    }
    bool publishPeer = havePeer && values.peerPresent && (retry == nullptr
                                                          || !retry->peerWithdrawn);
    // The retry/withdrawal budget runs only in the legacy regime. Under the duty
    // cycle the pacing IS the rate limit: bodies are peer-bearing at most once per
    // window, so no storm can build, and stacking the sticky withdrawal on top
    // would end sustainment after ~cap windows (the re-arm is unreachable, 20.300
    // R5). FINDINGS 20.306/20.307.
    const bool dutyCycled = serverSettings.membershipPeerDutyCycleMs != 0;
    if (publishPeer && retry != nullptr && serverSettings.membershipPeerRetryCap != 0
        && !dutyCycled
        && retry->unackedPeerBodies >= serverSettings.membershipPeerRetryCap) {
        retry->peerWithdrawn = true;
        retry->acksSinceWithdrawal = 0;  // the re-arm window starts AT the withdrawal
        publishPeer = false;
        std::array<char, 192> withdrawn{};
        const int withdrawnLine =
            std::snprintf(withdrawn.data(),
                          withdrawn.size(),
                          "ev=activity stage=membership_peer result=withdrawn variant=%s "
                          "unacked=%llu session=%llu",
                          variant_name(variant),
                          static_cast<unsigned long long>(retry->unackedPeerBodies),
                          static_cast<unsigned long long>(sessionId));
        if (withdrawnLine > 0) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::warn,
                             {withdrawn.data(), static_cast<std::size_t>(withdrawnLine)});
        }
    }
    // THE DUTY-CYCLE GATE (FINDINGS 20.306/20.307 R4b, settings-gated, 0 = off =
    // byte-identical): publish the peer row at most once per window. Between
    // windows the row is omitted, which gives the client's re-landing its quiet
    // window (~12-18 s measured, 20.307 R3) instead of starving it at body
    // cadence. A paced-out body is an INTENTIONAL omission, not a refusal: it
    // must not cost retry budget (there is no budget in this regime anyway) and
    // it must log, so the boot can tell paced silence from withdrawn silence.
    if (publishPeer && retry != nullptr && dutyCycled) {
        const std::uint64_t nowTick = GetTickCount64();
        if (retry->lastPeerPublishTick != 0
            && nowTick - retry->lastPeerPublishTick
                   < static_cast<std::uint64_t>(
                       serverSettings.membershipPeerDutyCycleMs)) {
            publishPeer = false;
            std::array<char, 192> paced{};
            const int pacedLine =
                std::snprintf(paced.data(),
                              paced.size(),
                              "ev=activity stage=membership_peer result=paced "
                              "since_ms=%llu window=%u session=%llu",
                              static_cast<unsigned long long>(
                                  nowTick - retry->lastPeerPublishTick),
                              serverSettings.membershipPeerDutyCycleMs,
                              static_cast<unsigned long long>(sessionId));
            if (pacedLine > 0) {
                core::log::write(core::log::Channel::server,
                                 core::log::Level::debug,
                                 {paced.data(), static_cast<std::size_t>(pacedLine)});
            }
        } else {
            retry->lastPeerPublishTick = nowTick;
        }
    }
    if (publishPeer) {
        apply_peer_row(peerIdentity, wire);
        wire.peerPresent = true;
        // 20.74.4: the peer's own join endpoint rides in its region slot, so the receiving
        // host sees a peer WITH an address instead of an unjoinable fixup row.
        //
        // The builder's OWN verdict stands. p2(54) overwrote it with `peerSessionId != 0`,
        // which marked a zeroed advertisement present whenever the peer's binding resolved -
        // even though `build_candidate` had skipped and cleared the whole struct. A cleared
        // advertisement carries `regionIndex = 0`, so the region writer matched it at bubble 0
        // and emitted 128 zero bytes there, and the body then failed to encode (FINDINGS 20.78
        // defect 2). Never second-guess a builder that clears its output on failure.
        wire.peerCitizen = peerCitizen;
        // The peer row's transport identity (schema field 10, the 86-byte array the client's
        // admission sweep compares against each reservation record - FINDINGS 20.277-20.280).
        //
        // SOURCE: the PEER'S OWN captured NetAddr blob, echoed byte exact from the connect
        // request that peer sent, located through group_host by the peer's member key.
        //
        // NOT the advertisement descriptor. p2-165 shipped that and it is wrong: the descriptor
        // `build_advertisement` produces is the ACTIVITY-HOST endpoint for a region, not the
        // peer's own transport endpoint, so both directions carried the SAME address. p2-165's
        // server log has addr=3232235940 (192.168.1.164, the mac) on all six builds - including
        // the body whose peer row named the RIG (key 0x846C8338F7D022E6) - so the mac was being
        // told its peer lived at the mac's own endpoint. A card naming the wrong machine cannot
        // match the reservation record no matter what the entry->slot compose hop does with it.
        //
        // Settings-gated: off reproduces every body this fork has ever sent.
        const char* transportResult = "off";
        // TRANSIENT means "the address is not knowable YET", as opposed to a wrong key. The
        // distinction drives the retry accounting below: waiting for the gameplay layer to
        // finish admitting the peer must not spend the withdrawal budget, because that budget
        // exists to stop a REFUSED body from repeating forever, and this body is not refused.
        bool transportPending = false;
        if (serverSettings.membershipPeerTransportIdentity) {
            const char* addressReason = "";
            if (server::gameplay::group::net_addr_for_member(peerIdentity.memberKey,
                                                             wire.peerTransportIdentity,
                                                             addressReason)) {
                wire.peerTransportIdentityPresent = true;
                transportResult = addressReason;  // `echoed` or `rebuilt`
            } else {
                // Publish NOTHING rather than a guessed endpoint, and say which cause it was.
                wire.peerTransportIdentity = {};
                wire.peerTransportIdentityPresent = false;
                transportResult = addressReason;  // `no_admitted_row` or `ambiguous_member_key`
                // Only the missing-row case resolves on its own; a bad key never will.
                transportPending = std::string_view(addressReason) == "no_admitted_row";
            }
        }
        // Fail-loud either way: a peer row whose transport identity did not go out is
        // unattributable from the client side alone (the sweep will disown the record and
        // nothing else will say why). Fires on every peer-bearing body, like peer_advert.
        {
            // The card's OWN leading bytes, not a pair of scalars re-derived beside it: the
            // blob is what goes on the wire, so the log has to be able to convict the blob.
            // Bytes 0-3 are the address and 4-5 the port, in the NetAddr's own byte order -
            // printed raw so a byte-order question is answerable from the log alone.
            const auto card = [&wire](std::size_t i) {
                return static_cast<unsigned>(
                    std::to_integer<std::uint8_t>(wire.peerTransportIdentity[i]));
            };
            std::array<char, 224> transportLine{};
            const int transportWritten = std::snprintf(
                transportLine.data(), transportLine.size(),
                "ev=activity stage=peer_transport_identity result=%s present=%d "
                "member=0x%016llX card=%02x%02x%02x%02x:%02x%02x waits=%llu/%llu",
                transportResult,
                wire.peerTransportIdentityPresent ? 1 : 0,
                static_cast<unsigned long long>(peerIdentity.memberKey),
                card(0), card(1), card(2), card(3), card(4), card(5),
                // Waits SPENT BEFORE this body: a run that ends with waits short of the cap
                // means the race resolved, one that pins at the cap means it never did.
                static_cast<unsigned long long>(retry != nullptr ? retry->peerAddressWaits : 0),
                static_cast<unsigned long long>(kPeerAddressWaitCap));
            if (transportWritten > 0) {
                core::log::write(core::log::Channel::server,
                                 core::log::Level::info,
                                 {transportLine.data(), static_cast<std::size_t>(transportWritten)});
            }
        }
        // Zero-valued peer-row bit groups published as ones, per settings. Default 0 sends
        // exactly the body this fork has always sent; the mask exists so a positive result
        // can be bisected without a rebuild between rounds.
        wire.peerRowFlags = serverSettings.membershipPeerRowFlags;
        // Zero leaves the encoder on its historical value, which is what `solo` wants.
        wire.trailingFirst = values.first;
        wire.trailingSecond = values.second;
        wire.trailingThird = values.third;
        wire.trailingFourth = values.fourth;
        if (retry != nullptr && !dutyCycled) {
            // A body sent while the peer's address is merely not-yet-knowable is charged to
            // its own bounded counter, so the withdrawal cap still bounds REFUSALS while the
            // admission race gets room to resolve. Past the wait cap the body is charged
            // normally again: an admission that never lands must not publish forever.
            // (Duty-cycled regime: no budget is charged at all - see the cap-check guard.)
            if (transportPending && retry->peerAddressWaits < kPeerAddressWaitCap) {
                ++retry->peerAddressWaits;
            } else {
                ++retry->unackedPeerBodies;
            }
        }
    }
    {
        // INSTRUMENT (FINDINGS 20.47): every type-12 body built anywhere converges here, so
        // this line is the boring-path proof the encoder input stage ran at all - its absence
        // means no membership body was due, which is a different finding from a refused one.
        std::array<char, 160> line{};
        int writtenLine = std::snprintf(line.data(),
                                        line.size(),
                                        "ev=activity stage=wire_snapshot session=%llu peer=%d",
                                        static_cast<unsigned long long>(sessionId),
                                        havePeer ? 1 : 0);
        if (!havePeer) {
            writtenLine = std::snprintf(line.data(),
                                        line.size(),
                                        "ev=activity stage=wire_snapshot session=%llu peer=0 "
                                        "reason=%s",
                                        static_cast<unsigned long long>(sessionId),
                                        peer_reason_name(peerReason));
        }
        if (writtenLine > 0) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::debug,
                             {line.data(), static_cast<std::size_t>(writtenLine)});
        }
    }
    if (publishPeer) {
        // 256, not 224: row_flags= pushed the widest form of this line past the old buffer,
        // and snprintf would have truncated the field silently.
        std::array<char, 256> line{};
        // ack= is the PREVIOUS body's verdict, which is exactly the correlation wanted: the
        // shape named here is the one the client was holding when it decided. A flip to ack=1
        // stops the republish loop, so the last shape logged before the log goes quiet is the
        // accepted one.
        const int includedLine =
            std::snprintf(line.data(),
                          line.size(),
                          "ev=activity stage=membership_peer result=included key=0x%016llX "
                          "variant=%s step=%llu ack=%d peer_row=%d first=0x%08X second=0x%08X "
                          "row_flags=0x%02X",
                          static_cast<unsigned long long>(peerIdentity.memberKey),
                          variant_name(variant),
                          static_cast<unsigned long long>(slot == nullptr ? 0 : slot->step),
                          state::activity::membership::acknowledged(sessionId) ? 1 : 0,
                          wire.peerPresent ? 1 : 0,
                          values.first,
                          values.second,
                          wire.peerRowFlags);
        if (includedLine > 0) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(includedLine)});
        }
    }
    if (slot != nullptr) {
        const std::uint64_t now = GetTickCount64();
        sweep_apply(*slot, decision, now);
        // THE POINT OF THE FIX. The client applies one update per revision and drops every
        // repeat, so the next body's new shape must ride a new revision or it is discarded
        // unread. Advancing here - after this body is built - pairs (new shape, new revision)
        // on the NEXT body. The first sweep run lacked this and therefore measured exactly one
        // shape while appearing to measure two (FINDINGS 20.49/20.50).
        if (decision.advance && state::activity::membership::republish(sessionId)) {
            std::array<char, 128> retire{};
            const int retireLine =
                std::snprintf(retire.data(),
                              retire.size(),
                              "ev=activity stage=membership_sweep result=retired variant=%s "
                              "next=%s",
                              variant_name(decision.variant),
                              variant_name(static_cast<TrailingVariant>(
                                  slot->step % kTrailingVariantCount)));
            if (retireLine > 0) {
                core::log::write(core::log::Channel::server,
                                 core::log::Level::info,
                                 {retire.data(), static_cast<std::size_t>(retireLine)});
            }
        }
    }
    return wire;
}

} // namespace

/** Appends one current membership svc9 notification and advances its local nonce. */
bool append_membership_notification(Scratch& scratch,
                                    const activity_message::ActivityPlan& activity,
                                    std::span<const std::byte, state::kAesKeySize> key,
                                    std::array<std::byte, state::kBapNonceSize>& nonce,
                                    std::span<std::byte> response,
                                    std::size_t& written) noexcept {
    if (written > response.size() || !activity.membershipMutation.hasSnapshot) {
        return false;
    }

    const std::size_t initialWritten = written;
    auto initialNonce = nonce;
    std::size_t messageSize = 0;
    const message::MembershipSnapshot snapshot =
        make_wire_snapshot(activity.sessionId, activity.membershipMutation);
    const bool encoded =
        message::encode_replicate_membership(snapshot, scratch.responseBody, messageSize)
        && append_notification_frame(scratch,
                                     activity.sessionId,
                                     message::kMessageType,
                                     std::span(scratch.responseBody).first(messageSize),
                                     key,
                                     nonce,
                                     response,
                                     written);
    // CAPTURE (FINDINGS 20.74.2): hex-dump the membership body head on every push that carries
    // a peer row. With the schema decoded (msg12-schema-decoded.md), these bytes transcribe
    // into exact per-field rows; local row vs foreign row diff names the field content that
    // makes a host fixup-release a foreign peer instead of admitting it.
    if (encoded && snapshot.peerPresent) {
        std::array<char, 512> dump{};
        std::size_t dumpBytes = messageSize < 160 ? messageSize : 160;
        int dumped = std::snprintf(dump.data(),
                                   dump.size(),
                                   "ev=activity stage=body_capture type=12 session=%llu "
                                   "size=%zu bytes=",
                                   static_cast<unsigned long long>(activity.sessionId),
                                   messageSize);
        for (std::size_t index = 0;
             dumped > 0 && index < dumpBytes
             && static_cast<std::size_t>(dumped) < dump.size() - 4;
             ++index) {
            const int step =
                std::snprintf(dump.data() + dumped,
                              dump.size() - static_cast<std::size_t>(dumped),
                              "%02X",
                              std::to_integer<unsigned>(scratch.responseBody[index]));
            dumped = step > 0 ? dumped + step : 0;
        }
        if (dumped > 0) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::info,
                             {dump.data(), static_cast<std::size_t>(dumped)});
        }
    }
    if (!encoded) {
        // A refused body used to fail silently and read as "no push was due". Name it.
        core::log::write(core::log::Channel::server,
                         core::log::Level::warn,
                         "ev=activity stage=membership result=encode_fail");
    }
    SecureZeroMemory(scratch.responseBody.data(), message::encoded_size(snapshot));
    if (encoded) {
        middleware::secure_channel::advance_nonce(nonce);
    }
    // TYPE 45 AFTER TYPE 12: mark the peer CONTACTABLE (FINDINGS 20.245/20.246 R6).
    // The membership body tells this client the peer EXISTS; nothing has ever told it the
    // peer is REACHABLE, and the per-tick evaluator 0x140C171F0 aborts on that byte -
    // measured 3,996 times on the mac and 2,297 on the rig in p2-153, never once nonzero.
    // It rides here rather than in the join burst because the peer is not known at join
    // time, and this push already recurs, so the mark retries for free: the handler marks
    // whatever rows exist when the body lands, and the client self-heals the row itself
    // (20.242), so a body that arrives early is a harmless no-op rather than an error.
    // Its own switch, so the burst stays byte-identical when off.
    if (encoded && snapshot.peerPresent
        && core::settings::get().server.gameplay.poolC4MarkPush) {
        // NEVER MARK THIS CLIENT'S OWN MACHINE ID (20.249, and it cost a client crash).
        // p2-156 sent {peer, self} on the theory that marking every row made "which row
        // does the evaluator read" moot. The mac's own row went c4 0x00 -> 0x01 and ~750
        // ms later its activity client lost its host (join result with a BLANK session
        // id), began rejecting message types it had been handling all boot (17, 52),
        // entered private_repair and crashed; the rig never reached the Tower. The byte
        // is a claim that a machine is a REMOTE PEER worth contacting - asserting it
        // about yourself is a state the client is built to exclude (the construction
        // gate's own cond 2 is "i != self index"). Peer only, always.
        const std::array<std::uint64_t, 1> machineIds{snapshot.peer.memberKey};
        const bool marked = append_peer_contact_notification(scratch,
                                                             activity.sessionId,
                                                             machineIds,
                                                             key,
                                                             nonce,
                                                             response,
                                                             written);
        // NAME THE OUTCOME, not the activity (lesson 5): a silent absence here would be
        // unattributable between "switch off", "no peer" and "encode refused".
        std::array<char, 160> markLine{};
        const int markWritten =
            std::snprintf(markLine.data(),
                          markLine.size(),
                          "ev=activity stage=peer_contact result=%s type=45 session=%llu "
                          "peer_machine=0x%llX ids=%zu",
                          marked ? "sent" : "encode_fail",
                          static_cast<unsigned long long>(activity.sessionId),
                          static_cast<unsigned long long>(snapshot.peer.memberKey),
                          machineIds.size());
        if (markWritten > 0) {
            core::log::write(core::log::Channel::server,
                             marked ? core::log::Level::info : core::log::Level::warn,
                             {markLine.data(), static_cast<std::size_t>(markWritten)});
        }
        // A refused mark must not strand the membership body that already encoded: the
        // appender restores `written` and the nonce itself, so the membership push stands.
    }
    if (!encoded) {
        if (written > initialWritten) {
            SecureZeroMemory(response.data() + initialWritten, written - initialWritten);
        }
        written = initialWritten;
        nonce = initialNonce;
    }
    SecureZeroMemory(&initialNonce, sizeof initialNonce);
    return encoded;
}

} // namespace sunrise::server::bap::encrypted::push::activity
