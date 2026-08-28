#include "bap_connection_publication.h"

#include <Windows.h>

#include <array>
#include <cstdio>

#include "../../../core/logging/log.h"

namespace sunrise::server::bap::encrypted {
namespace {

/** Measured delay before the second Family-4 snapshot. */
constexpr std::uint64_t kFamily4RepushDelayMs = 400;
/** The banner pair lands the same unsolicited way and hits the same record-state race. */
constexpr std::uint64_t kBannerRepushDelayMs = 400;
/** The ability-bucket rebuild's settling window before the refresh pair re-sends. */
constexpr std::uint64_t kAbilityRefreshDelayMs = 500;
/**
 * How long the roster keeps its faster cadence after a load starts.
 * The slice-set load step costs 9.2 to 14.1 s, so this covers it.
 */
constexpr std::uint64_t kTransitionWindowMs = 15'000;

} // namespace

/** Captures the connection fields one service outcome carries. */
ConnectionFields connection_fields(const ServiceOutcome& outcome) noexcept {
    ConnectionFields fields{};
    const auto* planPtr = transaction_if<activity_message::ActivityPlan>(outcome);
    if (planPtr == nullptr) {
        return fields;
    }
    const auto& plan = *planPtr;
    if (plan.delivery == activity_message::Delivery::joinNotifications) {
        fields.joinMemberKey = plan.entitySlotMutation.memberKey;
        fields.joinCharacterSoid = plan.joinCharacterSoid;
        fields.joinsActivity = true;
        fields.bindsPublicTarget = plan.bindsPublicTarget;
        fields.publicGroupSession = plan.publicGroupSession;
        fields.publicTargetSession = plan.sessionId;
        fields.namesPublicHostRow = plan.namesPublicHostRow;
        fields.publicHostSession = plan.publicHostSession;
    }
    // The initial load is a transition too, and its token does not arrive for several seconds.
    fields.opensTransitionWindow =
        plan.delivery == activity_message::Delivery::joinNotifications || plan.transitionStarted;
    if (plan.mutationDomain == activity_message::MutationDomain::patchEpoch) {
        fields.patchEpoch = plan.patchEpoch;
        fields.retainsPatchEpoch = true;
    }
    return fields;
}

/**
 * This process's per-account private activity sessions. Four slots, one per provisioned
 * account, written by whichever connection owns that account's private activity session and
 * read by that account's public link, which owns none. Plain array under the BAP route's
 * existing exclusive lock - every caller of both functions already holds it.
 */
std::array<std::uint64_t, core::settings::kAccountCapacity> g_privateActivitySessions{};

/** Records this account's private activity session. See the header for why the key is the slot. */
void note_private_activity_session(const core::settings::AccountKey accountKey,
                                   const std::uint64_t sessionId) noexcept {
    if (accountKey < core::settings::kAccountCapacity) {
        g_privateActivitySessions[accountKey] = sessionId;
    }
}

/** @return That account's private activity session, or zero when none has been recorded. */
std::uint64_t private_activity_session(const core::settings::AccountKey accountKey) noexcept {
    return accountKey < core::settings::kAccountCapacity ? g_privateActivitySessions[accountKey]
                                                         : 0;
}

/** Publishes the captured connection fields after a successful commit. */
void publish_connection_fields(Session& session,
                               const transactions::Publication& publication,
                               const ConnectionFields& fields) noexcept {
    if (publication.hasActivitySessionBinding) {
        session.activitySessionId = publication.activitySessionId;
        // A link that owns an activity session is this account's PRIVATE half by definition -
        // the public half never owns one (measured: `activesession=0x0` on every row-bearing
        // connection, p2(88)/p2(89)). Recorded so that half can find this session.
        if (publication.activitySessionId != session.activityPublicRowSession) {
            note_private_activity_session(session.accountKey, publication.activitySessionId);
        }
    }
    if (fields.joinMemberKey != 0) {
        session.activityMemberKey = fields.joinMemberKey;
    }
    if (fields.joinCharacterSoid != 0) {
        session.activityCharacterSoid = fields.joinCharacterSoid;
    }
    if (fields.retainsPatchEpoch) {
        session.activityPatchEpoch = fields.patchEpoch;
        session.activityPatchEpochSeen = true;
    }
    if (fields.opensTransitionWindow) {
        session.activityTransitionUntilTick = GetTickCount64() + kTransitionWindowMs;
    }
    // A join resets the client's roster container, so the warm-up is re-armed. Its unconditional
    // state-byte moves make the client deactivate and rebuild every roster-owned object, and the
    // player object binds to the published membership only on that rebuild.
    if (fields.joinsActivity) {
        session.activityRosterSends = 0;
        session.activityRosterGroups = 0;
    }
    // A join naming a session this server advertised makes THIS link the client's public half.
    // The private link keeps its own role, so the pair stays distinguishable and only the public
    // one is allowed to publish the membership body.
    if (fields.bindsPublicTarget) {
        session.activityRole = ActivityClientRole::publicTarget;
        session.activityPublicGroupSession = fields.publicGroupSession;
        session.activitySessionId = fields.publicTargetSession;
        session.activityPublicMembershipSent = false;
        core::log::write(core::log::Channel::server,
                         core::log::Level::info,
                         "ev=activity stage=bind result=public_target");
    } else if (fields.joinsActivity && session.activityRole == ActivityClientRole::none) {
        session.activityRole = ActivityClientRole::privateCurrent;
    }
    // L8b (FINDINGS 20.132), STRICTLY ADDITIVE: record the shared activity-host session this
    // link's client joined as its public target. Deliberately NOT an `else` and deliberately
    // NOT touching `activityRole` or `activitySessionId` - one BAP link multiplexes both of the
    // client's activity clients by the envelope's handle (which is why the envelope carries one
    // at all), so reassigning the link's activity session would move the PRIVATE client's whole
    // stream onto the public id, and the private member table is the only one carrying a member
    // the client matches as its local player. The keepalive appends the public body next to that
    // stream instead of replacing it.
    if (fields.namesPublicHostRow && fields.publicHostSession != 0
        && session.activityPublicRowSession != fields.publicHostSession) {
        session.activityPublicRowSession = fields.publicHostSession;
        session.activityPublicRowBodiesSent = 0;
        std::array<char, 128> line{};
        const int written =
            std::snprintf(line.data(),
                          line.size(),
                          "ev=activity stage=bind result=public_host_row host=0x%llX sameid=%u",
                          static_cast<unsigned long long>(fields.publicHostSession),
                          fields.bindsPublicTarget ? 0U : 1U);
        if (written > 0) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(written)});
        }
    }
}

/** Arms the owed Family-4 and banner re-pushes when the queuez publication asks for them. */
void arm_repushes(Session& session, const queuez::StagedPublication& queuezPublication) noexcept {
    if (!queuezPublication.armsFamily4Repush || queuezPublication.family4RepushRoot == 0) {
        return;
    }
    const std::uint64_t now = GetTickCount64();
    session.family4RepushDueTick = now + kFamily4RepushDelayMs;
    session.family4RepushRoot = queuezPublication.family4RepushRoot;
    session.family4RepushArmed = true;
    session.bannerRepushDueTick = now + kBannerRepushDelayMs;
    session.bannerRepushRoot = queuezPublication.family4RepushRoot;
    session.bannerRepushArmed = true;
}

/** Arms the delayed ability-refresh pair when the publication asks for it. */
void arm_ability_refresh(Session& session,
                         const queuez::StagedPublication& queuezPublication) noexcept {
    if (!queuezPublication.armsAbilityRefresh) {
        return;
    }
    const std::uint64_t now = GetTickCount64();
    session.abilityRefreshDueTick = now + kAbilityRefreshDelayMs;
    session.abilityRefreshArmed = true;
}

/** Arms the join's own family-4 refresh: the tower's slice-set waits on the requirement
 *  evaluation that the swap's traffic otherwise has to wake by accident (the boot-G
 *  black-screen). The re-push delivers the version-zero snapshot the fresh mirror accepts,
 *  and the client's apply wakes the evaluator the join never reached on its own. */
void arm_join_refresh(Session& session, const ConnectionFields& fields) noexcept {
    if (!fields.joinsActivity || session.queuez.family4RootSoid == 0) {
        return;
    }
    const std::uint64_t now = GetTickCount64();
    session.family4RepushDueTick = now + kFamily4RepushDelayMs;
    session.family4RepushRoot = session.queuez.family4RootSoid;
    session.family4RepushArmed = true;
}

} // namespace sunrise::server::bap::encrypted
