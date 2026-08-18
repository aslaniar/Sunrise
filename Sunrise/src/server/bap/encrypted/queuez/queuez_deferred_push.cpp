#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstdio>

#include "../../../../core/logging/log.h"
#include "../../../../state/account/account_state.h"
#include "../../../../state/runtime/runtime.h"
#include "../internal.h"
#include "../push/activity/activity_keepalive_push.h"
#include "queuez_state_validation.h"

namespace sunrise::server::bap::encrypted {
namespace {

/** Widest re-push report, sized for the fields below. */
constexpr std::size_t kRepushReportLimit = 96;

/**
 * Logs one delayed re-push with its framed size, so it can be compared to the first copy.
 * @param bytes Framed size of the published notification.
 */
void report_repush(const char* stage, std::size_t bytes) noexcept {
    std::array<char, kRepushReportLimit> line{};
    const int count = std::snprintf(
        line.data(), line.size(), "ev=queuez stage=%s result=ok bytes=%zu", stage, bytes);
    if (count > 0) {
        core::log::write(core::log::Channel::server,
                         core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(count)});
    }
}

/**
 * Sends the owed banner re-push once its delay has passed.
 * The banner has no subscribe of its own, so the timer is its only second chance.
 * @param session Auth, nonce and queuez state owned by the connection.
 * @param scratch Transform buffers owned by the lock.
 * @param response Whole-frame storage owned by the caller.
 * @param written Gets the encoded notification size in bytes.
 * @param touchesScratch Set before any scratch buffer is used.
 * @return True when a whole banner notification is published.
 */
[[nodiscard]] bool consume_banner_repush(Session& session,
                                         Scratch& scratch,
                                         std::span<std::byte> response,
                                         std::size_t& written,
                                         bool& touchesScratch) noexcept {
    if (!session.bannerRepushArmed || session.bannerRepushRoot == 0
        || GetTickCount64() < session.bannerRepushDueTick) {
        return false;
    }
    session.bannerRepushArmed = false;
    // Nothing is owed while no character is selected. The pair has no character to name, and the
    // first pick publishes it. Logging that as a failed re-push would be wrong.
    if (state::account::selected_character_soid(state::account_snapshot()) == 0) {
        return false;
    }
    touchesScratch = true;

    auto nextSendNonce = session.sendNonce;
    std::size_t framedSize = 0;
    queuez::SessionState bannerAfter{};
    if (!push::append_banner_notification(scratch,
                                          session.queuez,
                                          session.bannerRepushRoot,
                                          state::bap().sessionKey,
                                          nextSendNonce,
                                          scratch.framed,
                                          framedSize,
                                          bannerAfter)
        || framedSize == 0 || framedSize > response.size()) {
        core::log::write(core::log::Channel::server,
                         core::log::Level::warn,
                         "ev=queuez stage=banner_repush result=fail");
        return false;
    }
    std::copy_n(scratch.framed.begin(), framedSize, response.begin());
    written = framedSize;
    session.sendNonce = nextSendNonce;
    // The frame is committed here, so the recorded delivery is committed with it.
    if (valid(bannerAfter)) {
        session.queuez = bannerAfter;
    }
    report_repush("banner_repush", framedSize);
    return true;
}

/** Sends the delayed ability-refresh pair once its delay has passed (the fork's deferral:
 *  the ability-bucket rebuild runs asynchronously, so the appearance + the roster re-send
 *  once the rebuild settles instead of racing the client's refresh). */
[[nodiscard]] bool consume_ability_refresh(Session& session,
                                           Scratch& scratch,
                                           std::span<std::byte> response,
                                           std::size_t& written,
                                           bool& touchesScratch) noexcept {
    if (!session.abilityRefreshArmed || GetTickCount64() < session.abilityRefreshDueTick) {
        return false;
    }
    session.abilityRefreshArmed = false;
    touchesScratch = true;

    auto nextSendNonce = session.sendNonce;
    std::size_t framedSize = 0;
    queuez::SessionState current = session.queuez;
    bool wrote = false;
    const state::AccountState account = state::account_snapshot();
    const std::uint64_t selected = state::account::selected_character_soid(account);
    if (selected != 0 && current.family0Active) {
        queuez::SessionState appearanceAfter{};
        if (push::append_banner_refresh_notification(scratch,
                                                     current,
                                                     selected,
                                                     state::bap().sessionKey,
                                                     nextSendNonce,
                                                     scratch.framed,
                                                     framedSize,
                                                     appearanceAfter)) {
            current = appearanceAfter;
            wrote = true;
        }
    }
    if (selected != 0 && current.family3Active) {
        queuez::SessionState rosterAfter{};
        if (push::append_roster_refresh_notification(scratch,
                                                     current,
                                                     selected,
                                                     state::bap().sessionKey,
                                                     nextSendNonce,
                                                     scratch.framed,
                                                     framedSize,
                                                     rosterAfter)) {
            current = rosterAfter;
            wrote = true;
        }
    }
    if (!wrote || framedSize == 0 || framedSize > response.size() || !queuez::valid(current)) {
        core::log::write(core::log::Channel::server,
                         core::log::Level::warn,
                         "ev=queuez stage=ability_refresh result=fail");
        return false;
    }
    std::copy_n(scratch.framed.begin(), framedSize, response.begin());
    written = framedSize;
    session.sendNonce = nextSendNonce;
    session.queuez = current;
    report_repush("ability_refresh", framedSize);
    return true;
}

} // namespace

/**
 * Sends the owed Family-4 re-push once its delay has passed.
 * @param session Auth, nonce and queuez state owned by the connection.
 * @param scratch Transform buffers owned by the lock.
 * @param response Whole-frame storage owned by the caller.
 * @param written Gets the encoded notification size in bytes.
 * @param touchesScratch Set before any scratch buffer is used.
 * @return True when a whole Family-4 notification is published.
 */
bool consume_deferred(Session& session,
                      Scratch& scratch,
                      std::span<std::byte> response,
                      std::size_t& written,
                      bool& touchesScratch) noexcept {
    written = 0;
    if (!session.authenticated) {
        return false;
    }
    // The swap's delayed refresh pair outranks every other owed push.
    if (consume_ability_refresh(session, scratch, response, written, touchesScratch)) {
        return true;
    }
    if (!session.family4RepushArmed || session.family4RepushRoot == 0
        || GetTickCount64() < session.family4RepushDueTick) {
        return consume_banner_repush(session, scratch, response, written, touchesScratch)
               || push::activity::consume_activity_keepalive(
                   session, scratch, response, written, touchesScratch);
    }
    // One attempt is owed. Disarm before trying.
    session.family4RepushArmed = false;
    // The delayed second copy is only owed while the peer still holds the initial version: a
    // version-zero re-snapshot after the ladder advanced would regress the client's held
    // version and draw the same out-of-order rejection the skipped-increment crash did. The
    // mirror's version discipline is the client's contract; the repush never violates it.
    if (session.queuez.family4Active
        && session.queuez.family4Version != queuez::kInitialFamilyVersion) {
        core::log::write(core::log::Channel::server,
                         core::log::Level::warn,
                         "ev=queuez stage=repush result=skip reason=version_advanced");
        return false;
    }
    touchesScratch = true;

    middleware::queuez::Subscription subscription{};
    subscription.familyType = queuez::kAccountFamilyType;
    subscription.familyRootSoid = session.family4RepushRoot;

    auto nextSendNonce = session.sendNonce;
    std::size_t framedSize = 0;
    queuez::SessionState after{};
    bool armsRepush = false;
    push::append_queuez_notification(scratch,
                                     session.queuez,
                                     subscription,
                                     state::bap().sessionKey,
                                     nextSendNonce,
                                     scratch.framed,
                                     framedSize,
                                     after,
                                     armsRepush);
    if (framedSize == 0 || framedSize > response.size()) {
        core::log::write(core::log::Channel::server,
                         core::log::Level::warn,
                         "ev=queuez stage=repush result=fail");
        return false;
    }
    std::copy_n(scratch.framed.begin(), framedSize, response.begin());
    written = framedSize;
    session.sendNonce = nextSendNonce;
    if (queuez::valid(after)) {
        session.queuez = after;
    }
    report_repush("repush", framedSize);
    return true;
}

} // namespace sunrise::server::bap::encrypted
