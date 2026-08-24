#include "queuez_family_staging.h"

#include <array>
#include <cstddef>
#include <cstdio>
#include <limits>

#include "../../../../../core/logging/log.h"
#include "../queuez_state_validation.h"

namespace sunrise::server::bap::encrypted::queuez {

/** @return True for a logical match between two resident rows. */
bool staging::same_resident(const ResidentObject& left, const ResidentObject& right) noexcept {
    return left.objectSoid == right.objectSoid && left.definitionId == right.definitionId;
}

/**
 * Compares two canonical peer states field by field.
 * @return True when both are valid and every fixed Family-4 field matches.
 */
bool staging::same_state(const SessionState& left, const SessionState& right) noexcept {
    if (!valid(left) || !valid(right) || left.family4RootSoid != right.family4RootSoid
        || left.family4Version != right.family4Version
        || left.family4ResidentCount != right.family4ResidentCount
        || left.family3Phase != right.family3Phase
        || left.family3RootSoid != right.family3RootSoid
        || left.family3Version != right.family3Version
        || left.family3Active != right.family3Active
        || left.family4Active != right.family4Active) {
        return false;
    }
    for (std::size_t index = 0; index < left.family4Residents.size(); ++index) {
        if (!staging::same_resident(left.family4Residents[index], right.family4Residents[index])) {
            return false;
        }
    }
    return true;
}

namespace {

/**
 * Names the exact branch that refused one Family-4 staging attempt.
 * P2-C3 instrument: the dual-client front changed what the Client subscribes with, and
 * the bare refusal hid which invariant fired. Strip when the dual-account front closes.
 * @param why Short name of the refusing branch.
 * @param before Queuez state visible to the peer.
 * @param family The staged snapshot's family header.
 */
void report_family4_refusal(const char* why,
                            const SessionState& before,
                            const middleware::queuez::Family& family) noexcept {
    std::array<char, core::log::kLineCapacity> line{};
    const int written =
        std::snprintf(line.data(),
                      line.size(),
                      "ev=queuez stage=family4_refusal why=%s root=%016llX objs=%zu "
                      "front=%016llX ver=%u f4active=%d f3phase=%d key=%d",
                      why,
                      static_cast<unsigned long long>(family.rootSoid),
                      family.objects.size(),
                      family.objects.empty()
                          ? 0ULL
                          : static_cast<unsigned long long>(family.objects.front().id),
                      static_cast<unsigned>(family.version),
                      before.family4Active ? 1 : 0,
                      static_cast<int>(before.family3Phase),
                      static_cast<int>(before.accountKey));
    if (written > 0) {
        core::log::write(core::log::Channel::server,
                         core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(written)});
    }
}

/**
 * Names one changed-manifest re-subscribe the mirror adopted.
 * P2 instrument: the adopt branch replaced the refusal that desynced the two mirrors, so this
 * line is the only proof of whether that branch fires at all, and its key column names the
 * account the manifest was built from. Strip when the dual-account front closes.
 * @param before Queuez state visible to the peer.
 * @param family The staged snapshot's family header.
 */
void report_family4_resubscribe(const SessionState& before,
                                const middleware::queuez::Family& family) noexcept {
    std::array<char, core::log::kLineCapacity> line{};
    const int written =
        std::snprintf(line.data(),
                      line.size(),
                      "ev=queuez stage=family4_resubscribe result=adopt root=%016llX objs=%zu "
                      "prior_objs=%u prior_ver=%d key=%d",
                      static_cast<unsigned long long>(family.rootSoid),
                      family.objects.size(),
                      static_cast<unsigned>(before.family4ResidentCount),
                      before.family4Version,
                      static_cast<int>(before.accountKey));
    if (written > 0) {
        core::log::write(core::log::Channel::server,
                         core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(written)});
    }
}

/**
 * Compares one active resident manifest with a staged full snapshot.
 * @param state Active Family-4 state owned by the peer.
 * @param candidate Possible version-zero snapshot state.
 * @return True only when root, version, count and every resident id match.
 */
[[nodiscard]] bool same_manifest(const SessionState& state,
                                 const SessionState& candidate) noexcept {
    if (!valid(state) || !valid(candidate) || state.family4RootSoid != candidate.family4RootSoid
        || state.family4Version != candidate.family4Version
        || state.family4ResidentCount != candidate.family4ResidentCount
        || state.family3RootSoid != candidate.family3RootSoid
        || state.family3Version != candidate.family3Version
        || state.family3Active != candidate.family3Active) {
        return false;
    }
    for (std::size_t index = 0; index < state.family4ResidentCount; ++index) {
        if (!staging::same_resident(state.family4Residents[index],
                                    candidate.family4Residents[index])) {
            return false;
        }
    }
    return true;
}

} // namespace

/** Stages a first Family-4 manifest, or adopts the one a re-subscribe delivers. */
bool stage_family4_snapshot(const SessionState& before,
                            const middleware::queuez::Family& family,
                            SessionState& after) noexcept {
    after = before;
    if (!valid(before) || family.type != kAccountFamilyType || family.rootSoid == 0
        || family.version != kInitialFamilyVersion
        || family.flags != middleware::queuez::kFullSnapshotFlag || family.objects.empty()
        || family.objects.size() > kResidentCapacity
        || family.objects.size()
               > static_cast<std::size_t>((std::numeric_limits<std::uint8_t>::max)())) {
        report_family4_refusal("header", before, family);
        return false;
    }

    // The candidate starts from the peer's own state, so staging family four rewrites ONLY
    // family four. The scratch-built candidate this replaces silently reset every field family
    // four does not own. The family-three ladder was carried by hand once the boot-G roster
    // refusal proved one such loss; the fields still dropped were the provisioned account key
    // this mirror serves and the family-zero ladder. Losing the key is the P2 cross-account
    // defect: the mirror fell back to the legacy slot the moment a family-4 manifest recorded,
    // so every later snapshot on that session built the LEGACY account's objects for a slot-1
    // peer - proven on one connection's wire (FINDINGS 20.17): conn=3 served item soids
    // 4100.. and key=1 before the record, then 6000.. and key=0 after it.
    SessionState candidate = before;
    candidate.family4RootSoid = family.rootSoid;
    candidate.family4Version = family.version;
    candidate.family4ResidentCount = static_cast<std::uint8_t>(family.objects.size());
    candidate.family4Active = true;
    // A shorter manifest must not leave the old tail resident: valid() requires every unused
    // resident slot to be zero.
    candidate.family4Residents = {};
    for (std::size_t index = 0; index < family.objects.size(); ++index) {
        const middleware::queuez::Object& object = family.objects[index];
        if (object.id == 0 || object.version == 0) {
            report_family4_refusal("object_zero", before, family);
            return false;
        }
        for (std::size_t prior = 0; prior < index; ++prior) {
            if (family.objects[prior].version == object.version) {
                report_family4_refusal("duplicate_version", before, family);
                return false;
            }
        }
        candidate.family4Residents[index] = ResidentObject{object.version, object.id};
    }
    if (candidate.family4Residents.front().objectSoid != family.rootSoid) {
        report_family4_refusal("front_ne_root", before, family);
        return false;
    }
    if (before.family3Phase != Family3Phase::normal) {
        // The one window that cannot adopt. A character change is mid-flight and the
        // family-three ladder still owes its publish-once; the frame staged here carries the
        // initial version, and a peer state pairing the initial version with a pending phase
        // is not canonical (valid()). Adopting would either strand that debt - the boot-G
        // roster refusal, again - or publish a mirror the validator drops. This refuses
        // exactly the set the old replay branch refused: an active family four outside the
        // initial version never matched a replay either.
        report_family4_refusal("family3_phase", before, family);
        return false;
    }
    // THE RE-SUBSCRIBE POLICY (P2, 2026-08-24). A subscription is answered with the
    // full-snapshot flag at the initial version, and that REPLACES the peer's store for the
    // family - the measured family-three rule, stated in stage_family3_subscription: "An
    // explicit subscription establishes a fresh client-side store. Its current full body is
    // version zero even when the prior subscribed store had consumed incrementals." Both
    // families ride the same client-side per-family parser, so a family-four re-subscribe
    // means the same thing. The mirror therefore ADOPTS what goes out, instead of refusing to
    // record a frame the caller sends regardless ("a refused staging still sends the frame"):
    // a mirror that disagrees with the delivered manifest is the shape that drew the client's
    // out-of-order kick once already - the skipped-increment crash, where the mirror advanced
    // with nothing delivered, is the same invariant broken the other way round.
    // The UNSOLICITED re-push keeps its own regression guard in consume_deferred (a
    // version-zero re-snapshot after the ladder advanced is still skipped there); nothing
    // here relaxes it.
    if (before.family4Active && !same_manifest(before, candidate)) {
        report_family4_resubscribe(before, family);
    }
    after = candidate;
    return true;
}

/** Stages the family-zero publication policy. */
bool stage_family0_subscription(const SessionState& before,
                                std::uint64_t selectedCharacter,
                                bool& publish,
                                bool& incremental,
                                SessionState& after) noexcept {
    publish = false;
    incremental = false;
    after = before;
    if (!valid(before) || selectedCharacter == 0) {
        return false;
    }
    if (!before.family0Active) {
        publish = true;
        after.family0Active = true;
        after.family0Character = selectedCharacter;
        after.family0Version = kInitialFamilyVersion;
        return true;
    }
    if (before.family0Character == selectedCharacter) {
        return true;
    }
    publish = true;
    incremental = true;
    after.family0Character = selectedCharacter;
    after.family0Version = before.family0Version + 1;
    return true;
}

/** Stages the Family-0 refresh a subclass equip owes. */
bool stage_family0_refresh(const SessionState& before,
                           std::uint64_t characterSoid,
                           SessionState& after) noexcept {
    after = before;
    if (!valid(before) || !before.family0Active || characterSoid == 0
        || before.family0Character != characterSoid) {
        return false;
    }
    after.family0Version = before.family0Version + 1;
    return true;
}

/** Stages the measured Family-3 subscription policy: full first, then response-only. */
bool stage_family3_subscription(const SessionState& before,
                                const middleware::queuez::Subscription& subscription,
                                bool& publish,
                                SessionState& after) noexcept {
    publish = false;
    after = before;
    if (!valid(before) || subscription.familyType != kRosterFamilyType
        || subscription.familyRootSoid == 0) {
        return false;
    }
    if ((before.family4Active && subscription.familyRootSoid != before.family4RootSoid)
        || (before.family3Active && subscription.familyRootSoid != before.family3RootSoid)) {
        return false;
    }
    if (!before.family3Active) {
        // Publication is transactional: the caller installs this seed only after the full frame
        // is copied. Until then the before-image remains inactive and version zero has no meaning.
        publish = true;
        after.family3RootSoid = subscription.familyRootSoid;
        after.family3Version = kInitialFamilyVersion;
        after.family3Active = true;
        return valid(after);
    }
    if (before.family3Phase == Family3Phase::normal) {
        publish = true;
        // An explicit subscription establishes a fresh client-side store. Its current full body
        // is version zero even when the prior subscribed store had consumed incrementals.
        after.family3Version = kInitialFamilyVersion;
        return valid(after);
    }
    if (!before.family4Active) {
        return false;
    }
    if (before.family3Phase == Family3Phase::publishOnce) {
        publish = true;
        after.family3Version = kInitialFamilyVersion;
        after.family3Phase = Family3Phase::responseOnly;
        return valid(after);
    }
    return before.family3Phase == Family3Phase::responseOnly;
}

/** Stages one in-place Family-3 character refresh and its optional account roster upsert
 *  (the fork's shape — the roster record is a separate copy of the appearance). */
bool stage_roster_appearance_refresh(const SessionState& before,
                                     std::uint64_t characterSoid,
                                     bool includeRoster,
                                     RosterAppearanceRefresh& refresh) noexcept {
    refresh = {};
    if (!valid(before) || !before.family3Active || before.family3RootSoid == 0
        || characterSoid == 0
        || before.family3Version == (std::numeric_limits<std::int32_t>::max)()
        || (before.family4Active && before.family4RootSoid != before.family3RootSoid)) {
        std::array<char, core::log::kLineCapacity> line{};
        const int written = std::snprintf(
            line.data(),
            line.size(),
            "ev=queuez stage=roster_refresh result=fail reason=stage active=%u root=0x%llX "
            "version=%d character=0x%llX family4_active=%u",
            before.family3Active ? 1U : 0U,
            static_cast<unsigned long long>(before.family3RootSoid),
            before.family3Version,
            static_cast<unsigned long long>(characterSoid),
            before.family4Active ? 1U : 0U);
        if (written > 0) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::warn,
                             {line.data(), static_cast<std::size_t>(written)});
        }
        return false;
    }
    refresh.after = before;
    ++refresh.after.family3Version;
    refresh.characterSoid = characterSoid;
    refresh.includeRoster = includeRoster;
    return valid(refresh.after);
}

void stage_unsubscription(const SessionState& before,
                          std::uint64_t familyRootSoid,
                          SessionState& after) noexcept {
    after = before;
    if ((before.family4Active && familyRootSoid == before.family4RootSoid)
        || (before.family3Active && familyRootSoid == before.family3RootSoid)) {
        after = {};
    }
}

} // namespace sunrise::server::bap::encrypted::queuez
