#include "queuez_outcome_staging.h"

#include "../../../../core/logging/log.h"
#include "../../../../middleware/secure_channel/runtime.h"
#include "../../../../state/build_data/cache/internal.h"
#include "../../../../state/runtime/equipment/configured_equipment_identity.h"
#include "../../../../state/runtime/runtime.h"
#include "../../../persistence/persistence.h"
#include "queuez_state_validation.h"

namespace sunrise::server::bap::encrypted::queuez {

/** Stages queuez subscription, unsubscription, or character-move output for one peer. */
bool stage_service_outcome(Scratch& scratch,
                           const SessionState& before,
                           const ServiceOutcome& outcome,
                           std::span<const std::byte, state::kAesKeySize> key,
                           std::array<std::byte, state::kBapNonceSize>& nonce,
                           std::span<std::byte> response,
                           std::size_t& written,
                           StagedPublication& publication) noexcept {
    publication = {};
    SessionState after{};
    bool armsRepush = false;
    if (outcome.hasSubscription) {
        push::append_queuez_notification(scratch,
                                         before,
                                         outcome.subscription,
                                         key,
                                         nonce,
                                         response,
                                         written,
                                         after,
                                         armsRepush);
    } else if (outcome.hasUnsubscription) {
        stage_unsubscription(before, outcome.unsubscription.familyRootSoid, after);
    } else if (outcome.hasChangeCharacter) {
        // The reply already carries the version this patch promises. A patch that cannot be built
        // leaves the ladder where it is, instead of holding back that reply.
        if (!push::append_change_character_notification(
                scratch, outcome.changeCharacter, key, nonce, response, written)) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::warn,
                             "ev=queuez stage=change result=fail");
            return true;
        }
        middleware::secure_channel::advance_nonce(nonce);
        after = outcome.changeCharacter.after;
    } else if (outcome.hasSelectCharacter) {
        // The reply is the Client's task completion and the move is a separate frame. A move that
        // cannot be built leaves the selection where it is, instead of holding back that reply.
        if (!push::append_select_character_notification(
                scratch, outcome.selectCharacter, key, nonce, response, written)) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::warn,
                             "ev=queuez stage=select result=fail");
            return true;
        }
        middleware::secure_channel::advance_nonce(nonce);
        after = outcome.selectCharacter.after;
        // The banner pair follows the family-four move, so it is sent against the state that move
        // made. A pair that cannot be built leaves the emblem where it is.
        const SessionState& bannerBefore = after;
        SessionState bannerAfter{};
        if (push::append_banner_move_notification(scratch,
                                                  bannerBefore,
                                                  outcome.selectCharacter.selectedCharacterSoid,
                                                  key,
                                                  nonce,
                                                  response,
                                                  written,
                                                  bannerAfter)) {
            after = bannerAfter;
        }
    } else if (outcome.hasSubclassEquip) {
        // Persist-before-publish: the mutation lands in memory and the two rows commit before
        // the character after-image goes out, so a crash mid-flow converges at the next boot.
        // A persist failure reverts the memory swap (the F4 handling), so no observer sees a
        // state the database refused.
        std::uint64_t displacedSoid = 0;
        if (!state::equip_subclass_item(outcome.subclassEquip.itemSoid, displacedSoid)) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::warn,
                             "ev=queuez stage=subclass_equip result=fail step=mutate");
            return true;
        }
        if (!sunrise::server::persistence::persist_subclass_equip(
                outcome.subclassEquip.itemSoid, displacedSoid)) {
            std::uint64_t reverted = 0;
            (void)state::equip_subclass_item(displacedSoid, reverted);
            core::log::write(core::log::Channel::server,
                             core::log::Level::warn,
                             "ev=queuez stage=subclass_equip result=fail step=persist");
            return true;
        }
        // L5 stage 6: the equipment fingerprint moved with the persisted swap. Re-stamp the
        // cache header now (atomic temp+rename) so the next boot's identity gate matches the
        // post-mutation account without a manual repair step.
        const std::uint64_t postHash =
            state::runtime::equipment::configured_hash(state::account_snapshot());
        if (!state::build_data::cache::restamp_equipment_hash(postHash)) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::warn,
                             "ev=cache stage=restamp result=fail");
        }
        if (!push::append_subclass_equip_notification(
                scratch, outcome.subclassEquip, key, nonce, response, written)) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::warn,
                             "ev=queuez stage=subclass_equip result=fail step=push");
            return true;
        }
        middleware::secure_channel::advance_nonce(nonce);
        after = outcome.subclassEquip.after;
        // The banner record re-encodes from the mutated account (the subclass list changed),
        // so the family-zero pair follows the family-four increment as a same-key refresh.
        const SessionState& bannerBefore = after;
        SessionState bannerAfter{};
        if (push::append_banner_refresh_notification(scratch,
                                                     bannerBefore,
                                                     outcome.subclassEquip.characterSoid,
                                                     key,
                                                     nonce,
                                                     response,
                                                     written,
                                                     bannerAfter)) {
            after = bannerAfter;
        }
        // The fork's third publication: the family-three roster-side appearance copy (the
        // selector's icons are a roster-side read) follows the family-zero refresh at one
        // exact +1 family-three revision.
        const SessionState& rosterBefore = after;
        SessionState rosterAfter{};
        if (!push::append_roster_refresh_notification(scratch,
                                                      rosterBefore,
                                                      outcome.subclassEquip.characterSoid,
                                                      key,
                                                      nonce,
                                                      response,
                                                      written,
                                                      rosterAfter)) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::warn,
                             "ev=queuez stage=subclass_equip result=fail step=roster");
            return true;
        }
        after = rosterAfter;
        // The ability-bucket rebuild runs asynchronously off the content pump; the refresh
        // pair owes a delayed re-send once the rebuild settles (the fork's deferral — the
        // inline rebuild races the client's refresh).
        publication.armsAbilityRefresh = true;
    } else if (outcome.hasAbilityChange) {
        // The ability change moves only the family-zero banner record (the ability buckets
        // live there), so no Family-4 increment goes out. Persist-before-publish keeps the
        // same convergence contract as the subclass equip.
        if (!state::apply_ability_change(outcome.abilityChange.definitionHash)) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::warn,
                             "ev=queuez stage=ability_change result=fail step=mutate");
            return true;
        }
        if (!sunrise::server::persistence::persist_ability_change()) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::warn,
                             "ev=queuez stage=ability_change result=fail step=persist");
            return true;
        }
        // The ability picks mix into the configured equipment hash, so the cache header
        // re-stamps exactly like the subclass equip does.
        const std::uint64_t postHash =
            state::runtime::equipment::configured_hash(state::account_snapshot());
        if (!state::build_data::cache::restamp_equipment_hash(postHash)) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::warn,
                             "ev=cache stage=restamp result=fail");
        }
        // The changed ability fields live on the character record, so the Family-4 character
        // after-image goes out exactly like the subclass equip: one frame, flags 0, one object,
        // at exactly one above the peer's held version — before the family-zero banner refresh.
        if (!push::append_ability_change_notification(scratch,
                                                      outcome.abilityChange,
                                                      key,
                                                      nonce,
                                                      response,
                                                      written)) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::warn,
                             "ev=queuez stage=ability_change result=fail step=push");
            return true;
        }
        middleware::secure_channel::advance_nonce(nonce);
        after = outcome.abilityChange.after;
        // The banner record re-encodes from the mutated account, so the family-zero pair
        // follows the family-four increment as a same-key refresh.
        const SessionState& bannerBefore = after;
        SessionState bannerAfter{};
        if (!push::append_banner_refresh_notification(scratch,
                                                      bannerBefore,
                                                      outcome.abilityChange.characterSoid,
                                                      key,
                                                      nonce,
                                                      response,
                                                      written,
                                                      bannerAfter)) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::warn,
                             "ev=queuez stage=ability_change result=fail step=push");
            return true;
        }
        // The banner append advances the push nonce internally; no manual advance here.
        after = bannerAfter;
        std::array<char, 96> line{};
        const int lineWritten = std::snprintf(line.data(),
                                              line.size(),
                                              "ev=queuez stage=ability_change result=ok hash=0x%08X",
                                              outcome.abilityChange.definitionHash);
        if (lineWritten > 0) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(lineWritten)});
        }
    } else if (outcome.hasSubclassSelection) {
        // The opcode-801 selection: commit the ability picks, persist them, re-stamp the
        // equipment hash (the picks mix into it), and refresh the banner record that carries
        // the new ability buckets — the same shape as the ability-change branch.
        state::PendingSubclassSelection selectionMutation =
            outcome.subclassSelection.mutation;
        if (!state::commit_subclass_selection(selectionMutation)) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::warn,
                             "ev=queuez stage=subclass_selection result=fail step=commit");
            return true;
        }
        if (!sunrise::server::persistence::persist_ability_change()) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::warn,
                             "ev=queuez stage=subclass_selection result=fail step=persist");
            return true;
        }
        const std::uint64_t postHash =
            state::runtime::equipment::configured_hash(state::account_snapshot());
        if (!state::build_data::cache::restamp_equipment_hash(postHash)) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::warn,
                             "ev=cache stage=restamp result=fail");
        }
        // The selected ability fields live on the character record, so the Family-4 character
        // after-image goes out exactly like the subclass equip: one frame, flags 0, one object,
        // at exactly one above the peer's held version — before the family-zero banner refresh.
        // (The original port dropped the fork's append_subclass_selection_notification: the
        // mirror advanced with nothing delivered, so the next delivered frame skipped versions
        // and drew the client's out-of-order kick.)
        if (!push::append_subclass_selection_notification(scratch,
                                                          outcome.subclassSelection,
                                                          key,
                                                          nonce,
                                                          response,
                                                          written)) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::warn,
                             "ev=queuez stage=subclass_selection result=fail step=push");
            return true;
        }
        middleware::secure_channel::advance_nonce(nonce);
        after = outcome.subclassSelection.after;
        // The banner record re-encodes from the mutated account, so the family-zero pair
        // follows the family-four increment as a same-key refresh.
        const SessionState& bannerBefore = after;
        SessionState bannerAfter{};
        if (!push::append_banner_refresh_notification(scratch,
                                                      bannerBefore,
                                                      outcome.subclassSelection.characterSoid,
                                                      key,
                                                      nonce,
                                                      response,
                                                      written,
                                                      bannerAfter)) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::warn,
                             "ev=queuez stage=subclass_selection result=fail step=push");
            return true;
        }
        // The banner append advances the push nonce internally; no manual advance here.
        after = bannerAfter;
        std::array<char, 96> line{};
        const int lineWritten = std::snprintf(
            line.data(),
            line.size(),
            "ev=queuez stage=subclass_selection result=ok entry=%u",
            outcome.subclassSelection.mutation.requestedEntry);
        if (lineWritten > 0) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(lineWritten)});
        }
    } else {
        return true;
    }
    // The frame is already written by here. A mirror that fails validation is logged and dropped,
    // never turned into a refusal to send what the Client waits for.
    publication.hasState = valid(after);
    if (publication.hasState) {
        publication.after = after;
    } else {
        core::log::write(core::log::Channel::server,
                         core::log::Level::warn,
                         "ev=queuez stage=publish result=unrecorded");
    }
    publication.armsFamily4Repush = armsRepush;
    publication.family4RepushRoot = armsRepush ? outcome.subscription.familyRootSoid : 0;
    return true;
}

} // namespace sunrise::server::bap::encrypted::queuez
