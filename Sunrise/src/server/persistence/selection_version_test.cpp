#include "selection_version_test.h"

#include <Windows.h>

#include <array>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <span>

#include "../../core/logging/log.h"
#include "../../middleware/datagen/definitions.h"
#include "../../middleware/queuez/queuez_update.h"
#include "../../state/account/account_state.h"
#include "../../state/account/inventory/inventory_state.h"
#include "../../state/runtime/runtime.h"
#include "../bap/encrypted/push/snapshot/internal.h"
#include "../bap/encrypted/queuez/queuez_state_validation.h"
#include "../bap/internal.h"
#include "persistence.h"

namespace sunrise::server::persistence {
namespace {

namespace queuez = sunrise::server::bap::encrypted::queuez;
namespace push = sunrise::server::bap::encrypted::push;
namespace snapshot = sunrise::server::bap::encrypted::push::snapshot;

using queuez::SessionState;

/** Reports one structured line on the console and through the log. */
void report(const char* format, ...) noexcept {
    std::array<char, 192> line{};
    va_list args;
    va_start(args, format);
    const int written = std::vsnprintf(line.data(), line.size(), format, args);
    va_end(args);
    if (written <= 0) {
        return;
    }
    std::fputs(line.data(), stdout);
    std::fputc('\n', stdout);
    std::fflush(stdout);
    core::log::write(core::log::Channel::state,
                     core::log::Level::info,
                     {line.data(), static_cast<std::size_t>(written)});
}

/** One assertion with a named stage and a running failure count. */
struct Harness {
    std::size_t failures = 0;

    void check(bool condition, const char* what) noexcept {
        report("ev=selection_version stage=check result=%s what=%s",
               condition ? "ok" : "fail",
               what);
        if (!condition) {
            ++failures;
        }
    }
};

/**
 * Finds the first socket entry whose selection changes a pick on the equipped subclass —
 * the same prepare the live 801 handler runs, so a returning entry is a live-valid one.
 * @return The biased entry, or no value when none changes a pick.
 */
std::optional<std::uint8_t> find_changing_entry(std::uint64_t subclassSoid) noexcept {
    for (int entry = 0; entry <= 255; ++entry) {
        state::PendingSubclassSelection probe{};
        if (state::prepare_subclass_selection(
                subclassSoid, static_cast<std::uint8_t>(entry), probe)) {
            return static_cast<std::uint8_t>(entry);
        }
    }
    return std::nullopt;
}

} // namespace

/** Runs the family-4 version-discipline test. */
int run_selection_version_test(void* module) noexcept {
    (void)module;
    // The prepare path compresses through the installed Oodle module; the test blocks run
    // before the boot's initialize_oodle(), so the harness loads the codec itself (the DLL
    // sits beside the harness exe).
    if (LoadLibraryW(L"oo2core_3_win64.dll") == nullptr) {
        report("ev=selection_version stage=oodle result=fail");
    } else {
        report("ev=selection_version stage=oodle result=ok");
    }
    report("ev=selection_version stage=start result=ok");
    Harness harness{};
    state::AccountState account{};
    state::unlocks::Table unlocks{};
    state::Family5State family5{};
    if (!persistence::load_account(account, unlocks, family5) || !state::account::valid(account)) {
        report("ev=selection_version stage=load result=fail");
        persistence::shutdown();
        return 1;
    }
    report("ev=selection_version stage=load result=ok characters=%zu", account.characterCount);
    if (account.characterCount == 0) {
        report("ev=selection_version stage=load result=fail reason=no_characters");
        persistence::shutdown();
        return 1;
    }

    // The runtime State carries no selection from the DB (the equip-diff pattern), so publish
    // character 0's selection first — the server's own 504 flow.
    bool selectionChanged = false;
    if (!state::set_selected_character(account.characters[0].soid, selectionChanged)) {
        report("ev=selection_version stage=select result=fail");
        persistence::shutdown();
        return 1;
    }
    report("ev=selection_version stage=select result=ok changed=%d", selectionChanged ? 1 : 0);

    // The live snapshot after the selection: the account identity, the selected character's
    // equipped subclass, and the equip pick the 403 flow accepts.
    const state::AccountState live = state::account_snapshot();
    const std::uint64_t accountSoid = live.primarySoid;
    harness.check(accountSoid != 0, "account_soid_present");
    const state::CharacterState& character0 = live.characters[0];
    const std::optional<state::account::inventory::Item> subclassSlot =
        character0.equipment
            .slots[static_cast<std::size_t>(state::account::inventory::EquipmentSlot::subclass)];
    harness.check(subclassSlot.has_value(), "subclass_equipped");
    const std::uint64_t subclassSoid = subclassSlot.has_value() ? subclassSlot->instanceSoid : 0;

    std::uint64_t pickSoid = 0;
    for (std::size_t index = 0; index < character0.storageItemCount; ++index) {
        if (state::subclass_equip_request_valid(character0.storageItems[index].instanceSoid)) {
            pickSoid = character0.storageItems[index].instanceSoid;
            break;
        }
    }
    harness.check(pickSoid != 0, "equip_pick_found");
    report("ev=selection_version stage=pick result=%s subclass=0x%llX equip=0x%llX",
           pickSoid != 0 ? "ok" : "fail",
           subclassSoid,
           pickSoid);

    // THE SUBSCRIPTION REPLAY: the version-zero full snapshot the Client's subscribe replays —
    // the account object as the root plus the selected character resident.
    std::uint32_t accountObjectId = 0;
    std::uint32_t characterObjectId = 0;
    harness.check(middleware::datagen::object_id(middleware::datagen::kAccountFamily,
                                                 middleware::datagen::kAccountSlot,
                                                 accountObjectId),
                  "account_object_id_maps");
    harness.check(middleware::datagen::object_id(middleware::datagen::kAccountFamily,
                                                 middleware::datagen::kCharacterSlot,
                                                 characterObjectId),
                  "character_object_id_maps");
    std::array<middleware::queuez::Object, 2> replayObjects{};
    std::size_t replayCount = 0;
    replayObjects[replayCount++] = middleware::queuez::Object{
        accountObjectId, accountSoid, middleware::queuez::Encoding::raw, {}};
    if (replayCount < replayObjects.size() && account.characterCount > 0) {
        replayObjects[replayCount++] = middleware::queuez::Object{
            characterObjectId, account.characters[0].soid, middleware::queuez::Encoding::raw, {}};
    }
    const middleware::queuez::Family replayFamily{
        queuez::kAccountFamilyType,
        accountSoid,
        queuez::kInitialFamilyVersion,
        middleware::queuez::kFullSnapshotFlag,
        std::span(replayObjects).first(replayCount),
    };
    SessionState before{};
    SessionState afterReplay{};
    harness.check(queuez::stage_family4_snapshot(before, replayFamily, afterReplay),
                  "replay_subscription_stages");
    harness.check(afterReplay.family4Active, "replay_activates_family4");
    harness.check(afterReplay.family4Version == queuez::kInitialFamilyVersion,
                  "replay_holds_initial_version");

    // THE FIRST 801: one prepared selection, staged at exactly +1, committed, and its
    // family-4 character after-image prepared + appended at the staged version.
    const std::optional<std::uint8_t> entry1 = find_changing_entry(subclassSoid);
    harness.check(entry1.has_value(), "entry1_changes_a_pick");
    queuez::SubclassSelection selection1{};
    state::PendingSubclassSelection mutation1{};
    if (entry1.has_value()) {
        harness.check(state::prepare_subclass_selection(subclassSoid, *entry1, mutation1),
                      "entry1_prepares");
        harness.check(queuez::stage_subclass_selection(afterReplay, mutation1, selection1),
                      "selection1_stages");
        harness.check(selection1.after.family4Version == afterReplay.family4Version + 1,
                      "selection1_version_exactly_plus_one");
        harness.check(state::commit_subclass_selection(mutation1), "selection1_commits");
        bap::Scratch scratch{};
        snapshot::Prepared prepared{};
        harness.check(snapshot::prepare_subclass_selection(scratch, selection1, prepared),
                      "selection1_prepares_frame");
        harness.check(prepared.family.version == selection1.after.family4Version,
                      "selection1_frame_versions_match");
        std::uint32_t itemObjectId = 0;
        harness.check(middleware::datagen::object_id(
                          middleware::datagen::kAccountFamily,
                          middleware::datagen::kItemInstanceSlot,
                          itemObjectId),
                      "item_object_id_maps");
        harness.check(prepared.family.type == queuez::kAccountFamilyType && prepared.family.flags == 0
                          && prepared.family.objects.size() == 1,
                      "selection1_frame_shape");
        harness.check(prepared.family.objects.size() == 1
                          && prepared.family.objects[0].id == itemObjectId
                          && prepared.family.objects[0].version == subclassSoid,
                      "selection1_frame_is_the_item_upsert");
        std::array<std::byte, state::kAesKeySize> key{};
        std::array<std::byte, state::kBapNonceSize> nonce{};
        std::size_t written = 0;
        harness.check(push::append_subclass_selection_notification(
                          scratch,
                          selection1,
                          std::span<const std::byte, state::kAesKeySize>(key),
                          std::span<const std::byte, state::kBapNonceSize>(nonce),
                          std::span(scratch.responseBody),
                          written),
                      "selection1_full_frame_appends");
    }

    // THE SECOND 801: the same ladder from the first selection's after-image — the delivered
    // version must be exactly +1 again, never skipped.
    const std::optional<std::uint8_t> entry2 = find_changing_entry(subclassSoid);
    harness.check(entry2.has_value(), "entry2_changes_a_pick");
    queuez::SubclassSelection selection2{};
    state::PendingSubclassSelection mutation2{};
    if (entry2.has_value()) {
        harness.check(state::prepare_subclass_selection(subclassSoid, *entry2, mutation2),
                      "entry2_prepares");
        harness.check(queuez::stage_subclass_selection(selection1.after, mutation2, selection2),
                      "selection2_stages");
        harness.check(selection2.after.family4Version == selection1.after.family4Version + 1,
                      "selection2_version_exactly_plus_one");
        harness.check(state::commit_subclass_selection(mutation2), "selection2_commits");
        bap::Scratch scratch{};
        snapshot::Prepared prepared{};
        harness.check(snapshot::prepare_subclass_selection(scratch, selection2, prepared),
                      "selection2_prepares_frame");
        harness.check(prepared.family.version == selection2.after.family4Version,
                      "selection2_frame_versions_match");
        harness.check(prepared.family.objects.size() == 1
                          && prepared.family.objects[0].version == subclassSoid,
                      "selection2_frame_is_the_item_upsert");
        std::array<std::byte, state::kAesKeySize> key{};
        std::array<std::byte, state::kBapNonceSize> nonce{};
        std::size_t written = 0;
        harness.check(push::append_subclass_selection_notification(
                          scratch,
                          selection2,
                          std::span<const std::byte, state::kAesKeySize>(key),
                          std::span<const std::byte, state::kBapNonceSize>(nonce),
                          std::span(scratch.responseBody),
                          written),
                      "selection2_full_frame_appends");
    }

    // THE 403 EQUIP: the working reference path — staged at exactly +1 over the second
    // selection and delivered the same way. With the fix, this lands at version 3 against the
    // client's held 2 instead of skipping to 4.
    queuez::SubclassEquip equip{};
    harness.check(queuez::stage_subclass_equip(selection2.after, pickSoid, equip),
                  "equip_stages");
    harness.check(equip.after.family4Version == selection2.after.family4Version + 1,
                  "equip_version_exactly_plus_one");
    std::uint64_t displaced = 0;
    harness.check(state::equip_subclass_item(pickSoid, displaced), "equip_mutates");
    {
        bap::Scratch scratch{};
        snapshot::Prepared prepared{};
        harness.check(snapshot::prepare_subclass_equip(scratch, equip, prepared),
                      "equip_prepares_frame");
        harness.check(prepared.family.version == equip.after.family4Version,
                      "equip_frame_versions_match");
    }

    // THE DEFERRED-REPUSH CASES. (a) The version-zero replay is permitted only while the peer
    // holds the initial version — after the ladder advanced, the replay staging must refuse.
    SessionState refusedReplay{};
    harness.check(!queuez::stage_family4_snapshot(equip.after, replayFamily, refusedReplay),
                  "replay_refused_after_advance");
    // (b) The owed repush must not deliver a regressed frame: the guard disarms and skips it
    // when the mirror's version advanced past the initial, leaving the mirror untouched.
    {
        bap::Session session{};
        session.authenticated = true;
        session.family4RepushArmed = true;
        session.family4RepushDueTick = 0;
        session.family4RepushRoot = accountSoid;
        session.queuez = equip.after;
        bap::Scratch scratch{};
        std::size_t written = 0;
        bool touchesScratch = false;
        const bool repushed = sunrise::server::bap::encrypted::consume_deferred(
            session, scratch, std::span(scratch.responseBody), written, touchesScratch);
        harness.check(!repushed, "repush_skips_after_advance");
        harness.check(written == 0, "repush_sends_no_frame");
        harness.check(!touchesScratch, "repush_touches_no_scratch");
        harness.check(session.queuez.family4Version == equip.after.family4Version,
                      "repush_mirror_not_regressed");
        harness.check(!session.family4RepushArmed, "repush_disarms");
    }

    persistence::shutdown();
    report("ev=selection_version stage=done result=%s failures=%zu",
           harness.failures == 0 ? "ok" : "fail",
           harness.failures);
    return harness.failures == 0 ? 0 : 1;
}

} // namespace sunrise::server::persistence
