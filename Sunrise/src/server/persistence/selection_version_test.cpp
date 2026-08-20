#include "selection_version_test.h"

#include <Windows.h>

#include <array>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <optional>
#include <span>

#include "../../core/logging/log.h"
#include "../../middleware/datagen/definitions.h"
#include "../../middleware/queuez/queuez_update.h"
#include "../../middleware/web_service/web_service_envelope.h"
#include "../../state/account/account_state.h"
#include "../../state/account/inventory/inventory_state.h"
#include "../../state/runtime/runtime.h"
#include "../web_service/web_service_runtime.h"
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

    // The family-zero and family-three subscriptions (the fork's full ladder): the equip's
    // refresh pair stages only when both sides are active.
    SessionState beforeAll = afterReplay;
    bool family0Publish = false;
    bool family0Incremental = false;
    harness.check(queuez::stage_family0_subscription(beforeAll,
                                                     account.characters[0].soid,
                                                     family0Publish,
                                                     family0Incremental,
                                                     beforeAll),
                  "family0_subscription_stages");
    harness.check(beforeAll.family0Active, "family0_subscription_activates");
    const middleware::queuez::Subscription rosterSub{queuez::kRosterFamilyType, accountSoid};
    bool rosterPublish = false;
    harness.check(
        queuez::stage_family3_subscription(beforeAll, rosterSub, rosterPublish, beforeAll),
        "roster_subscription_stages");
    harness.check(beforeAll.family3Active, "roster_subscription_activates_family3");

    // THE REVERSED-ORDER GATE (the boot-G bug): the family-3 subscription FIRST, then the
    // family-4 replay — the family-3 ladder must survive the family-4 staging (the
    // scratch-built candidate used to drop these fields).
    {
        SessionState reversed{};
        bool reversedRosterPublish = false;
        harness.check(queuez::stage_family3_subscription(
                          reversed, rosterSub, reversedRosterPublish, reversed),
                      "reversed_roster_stages_first");
        SessionState reversedReplay{};
        harness.check(queuez::stage_family4_snapshot(reversed, replayFamily, reversedReplay),
                      "reversed_replay_stages");
        harness.check(reversedReplay.family3Active
                          && reversedReplay.family3RootSoid == accountSoid
                          && reversedReplay.family3Version
                                 == queuez::kInitialFamilyVersion,
                      "reversed_replay_preserves_family3");
    }

    // THE FIRST 801: one prepared selection, staged at exactly +1, committed, and its
    // family-4 character after-image prepared + appended at the staged version.
    const std::optional<std::uint8_t> entry1 = find_changing_entry(subclassSoid);
    harness.check(entry1.has_value(), "entry1_changes_a_pick");
    queuez::SubclassSelection selection1{};
    state::PendingSubclassSelection mutation1{};
    if (entry1.has_value()) {
        harness.check(state::prepare_subclass_selection(subclassSoid, *entry1, mutation1),
                      "entry1_prepares");
        harness.check(queuez::stage_subclass_selection(beforeAll, mutation1, selection1),
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

    // THE 403 EQUIP: the upstream-exact delivery — staged at exactly +1 over the second
    // selection, the reply promising that same revision, and ONE character-upsert frame
    // delivered at it (the boot-P synthetic reset→select two-frame is gone).
    queuez::SubclassEquip equip{};
    harness.check(queuez::stage_subclass_equip(selection2.after, pickSoid, equip),
                  "equip_stages");
    harness.check(equip.after.family4Version == selection2.after.family4Version + 1,
                  "equip_version_exactly_plus_one");
    // THE SERIAL HAND-OFF GATE (the 6164a3b rule): the mover takes the freshest generation,
    // the displaced item keeps the mover's PRIOR serial, and the swap consumes exactly two
    // counter values.
    std::uint64_t displaced = 0;
    {
        const state::AccountState preEquip = state::account_snapshot();
        const state::CharacterState& preCharacter = preEquip.characters[0];
        const auto& preSubclass =
            preCharacter.equipment
                .slots[static_cast<std::size_t>(state::account::inventory::EquipmentSlot::subclass)];
        harness.check(preSubclass.has_value() && preSubclass->instanceSoid == subclassSoid,
                      "equip_serial_pre_subclass_matches");
        const std::uint32_t counterBefore = preCharacter.nextInventorySerial;
        std::int32_t pickSerialBefore = 0;
        std::size_t pickRowBefore = preCharacter.storageItemCount;
        bool pickSerialFound = false;
        for (std::size_t index = 0; index < preCharacter.storageItemCount; ++index) {
            if (preCharacter.storageItems[index].instanceSoid == pickSoid) {
                pickSerialBefore = preCharacter.storageItems[index].mutationSerial;
                pickRowBefore = index;
                pickSerialFound = true;
                break;
            }
        }
        harness.check(pickSerialFound, "equip_serial_pick_found_before");
        harness.check(state::equip_subclass_item(pickSoid, displaced), "equip_mutates");
        harness.check(displaced == subclassSoid, "equip_displaces_previous_subclass");
        const state::AccountState postEquip = state::account_snapshot();
        const state::CharacterState& postCharacter = postEquip.characters[0];
        const auto& postSubclass =
            postCharacter.equipment
                .slots[static_cast<std::size_t>(state::account::inventory::EquipmentSlot::subclass)];
        harness.check(postSubclass.has_value() && postSubclass->instanceSoid == pickSoid,
                      "equip_serial_post_subclass_matches");
        harness.check(
            postSubclass.has_value()
                && postSubclass->mutationSerial == static_cast<std::int32_t>(counterBefore),
            "equip_serial_mover_takes_freshest");
        // THE CLICKED-ROW PLACEMENT (D4): the displaced item sits in the row the player
        // clicked — the pick's pre-equip storage row — not the storage tail (the upstream's
        // std::swap shape).
        harness.check(pickRowBefore < postCharacter.storageItemCount,
                      "equip_clicked_row_in_bounds");
        harness.check(pickRowBefore < postCharacter.storageItemCount
                          && postCharacter.storageItems[pickRowBefore].instanceSoid
                                 == subclassSoid,
                      "equip_clicked_row_holds_displaced");
        harness.check(postCharacter.storageItemCount == preCharacter.storageItemCount,
                      "equip_clicked_row_keeps_storage_count");
        std::int32_t displacedSerial = 0;
        bool displacedSerialFound = false;
        for (std::size_t index = 0; index < postCharacter.storageItemCount; ++index) {
            if (postCharacter.storageItems[index].instanceSoid == subclassSoid) {
                displacedSerial = postCharacter.storageItems[index].mutationSerial;
                displacedSerialFound = true;
                break;
            }
        }
        harness.check(displacedSerialFound, "equip_serial_displaced_in_storage");
        harness.check(displacedSerial == pickSerialBefore, "equip_serial_displaced_keeps_prior");
        harness.check(postCharacter.nextInventorySerial == counterBefore + 2,
                      "equip_serial_counter_consumes_two");
    }
    {
        bap::Scratch scratch{};
        snapshot::Prepared prepared{};
        harness.check(snapshot::prepare_subclass_equip(scratch, equip, prepared),
                      "equip_prepares_frame");
        harness.check(prepared.family.version == equip.after.family4Version,
                      "equip_frame_versions_match");
        harness.check(prepared.family.type == queuez::kAccountFamilyType
                          && prepared.family.flags == 0
                          && prepared.family.objects.size() == 1,
                      "equip_frame_shape_single_object");
        harness.check(prepared.family.objects.size() == 1
                          && prepared.family.objects[0].id == characterObjectId
                          && prepared.family.objects[0].version == equip.characterSoid,
                      "equip_frame_is_the_character_upsert");
        std::array<std::byte, state::kAesKeySize> key{};
        std::array<std::byte, state::kBapNonceSize> nonce{};
        std::size_t written = 0;
        harness.check(push::append_subclass_equip_notification(
                          scratch,
                          equip,
                          std::span<const std::byte, state::kAesKeySize>(key),
                          std::span<const std::byte, state::kBapNonceSize>(nonce),
                          std::span(scratch.responseBody),
                          written),
                      "equip_full_frame_appends");
    }
    // THE PROMISED REPLY (D1): the full production sequence for the swap-back equip —
    // consume() defers the reply, the BAP body layer stages at +1, and the encoded
    // status-pair value round-trips as the staged revision (the upstream contract:
    // status.value = the staged Family-4 version, never the INT32_MIN default).
    {
        const std::uint64_t swapBackSoid = subclassSoid; // now the displaced storage item
        std::array<std::byte, 64> request{};
        // {u16 BE opcode 403, u32 BE transaction id 0x7B, u64 BE item soid, u8 flag 1}
        request[0] = std::byte{0x01};
        request[1] = std::byte{0x93};
        request[2] = std::byte{0x00};
        request[3] = std::byte{0x00};
        request[4] = std::byte{0x00};
        request[5] = std::byte{0x7B};
        for (std::size_t byte = 0; byte < 8; ++byte) {
            request[6 + byte] = std::byte{static_cast<std::uint8_t>(
                (swapBackSoid >> (8U * (7U - byte))) & 0xFFULL)};
        }
        request[14] = std::byte{0x01};
        const std::span<const std::byte> body(request.data(), 15);
        std::array<std::byte, 64> response{};
        std::size_t written = 0;
        sunrise::server::web_service::Outcome webOutcome{};
        harness.check(sunrise::server::web_service::consume(
                          body, std::span(response), written, webOutcome),
                      "reply_consume_parses");
        harness.check(webOutcome.hasSubclassEquip && webOutcome.subclassEquipSoid == swapBackSoid,
                      "reply_consume_policy_accepts");
        harness.check(written == 0, "reply_consume_defers_encode");
        queuez::SubclassEquip swapBack{};
        harness.check(queuez::stage_subclass_equip(equip.after, swapBackSoid, swapBack),
                      "reply_stage_swaps_back");
        harness.check(swapBack.after.family4Version == equip.after.family4Version + 1,
                      "reply_staged_version_plus_one");
        middleware::web_service::Message message{};
        harness.check(middleware::web_service::parse_request(body, message),
                      "reply_message_parses");
        middleware::web_service::StatusResponse status{};
        status.value = swapBack.after.family4Version;
        harness.check(middleware::web_service::encode_response(
                          message,
                          middleware::web_service::ResponseShape::statusPair,
                          status,
                          std::span(response),
                          written),
                      "reply_status_pair_encodes");
        harness.check(written == middleware::web_service::kEnvelopeHeaderSize + 5,
                      "reply_status_pair_size");
        // Decode the 5-bit code + 32-bit value + 2-bit trailer from the MSB-first bit
        // stream — the exact inverse of status_fields.cpp write_code/write_value.
        const auto bit_at = [&](int bit) noexcept {
            const std::byte byte = response[6 + bit / 8];
            return (std::to_integer<unsigned>(byte) >> (7 - bit % 8)) & 1U;
        };
        std::uint32_t code = 0;
        for (int bit = 0; bit < 5; ++bit) {
            code = (code << 1) | bit_at(bit);
        }
        std::uint32_t biasedValue = 0;
        for (int bit = 0; bit < 32; ++bit) {
            biasedValue = (biasedValue << 1) | bit_at(5 + bit);
        }
        const std::int64_t decodedValue =
            static_cast<std::int64_t>(biasedValue) - 2147483648LL; // the -INT32_MIN bias
        harness.check(code == 1U, "reply_status_code_is_success");
        harness.check(decodedValue == swapBack.after.family4Version,
                      "reply_value_is_the_staged_revision");
        // The refuse-path contrast: the plain pair still decodes as the INT32_MIN default,
        // proving the promised value is exactly what this fix changes.
        std::size_t plainWritten = 0;
        middleware::web_service::StatusResponse plain{};
        harness.check(middleware::web_service::encode_response(
                          message,
                          middleware::web_service::ResponseShape::statusPair,
                          plain,
                          std::span(response),
                          plainWritten),
                      "reply_plain_pair_encodes");
        std::uint32_t plainBiased = 0;
        const auto plain_bit_at = [&](int bit) noexcept {
            const std::byte byte = response[6 + bit / 8];
            return (std::to_integer<unsigned>(byte) >> (7 - bit % 8)) & 1U;
        };
        for (int bit = 0; bit < 32; ++bit) {
            plainBiased = (plainBiased << 1) | plain_bit_at(5 + bit);
        }
        harness.check(static_cast<std::int64_t>(plainBiased) - 2147483648LL
                          == (std::numeric_limits<std::int32_t>::min)(),
                      "reply_plain_pair_carries_default");
    }

    // THE THREE-FRAME TRANSACTION (the fork's atomic shape): the family-0 in-place refresh
    // and the family-3 roster-side refresh follow the family-4 pair, each at exactly +1.
    {
        queuez::SessionState bannerBefore = equip.after;
        queuez::SessionState bannerAfter{};
        harness.check(
            queuez::stage_family0_refresh(bannerBefore, equip.characterSoid, bannerAfter),
            "equip_family0_refresh_stages");
        harness.check(bannerAfter.family0Version == bannerBefore.family0Version + 1,
                      "equip_family0_refresh_plus_one");
        bap::Scratch scratch{};
        snapshot::Prepared bannerPrepared{};
        harness.check(snapshot::prepare_banner_refresh(scratch,
                                                       bannerAfter.family4RootSoid,
                                                       bannerAfter.family0Version,
                                                       equip.characterSoid,
                                                       bannerPrepared),
                      "equip_family0_refresh_prepares_frame");
        harness.check(bannerPrepared.family.flags == 0
                          && bannerPrepared.family.objects.size() == 1,
                      "equip_family0_refresh_inplace_shape");

        queuez::RosterAppearanceRefresh rosterRefresh{};
        harness.check(queuez::stage_roster_appearance_refresh(
                          bannerAfter, equip.characterSoid, true, rosterRefresh),
                      "equip_roster_refresh_stages");
        harness.check(rosterRefresh.after.family3Version == bannerAfter.family3Version + 1,
                      "equip_roster_refresh_plus_one");
        const state::AccountState liveAfter = state::account_snapshot();
        std::size_t characterIndex = liveAfter.characterCount;
        for (std::size_t index = 0; index < liveAfter.characterCount; ++index) {
            if (liveAfter.characters[index].soid == equip.characterSoid) {
                characterIndex = index;
                break;
            }
        }
        harness.check(characterIndex < liveAfter.characterCount, "equip_roster_character_found");
        if (characterIndex < liveAfter.characterCount) {
            snapshot::Prepared rosterPrepared{};
            harness.check(snapshot::prepare_roster_appearance_refresh(
                              scratch,
                              rosterRefresh,
                              liveAfter.characters[characterIndex],
                              characterIndex,
                              rosterPrepared),
                          "equip_roster_refresh_prepares_frame");
            harness.check(rosterPrepared.family.type == queuez::kRosterFamilyType
                              && rosterPrepared.family.version
                                     == rosterRefresh.after.family3Version
                              && rosterPrepared.family.objects.size() == 2,
                          "equip_roster_frame_shape");
        }
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
