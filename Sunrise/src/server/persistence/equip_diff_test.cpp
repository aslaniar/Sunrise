#include "equip_diff_test.h"

#include <Windows.h>

#include <array>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>

#include "../../core/filesystem/path.h"
#include "../../core/logging/log.h"
#include "../../middleware/datagen/family4/character/character_encoder.h"
#include "../../middleware/datagen/family4/character/layout.h"
#include "../../middleware/datagen/family4/loadout/loadout_resolver.h"
#include "../../state/build_data/runtime.h"
#include "../../state/equipment/light/resolution/configured_equipment_light_resolver.h"
#include "../../state/runtime/runtime.h"
#include "persistence.h"

namespace sunrise::server::persistence {
namespace {

namespace character = middleware::datagen::family4::character;
namespace inventory_layout = middleware::datagen::family4::inventory::layout;
namespace light_resolution = state::equipment::light::resolution;

using core::path::Buffer;
using sunrise::middleware::datagen::family4::loadout::ResolvedLoadout;

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

/** Writes one encoded object to the artifact directory. */
bool write_object(const Buffer& directory,
                  std::wstring_view name,
                  std::span<const std::byte> bytes) noexcept {
    Buffer path = directory;
    if (!core::path::append(path, name)) {
        return false;
    }
    const HANDLE file = CreateFileW(path.chars.data(),
                                    GENERIC_WRITE,
                                    0,
                                    nullptr,
                                    CREATE_ALWAYS,
                                    FILE_ATTRIBUTE_NORMAL,
                                    nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }
    DWORD written = 0;
    const bool ok = WriteFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr)
                        != FALSE
                    && written == bytes.size();
    (void)CloseHandle(file);
    return ok;
}

/** One character-object region for the diff attribution. */
struct Region {
    const char* name;
    std::size_t offset;
    std::size_t size;
};

/** @return The character-object region table (offsetof-based, the layout's order). */
std::array<Region, 6> regions() noexcept {
    using Object = character::layout::Object;
    const std::size_t stampOffset =
        offsetof(Object, contentTailPadding)
        + character::layout::kContentTailPaddingSize - 4;
    return {{
        {"inventory_items", offsetof(Object, inventoryItems),
         character::layout::kInventoryCapacity * sizeof(inventory_layout::Entry)},
        {"equipped_soids", offsetof(Object, equippedInstanceSoids),
         character::layout::kEquipmentCapacity * sizeof(std::uint64_t)},
        {"equipment_summary", offsetof(Object, equipmentSummary),
         sizeof(character::layout::EquipmentSummary)},
        {"content_stamp", stampOffset, 2},
        {"flags_and_tail", offsetof(Object, acquiredFlags),
         character::layout::kObjectSize - offsetof(Object, acquiredFlags)},
        {"head_to_inventory", 0, offsetof(Object, inventoryItems)},
    }};
}

/** Reports the byte-offset diff between the pre-equip and post-equip objects. */
void report_diff(std::span<const std::byte> pre, std::span<const std::byte> post) noexcept {
    std::size_t differing = 0;
    std::size_t first = character::layout::kObjectSize;
    std::size_t last = 0;
    for (std::size_t i = 0; i < character::layout::kObjectSize; ++i) {
        if (pre[i] != post[i]) {
            ++differing;
            first = (std::min)(first, i);
            last = (std::max)(last, i);
        }
    }
    report("ev=equip_diff stage=scan result=ok differing=%zu first=0x%zX last=0x%zX",
           differing,
           first,
           last);
    for (const Region& region : regions()) {
        const std::size_t begin = region.offset;
        const std::size_t end = (std::min)(region.offset + region.size,
                                           character::layout::kObjectSize);
        std::size_t regionDiffs = 0;
        for (std::size_t i = begin; i < end; ++i) {
            if (pre[i] != post[i]) {
                ++regionDiffs;
            }
        }
        report("ev=equip_diff stage=region result=%s name=%s offset=0x%zX bytes=%zu",
               regionDiffs == 0 ? "equal" : "differ",
               region.name,
               region.offset,
               regionDiffs);
    }
    // The first 24 differing offsets, verbatim.
    std::size_t shown = 0;
    for (std::size_t i = first; i <= last && shown < 24; ++i) {
        if (pre[i] != post[i]) {
            report("ev=equip_diff stage=byte offset=0x%zX pre=0x%02X post=0x%02X",
                   i,
                   static_cast<unsigned>(pre[i]),
                   static_cast<unsigned>(post[i]));
            ++shown;
        }
    }
}

} // namespace

/** Runs the subclass-equip diff test: the character object pre-equip vs post-equip. */
int run_equip_diff_test(void* module) noexcept {
    report("ev=equip_diff stage=start result=ok");
    state::AccountState account{};
    state::unlocks::Table unlocks{};
    state::Family5State family5{};
    if (!persistence::load_account(account, unlocks, family5) || !state::account::valid(account)) {
        report("ev=equip_diff stage=load result=fail");
        persistence::shutdown();
        return 1;
    }
    report("ev=equip_diff stage=load result=ok characters=%zu",
           account.characterCount);
    if (account.characterCount == 0) {
        report("ev=equip_diff stage=load result=fail reason=no_characters");
        persistence::shutdown();
        return 1;
    }

    // The pick: the first storage item of character 0 that passes the subclass policy.
    // The runtime State carries no selection from the DB (the schema has no selected
    // column), so publish character 0's selection first — the server's own 504 flow.
    bool selectionChanged = false;
    if (!state::set_selected_character(account.characters[0].soid, selectionChanged)) {
        report("ev=equip_diff stage=select result=fail");
        persistence::shutdown();
        return 1;
    }
    report("ev=equip_diff stage=select result=ok changed=%d", selectionChanged ? 1 : 0);
    std::uint64_t pickSoid = 0;
    const state::CharacterState& character0 = account.characters[0];
    report("ev=equip_diff stage=debug storage_items=%zu", character0.storageItemCount);
    for (std::size_t index = 0; index < character0.storageItemCount; ++index) {
        const std::uint64_t candidate = character0.storageItems[index].instanceSoid;
        const std::uint32_t definitionHash = character0.storageItems[index].definitionHash;
        state::build_data::items::Definition definition{};
        const bool resolved =
            state::build_data::find_item_definition_hash(definitionHash, definition);
        report("ev=equip_diff stage=debug item=%zu soid=0x%llX defHash=0x%08X resolved=%d "
               "bucket=%u",
               index,
               candidate,
               definitionHash,
               resolved ? 1 : 0,
               resolved ? static_cast<unsigned>(definition.bucketId) : 0U);
        if (state::subclass_equip_request_valid(candidate)) {
            pickSoid = candidate;
            break;
        }
    }
    if (pickSoid == 0) {
        report("ev=equip_diff stage=pick result=fail reason=no_subclass_item");
        persistence::shutdown();
        return 1;
    }
    report("ev=equip_diff stage=pick result=ok soid=0x%llX", pickSoid);

    // PRE: the current character object (the runtime State = the boot account).
    std::array<std::byte, character::layout::kObjectSize> pre{};
    {
        const state::AccountState snapshot = state::account_snapshot();
        state::AccountState selected = snapshot;
        for (std::size_t index = 0; index < selected.characterCount; ++index) {
            selected.characters[index].selected = index == 0;
        }
        ResolvedLoadout loadout{};
        state::equipment::light::Evaluation evaluation{};
        if (!middleware::datagen::family4::loadout::resolve(selected, 0, loadout)
            || !light_resolution::resolve(selected, 0, evaluation)
            || !character::encode(selected.characters[0], loadout, evaluation, pre)) {
            report("ev=equip_diff stage=encode_pre result=fail");
            persistence::shutdown();
            return 1;
        }
        report("ev=equip_diff stage=encode_pre result=ok bytes=%zu", pre.size());
    }

    // The pick's pre-equip storage row (the CLICKED row, D4): the displaced item must land
    // there, not at the storage tail.
    std::size_t pickRowBefore = character0.storageItemCount;
    for (std::size_t index = 0; index < character0.storageItemCount; ++index) {
        if (character0.storageItems[index].instanceSoid == pickSoid) {
            pickRowBefore = index;
            break;
        }
    }
    report("ev=equip_diff stage=clicked_row pre=row=%zu storage_items=%zu",
           pickRowBefore,
           character0.storageItemCount);

    // The mutation: the same call the queuez outcome staging runs.
    std::uint64_t displaced = 0;
    if (!state::equip_subclass_item(pickSoid, displaced)) {
        report("ev=equip_diff stage=mutate result=fail");
        persistence::shutdown();
        return 1;
    }
    report("ev=equip_diff stage=mutate result=ok displaced=0x%llX", displaced);

    // THE CLICKED-ROW PLACEMENT PROOF (D4): after a swap the displaced subclass sits at the
    // row the pick occupied; after a first equip the storage compacts over it.
    {
        const state::AccountState postMutate = state::account_snapshot();
        const state::CharacterState& postCharacter = postMutate.characters[0];
        if (displaced != 0) {
            const bool inBounds = pickRowBefore < postCharacter.storageItemCount;
            report("ev=equip_diff stage=clicked_row post=row=%zu occupant=0x%llX count=%zu "
                   "placed=%s",
                   pickRowBefore,
                   inBounds ? postCharacter.storageItems[pickRowBefore].instanceSoid : 0,
                   postCharacter.storageItemCount,
                   inBounds && postCharacter.storageItems[pickRowBefore].instanceSoid == displaced
                       ? "ok"
                       : "fail");
        } else {
            report("ev=equip_diff stage=clicked_row post=first_equip count=%zu placed=ok",
                   postCharacter.storageItemCount);
        }
    }

    // POST: the re-encode from the mutated runtime State (the server's push path).
    std::array<std::byte, character::layout::kObjectSize> post{};
    {
        const state::AccountState snapshot = state::account_snapshot();
        state::AccountState selected = snapshot;
        for (std::size_t index = 0; index < selected.characterCount; ++index) {
            selected.characters[index].selected = index == 0;
        }
        ResolvedLoadout loadout{};
        state::equipment::light::Evaluation evaluation{};
        if (!middleware::datagen::family4::loadout::resolve(selected, 0, loadout)
            || !light_resolution::resolve(selected, 0, evaluation)
            || !character::encode(selected.characters[0], loadout, evaluation, post)) {
            report("ev=equip_diff stage=encode_post result=fail");
            persistence::shutdown();
            return 1;
        }
        report("ev=equip_diff stage=encode_post result=ok bytes=%zu", post.size());
    }

    report_diff(pre, post);

    Buffer directory;
    if (core::path::artifact_directory(module, directory)) {
        (void)write_object(directory, L"\\equip_diff_pre.bin", pre);
        (void)write_object(directory, L"\\equip_diff_post.bin", post);
    }
    persistence::shutdown();
    report("ev=equip_diff stage=done result=ok");
    return 0;
}

} // namespace sunrise::server::persistence
