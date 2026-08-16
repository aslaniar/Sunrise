#include "account_memcmp_test.h"

#include <Windows.h>

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <limits>
#include <span>
#include <string_view>

#include "../../core/filesystem/path.h"
#include "../../core/logging/log.h"
#include "../../core/settings/settings.h"
#include "../../middleware/datagen/family4/account/account_encoder.h"
#include "../../middleware/datagen/family4/account/layout.h"
#include "../../middleware/datagen/family4/character/character_encoder.h"
#include "../../middleware/datagen/family4/character/layout.h"
#include "../../middleware/datagen/family4/loadout/loadout_resolver.h"
#include "../../middleware/encoding/bit_writer.h"
#include "../../middleware/web_service/messages/family5/family5_codec.h"
#include "../../state/equipment/light/resolution/configured_equipment_light_resolver.h"
#include "../../state/runtime/runtime.h"
#include "../../state/unlocks/unlocks_runtime.h"
#include "persistence.h"

namespace sunrise::server::persistence {
namespace {

namespace family4_datagen = middleware::datagen::family4;
namespace character = middleware::datagen::family4::character;
namespace light_resolution = state::equipment::light::resolution;

using sunrise::core::path::Buffer;
using sunrise::middleware::datagen::family4::account::layout::kAcquiredFlagsOffset;
using sunrise::middleware::datagen::family4::account::layout::kCharacterUnlocksOffset;
using sunrise::middleware::datagen::family4::account::layout::kObjectiveValuesOffset;
using sunrise::middleware::datagen::family4::account::layout::kObjectSize;
using sunrise::middleware::datagen::family4::account::layout::kProfileFlagsTailPaddingSize;
using sunrise::middleware::datagen::family4::account::layout::kProfileItemCapacity;
using sunrise::middleware::datagen::family4::account::layout::kProfileItemsOffset;
using sunrise::middleware::datagen::family4::account::layout::kProfileUnlockFlagsOffset;
using sunrise::middleware::datagen::family4::account::layout::kProgressionsOffset;

/** One fixed byte region of the native account object, for pinpoint diff reporting. */
struct Region {
    std::string_view name;
    std::size_t offset;
    std::size_t size;
};

constexpr std::array<Region, 8> kRegions{{
    {"header_and_roster", 0, kProfileItemsOffset},
    {"profile_items", kProfileItemsOffset, kProfileItemCapacity * 32},
    {"progressions", kProgressionsOffset, 1'032},
    {"acquired_flags", kAcquiredFlagsOffset, 12'300},
    {"objective_values", kObjectiveValuesOffset, 6'200 * 4},
    {"character_unlocks", kCharacterUnlocksOffset, 4 * (256 + 256 * 4)},
    {"profile_unlock_flags", kProfileUnlockFlagsOffset, 512},
    {"tail", kProfileUnlockFlagsOffset + 512, kProfileFlagsTailPaddingSize},
}};

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

/** Encodes one account through the existing datagen into fixed native storage. */
bool encode_account(const state::AccountState& account,
                    std::span<std::byte> output) noexcept {
    return sunrise::middleware::datagen::family4::account::encode(account, output);
}

/** Reports which byte regions differ between the two objects. */
void report_regions(std::span<const std::byte> reference,
                    std::span<const std::byte> database) noexcept {
    for (const Region& region : kRegions) {
        const bool equal =
            std::memcmp(reference.data() + region.offset,
                        database.data() + region.offset,
                        region.size)
            == 0;
        if (equal) {
            report("ev=s1_memcmp stage=region result=equal name=%.*s",
                   static_cast<int>(region.name.size()),
                   region.name.data());
        } else {
            report("ev=s1_memcmp stage=region result=differ name=%.*s",
                   static_cast<int>(region.name.size()),
                   region.name.data());
        }
    }
}

/** Writes one encoded object to the artifact directory for external inspection. */
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

/** Encodes one family-5 object through the exact codec the ws-503/ws-205 wire path uses. */
bool encode_family5(const state::Family5State& family,
                    std::span<std::byte> output,
                    std::size_t& size) noexcept {
    middleware::encoding::bits::Writer writer(output);
    if (!middleware::web_service::messages::family5::write(writer, family)
        || !writer.finish(size)) {
        return false;
    }
    return true;
}

/** Reports whether one family-5 encoded payload matches the reference bytes. */
void report_family5_equal(std::string_view source,
                          std::size_t size,
                          bool equal) noexcept {
    if (equal) {
        report("ev=s1_family5 stage=compare result=equal bytes=%zu source=%.*s",
               size,
               static_cast<int>(source.size()),
               source.data());
    } else {
        report("ev=s1_family5 stage=compare result=differ source=%.*s",
               static_cast<int>(source.size()),
               source.data());
    }
}

} // namespace

/** Runs the S1-1 account-object memcmp acceptance test. */
int run_account_memcmp_test(void* module) noexcept {
    report("ev=s1_memcmp stage=start result=ok");
    const core::settings::Settings& settings = core::settings::get();
    const state::AccountState& authored = settings.initialAccount;
    if (authored.primarySoid == 0) {
        report("ev=s1_memcmp stage=start result=fail reason=no_authored_account");
        return 1;
    }

    // Reference: the current settings-driven datagen output. The deployed settings may carry
    // only account policy (S1-2 configuration, no characters) or a loadout the installed cache
    // no longer serves (S1-6 picked loadout), so the reference is optional; the DB-driven
    // encode below is always the gate.
    state::unlocks::publish(settings.initialUnlocks);
    std::array<std::byte, kObjectSize> reference{};
    bool settingsUsable = authored.characterCount != 0;
    if (settingsUsable && !encode_account(authored, reference)) {
        report("ev=s1_memcmp stage=encode_reference result=skipped "
               "reason=settings_loadout_unresolvable");
        settingsUsable = false;
    } else if (settingsUsable) {
        report("ev=s1_memcmp stage=encode_reference result=ok size=96280");
    } else {
        report("ev=s1_memcmp stage=encode_reference result=skipped "
               "reason=settings_account_incomplete");
    }

    // The boot chain seeded the state database from the same authored settings; ensure it is
    // still open (the seed ran under this process before the network stages).
    if (!persistence::ready() && !persistence::initialize(module)) {
        report("ev=s1_memcmp stage=seed result=fail");
        return 1;
    }
    report("ev=s1_memcmp stage=seed result=ok db=state.db");

    state::AccountState databaseAccount{};
    state::unlocks::Table databaseUnlocks{};
    state::Family5State databaseFamily5{};
    if (!persistence::load_account(databaseAccount, databaseUnlocks, databaseFamily5)
        || !state::account::valid(databaseAccount)) {
        report("ev=s1_memcmp stage=load result=fail");
        persistence::shutdown();
        return 1;
    }
    report("ev=s1_memcmp stage=load result=ok characters=%zu profile_items=%zu",
           databaseAccount.characterCount,
           databaseAccount.profileItemCount);

    // Database-driven re-encode through the exact same encoder. This is always a gate.
    state::unlocks::publish(databaseUnlocks);
    std::array<std::byte, kObjectSize> database{};
    if (!encode_account(databaseAccount, database)) {
        report("ev=s1_memcmp stage=encode_db result=fail");
        persistence::shutdown();
        return 1;
    }
    report("ev=s1_memcmp stage=encode_db result=ok size=96280");

    bool accountEqual = true;
    if (settingsUsable) {
        accountEqual = std::memcmp(reference.data(), database.data(), kObjectSize) == 0;
        if (accountEqual) {
            report("ev=s1_memcmp stage=compare result=equal bytes=96280");
        } else {
            report("ev=s1_memcmp stage=compare result=differ bytes=96280");
            report_regions(reference, database);
        }
    } else {
        report("ev=s1_memcmp stage=compare result=skipped reason=no_reference");
    }

    // S1-5: family-5 frame bit-parity. The DB-loaded override lists must encode to the same
    // payload bytes as the settings-authored lists through the same codec the ws-503/ws-205
    // wire path uses (family5_codec.cpp:126-148). Object identity (INT64_MAX) and the
    // content-gate arm are State-owned (state_runtime.cpp:111-126); the arm is computed from
    // the BOOT account, which is the database account whenever one loaded, so both sides get
    // the same State-owned values from that account.
    const state::AccountState& armAccount =
        databaseAccount.primarySoid != 0 ? databaseAccount : authored;
    state::Family5State referenceFamily = settings.initialFamily5;
    referenceFamily.objectSoid =
        static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)());
    for (std::size_t index = 0; index < armAccount.characterCount; ++index) {
        if (armAccount.characters[index].contentBypass) {
            referenceFamily.contentGateArm = true;
            break;
        }
    }
    state::Family5State databaseFamily = databaseFamily5;
    databaseFamily.objectSoid = referenceFamily.objectSoid;
    databaseFamily.contentGateArm = referenceFamily.contentGateArm;
    // The boot chain already published the DB family-5 into State (server_main.cpp); the
    // published object is what ws-503/ws-205 actually serve on the wire.
    const state::Family5State published = state::investment_snapshot().family5;
    std::array<std::byte, 512> referenceFamilyBytes{};
    std::array<std::byte, 512> databaseFamilyBytes{};
    std::array<std::byte, 512> publishedFamilyBytes{};
    std::size_t referenceFamilySize = 0;
    std::size_t databaseFamilySize = 0;
    std::size_t publishedFamilySize = 0;
    if (!encode_family5(referenceFamily, referenceFamilyBytes, referenceFamilySize)
        || !encode_family5(databaseFamily, databaseFamilyBytes, databaseFamilySize)
        || !encode_family5(published, publishedFamilyBytes, publishedFamilySize)) {
        report("ev=s1_family5 stage=encode result=fail");
        persistence::shutdown();
        return 1;
    }
    report("ev=s1_family5 stage=load result=ok settings_flags=%zu settings_values=%zu "
           "db_flags=%zu db_values=%zu",
           referenceFamily.flagCount,
           referenceFamily.valueCount,
           databaseFamily.flagCount,
           databaseFamily.valueCount);
    const bool settingsFamily5Usable = referenceFamily.flagCount != 0
                                       || referenceFamily.valueCount != 0;
    bool family5SettingsEqual = true;
    if (settingsFamily5Usable) {
        family5SettingsEqual =
            referenceFamilySize == databaseFamilySize
            && std::memcmp(referenceFamilyBytes.data(),
                           databaseFamilyBytes.data(),
                           databaseFamilySize)
                   == 0;
        report_family5_equal("db_vs_settings", databaseFamilySize, family5SettingsEqual);
    } else {
        report("ev=s1_family5 stage=compare result=skipped source=db_vs_settings "
               "reason=no_settings_rows");
    }
    // The published State always carries the DB rows (server_main publish_family5); this gate
    // catches a publish that silently keeps stale lists.
    const bool publishedMatchesDatabase =
        publishedFamilySize == databaseFamilySize
        && std::memcmp(publishedFamilyBytes.data(),
                       databaseFamilyBytes.data(),
                       publishedFamilySize)
               == 0;
    report_family5_equal("published_vs_db", publishedFamilySize, publishedMatchesDatabase);

    // S1-6: the selected-character object. The DB account carries no selection (the schema has
    // no selected column), so the harness marks character 0 the way the client's pick would.
    // loadout::resolve + light resolution + character::encode run the full summary_matches_loadout
    // gate (character_encoder.cpp:93-111).
    bool characterEncoded = false;
    bool characterSettingsEqual = true;
    std::array<std::byte, character::layout::kObjectSize> characterBytes{};
    if (databaseAccount.characterCount == 0) {
        report("ev=s1_character stage=resolve result=skipped reason=no_characters");
    } else {
        state::AccountState selectedAccount = databaseAccount;
        for (std::size_t index = 0; index < selectedAccount.characterCount; ++index) {
            selectedAccount.characters[index].selected = index == 0;
        }
        family4_datagen::loadout::ResolvedLoadout loadout{};
        state::equipment::light::Evaluation evaluation{};
        if (!family4_datagen::loadout::resolve(selectedAccount, 0, loadout)
            || !light_resolution::resolve(selectedAccount, 0, evaluation)) {
            report("ev=s1_character stage=resolve result=fail");
        } else {
            report("ev=s1_character stage=resolve result=ok items=%zu",
                   loadout.itemCount);
            // The family-4 prepare resolves every character's item instances, selected or not;
            // prove all 48 picked items resolve (S1-6 acceptance, offline half).
            bool allCharactersResolve = true;
            for (std::size_t index = 0; index < selectedAccount.characterCount; ++index) {
                family4_datagen::loadout::ResolvedInstances instances{};
                if (!family4_datagen::loadout::resolve_instances(selectedAccount, index,
                                                                 instances)) {
                    allCharactersResolve = false;
                    report("ev=s1_character stage=resolve_all result=fail character=%zu", index);
                } else {
                    report("ev=s1_character stage=resolve_all result=ok character=%zu items=%zu",
                           index,
                           instances.itemCount);
                }
            }
            if (!allCharactersResolve) {
                persistence::shutdown();
                return 1;
            }
            if (!character::encode(selectedAccount.characters[0],
                                   loadout,
                                   evaluation,
                                   characterBytes)) {
                report("ev=s1_character stage=encode result=fail");
            } else {
                report("ev=s1_character stage=encode result=ok bytes=46928");
                characterEncoded = true;
                if (settingsUsable) {
                    state::AccountState settingsAccount = authored;
                    for (std::size_t index = 0; index < settingsAccount.characterCount;
                         ++index) {
                        settingsAccount.characters[index].selected = index == 0;
                    }
                    family4_datagen::loadout::ResolvedLoadout settingsLoadout{};
                    state::equipment::light::Evaluation settingsEvaluation{};
                    std::array<std::byte, character::layout::kObjectSize>
                        settingsCharacterBytes{};
                    if (!family4_datagen::loadout::resolve(settingsAccount, 0, settingsLoadout)
                        || !light_resolution::resolve(settingsAccount, 0, settingsEvaluation)
                        || !character::encode(settingsAccount.characters[0],
                                              settingsLoadout,
                                              settingsEvaluation,
                                              settingsCharacterBytes)) {
                        report("ev=s1_character stage=compare result=skipped "
                               "source=db_vs_settings reason=settings_loadout_unresolvable");
                    } else {
                        characterSettingsEqual =
                            std::memcmp(settingsCharacterBytes.data(),
                                        characterBytes.data(),
                                        characterBytes.size())
                            == 0;
                        if (characterSettingsEqual) {
                            report("ev=s1_character stage=compare result=equal bytes=46928 "
                                   "source=db_vs_settings");
                        } else {
                            report("ev=s1_character stage=compare result=differ bytes=46928 "
                                   "source=db_vs_settings");
                        }
                    }
                } else {
                    report("ev=s1_character stage=compare result=skipped "
                           "source=db_vs_settings reason=no_reference");
                }
                Buffer directory;
                if (core::path::artifact_directory(module, directory)) {
                    (void)write_object(directory,
                                       L"\\s1_character_database.bin",
                                       characterBytes);
                }
            }
        }
    }

    // S1-7: persistence write-back (Stage 5). The published State (account, unlocks, family5,
    // entitlements) is written back into the DB, then re-loaded as a second boot and re-encoded.
    // The three frames must be byte-identical across the two boots: account 96,280 B, family-5
    // 163 B, selected character 46,928 B.
    bool persistEqual = false;
    if (characterEncoded) {
        if (!persistence::write_back()) {
            report("ev=s1_persist stage=write_back result=fail");
            persistence::shutdown();
            return 1;
        }
        report("ev=s1_persist stage=write_back result=ok");
        state::AccountState secondAccount{};
        state::unlocks::Table secondUnlocks{};
        state::Family5State secondFamily5{};
        if (!persistence::load_account(secondAccount, secondUnlocks, secondFamily5)
            || !state::account::valid(secondAccount)) {
            report("ev=s1_persist stage=second_boot result=fail reason=load");
            persistence::shutdown();
            return 1;
        }
        state::unlocks::publish(secondUnlocks);
        std::array<std::byte, kObjectSize> database2{};
        if (!encode_account(secondAccount, database2)) {
            report("ev=s1_persist stage=second_boot result=fail reason=account_encode");
            persistence::shutdown();
            return 1;
        }
        const bool account2Equal =
            std::memcmp(database.data(), database2.data(), kObjectSize) == 0;
        if (account2Equal) {
            report("ev=s1_persist stage=second_boot result=equal object=account bytes=96280");
        } else {
            report("ev=s1_persist stage=second_boot result=differ object=account bytes=96280");
        }

        std::array<std::byte, 512> family5Bytes2{};
        std::size_t family5Size2 = 0;
        state::Family5State secondFamily = secondFamily5;
        secondFamily.objectSoid = referenceFamily.objectSoid;
        secondFamily.contentGateArm = referenceFamily.contentGateArm;
        if (!encode_family5(secondFamily, family5Bytes2, family5Size2)) {
            report("ev=s1_persist stage=second_boot result=fail reason=family5_encode");
            persistence::shutdown();
            return 1;
        }
        const bool family2Equal = family5Size2 == publishedFamilySize
                                  && std::memcmp(family5Bytes2.data(),
                                                 publishedFamilyBytes.data(),
                                                 family5Size2)
                                         == 0;
        if (family2Equal) {
            report("ev=s1_persist stage=second_boot result=equal object=family5 bytes=%zu",
                   family5Size2);
        } else {
            report("ev=s1_persist stage=second_boot result=differ object=family5 bytes=%zu",
                   family5Size2);
        }

        state::AccountState secondSelected = secondAccount;
        for (std::size_t index = 0; index < secondSelected.characterCount; ++index) {
            secondSelected.characters[index].selected = index == 0;
        }
        family4_datagen::loadout::ResolvedLoadout secondLoadout{};
        state::equipment::light::Evaluation secondEvaluation{};
        std::array<std::byte, character::layout::kObjectSize> secondCharacterBytes{};
        const bool character2Encoded =
            family4_datagen::loadout::resolve(secondSelected, 0, secondLoadout)
            && light_resolution::resolve(secondSelected, 0, secondEvaluation)
            && character::encode(secondSelected.characters[0],
                                 secondLoadout,
                                 secondEvaluation,
                                 secondCharacterBytes);
        if (!character2Encoded) {
            report("ev=s1_persist stage=second_boot result=fail reason=character_encode");
            persistence::shutdown();
            return 1;
        }
        const bool character2Equal =
            std::memcmp(characterBytes.data(), secondCharacterBytes.data(), characterBytes.size())
            == 0;
        if (character2Equal) {
            report("ev=s1_persist stage=second_boot result=equal object=character bytes=46928");
        } else {
            report("ev=s1_persist stage=second_boot result=differ object=character bytes=46928");
        }

        persistEqual = account2Equal && family2Equal && character2Equal;
        if (persistEqual) {
            report("ev=s1_persist stage=second_boot result=equal bytes=143371");
        } else {
            report("ev=s1_persist stage=second_boot result=differ bytes=143371");
        }
    } else {
        report("ev=s1_persist stage=second_boot result=skipped reason=no_character_encode");
    }

    Buffer directory;
    if (core::path::artifact_directory(module, directory)) {
        (void)write_object(directory, L"\\s1_account_reference.bin", reference);
        (void)write_object(directory, L"\\s1_account_database.bin", database);
    }
    persistence::shutdown();
    return accountEqual && family5SettingsEqual && publishedMatchesDatabase
                   && characterEncoded && characterSettingsEqual && persistEqual
               ? 0
               : 1;
}

} // namespace sunrise::server::persistence
