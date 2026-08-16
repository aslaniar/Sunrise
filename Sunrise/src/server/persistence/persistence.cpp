#include "persistence.h"

#include <Windows.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <span>
#include <string_view>

#include "../../core/filesystem/path.h"
#include "../../core/logging/log.h"
#include "../../core/settings/settings.h"
#include "../../state/build_data/runtime.h"
#include "../../state/entitlements/entitlement_runtime.h"
#include "../../state/runtime/runtime.h"
#include "../../state/unlocks/unlocks_runtime.h"

#include "sqlite3.h"

namespace sunrise::server::persistence {
namespace {

using sunrise::core::path::Buffer;

/** The seeded database file replaces the settings file's role for account rows. */
inline constexpr std::wstring_view kDatabaseSuffix = L"\\state.db";
/** Schema layout this build expects. Raise it when a stored shape changes. */
inline constexpr std::uint32_t kSchemaVersion = 1;
/** Seed build id carried in the meta table (spec §3.2 example value). */
inline constexpr std::string_view kBuildId = "84291.20.05.27.1646-1";
/** Seed manifest era carried in the meta table (spec §3.2 example value). */
inline constexpr std::string_view kManifestEra = "arrivals_2020_07_16";

sqlite3* g_database = nullptr;
SRWLOCK g_lock{SRWLOCK_INIT};

/** @param stage Short stage name. @param detail sqlite error text, or null. */
void fail(std::string_view stage, const char* detail) noexcept {
    std::array<char, 192> line{};
    const int written = std::snprintf(line.data(),
                                      line.size(),
                                      "ev=persistence stage=%.*s result=fail reason=%.*s",
                                      static_cast<int>(stage.size()),
                                      stage.data(),
                                      detail != nullptr ? static_cast<int>(std::strlen(detail))
                                                        : 0,
                                      detail != nullptr ? detail : "");
    if (written > 0) {
        core::log::write(core::log::Channel::state,
                         core::log::Level::error,
                         {line.data(), static_cast<std::size_t>(written)});
    }
}

/** Closes the database while the caller already holds the module lock. */
void close_locked() noexcept {
    if (g_database != nullptr) {
        // close_v2 defers the actual close until every prepared statement and transaction
        // finishes, so a mid-seed failure path cannot leak the connection handle.
        (void)sqlite3_close_v2(g_database);
        g_database = nullptr;
    }
}

/** @return The active sqlite error message, or a fixed fallback. */
[[nodiscard]] const char* error_text() noexcept {
    return g_database != nullptr ? sqlite3_errmsg(g_database) : "no database";
}

/** Runs one complete SQL statement. @return True when sqlite reports DONE. */
[[nodiscard]] bool exec(const char* sql) noexcept {
    if (g_database == nullptr) {
        return false;
    }
    char* message = nullptr;
    const int code = sqlite3_exec(g_database, sql, nullptr, nullptr, &message);
    if (code != SQLITE_OK) {
        fail("exec", message != nullptr ? message : error_text());
        sqlite3_free(message);
        return false;
    }
    return true;
}

/** Steps one prepared statement to completion. */
[[nodiscard]] bool step_done(sqlite3_stmt* statement) noexcept {
    const int code = sqlite3_step(statement);
    if (code != SQLITE_DONE) {
        fail("step", error_text());
        return false;
    }
    return true;
}

/** @param value 64-bit id. @param output Receives `0x%016llX`. */
void format_soid(std::uint64_t value, std::array<char, 24>& output) noexcept {
    const int written =
        std::snprintf(output.data(), output.size(), "0x%016llX", static_cast<unsigned long long>(value));
    if (written < 0) {
        output = {};
    }
}

/** @param value 32-bit hash. @param output Receives `0x%08X`. */
void format_hash(std::uint32_t value, std::array<char, 16>& output) noexcept {
    const int written = std::snprintf(output.data(), output.size(), "0x%08X", value);
    if (written < 0) {
        output = {};
    }
}

/** Parses a `0x`-prefixed hex string back into a 64-bit id. */
[[nodiscard]] bool parse_hex(std::string_view text, std::uint64_t& value) noexcept {
    if (text.size() < 3 || text[0] != '0' || (text[1] != 'x' && text[1] != 'X')) {
        return false;
    }
    char* end = nullptr;
    const unsigned long long parsed = std::strtoull(text.data(), &end, 16);
    if (end == nullptr || static_cast<std::size_t>(end - text.data()) != text.size()) {
        return false;
    }
    value = static_cast<std::uint64_t>(parsed);
    return true;
}

/** Binds one owned text value, copying it into the statement. */
[[nodiscard]] bool bind_text(sqlite3_stmt* statement,
                             int index,
                             std::string_view text) noexcept {
    return sqlite3_bind_text(statement,
                             index,
                             text.data(),
                             static_cast<int>(text.size()),
                             SQLITE_TRANSIENT)
           == SQLITE_OK;
}

/** Binds one nullable text value. */
[[nodiscard]] bool bind_text_or_null(sqlite3_stmt* statement,
                                     int index,
                                     std::string_view text,
                                     bool present) noexcept {
    if (!present) {
        return sqlite3_bind_null(statement, index) == SQLITE_OK;
    }
    return bind_text(statement, index, text);
}

/** @return The authored account id the seed writes every row under. */
[[nodiscard]] std::string_view seed_account_id() noexcept {
    static std::array<char, 24> storage{};
    format_soid(core::settings::get().initialAccount.primarySoid, storage);
    return {storage.data(), std::strlen(storage.data())};
}

/** Seeds the meta and account identity rows. */
bool seed_meta_and_account() noexcept {
    static constexpr char kMetaSql[] =
        "INSERT INTO meta (key, value) VALUES ('schema_version', '1'), ('build_id', ?), "
        "('manifest_era', ?);";
    sqlite3_stmt* meta = nullptr;
    if (sqlite3_prepare_v2(g_database, kMetaSql, -1, &meta, nullptr) != SQLITE_OK
        || !bind_text(meta, 1, kBuildId) || !bind_text(meta, 2, kManifestEra)
        || !step_done(meta)) {
        fail("seed_meta", error_text());
        sqlite3_finalize(meta);
        return false;
    }
    sqlite3_finalize(meta);

    static constexpr char kAccountSql[] =
        "INSERT INTO accounts (account_id, created_at) VALUES (?, unixepoch());";
    sqlite3_stmt* account = nullptr;
    if (sqlite3_prepare_v2(g_database, kAccountSql, -1, &account, nullptr) != SQLITE_OK
        || !bind_text(account, 1, seed_account_id()) || !step_done(account)) {
        fail("seed_account", error_text());
        sqlite3_finalize(account);
        return false;
    }
    sqlite3_finalize(account);
    return true;
}

/** Seeds one authored character row and its equipment item rows. */
bool seed_character(std::size_t index, const state::CharacterState& character) noexcept {
    static constexpr char kCharacterSql[] =
        "INSERT INTO characters (account_id, character_index, soid, char_class, race, gender, "
        "level, accepted, preview_available, appearance_value, last_orbited_destination, "
        "content_bypass, movement_ability_entry, grenade_ability_entry, super_ability_entry, "
        "melee_ability_entry, class_ability_entry) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";
    sqlite3_stmt* statement = nullptr;
    if (sqlite3_prepare_v2(g_database, kCharacterSql, -1, &statement, nullptr) != SQLITE_OK) {
        fail("seed_character_prepare", error_text());
        return false;
    }
    std::array<char, 24> soid{};
    std::array<char, 16> destination{};
    format_soid(character.soid, soid);
    format_hash(character.lastOrbitedDestination, destination);
    const int ok = bind_text(statement, 1, seed_account_id())
                   && sqlite3_bind_int(statement, 2, static_cast<int>(index)) == SQLITE_OK
                   && bind_text(statement, 3, {soid.data(), std::strlen(soid.data())})
                   && sqlite3_bind_int(statement,
                                       4,
                                       static_cast<int>(character.characterClass))
                          == SQLITE_OK
                   && sqlite3_bind_int(statement, 5, static_cast<int>(character.race)) == SQLITE_OK
                   && sqlite3_bind_int(statement, 6, static_cast<int>(character.gender)) == SQLITE_OK
                   && sqlite3_bind_int(statement, 7, character.level) == SQLITE_OK
                   && sqlite3_bind_int(statement, 8, character.accepted ? 1 : 0) == SQLITE_OK
                   && sqlite3_bind_int(statement, 9, character.previewAvailable ? 1 : 0) == SQLITE_OK
                   && sqlite3_bind_double(statement, 10, character.appearanceValue) == SQLITE_OK
                   && bind_text(
                          statement, 11, {destination.data(), std::strlen(destination.data())})
                   && sqlite3_bind_int(statement, 12, character.contentBypass ? 1 : 0) == SQLITE_OK
                   && sqlite3_bind_int(statement, 13, character.movementAbilityEntry) == SQLITE_OK
                   && sqlite3_bind_int(statement, 14, character.grenadeAbilityEntry) == SQLITE_OK
                   && sqlite3_bind_int(statement, 15, character.superAbilityEntry) == SQLITE_OK
                   && sqlite3_bind_int(statement, 16, character.meleeAbilityEntry) == SQLITE_OK
                   && sqlite3_bind_int(statement, 17, character.classAbilityEntry) == SQLITE_OK
                   && step_done(statement);
    sqlite3_finalize(statement);
    if (!ok) {
        fail("seed_character", error_text());
        return false;
    }

    static constexpr char kItemSql[] =
        "INSERT INTO items (account_id, character_index, definition_hash, instance_soid, "
        "quantity, bucket_id, equipment_slot, instance_level, in_equipment, socket_policy) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?);";
    static constexpr char kStorageItemSql[] =
        "INSERT INTO items (account_id, character_index, definition_hash, instance_soid, "
        "quantity, bucket_id, equipment_slot, instance_level, in_equipment, socket_policy) "
        "VALUES (?, ?, ?, ?, ?, ?, NULL, ?, 0, ?);";
    static constexpr char kPlugSql[] =
        "INSERT INTO item_plugs (item_id, lane, plug_definition_hash) VALUES (?, ?, ?);";
    sqlite3_stmt* itemStatement = nullptr;
    sqlite3_stmt* storageStatement = nullptr;
    sqlite3_stmt* plugStatement = nullptr;
    if (sqlite3_prepare_v2(g_database, kItemSql, -1, &itemStatement, nullptr) != SQLITE_OK
        || sqlite3_prepare_v2(g_database, kStorageItemSql, -1, &storageStatement, nullptr)
               != SQLITE_OK
        || sqlite3_prepare_v2(g_database, kPlugSql, -1, &plugStatement, nullptr) != SQLITE_OK) {
        fail("seed_equipment_prepare", error_text());
        sqlite3_finalize(itemStatement);
        sqlite3_finalize(storageStatement);
        sqlite3_finalize(plugStatement);
        return false;
    }
    const std::span<const std::optional<state::account::inventory::Item>> slots(
        character.equipment.slots);
    for (std::size_t slot = 0; slot < slots.size(); ++slot) {
        const std::optional<state::account::inventory::Item>& item = slots[slot];
        if (!item.has_value()) {
            continue;
        }
        state::build_data::items::Definition definition{};
        if (!state::build_data::find_item_definition_hash(item->definitionHash, definition)) {
            fail("seed_equipment_resolve", "definition hash not in build data");
            sqlite3_finalize(itemStatement);
            sqlite3_finalize(storageStatement);
            sqlite3_finalize(plugStatement);
            return false;
        }
        std::array<char, 16> hashText{};
        std::array<char, 24> soidText{};
        format_hash(item->definitionHash, hashText);
        format_soid(item->instanceSoid, soidText);
        const bool itemOk =
            bind_text(itemStatement, 1, seed_account_id())
            && sqlite3_bind_int(itemStatement, 2, static_cast<int>(index)) == SQLITE_OK
            && bind_text(itemStatement, 3, {hashText.data(), std::strlen(hashText.data())})
            && bind_text(itemStatement, 4, {soidText.data(), std::strlen(soidText.data())})
            && sqlite3_bind_int(itemStatement, 5, item->quantity) == SQLITE_OK
            && sqlite3_bind_int(itemStatement, 6, definition.bucketId) == SQLITE_OK
            && sqlite3_bind_int(itemStatement, 7, static_cast<int>(slot)) == SQLITE_OK
            && sqlite3_bind_int(itemStatement, 8, item->level) == SQLITE_OK
            && sqlite3_bind_int(itemStatement,
                                9,
                                item->sockets.policy
                                        == state::account::inventory::SocketPolicy::authored
                                    ? 1
                                    : 0)
                   == SQLITE_OK
            && step_done(itemStatement);
        sqlite3_reset(itemStatement);
        if (!itemOk) {
            fail("seed_equipment_item", error_text());
            sqlite3_finalize(itemStatement);
            sqlite3_finalize(storageStatement);
            sqlite3_finalize(plugStatement);
            return false;
        }
        const sqlite3_int64 itemId = sqlite3_last_insert_rowid(g_database);
        for (std::size_t lane = 0; lane < item->sockets.plugCount; ++lane) {
            const std::optional<std::uint32_t>& plug = item->sockets.plugs[lane];
            std::array<char, 16> plugText{};
            if (plug.has_value()) {
                format_hash(*plug, plugText);
            }
            const bool plugOk =
                sqlite3_bind_int64(plugStatement, 1, itemId) == SQLITE_OK
                && sqlite3_bind_int(plugStatement, 2, static_cast<int>(lane)) == SQLITE_OK
                && bind_text_or_null(plugStatement,
                                     3,
                                     {plugText.data(), std::strlen(plugText.data())},
                                     plug.has_value())
                && step_done(plugStatement);
            sqlite3_reset(plugStatement);
            if (!plugOk) {
                fail("seed_plug", error_text());
                sqlite3_finalize(itemStatement);
                sqlite3_finalize(storageStatement);
                sqlite3_finalize(plugStatement);
                return false;
            }
        }
    }
    // Non-equipped storage rows seed with in_equipment=0 and no semantic equipment slot; the
    // bucket_id comes from the definition exactly like the equipped rows above.
    for (std::size_t storageIndex = 0; storageIndex < character.storageItemCount;
         ++storageIndex) {
        const state::account::inventory::Item& item = character.storageItems[storageIndex];
        state::build_data::items::Definition definition{};
        if (!state::build_data::find_item_definition_hash(item.definitionHash, definition)) {
            fail("seed_storage_resolve", "definition hash not in build data");
            sqlite3_finalize(itemStatement);
            sqlite3_finalize(storageStatement);
            sqlite3_finalize(plugStatement);
            return false;
        }
        std::array<char, 16> hashText{};
        std::array<char, 24> soidText{};
        format_hash(item.definitionHash, hashText);
        format_soid(item.instanceSoid, soidText);
        const bool storageOk =
            bind_text(storageStatement, 1, seed_account_id())
            && sqlite3_bind_int(storageStatement, 2, static_cast<int>(index)) == SQLITE_OK
            && bind_text(storageStatement, 3, {hashText.data(), std::strlen(hashText.data())})
            && bind_text(storageStatement, 4, {soidText.data(), std::strlen(soidText.data())})
            && sqlite3_bind_int(storageStatement, 5, item.quantity) == SQLITE_OK
            && sqlite3_bind_int(storageStatement, 6, definition.bucketId) == SQLITE_OK
            && sqlite3_bind_int(storageStatement, 7, item.level) == SQLITE_OK
            && sqlite3_bind_int(storageStatement,
                                8,
                                item.sockets.policy
                                        == state::account::inventory::SocketPolicy::authored
                                    ? 1
                                    : 0)
                   == SQLITE_OK
            && step_done(storageStatement);
        sqlite3_reset(storageStatement);
        if (!storageOk) {
            fail("seed_storage_item", error_text());
            sqlite3_finalize(itemStatement);
            sqlite3_finalize(storageStatement);
            sqlite3_finalize(plugStatement);
            return false;
        }
        const sqlite3_int64 itemId = sqlite3_last_insert_rowid(g_database);
        for (std::size_t lane = 0; lane < item.sockets.plugCount; ++lane) {
            const std::optional<std::uint32_t>& plug = item.sockets.plugs[lane];
            std::array<char, 16> plugText{};
            if (plug.has_value()) {
                format_hash(*plug, plugText);
            }
            const bool plugOk =
                sqlite3_bind_int64(plugStatement, 1, itemId) == SQLITE_OK
                && sqlite3_bind_int(plugStatement, 2, static_cast<int>(lane)) == SQLITE_OK
                && bind_text_or_null(plugStatement,
                                     3,
                                     {plugText.data(), std::strlen(plugText.data())},
                                     plug.has_value())
                && step_done(plugStatement);
            sqlite3_reset(plugStatement);
            if (!plugOk) {
                fail("seed_storage_plug", error_text());
                sqlite3_finalize(itemStatement);
                sqlite3_finalize(storageStatement);
                sqlite3_finalize(plugStatement);
                return false;
            }
        }
    }
    sqlite3_finalize(itemStatement);
    sqlite3_finalize(storageStatement);
    sqlite3_finalize(plugStatement);
    return true;
}

/** Seeds the profile inventory rows (account-scoped items). */
bool seed_profile_items_from(const state::AccountState& account) noexcept {
    static constexpr char kItemSql[] =
        "INSERT INTO items (account_id, character_index, definition_hash, instance_soid, "
        "quantity, bucket_id, in_equipment) VALUES (?, NULL, ?, NULL, ?, ?, 0);";
    sqlite3_stmt* statement = nullptr;
    if (sqlite3_prepare_v2(g_database, kItemSql, -1, &statement, nullptr) != SQLITE_OK) {
        fail("seed_profile_prepare", error_text());
        return false;
    }
    for (std::size_t index = 0; index < account.profileItemCount; ++index) {
        const state::account::inventory::ProfileItem& item = account.profileItems[index];
        state::build_data::items::Definition definition{};
        if (!state::build_data::find_item_definition_hash(item.definitionHash, definition)) {
            fail("seed_profile_resolve", "definition hash not in build data");
            sqlite3_finalize(statement);
            return false;
        }
        std::array<char, 16> hashText{};
        format_hash(item.definitionHash, hashText);
        const bool ok =
            bind_text(statement, 1, seed_account_id())
            && bind_text(statement, 2, {hashText.data(), std::strlen(hashText.data())})
            && sqlite3_bind_int(statement, 3, item.quantity) == SQLITE_OK
            && sqlite3_bind_int(statement, 4, definition.bucketId) == SQLITE_OK
            && step_done(statement);
        sqlite3_reset(statement);
        if (!ok) {
            fail("seed_profile_item", error_text());
            sqlite3_finalize(statement);
            return false;
        }
    }
    sqlite3_finalize(statement);
    return true;
}

/** Seeds the profile rows from the authored settings. */
bool seed_profile_items() noexcept {
    return seed_profile_items_from(core::settings::get().initialAccount);
}

/** Seeds one expanded flag bank. */
bool seed_flags(std::string_view scope, std::span<const std::uint8_t> bank) noexcept {
    static constexpr char kFlagSql[] =
        "INSERT INTO flags (account_id, scope, flag_index, value) VALUES (?, ?, ?, ?);";
    sqlite3_stmt* statement = nullptr;
    if (sqlite3_prepare_v2(g_database, kFlagSql, -1, &statement, nullptr) != SQLITE_OK) {
        fail("seed_flags_prepare", error_text());
        return false;
    }
    for (std::size_t index = 0; index < bank.size(); ++index) {
        if (bank[index] == state::unlocks::kFlagClear) {
            continue;
        }
        const bool ok =
            bind_text(statement, 1, seed_account_id()) && bind_text(statement, 2, scope)
            && sqlite3_bind_int(statement, 3, static_cast<int>(index)) == SQLITE_OK
            && sqlite3_bind_int(statement, 4, bank[index]) == SQLITE_OK && step_done(statement);
        sqlite3_reset(statement);
        if (!ok) {
            fail("seed_flags_row", error_text());
            sqlite3_finalize(statement);
            return false;
        }
    }
    sqlite3_finalize(statement);
    return true;
}

/** Seeds one expanded objective bank. */
bool seed_objectives(std::string_view scope, std::span<const std::int32_t> bank) noexcept {
    static constexpr char kObjectiveSql[] =
        "INSERT INTO objectives (account_id, scope, objective_index, value) "
        "VALUES (?, ?, ?, ?);";
    sqlite3_stmt* statement = nullptr;
    if (sqlite3_prepare_v2(g_database, kObjectiveSql, -1, &statement, nullptr) != SQLITE_OK) {
        fail("seed_objectives_prepare", error_text());
        return false;
    }
    for (std::size_t index = 0; index < bank.size(); ++index) {
        if (bank[index] == 0) {
            continue;
        }
        const bool ok =
            bind_text(statement, 1, seed_account_id()) && bind_text(statement, 2, scope)
            && sqlite3_bind_int(statement, 3, static_cast<int>(index)) == SQLITE_OK
            && sqlite3_bind_int(statement, 4, bank[index]) == SQLITE_OK && step_done(statement);
        sqlite3_reset(statement);
        if (!ok) {
            fail("seed_objectives_row", error_text());
            sqlite3_finalize(statement);
            return false;
        }
    }
    sqlite3_finalize(statement);
    return true;
}

/** Seeds the family-5 override lists. */
bool seed_family5_from(const state::Family5State& family5) noexcept {
    static constexpr char kFlagSql[] =
        "INSERT INTO family5_overrides (account_id, kind, slot, value) "
        "VALUES (?, 'flag', ?, ?);";
    static constexpr char kValueSql[] =
        "INSERT INTO family5_overrides (account_id, kind, slot, value) "
        "VALUES (?, 'value', ?, ?);";
    sqlite3_stmt* flagStatement = nullptr;
    sqlite3_stmt* valueStatement = nullptr;
    if (sqlite3_prepare_v2(g_database, kFlagSql, -1, &flagStatement, nullptr) != SQLITE_OK
        || sqlite3_prepare_v2(g_database, kValueSql, -1, &valueStatement, nullptr) != SQLITE_OK) {
        fail("seed_family5_prepare", error_text());
        sqlite3_finalize(flagStatement);
        sqlite3_finalize(valueStatement);
        return false;
    }
    for (std::size_t index = 0; index < family5.flagCount; ++index) {
        const bool ok =
            bind_text(flagStatement, 1, seed_account_id())
            && sqlite3_bind_int(flagStatement, 2, family5.flags[index].slot) == SQLITE_OK
            && sqlite3_bind_int(flagStatement, 3, family5.flags[index].value) == SQLITE_OK
            && step_done(flagStatement);
        sqlite3_reset(flagStatement);
        if (!ok) {
            fail("seed_family5_flag", error_text());
            sqlite3_finalize(flagStatement);
            sqlite3_finalize(valueStatement);
            return false;
        }
    }
    for (std::size_t index = 0; index < family5.valueCount; ++index) {
        const bool ok =
            bind_text(valueStatement, 1, seed_account_id())
            && sqlite3_bind_int(valueStatement, 2, family5.values[index].slot) == SQLITE_OK
            && sqlite3_bind_int(valueStatement, 3, family5.values[index].value) == SQLITE_OK
            && step_done(valueStatement);
        sqlite3_reset(valueStatement);
        if (!ok) {
            fail("seed_family5_value", error_text());
            sqlite3_finalize(flagStatement);
            sqlite3_finalize(valueStatement);
            return false;
        }
    }
    sqlite3_finalize(flagStatement);
    sqlite3_finalize(valueStatement);
    return true;
}

/** Seeds the family-5 lists from the authored settings. */
bool seed_family5() noexcept {
    return seed_family5_from(core::settings::get().initialFamily5);
}

/** Seeds the entitlement policy. */
bool seed_entitlements_from(const state::entitlements::Table& table) noexcept {
    static constexpr char kSql[] =
        "INSERT INTO entitlements (account_id, name, ownership) VALUES (?, ?, ?);";
    sqlite3_stmt* statement = nullptr;
    if (sqlite3_prepare_v2(g_database, kSql, -1, &statement, nullptr) != SQLITE_OK) {
        fail("seed_entitlements_prepare", error_text());
        return false;
    }
    for (const state::entitlements::Entitlement& entry : state::entitlements::used(table)) {
        const std::string_view name = state::entitlements::name_of(entry);
        const std::string_view ownership =
            entry.ownership == state::entitlements::Ownership::handle
                ? std::string_view{"handle"}
                : entry.ownership == state::entitlements::Ownership::application
                      ? std::string_view{"application"}
                      : std::string_view{"none"};
        const bool ok = bind_text(statement, 1, seed_account_id())
                        && bind_text(statement, 2, name) && bind_text(statement, 3, ownership)
                        && step_done(statement);
        sqlite3_reset(statement);
        if (!ok) {
            fail("seed_entitlements_row", error_text());
            sqlite3_finalize(statement);
            return false;
        }
    }
    sqlite3_finalize(statement);
    return true;
}

/** Seeds the entitlement policy from the authored settings. */
bool seed_entitlements() noexcept {
    return seed_entitlements_from(core::settings::get().server.entitlements);
}

/** Seeds every authored row inside one transaction. */
bool seed_from_settings() noexcept {
    if (!exec("BEGIN;")) {
        return false;
    }
    const state::AccountState& account = core::settings::get().initialAccount;
    const state::unlocks::Table& unlocks = core::settings::get().initialUnlocks;
    bool seeded =
        seed_meta_and_account() && seed_profile_items() && seed_family5() && seed_entitlements()
        && seed_flags("account", unlocks.accountFlags)
        && seed_flags("profile", unlocks.profileFlags)
        && seed_flags("character", unlocks.characterFlags)
        && seed_flags("character_object", unlocks.characterObjectFlags)
        && seed_objectives("account", unlocks.objectiveValues)
        && seed_objectives("character_object", unlocks.characterObjectValues);
    for (std::size_t index = 0; seeded && index < account.characterCount; ++index) {
        seeded = seed_character(index, account.characters[index]);
    }
    if (!seeded) {
        fail("seed", error_text());
        (void)exec("ROLLBACK;");
        return false;
    }
    if (!exec("COMMIT;")) {
        (void)exec("ROLLBACK;");
        return false;
    }
    core::log::write(core::log::Channel::state,
                     core::log::Level::info,
                     "ev=persistence stage=seed result=ok");
    return true;
}

/** @return True when the accounts table holds at least one row. */
bool account_rows_exist() noexcept {
    sqlite3_stmt* statement = nullptr;
    if (sqlite3_prepare_v2(g_database, "SELECT count(*) FROM accounts;", -1, &statement, nullptr)
        != SQLITE_OK) {
        fail("count_accounts", error_text());
        return false;
    }
    const int code = sqlite3_step(statement);
    const bool exists = code == SQLITE_ROW && sqlite3_column_int(statement, 0) > 0;
    sqlite3_finalize(statement);
    return exists;
}

/** Reads one scope's expanded flag bank back into native storage. */
bool load_flags(std::string_view scope, std::span<std::uint8_t> bank) noexcept {
    static constexpr char kSql[] =
        "SELECT flag_index, value FROM flags WHERE account_id = ? AND scope = ? "
        "ORDER BY flag_index;";
    sqlite3_stmt* statement = nullptr;
    if (sqlite3_prepare_v2(g_database, kSql, -1, &statement, nullptr) != SQLITE_OK) {
        fail("load_flags_prepare", error_text());
        return false;
    }
    std::fill(bank.begin(), bank.end(), state::unlocks::kFlagClear);
    bool ok = bind_text(statement, 1, seed_account_id()) && bind_text(statement, 2, scope);
    while (ok) {
        const int code = sqlite3_step(statement);
        if (code == SQLITE_DONE) {
            break;
        }
        if (code != SQLITE_ROW) {
            fail("load_flags_step", error_text());
            ok = false;
            break;
        }
        const int index = sqlite3_column_int(statement, 0);
        if (index < 0 || static_cast<std::size_t>(index) >= bank.size()) {
            ok = false;
            break;
        }
        bank[static_cast<std::size_t>(index)] =
            static_cast<std::uint8_t>(sqlite3_column_int(statement, 1));
    }
    sqlite3_finalize(statement);
    return ok;
}

/** Reads one scope's expanded objective bank back into native storage. */
bool load_objectives(std::string_view scope, std::span<std::int32_t> bank) noexcept {
    static constexpr char kSql[] =
        "SELECT objective_index, value FROM objectives WHERE account_id = ? AND scope = ? "
        "ORDER BY objective_index;";
    sqlite3_stmt* statement = nullptr;
    if (sqlite3_prepare_v2(g_database, kSql, -1, &statement, nullptr) != SQLITE_OK) {
        fail("load_objectives_prepare", error_text());
        return false;
    }
    std::fill(bank.begin(), bank.end(), 0);
    bool ok = bind_text(statement, 1, seed_account_id()) && bind_text(statement, 2, scope);
    while (ok) {
        const int code = sqlite3_step(statement);
        if (code == SQLITE_DONE) {
            break;
        }
        if (code != SQLITE_ROW) {
            fail("load_objectives_step", error_text());
            ok = false;
            break;
        }
        const int index = sqlite3_column_int(statement, 0);
        if (index < 0 || static_cast<std::size_t>(index) >= bank.size()) {
            ok = false;
            break;
        }
        bank[static_cast<std::size_t>(index)] = sqlite3_column_int(statement, 1);
    }
    sqlite3_finalize(statement);
    return ok;
}

/** Loads one character row's equipment items from the items and plugs tables. */
bool load_equipment(std::string_view accountId,
                    std::size_t characterIndex,
                    state::CharacterState& character) noexcept {
    static constexpr char kItemSql[] =
        "SELECT item_id, equipment_slot, instance_soid, definition_hash, instance_level, "
        "quantity, socket_policy FROM items WHERE account_id = ? AND character_index = ? "
        "AND in_equipment = 1 ORDER BY equipment_slot;";
    static constexpr char kPlugSql[] =
        "SELECT lane, plug_definition_hash FROM item_plugs WHERE item_id = ? ORDER BY lane;";
    sqlite3_stmt* itemStatement = nullptr;
    sqlite3_stmt* plugStatement = nullptr;
    if (sqlite3_prepare_v2(g_database, kItemSql, -1, &itemStatement, nullptr) != SQLITE_OK
        || sqlite3_prepare_v2(g_database, kPlugSql, -1, &plugStatement, nullptr) != SQLITE_OK) {
        fail("load_equipment_prepare", error_text());
        sqlite3_finalize(itemStatement);
        sqlite3_finalize(plugStatement);
        return false;
    }
    bool ok = bind_text(itemStatement, 1, accountId)
              && sqlite3_bind_int(itemStatement, 2, static_cast<int>(characterIndex)) == SQLITE_OK;
    while (ok) {
        const int code = sqlite3_step(itemStatement);
        if (code == SQLITE_DONE) {
            break;
        }
        if (code != SQLITE_ROW) {
            fail("load_equipment_step", error_text());
            ok = false;
            break;
        }
        const sqlite3_int64 itemId = sqlite3_column_int64(itemStatement, 0);
        const int slot = sqlite3_column_int(itemStatement, 1);
        if (slot < 0 || static_cast<std::size_t>(slot) >= character.equipment.slots.size()) {
            ok = false;
            break;
        }
        std::uint64_t soid = 0;
        std::uint64_t hash = 0;
        const auto* soidText = sqlite3_column_text(itemStatement, 2);
        const auto* hashText = sqlite3_column_text(itemStatement, 3);
        if (soidText == nullptr || hashText == nullptr
            || !parse_hex({reinterpret_cast<const char*>(soidText),
                           static_cast<std::size_t>(sqlite3_column_bytes(itemStatement, 2))},
                          soid)
            || !parse_hex({reinterpret_cast<const char*>(hashText),
                           static_cast<std::size_t>(sqlite3_column_bytes(itemStatement, 3))},
                          hash)) {
            ok = false;
            break;
        }
        state::account::inventory::Item item{};
        item.instanceSoid = soid;
        item.definitionHash = static_cast<std::uint32_t>(hash);
        item.level = sqlite3_column_int(itemStatement, 4);
        item.quantity = sqlite3_column_int(itemStatement, 5);
        item.sockets.policy = sqlite3_column_int(itemStatement, 6) != 0
                                  ? state::account::inventory::SocketPolicy::authored
                                  : state::account::inventory::SocketPolicy::nativeDefaults;
        item.sockets.plugCount = 0;
        if (sqlite3_bind_int64(plugStatement, 1, itemId) != SQLITE_OK) {
            fail("load_plugs_bind", error_text());
            ok = false;
            break;
        }
        for (;;) {
            const int plugCode = sqlite3_step(plugStatement);
            if (plugCode == SQLITE_DONE) {
                break;
            }
            if (plugCode != SQLITE_ROW) {
                fail("load_plugs_step", error_text());
                ok = false;
                break;
            }
            const int lane = sqlite3_column_int(plugStatement, 0);
            if (lane < 0 || static_cast<std::size_t>(lane) >= item.sockets.plugs.size()) {
                ok = false;
                break;
            }
            if (lane + 1 > static_cast<int>(item.sockets.plugCount)) {
                item.sockets.plugCount = static_cast<std::size_t>(lane + 1);
            }
            const auto* plugText = sqlite3_column_text(plugStatement, 1);
            if (plugText == nullptr) {
                item.sockets.plugs[static_cast<std::size_t>(lane)].reset();
            } else {
                std::uint64_t plug = 0;
                if (!parse_hex(
                        {reinterpret_cast<const char*>(plugText),
                         static_cast<std::size_t>(sqlite3_column_bytes(plugStatement, 1))},
                        plug)) {
                    ok = false;
                    break;
                }
                item.sockets.plugs[static_cast<std::size_t>(lane)] =
                    static_cast<std::uint32_t>(plug);
            }
        }
        sqlite3_reset(plugStatement);
        if (!ok) {
            break;
        }
        if (!state::account::inventory::valid(item.sockets)) {
            ok = false;
            break;
        }
        character.equipment.slots[static_cast<std::size_t>(slot)] = item;
    }
    sqlite3_finalize(itemStatement);
    sqlite3_finalize(plugStatement);
    return ok;
}

/** Loads one character row's non-equipped storage items from the items and plugs tables. */
bool load_storage(std::string_view accountId,
                  std::size_t characterIndex,
                  state::CharacterState& character) noexcept {
    static constexpr char kItemSql[] =
        "SELECT item_id, instance_soid, definition_hash, instance_level, quantity, "
        "socket_policy FROM items WHERE account_id = ? AND character_index = ? "
        "AND in_equipment = 0 ORDER BY item_id;";
    static constexpr char kPlugSql[] =
        "SELECT lane, plug_definition_hash FROM item_plugs WHERE item_id = ? ORDER BY lane;";
    sqlite3_stmt* itemStatement = nullptr;
    sqlite3_stmt* plugStatement = nullptr;
    if (sqlite3_prepare_v2(g_database, kItemSql, -1, &itemStatement, nullptr) != SQLITE_OK
        || sqlite3_prepare_v2(g_database, kPlugSql, -1, &plugStatement, nullptr) != SQLITE_OK) {
        fail("load_storage_prepare", error_text());
        sqlite3_finalize(itemStatement);
        sqlite3_finalize(plugStatement);
        return false;
    }
    bool ok = bind_text(itemStatement, 1, accountId)
              && sqlite3_bind_int(itemStatement, 2, static_cast<int>(characterIndex)) == SQLITE_OK;
    while (ok) {
        const int code = sqlite3_step(itemStatement);
        if (code == SQLITE_DONE) {
            break;
        }
        if (code != SQLITE_ROW) {
            fail("load_storage_step", error_text());
            ok = false;
            break;
        }
        if (character.storageItemCount >= character.storageItems.size()) {
            fail("load_storage_capacity", "storage item count exceeds the State ceiling");
            ok = false;
            break;
        }
        const sqlite3_int64 itemId = sqlite3_column_int64(itemStatement, 0);
        std::uint64_t soid = 0;
        std::uint64_t hash = 0;
        const auto* soidText = sqlite3_column_text(itemStatement, 1);
        const auto* hashText = sqlite3_column_text(itemStatement, 2);
        if (soidText == nullptr || hashText == nullptr
            || !parse_hex({reinterpret_cast<const char*>(soidText),
                           static_cast<std::size_t>(sqlite3_column_bytes(itemStatement, 1))},
                          soid)
            || !parse_hex({reinterpret_cast<const char*>(hashText),
                           static_cast<std::size_t>(sqlite3_column_bytes(itemStatement, 2))},
                          hash)) {
            ok = false;
            break;
        }
        state::account::inventory::Item& item = character.storageItems[character.storageItemCount];
        item.instanceSoid = soid;
        item.definitionHash = static_cast<std::uint32_t>(hash);
        item.level = sqlite3_column_int(itemStatement, 3);
        item.quantity = sqlite3_column_int(itemStatement, 4);
        item.sockets.policy = sqlite3_column_int(itemStatement, 5) != 0
                                  ? state::account::inventory::SocketPolicy::authored
                                  : state::account::inventory::SocketPolicy::nativeDefaults;
        item.sockets.plugCount = 0;
        if (sqlite3_bind_int64(plugStatement, 1, itemId) != SQLITE_OK) {
            fail("load_storage_plugs_bind", error_text());
            ok = false;
            break;
        }
        for (;;) {
            const int plugCode = sqlite3_step(plugStatement);
            if (plugCode == SQLITE_DONE) {
                break;
            }
            if (plugCode != SQLITE_ROW) {
                fail("load_storage_plugs_step", error_text());
                ok = false;
                break;
            }
            const int lane = sqlite3_column_int(plugStatement, 0);
            if (lane < 0 || static_cast<std::size_t>(lane) >= item.sockets.plugs.size()) {
                ok = false;
                break;
            }
            if (lane + 1 > static_cast<int>(item.sockets.plugCount)) {
                item.sockets.plugCount = static_cast<std::size_t>(lane + 1);
            }
            const auto* plugText = sqlite3_column_text(plugStatement, 1);
            if (plugText == nullptr) {
                item.sockets.plugs[static_cast<std::size_t>(lane)].reset();
            } else {
                std::uint64_t plug = 0;
                if (!parse_hex(
                        {reinterpret_cast<const char*>(plugText),
                         static_cast<std::size_t>(sqlite3_column_bytes(plugStatement, 1))},
                        plug)) {
                    ok = false;
                    break;
                }
                item.sockets.plugs[static_cast<std::size_t>(lane)] =
                    static_cast<std::uint32_t>(plug);
            }
        }
        sqlite3_reset(plugStatement);
        if (!ok) {
            break;
        }
        if (!state::account::inventory::valid(item.sockets)
            || !state::account::inventory::valid(item)) {
            ok = false;
            break;
        }
        ++character.storageItemCount;
    }
    sqlite3_finalize(itemStatement);
    sqlite3_finalize(plugStatement);
    return ok;
}

} // namespace

/** Opens and migrates the state database, seeding it from settings when empty. */
bool initialize(void* module) noexcept {
    AcquireSRWLockExclusive(&g_lock);
    if (g_database != nullptr) {
        ReleaseSRWLockExclusive(&g_lock);
        return true;
    }
    Buffer path;
    if (!core::path::artifact_directory(module, path) || !core::path::append(path, kDatabaseSuffix)
        || sqlite3_open16(path.chars.data(), &g_database) != SQLITE_OK) {
        fail("open", g_database != nullptr ? sqlite3_errmsg(g_database) : "path");
        if (g_database != nullptr) {
            sqlite3_close(g_database);
            g_database = nullptr;
        }
        ReleaseSRWLockExclusive(&g_lock);
        return false;
    }
    if (!exec("PRAGMA journal_mode = WAL;") || !exec("PRAGMA foreign_keys = ON;")
        || !exec("PRAGMA user_version = 1;")) {
        fail("pragma", error_text());
        close_locked();
        ReleaseSRWLockExclusive(&g_lock);
        return false;
    }
    static constexpr char kSchema[] =
        "CREATE TABLE IF NOT EXISTS meta ("
        "  key        TEXT PRIMARY KEY,"
        "  value      TEXT NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS accounts ("
        "  account_id    TEXT PRIMARY KEY,"
        "  created_at    INTEGER NOT NULL DEFAULT (unixepoch()),"
        "  last_login    INTEGER"
        ");"
        "CREATE TABLE IF NOT EXISTS characters ("
        "  account_id    TEXT NOT NULL REFERENCES accounts(account_id),"
        "  character_index INTEGER NOT NULL,"
        "  soid          TEXT NOT NULL,"
        "  char_class    INTEGER NOT NULL,"
        "  race          INTEGER NOT NULL,"
        "  gender        INTEGER NOT NULL,"
        "  level         INTEGER NOT NULL,"
        "  accepted      INTEGER NOT NULL DEFAULT 1,"
        "  preview_available INTEGER NOT NULL DEFAULT 1,"
        "  appearance_value REAL NOT NULL DEFAULT 1.0,"
        "  last_orbited_destination TEXT NOT NULL,"
        "  content_bypass INTEGER NOT NULL DEFAULT 0,"
        "  movement_ability_entry INTEGER NOT NULL DEFAULT 4,"
        "  grenade_ability_entry   INTEGER NOT NULL DEFAULT 7,"
        "  super_ability_entry     INTEGER NOT NULL DEFAULT 10,"
        "  melee_ability_entry     INTEGER NOT NULL DEFAULT 11,"
        "  class_ability_entry     INTEGER NOT NULL DEFAULT 2,"
        "  PRIMARY KEY (account_id, character_index)"
        ");"
        "CREATE TABLE IF NOT EXISTS items ("
        "  item_id       INTEGER PRIMARY KEY,"
        "  account_id    TEXT NOT NULL REFERENCES accounts(account_id),"
        "  character_index INTEGER,"
        "  definition_hash TEXT NOT NULL,"
        "  instance_soid TEXT,"
        "  quantity      INTEGER NOT NULL,"
        "  bucket_id     INTEGER NOT NULL,"
        "  equipment_slot INTEGER,"
        "  instance_level INTEGER NOT NULL DEFAULT 0,"
        "  in_equipment  INTEGER NOT NULL DEFAULT 0,"
        "  inventory_row INTEGER,"
        "  mutation_serial INTEGER NOT NULL DEFAULT 0,"
        "  flags         INTEGER NOT NULL DEFAULT 0,"
        "  socket_policy INTEGER NOT NULL DEFAULT 0,"
        "  UNIQUE (account_id, instance_soid)"
        ");"
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_items_equip_slot "
        "  ON items(account_id, character_index, equipment_slot) WHERE in_equipment = 1;"
        "CREATE INDEX IF NOT EXISTS idx_items_acct_char ON items(account_id, character_index);"
        "CREATE INDEX IF NOT EXISTS idx_items_hash ON items(definition_hash);"
        "CREATE TABLE IF NOT EXISTS item_plugs ("
        "  item_id       INTEGER NOT NULL REFERENCES items(item_id) ON DELETE CASCADE,"
        "  lane          INTEGER NOT NULL,"
        "  plug_definition_hash TEXT,"
        "  PRIMARY KEY (item_id, lane)"
        ");"
        "CREATE TABLE IF NOT EXISTS flags ("
        "  account_id    TEXT NOT NULL REFERENCES accounts(account_id),"
        "  scope         TEXT NOT NULL CHECK (scope IN ('account','profile','character','character_object')),"
        "  flag_index    INTEGER NOT NULL,"
        "  value         INTEGER NOT NULL,"
        "  PRIMARY KEY (account_id, scope, flag_index)"
        ");"
        "CREATE TABLE IF NOT EXISTS objectives ("
        "  account_id      TEXT NOT NULL REFERENCES accounts(account_id),"
        "  scope           TEXT NOT NULL CHECK (scope IN ('account','character_object')),"
        "  objective_index INTEGER NOT NULL,"
        "  value           INTEGER NOT NULL,"
        "  PRIMARY KEY (account_id, scope, objective_index)"
        ");"
        "CREATE TABLE IF NOT EXISTS family5_overrides ("
        "  account_id    TEXT NOT NULL REFERENCES accounts(account_id),"
        "  kind          TEXT NOT NULL CHECK (kind IN ('flag','value')),"
        "  slot          INTEGER NOT NULL,"
        "  value         INTEGER NOT NULL,"
        "  PRIMARY KEY (account_id, kind, slot)"
        ");"
        "CREATE TABLE IF NOT EXISTS entitlements ("
        "  account_id    TEXT NOT NULL REFERENCES accounts(account_id),"
        "  name          TEXT NOT NULL,"
        "  ownership     TEXT NOT NULL CHECK (ownership IN ('handle','application','none')),"
        "  PRIMARY KEY (account_id, name)"
        ");"
        "CREATE TABLE IF NOT EXISTS progression ("
        "  account_id        TEXT NOT NULL REFERENCES accounts(account_id),"
        "  scope             TEXT NOT NULL CHECK (scope IN ('account','character')),"
        "  character_index   INTEGER,"
        "  row_index         INTEGER NOT NULL,"
        "  definition_index  INTEGER NOT NULL,"
        "  value             INTEGER NOT NULL,"
        "  PRIMARY KEY (account_id, scope, character_index, row_index)"
        ");"
        "CREATE TABLE IF NOT EXISTS instance_state ("
        "  instance_soid         TEXT PRIMARY KEY,"
        "  base_definition_index INTEGER NOT NULL,"
        "  level                 INTEGER NOT NULL,"
        "  curve_x               INTEGER NOT NULL,"
        "  cap_row               INTEGER NOT NULL,"
        "  socket_entry_list_index INTEGER NOT NULL,"
        "  socket_entry_count    INTEGER NOT NULL,"
        "  ordinary_sockets_json TEXT,"
        "  roll_state_json       TEXT,"
        "  creation_json         TEXT,"
        "  tail_values_json      TEXT"
        ");"
        "CREATE TABLE IF NOT EXISTS vendors ("
        "  vendor_hash   TEXT PRIMARY KEY,"
        "  vendor_index  INTEGER NOT NULL,"
        "  name          TEXT,"
        "  item_list_json TEXT NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS vendor_sale_items ("
        "  vendor_hash    TEXT NOT NULL REFERENCES vendors(vendor_hash),"
        "  vendor_item_index INTEGER NOT NULL,"
        "  item_hash      TEXT NOT NULL,"
        "  quantity       INTEGER NOT NULL,"
        "  currencies_json TEXT,"
        "  action_json    TEXT,"
        "  category_index INTEGER NOT NULL,"
        "  display_category_index INTEGER NOT NULL,"
        "  minimum_level  INTEGER NOT NULL,"
        "  maximum_level  INTEGER NOT NULL,"
        "  inventory_bucket_hash INTEGER NOT NULL,"
        "  visibility_scope INTEGER NOT NULL,"
        "  purchasable_scope INTEGER NOT NULL,"
        "  socket_overrides_json TEXT,"
        "  PRIMARY KEY (vendor_hash, vendor_item_index)"
        ");";
    if (!exec(kSchema)) {
        fail("schema", error_text());
        close_locked();
        ReleaseSRWLockExclusive(&g_lock);
        return false;
    }
    if (!account_rows_exist() && !seed_from_settings()) {
        fail("seed", error_text());
        (void)sqlite3_exec(g_database, "ROLLBACK;", nullptr, nullptr, nullptr);
        close_locked();
        ReleaseSRWLockExclusive(&g_lock);
        return false;
    }
    core::log::write(core::log::Channel::state,
                     core::log::Level::info,
                     "ev=persistence stage=initialize result=ok");
    ReleaseSRWLockExclusive(&g_lock);
    return true;
}

/** Closes the state database and releases its lock. */
void shutdown() noexcept {
    AcquireSRWLockExclusive(&g_lock);
    close_locked();
    ReleaseSRWLockExclusive(&g_lock);
}

/** @return True when a state database is open and usable. */
bool ready() noexcept {
    AcquireSRWLockShared(&g_lock);
    const bool open = g_database != nullptr;
    ReleaseSRWLockShared(&g_lock);
    return open;
}

/** Reads the persisted account back into native State. */
bool load_account(state::AccountState& account,
                  state::unlocks::Table& unlocks,
                  state::Family5State& family5) noexcept {
    AcquireSRWLockExclusive(&g_lock);
    if (g_database == nullptr) {
        ReleaseSRWLockExclusive(&g_lock);
        return false;
    }
    account = {};
    unlocks = {};
    family5 = {};

    static constexpr char kAccountSql[] = "SELECT account_id FROM accounts LIMIT 1;";
    sqlite3_stmt* statement = nullptr;
    bool ok = sqlite3_prepare_v2(g_database, kAccountSql, -1, &statement, nullptr) == SQLITE_OK
              && sqlite3_step(statement) == SQLITE_ROW;
    if (ok) {
        const auto* text = sqlite3_column_text(statement, 0);
        std::uint64_t soid = 0;
        ok = text != nullptr
             && parse_hex(
                 {reinterpret_cast<const char*>(text),
                  static_cast<std::size_t>(sqlite3_column_bytes(statement, 0))},
                 soid);
        account.primarySoid = soid;
    }
    sqlite3_finalize(statement);
    if (!ok) {
        fail("load_account_id", error_text());
        ReleaseSRWLockExclusive(&g_lock);
        return false;
    }

    static constexpr char kCharacterSql[] =
        "SELECT soid, char_class, race, gender, level, accepted, preview_available, "
        "appearance_value, last_orbited_destination, content_bypass, movement_ability_entry, "
        "grenade_ability_entry, super_ability_entry, melee_ability_entry, class_ability_entry "
        "FROM characters WHERE account_id = ? ORDER BY character_index;";
    statement = nullptr;
    ok = sqlite3_prepare_v2(g_database, kCharacterSql, -1, &statement, nullptr) == SQLITE_OK
         && bind_text(statement, 1, seed_account_id());
    while (ok) {
        const int code = sqlite3_step(statement);
        if (code == SQLITE_DONE) {
            break;
        }
        if (code != SQLITE_ROW || account.characterCount >= account.characters.size()) {
            ok = code == SQLITE_ROW;
            fail("load_characters", error_text());
            break;
        }
        state::CharacterState& character = account.characters[account.characterCount];
        std::uint64_t soid = 0;
        std::uint64_t destination = 0;
        const auto* soidText = sqlite3_column_text(statement, 0);
        const auto* destinationText = sqlite3_column_text(statement, 8);
        ok = soidText != nullptr && destinationText != nullptr
             && parse_hex(
                 {reinterpret_cast<const char*>(soidText),
                  static_cast<std::size_t>(sqlite3_column_bytes(statement, 0))},
                 soid)
             && parse_hex(
                 {reinterpret_cast<const char*>(destinationText),
                  static_cast<std::size_t>(sqlite3_column_bytes(statement, 8))},
                 destination);
        if (!ok) {
            fail("load_character_hex", error_text());
            break;
        }
        character.soid = soid;
        character.characterClass = static_cast<state::CharacterClass>(sqlite3_column_int(statement, 1));
        character.race = static_cast<state::CharacterRace>(sqlite3_column_int(statement, 2));
        character.gender = static_cast<state::CharacterGender>(sqlite3_column_int(statement, 3));
        character.level = static_cast<std::uint8_t>(sqlite3_column_int(statement, 4));
        character.accepted = sqlite3_column_int(statement, 5) != 0;
        character.previewAvailable = sqlite3_column_int(statement, 6) != 0;
        character.appearanceValue = static_cast<float>(sqlite3_column_double(statement, 7));
        character.lastOrbitedDestination = static_cast<std::uint32_t>(destination);
        character.contentBypass = sqlite3_column_int(statement, 9) != 0;
        character.movementAbilityEntry = static_cast<std::uint8_t>(sqlite3_column_int(statement, 10));
        character.grenadeAbilityEntry = static_cast<std::uint8_t>(sqlite3_column_int(statement, 11));
        character.superAbilityEntry = static_cast<std::uint8_t>(sqlite3_column_int(statement, 12));
        character.meleeAbilityEntry = static_cast<std::uint8_t>(sqlite3_column_int(statement, 13));
        character.classAbilityEntry = static_cast<std::uint8_t>(sqlite3_column_int(statement, 14));
        ++account.characterCount;
    }
    sqlite3_finalize(statement);
    if (!ok) {
        ReleaseSRWLockExclusive(&g_lock);
        return false;
    }

    static constexpr char kProfileSql[] =
        "SELECT definition_hash, quantity FROM items WHERE account_id = ? "
        "AND character_index IS NULL ORDER BY item_id;";
    statement = nullptr;
    ok = sqlite3_prepare_v2(g_database, kProfileSql, -1, &statement, nullptr) == SQLITE_OK
         && bind_text(statement, 1, seed_account_id());
    while (ok) {
        const int code = sqlite3_step(statement);
        if (code == SQLITE_DONE) {
            break;
        }
        if (code != SQLITE_ROW || account.profileItemCount >= account.profileItems.size()) {
            ok = false;
            fail("load_profile_items", error_text());
            break;
        }
        std::uint64_t hash = 0;
        const auto* hashText = sqlite3_column_text(statement, 0);
        ok = hashText != nullptr
             && parse_hex(
                 {reinterpret_cast<const char*>(hashText),
                  static_cast<std::size_t>(sqlite3_column_bytes(statement, 0))},
                 hash);
        if (!ok) {
            break;
        }
        state::account::inventory::ProfileItem& item =
            account.profileItems[account.profileItemCount++];
        item.definitionHash = static_cast<std::uint32_t>(hash);
        item.quantity = sqlite3_column_int(statement, 1);
    }
    sqlite3_finalize(statement);
    if (!ok) {
        ReleaseSRWLockExclusive(&g_lock);
        return false;
    }

    for (std::size_t index = 0; ok && index < account.characterCount; ++index) {
        ok = load_equipment(seed_account_id(), index, account.characters[index])
             && load_storage(seed_account_id(), index, account.characters[index]);
    }
    if (!ok) {
        ReleaseSRWLockExclusive(&g_lock);
        return false;
    }

    // Account settings and family-5 object identity stay authored policy (spec §3.3); the
    // persisted rows cover identity, characters, items, unlocks, and overrides.
    account.settings = core::settings::get().initialAccount.settings;

    ok = load_flags("account", unlocks.accountFlags)
         && load_flags("profile", unlocks.profileFlags)
         && load_flags("character", unlocks.characterFlags)
         && load_flags("character_object", unlocks.characterObjectFlags)
         && load_objectives("account", unlocks.objectiveValues)
         && load_objectives("character_object", unlocks.characterObjectValues);
    if (!ok) {
        ReleaseSRWLockExclusive(&g_lock);
        return false;
    }

    static constexpr char kFamily5Sql[] =
        "SELECT kind, slot, value FROM family5_overrides WHERE account_id = ? "
        "ORDER BY kind, rowid;";
    statement = nullptr;
    ok = sqlite3_prepare_v2(g_database, kFamily5Sql, -1, &statement, nullptr) == SQLITE_OK
         && bind_text(statement, 1, seed_account_id());
    while (ok) {
        const int code = sqlite3_step(statement);
        if (code == SQLITE_DONE) {
            break;
        }
        if (code != SQLITE_ROW) {
            fail("load_family5_step", error_text());
            ok = false;
            break;
        }
        const auto* kind = sqlite3_column_text(statement, 0);
        if (kind == nullptr) {
            ok = false;
            break;
        }
        const bool flag = std::strcmp(reinterpret_cast<const char*>(kind), "flag") == 0;
        const int slot = sqlite3_column_int(statement, 1);
        const int value = sqlite3_column_int(statement, 2);
        if (flag) {
            if (family5.flagCount >= family5.flags.size()) {
                ok = false;
                break;
            }
            family5.flags[family5.flagCount++] = {
                static_cast<std::uint16_t>(slot), static_cast<std::uint8_t>(value)};
        } else {
            if (family5.valueCount >= family5.values.size()) {
                ok = false;
                break;
            }
            family5.values[family5.valueCount++] = {static_cast<std::uint16_t>(slot), value};
        }
    }
    sqlite3_finalize(statement);
    ReleaseSRWLockExclusive(&g_lock);
    return ok;
}

/** Reads the persisted entitlement policy back into native State. */
bool load_entitlements(state::entitlements::Table& output) noexcept {
    AcquireSRWLockExclusive(&g_lock);
    output = {};
    if (g_database == nullptr) {
        ReleaseSRWLockExclusive(&g_lock);
        return false;
    }
    // The ContentConfig entitlement handles are table POSITIONS (handle = base + index,
    // content_manifest_encoder.cpp kEntitlementsField); the seed and the write-back insert in
    // the settings (handle) order, so rowid preserves the proven handle mapping. An ASCII
    // name sort would shift the digit-named DLC ahead of the STEAM_* entries.
    static constexpr char kSql[] =
        "SELECT name, ownership FROM entitlements WHERE account_id = ? ORDER BY rowid;";
    sqlite3_stmt* statement = nullptr;
    bool ok = sqlite3_prepare_v2(g_database, kSql, -1, &statement, nullptr) == SQLITE_OK
              && bind_text(statement, 1, seed_account_id());
    while (ok) {
        const int code = sqlite3_step(statement);
        if (code == SQLITE_DONE) {
            break;
        }
        if (code != SQLITE_ROW || output.count >= output.entries.size()) {
            ok = false;
            break;
        }
        const auto* name = sqlite3_column_text(statement, 0);
        const auto* ownership = sqlite3_column_text(statement, 1);
        if (name == nullptr || ownership == nullptr) {
            ok = false;
            break;
        }
        const std::string_view nameView{
            reinterpret_cast<const char*>(name),
            static_cast<std::size_t>(sqlite3_column_bytes(statement, 0))};
        const std::string_view ownershipView{
            reinterpret_cast<const char*>(ownership),
            static_cast<std::size_t>(sqlite3_column_bytes(statement, 1))};
        state::entitlements::Entitlement& entry = output.entries[output.count];
        if (nameView.size() >= entry.name.size()) {
            ok = false;
            break;
        }
        std::copy(nameView.begin(), nameView.end(), entry.name.begin());
        entry.nameLength = static_cast<std::uint8_t>(nameView.size());
        entry.ownership = ownershipView == "handle"
                              ? state::entitlements::Ownership::handle
                              : ownershipView == "application"
                                    ? state::entitlements::Ownership::application
                                    : state::entitlements::Ownership::none;
        ++output.count;
    }
    sqlite3_finalize(statement);
    ReleaseSRWLockExclusive(&g_lock);
    return ok;
}

/** Writes the current published State back into the state database (spec §4 Stage 5). */
bool write_back() noexcept {
    AcquireSRWLockExclusive(&g_lock);
    if (g_database == nullptr) {
        ReleaseSRWLockExclusive(&g_lock);
        return false;
    }
    // The published State is the boot's source of truth: the account (identity, characters,
    // profile items), the unlock banks, the family-5 override lists, and the entitlement
    // policy. Vendors/vendor_sale_items are a content mirror (ETL-owned) and instance_state /
    // progression are derived at encode time, so none of those tables are rewritten here.
    const state::AccountState account = state::account_snapshot();
    const state::unlocks::Table& unlocks = state::unlocks::get();
    const state::Family5State family5 = state::investment_snapshot().family5;
    const state::entitlements::Table& entitlements = state::entitlements::get();
    if (account.primarySoid == 0 || !state::account::valid(account)) {
        fail("write_back", "invalid account state");
        ReleaseSRWLockExclusive(&g_lock);
        return false;
    }
    // Publish-scoped deletes (the L6 design): the publish owns every items row of the seed
    // account — equipped, profile, and (now that load_storage carries them into State) the
    // non-equipped storage rows alike. The old write_back deleted EVERY account's rows; the
    // scoped form preserves any other account's rows and re-seeds only the seed account's
    // in-memory State. item_plugs rows follow their items via the ON DELETE CASCADE foreign
    // key, so no global plug delete exists here (one would wipe storage plugs).
    std::array<char, 160> deleteItemsSql{};
    std::array<char, 160> deleteCharactersSql{};
    const std::string_view accountId = seed_account_id();
    (void)std::snprintf(deleteItemsSql.data(), deleteItemsSql.size(),
                        "DELETE FROM items WHERE account_id = '%s';", accountId.data());
    (void)std::snprintf(deleteCharactersSql.data(), deleteCharactersSql.size(),
                        "DELETE FROM characters WHERE account_id = '%s';", accountId.data());
    bool ok = exec("BEGIN;") && exec(deleteItemsSql.data()) && exec(deleteCharactersSql.data())
              && exec("DELETE FROM flags;") && exec("DELETE FROM objectives;")
              && exec("DELETE FROM family5_overrides;") && exec("DELETE FROM entitlements;")
              && seed_profile_items_from(account)
              && seed_family5_from(family5) && seed_entitlements_from(entitlements)
              && seed_flags("account", unlocks.accountFlags)
              && seed_flags("profile", unlocks.profileFlags)
              && seed_flags("character", unlocks.characterFlags)
              && seed_flags("character_object", unlocks.characterObjectFlags)
              && seed_objectives("account", unlocks.objectiveValues)
              && seed_objectives("character_object", unlocks.characterObjectValues);
    for (std::size_t index = 0; ok && index < account.characterCount; ++index) {
        ok = seed_character(index, account.characters[index]);
    }
    if (!ok) {
        fail("write_back", error_text());
        (void)exec("ROLLBACK;");
        ReleaseSRWLockExclusive(&g_lock);
        return false;
    }
    ok = exec("COMMIT;");
    if (!ok) {
        (void)exec("ROLLBACK;");
    }
    if (ok) {
        core::log::write(core::log::Channel::state,
                         core::log::Level::info,
                         "ev=persistence stage=write_back result=ok");
    }
    ReleaseSRWLockExclusive(&g_lock);
    return ok;
}

} // namespace sunrise::server::persistence
