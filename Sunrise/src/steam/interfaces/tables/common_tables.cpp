#include "internal.h"
#include "logged_empty.h"

namespace sunrise::steam::interfaces::tables {
namespace {

/** STEAMAPPS_INTERFACE_VERSION008 has 30 vtable slots. */
constexpr std::size_t kAppsMethodCount = 30;
/** SteamInput001 has 35 vtable slots. */
constexpr std::size_t kInputMethodCount = 35;
/** SteamUtils009 has 34 vtable slots. */
constexpr std::size_t kUtilsMethodCount = 34;
/**
 * The friends table must span what the CLIENT CALLS, not what SteamFriends017 declares.
 * The vtable audit (steamfriends-vtable-audit.md, 20.97) measured destiny2 issuing
 * friends-interface calls at offsets up to 0x690 = slot 210; an 80-slot table ends at
 * offset 0x278, so every call past it read whatever global followed the array. 256 slots
 * cover the audit with margin, and every unimplemented one is logged_empty - so a call we
 * did not expect NAMES ITSELF in the log instead of jumping into a neighbour (20.99).
 */
constexpr std::size_t kFriendsMethodCount = 256;
/** SteamUser020 has 31 vtable slots. */
constexpr std::size_t kUserMethodCount = 31;
/** STEAMUSERSTATS_INTERFACE_VERSION011 has 48 vtable slots. */
constexpr std::size_t kUserStatsMethodCount = 48;

/** Slots used from STEAMAPPS_INTERFACE_VERSION008. */
enum class AppsSlot : std::size_t {
    subscribed = 0,
    currentLanguage = 4,
    availableLanguages = 5,
    subscribedApp = 6,
    dlcInstalled = 7,
    dlcCount = 10,
    dlcData = 11,
    betaName = 15,
    installDir = 18,
    installed = 19,
    launchQueryParam = 21,
    buildId = 23,
};

/** Slots used from SteamInput001. */
enum class InputSlot : std::size_t {
    initialize = 0,
    shutdown = 1,
    actionSetHandle = 4,
    digitalActionHandle = 11,
    digitalActionData = 12,
    analogActionHandle = 14,
    analogActionData = 15,
    motionData = 20,
};

/** Slots used from SteamUtils009. */
enum class UtilsSlot : std::size_t {
    universe = 2,
    country = 4,
    appId = 9,
    ipv6Connectivity = 31,
    filterText = 32,
};

/** Slots used from SteamFriends017. */
enum class FriendsSlot : std::size_t {
    personaName = 0,
    overlayNeedsPresent = 49,
    richPresence = 64,
    inviteRichPresence = 65,
};

/** Slots used from SteamUser020. */
enum class UserSlot : std::size_t {
    handle = 0,
    loggedOn = 1,
    steamId = 2,
    requestEncryptedAppTicket = 20,
    getEncryptedAppTicket = 21,
};

/** Slots used from STEAMUSERSTATS_INTERFACE_VERSION011. */
enum class UserStatsSlot : std::size_t {
    requestCurrent = 0,
    achievement = 6,
    setAchievement = 7,
    store = 10,
};

std::array<FARPROC, kAppsMethodCount> g_appsMethods{};
std::array<FARPROC, kInputMethodCount> g_inputMethods{};
std::array<FARPROC, kUtilsMethodCount> g_utilsMethods{};
std::array<FARPROC, kFriendsMethodCount> g_friendsMethods{};
std::array<FARPROC, kUserMethodCount> g_userMethods{};
std::array<FARPROC, kUserStatsMethodCount> g_userStatsMethods{};
InterfaceObject g_apps{g_appsMethods.data()};
InterfaceObject g_input{g_inputMethods.data()};
InterfaceObject g_utils{g_utilsMethods.data()};
InterfaceObject g_friends{g_friendsMethods.data()};
InterfaceObject g_user{g_userMethods.data()};
InterfaceObject g_userStats{g_userStatsMethods.data()};

} // namespace

/** Sets up the common interface tables and fills the slots they use. */
void initialize_common() noexcept {
    fill_empty(g_appsMethods);
    fill_empty(g_inputMethods);
    fill_empty(g_utilsMethods);
    // INSTRUMENT (FINDINGS 20.42): the friends table is where invite/presence questions
    // would land, and its unimplemented slots must name themselves instead of vanishing.
    fill_logged_empty<kFriendsMethodCount, 0>(g_friendsMethods);
    fill_empty(g_userMethods);
    fill_empty(g_userStatsMethods);

    set_method(g_appsMethods[index(AppsSlot::subscribed)], &methods::return_true);
    set_method(g_appsMethods[index(AppsSlot::currentLanguage)], &methods::language);
    set_method(g_appsMethods[index(AppsSlot::availableLanguages)], &methods::language);
    set_method(g_appsMethods[index(AppsSlot::subscribedApp)], &methods::return_true);
    set_method(g_appsMethods[index(AppsSlot::dlcInstalled)], &methods::dlc_installed);
    set_method(g_appsMethods[index(AppsSlot::dlcCount)], &methods::get_dlc_count);
    set_method(g_appsMethods[index(AppsSlot::dlcData)], &methods::get_dlc_data);
    set_method(g_appsMethods[index(AppsSlot::betaName)], &methods::current_beta_name);
    set_method(g_appsMethods[index(AppsSlot::installDir)], &methods::app_install_dir);
    set_method(g_appsMethods[index(AppsSlot::installed)], &methods::app_is_installed);
    set_method(g_appsMethods[index(AppsSlot::launchQueryParam)], &methods::launch_query_param);
    set_method(g_appsMethods[index(AppsSlot::buildId)], &methods::app_build_id);

    set_method(g_inputMethods[index(InputSlot::initialize)], &methods::return_true);
    set_method(g_inputMethods[index(InputSlot::shutdown)], &methods::return_true);
    set_method(g_inputMethods[index(InputSlot::actionSetHandle)], &methods::input_handle);
    set_method(g_inputMethods[index(InputSlot::digitalActionHandle)], &methods::input_handle);
    set_method(g_inputMethods[index(InputSlot::digitalActionData)], &methods::input_digital_data);
    set_method(g_inputMethods[index(InputSlot::analogActionHandle)], &methods::input_handle);
    set_method(g_inputMethods[index(InputSlot::analogActionData)], &methods::input_analog_data);
    set_method(g_inputMethods[index(InputSlot::motionData)], &methods::input_motion_data);

    set_method(g_utilsMethods[index(UtilsSlot::universe)], &methods::connected_universe);
    set_method(g_utilsMethods[index(UtilsSlot::country)], &methods::country);
    set_method(g_utilsMethods[index(UtilsSlot::appId)], &methods::get_app_id);
    set_method(g_utilsMethods[index(UtilsSlot::ipv6Connectivity)], &methods::return_true);
    set_method(g_utilsMethods[index(UtilsSlot::filterText)], &methods::filter_text);

    set_method(g_friendsMethods[index(FriendsSlot::personaName)], &methods::persona_name);
    set_method(g_friendsMethods[index(FriendsSlot::overlayNeedsPresent)], &methods::return_true);
    /*
     * FRIENDS BINDINGS ARE NOW MEASURED, NOT DERIVED (20.99 / p2(66)).
     *
     * p2(64) bound eight slots from sdk isteamfriends.h. Five of them (2, 6, 36, 41, 46)
     * have NEVER been observed being called, and the binding moved SetRichPresence off
     * slot 64 - the one slot with direct runtime evidence, seen at t=2662 on every boot -
     * onto 41, where the publish would simply have been dropped.
     *
     * The complete runtime record, from logged_empty across every capture we hold:
     *     slot 3   seen 25x  (Tower era)
     *     slot 5   seen 51x  (Tower era)
     *     slot 43  seen 51x  (Tower era)
     *     slot 64  seen  1x  (t=2662, early boot - the '/connect:' publish)
     * Nothing else, ever. What 3/5/43 actually ARE is still unknown: p2(62) assigned them
     * count/by_index/persona_state and froze pre-title, and that freeze was never isolated
     * from its other two bindings (44, 65). Guessing again is the DO-NOT.
     *
     * p2(66) bound slot 64 to set_rich_presence to test that reading. THE BOOT REFUTED IT
     * (20.101): the argument guard fired on BOTH machines with non-string arguments that
     * differ per machine (mac 1/0x114, rig 1/0x7FFFFFFFFFFFFFFC), so slot 64 takes numbers,
     * not a key/value pair. NOTHING on this interface is bound now, and the friends
     * rich-presence lane is closed. The join target is a STEAM LOBBY ID - see
     * methods/matchmaking.cpp.
     */

    set_method(g_userMethods[index(UserSlot::handle)], &methods::get_user_handle);
    set_method(g_userMethods[index(UserSlot::loggedOn)], &methods::return_true);
    set_method(g_userMethods[index(UserSlot::steamId)], &methods::get_steam_id);
    set_method(g_userMethods[index(UserSlot::requestEncryptedAppTicket)],
               &methods::request_encrypted_app_ticket);
    set_method(g_userMethods[index(UserSlot::getEncryptedAppTicket)],
               &methods::get_encrypted_app_ticket);

    set_method(g_userStatsMethods[index(UserStatsSlot::requestCurrent)],
               &methods::request_current_stats);
    set_method(g_userStatsMethods[index(UserStatsSlot::achievement)], &methods::get_achievement);
    set_method(g_userStatsMethods[index(UserStatsSlot::setAchievement)], &methods::return_true);
    set_method(g_userStatsMethods[index(UserStatsSlot::store)], &methods::return_true);
}

/** @return The apps interface. */
void* apps() noexcept {
    return &g_apps;
}
/** @return The input interface. */
void* input() noexcept {
    return &g_input;
}
/** @return The utils interface. */
void* utils() noexcept {
    return &g_utils;
}
/** @return The friends interface. */
void* friends() noexcept {
    return &g_friends;
}
/** @return The user interface. */
void* user() noexcept {
    return &g_user;
}
/** @return The user stats interface. */
void* user_stats() noexcept {
    return &g_userStats;
}

} // namespace sunrise::steam::interfaces::tables
