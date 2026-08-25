#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace sunrise::core::settings::steam {

/** Steam persona policy allows at most 63 printable ASCII bytes. */
inline constexpr std::size_t kMaximumPersonaNameBytes = 63;
/** Fixed persona storage includes one trailing null byte. */
inline constexpr std::size_t kPersonaNameCapacity = kMaximumPersonaNameBytes + 1;
/** Comfortably longer than any published Steam API language token (e.g. "vietnamese"). */
inline constexpr std::size_t kMaximumLanguageBytes = 15;
/** Fixed language storage includes one trailing null byte. */
inline constexpr std::size_t kLanguageCapacity = kMaximumLanguageBytes + 1;

/**
 * The identity this build answered with before it became configurable. Every instance shipped
 * it, so two machines presented one Steam user; kept as the default so an unauthored file
 * reproduces the historical behaviour exactly.
 */
inline constexpr std::uint64_t kDefaultSteamId = 0x0110000130AA9EC5ULL;
/** High 32 bits of every individual-account SteamID64 (the only kind the Client presents). */
inline constexpr std::uint64_t kSteamIdIndividualPrefix = 0x0110000100000000ULL;

/** Read-only settings for the single local Steam user. */
struct User {
    /** Process-owned persona storage. Defaults to a neutral made-up name. */
    std::array<char, kPersonaNameCapacity> personaName{"Player"};
    /**
     * SteamID64 answered for GetSteamID. The Client builds its whole account identity from it,
     * so instances that must be distinct users must author distinct values here.
     */
    std::uint64_t steamId{kDefaultSteamId};
};

/** Read-only Steam compatibility settings parsed by Core. */
struct Settings {
    /** Options for the single local user exposed through Steam interfaces. */
    User user;
    /** Steam API language token answered for GetCurrentGameLanguage/GetAvailableGameLanguages. */
    std::array<char, kLanguageCapacity> language{"english"};
};

} // namespace sunrise::core::settings::steam
