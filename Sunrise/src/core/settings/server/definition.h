#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "../../../state/entitlements/definition.h"

namespace sunrise::core::settings::server {

/** The loopback port the BAP listener binds, and the relay port SignOn hands the Client. */
inline constexpr std::uint16_t kDefaultBapPort = 30974;
/** The Client rewrites every external URL onto the HTTPS default port. */
inline constexpr std::uint16_t kDefaultHttpsPort = 443;
/** A 16-byte bootstrap token is configured as exactly 32 hex characters plus a null. */
inline constexpr std::size_t kBootstrapTokenCapacity = 33;
/** The served ContentConfig id matches the Client token size: 36 bytes plus a null. */
inline constexpr std::size_t kConfigGuidCapacity = 37;
/** One configured path fits the classic MAX_PATH window. */
inline constexpr std::size_t kPathCapacity = 260;

/** Read-only Server settings. */
struct Settings {
    /** Authored ownership policy declared by SignOn and defined by the content manifest. */
    state::entitlements::Table entitlements{};
    /** BAP port. The listener binds it and SignOn publishes it. Zero is the no-relay sentinel. */
    std::uint16_t bapPort{kDefaultBapPort};
    /** HTTPS listener port. 443 is forced by the Client's scheme-preserving URL rewrite. */
    std::uint16_t httpsPort{kDefaultHttpsPort};
    /** 16 content-id bytes as uppercase or lowercase hex text. Published into State at boot. */
    std::array<char, kBootstrapTokenCapacity> bootstrapToken{"324D466958746F37416941554E34516A"};
    /** Optional served ContentConfig id. Empty serves the State fingerprint id. */
    std::array<char, kConfigGuidCapacity> configGuid{};
    /** Optional installed-packages directory. Empty resolves `<exe>\packages`. */
    std::array<wchar_t, kPathCapacity> packagesDir{};
    /** Optional build-data cache file. Empty resolves `<exe>\Sunrise\cache\build_data.bin`. */
    std::array<wchar_t, kPathCapacity> buildDataPath{};
    /** Optional decoded-content directory for the S1-3 oracle swap. Empty resolves `<exe>\content`. */
    std::array<wchar_t, kPathCapacity> contentDir{};
    /**
     * S2-0 probe switch: after the join burst, emit ONE static vendor baseline (the
     * type-7 sobject_message carrier with Commander Zavala at his Tower spot) plus a
     * patch-epoch bump. Default OFF: the schemaTagHash row is still an open R1 item
     * (s2-world-population-spec 5.3 R1; closed by the schema_capture hook's log), so
     * nothing reaches the wire unless a boot explicitly turns this on.
     */
    bool worldPopulation{false};
    /**
     * S2-0 probe knob: the sim-event type that carries the entity baseline. Default 7 =
     * _simulation_event_type_sobject_message (RESOLVED carrier, claims/sobject-carrier.md
     * -- the type-7 decoder FUN_140E739D0 gates on the 0x89-byte record with kind byte 2).
     * The carrier rides the svc-9 queue-event envelope (activity message type 17, the
     * client's FUN_1416E6ED0 case 0x11 -> FUN_1416F0F60). See activity_world_population_
     * push.cpp for the envelope constants.
     */
    std::uint32_t worldPopulationCarrier{7};
    /**
     * S2-0 probe knob: the archetype schemaTagHash the baseline names. The default
     * 0x7F6000 = bucket 1019, row 0 -- the ONLY hash with a VERIFIED bucket that lands on
     * schema node n1019's group (the combatant-baseline-shaped node of the 8
     * destination-loaded nodes; claims/schema-hash-mine.md). The ROW is closed by the
     * schema_capture hook (FUN_1404C74D0 log): the client's own player-baseline decode
     * passes the exact hash, and this knob is set to that logged value at the boot.
     */
    std::uint32_t worldPopulationSchemaHash{0x7F6000U};
};

} // namespace sunrise::core::settings::server
