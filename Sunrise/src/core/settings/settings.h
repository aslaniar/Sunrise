#pragma once

#include <array>
#include <string_view>

#include "../../state/account/account_state.h"
#include "../../state/activity/defaults/definition.h"
#include "../../state/investment/investment.h"
#include "../../state/unlocks/definition.h"
#include "../logging/log.h"
#include "client/definition.h"
#include "provisioning.h"
#include "server/definition.h"
#include "steam/definition.h"

namespace sunrise::core::settings {

/** One provisioned account: its authored State block plus the token that names it. */
struct ProvisionedAccount {
    /** Complete checked account, same shape and rules as the legacy initialAccount. */
    state::AccountState account{};
    /** 32 hex characters + NUL. Derives this account's wrap keys and session token. */
    std::array<char, 33> bootstrapToken{};
};

/**
 * Layout version of the settings file this build writes and expects.
 * Raise it when a key is renamed, removed, changes meaning, or must take a new default.
 * Adding a key needs no raise, because a missing key already takes its default.
 */
inline constexpr std::uint32_t kSettingsVersion = 6;

/** Parsed read-only process settings. */
struct Settings {
    /**
     * Layout version the file was written against. Zero means the key was missing, which is
     * every file written before versioning. Checked against kSettingsVersion at load.
     */
    std::uint32_t version{};
    /** Core-owned sink and channel policy. */
    log::Settings logging;
    /** Options used only by the Client layer. */
    client::Settings client;
    /** Options used only by the Server layer. */
    server::Settings server;
    /** Options used only by the Steam compatibility layer. */
    steam::Settings steam;
    /** Complete authored account State, or an empty account. */
    state::AccountState initialAccount;
    /** Small local destination fallback published when State starts. */
    state::activity::defaults::ActivityDefaults initialActivityDefaults;
    /** Authored acquired-flag and objective policy published into the account object. */
    state::unlocks::Table initialUnlocks;
    /** Authored family-5 unlock overrides. Only the two override lists are authored here. */
    state::Family5State initialFamily5;
    /**
     * Optional P2 provisioned accounts. Empty (count zero) means legacy single-account mode:
     * exactly one account built from initialAccount + server.bootstrap_token, written here at
     * parse time so every consumer reads the same normalized list. Entry 0 in explicit arrays
     * replaces the legacy block entirely.
     */
    std::array<ProvisionedAccount, kAccountCapacity> accounts{};
    std::size_t provisionedAccountCount{};
    /**
     * WHICH provisioned account THIS INSTALL plays as. Defaults to slot 0.
     *
     * The client is structurally single-account: every client-side read took
     * `kLegacyAccount` outright, so an install's identity WAS whatever sat at
     * `accounts[0]` - and both machines ship the same accounts array. Two machines with
     * distinct Steam identities and distinct bootstrap tokens therefore both published
     * `acct=0x9EAA300100100100`, and the client refused its own roster naming
     * `tried-to-join-self` (FINDINGS 20.64). The server never had this problem: it keys
     * each session off the sign-on token it matched.
     *
     * This is the install's answer to "who am I", and it must agree with the bootstrap
     * token the installed client was activated with - the rig's install carries
     * accounts[1]'s token, so the rig sets this to 1. Reordering the accounts array to
     * fake it would work and would be invisible to the next reader; this is not.
     */
    AccountKey localAccountKey{kLegacyAccount};
};

/** @return The complete default settings. */
[[nodiscard]] Settings defaults() noexcept;

/**
 * Parses supported JSON settings on top of the defaults.
 * @param json Complete settings text.
 * @param output Receives the settings only after the whole document is valid.
 * @return True when the document matches the supported settings.
 */
[[nodiscard]] bool parse(std::string_view json, Settings& output) noexcept;

/**
 * Loads the settings file next to the module when it is there.
 * @param module Loaded DLL, used to find the settings path.
 * @return True when defaults or a valid settings file are active.
 */
[[nodiscard]] bool initialize(void* module) noexcept;
/** Re-reads the settings file into the live object WITHOUT a restart (the
 *  weasel/marionberry arc's FIX B). The boot-time identity/transport fields
 *  (the bootstrap token, the bind/relay addresses, the ports, the client's
 *  external-server endpoint) are PRESERVED from the running object - they
 *  seeded state that a mid-flight swap cannot re-derive. Everything else
 *  (the gameplay flags, the client toggles) applies live. The readers are
 *  lock-free per call; a torn read during the swap is a transient wrong
 *  flag, not a crash - documented, accepted. */
[[nodiscard]] bool reload() noexcept;

/** Resets active settings to the fixed defaults. */
void shutdown() noexcept;

/** @return Active read-only Core settings. */
[[nodiscard]] const Settings& get() noexcept;

} // namespace sunrise::core::settings
