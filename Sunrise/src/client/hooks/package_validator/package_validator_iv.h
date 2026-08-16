#pragma once

namespace sunrise::client::hooks::package_validator {

/**
 * Re-asserts the healthy kind0 IV bytes before the package-registration validator runs.
 * The registration path writes a wrong ("hybrid") value into the kind0 IV buffer
 * (destiny2 + 0x1F44CE0) just before the validator (destiny2 + 0x381DD0) reads it, so
 * the validator's computed hash no longer matches and it returns -87. The detour writes
 * the healthy 16 bytes at every validator entry, then passes through unchanged.
 * Attaches only while client.externalServer.enabled is true.
 * @return True when attached, or when the mode does not need the hook.
 */
[[nodiscard]] bool install() noexcept;

/** Detaches the IV re-assertion detour. */
[[nodiscard]] bool uninstall() noexcept;

/** @return True while the IV re-assertion detour is attached. */
[[nodiscard]] bool is_installed() noexcept;

} // namespace sunrise::client::hooks::package_validator
