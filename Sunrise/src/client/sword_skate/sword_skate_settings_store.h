#pragma once

#include <cstdint>

namespace sunrise::client::sword_skate {

/** No key is bound until one is picked, so a fresh install cannot change movement by accident. */
inline constexpr std::uint32_t kNoKey = 0;
/** Space is the stock jump binding, and the one this feature has to watch to do anything. */
inline constexpr std::uint32_t kDefaultJumpKey = 0x20;

/** Runtime sword-skate configuration. This module owns it; Core settings do not carry it. */
struct Settings {
    bool enabled{false};
    /** The player's jump key. The refusal is only cleared on the tick this key goes down. */
    std::uint32_t jumpKey{kDefaultJumpKey};
};

/**
 * Resolves the configuration file and loads it when one exists.
 * @param module Loaded DLL used to resolve the owned artifact directory.
 */
void initialize(void* module) noexcept;

/** Drops the runtime configuration and the resolved file path. */
void shutdown() noexcept;

/** @return One lock-consistent copy of the current configuration. */
[[nodiscard]] Settings get() noexcept;

/**
 * Publishes one configuration and writes it straight to disk.
 * @param settings Candidate configuration, refused when a field is out of range.
 * @return True when the value was published. A failed write is logged, not returned.
 */
bool publish(const Settings& settings) noexcept;

} // namespace sunrise::client::sword_skate
