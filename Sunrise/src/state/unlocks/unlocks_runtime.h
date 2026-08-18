#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

#include "definition.h"

namespace sunrise::state::unlocks {

/**
 * Publishes the immutable unlock policy for this process.
 * @param table Complete authored policy.
 */
void publish(const Table& table) noexcept;

/** @return The active unlock policy, or an empty policy when none was published. */
[[nodiscard]] const Table& get() noexcept;

/** Restores the empty unlock policy. */
void clear() noexcept;

/**
 * Sets one inclusive flag range in the active policy behind the lock — the admin
 * verb's live half (the DB write is the persistence layer's matching update; the
 * journal entry is the caller's bookkeeping). The next account encode carries the
 * new bytes.
 * @param scope One of "account", "profile", "character", "character_object".
 * @param first First flag index in the range.
 * @param last Last flag index in the range.
 * @param value The new byte (the bisection uses 0 = suppressed, 2 = restored).
 * @return True when the scope is known and the range fits its bank.
 */
[[nodiscard]] bool mutate_flags(std::string_view scope,
                                std::size_t first,
                                std::size_t last,
                                std::uint8_t value) noexcept;

} // namespace sunrise::state::unlocks
