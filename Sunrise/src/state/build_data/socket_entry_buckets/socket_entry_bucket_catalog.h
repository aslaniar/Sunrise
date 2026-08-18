#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "definition.h"

namespace sunrise::state::build_data::socket_entry_buckets {

/** Clears every resolved entry-bucket row under the catalog lock. */
void clear() noexcept;

/** Checks that no two rows name the same socket-entry list. */
[[nodiscard]] bool valid(std::span<const Definition> definitions) noexcept;

/** Replaces the resolved entry-bucket rows in one step. */
[[nodiscard]] bool replace(std::span<const Definition> definitions) noexcept;

/** Finds one socket-entry list's resolved per-entry ability-bucket destinations. */
[[nodiscard]] bool find(std::uint16_t socketEntryListIndex, Definition& definition) noexcept;

/** @return Number of resolved entry-bucket rows, read under the lock. */
[[nodiscard]] std::size_t count() noexcept;

} // namespace sunrise::state::build_data::socket_entry_buckets
