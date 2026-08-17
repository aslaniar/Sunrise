#pragma once

#include <cstdint>

namespace sunrise::server::gameplay::group {

/**
 * Reports the activity host session already held for one region, without claiming a slot.
 * @param groupSessionId Group session the region advertises.
 * @return The host session id, or the absent id when none is held yet.
 */
[[nodiscard]] std::uint64_t held_host_session(std::uint64_t groupSessionId) noexcept;

/**
 * Fills every claimed host-session slot that has no session yet, and frees every evicted session.
 * The allocation advances the state revision, so it must never run inside a staged push. That
 * push would fail its own revision guard. Callers hold no lock.
 */
void allocate_claimed_host_sessions() noexcept;

/** Returns every held host session to State and clears the table. */
void reset_host_sessions() noexcept;

} // namespace sunrise::server::gameplay::group
