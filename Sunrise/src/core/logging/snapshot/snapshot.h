#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include "../log.h"

namespace sunrise::core::log::snapshot {

/**
 * Retained events: the standalone server holds a few thousand so its admin
 * event feed pages real history; the in-process DLL keeps the short window so
 * no game-thread caller ever stacks a multi-megabyte snapshot.
 */
#if defined(SUNRISE_STANDALONE_SERVER)
inline constexpr std::size_t kEntryCapacity = 4096;
#else
inline constexpr std::size_t kEntryCapacity = 128;
#endif

namespace internal {

/** Stores one already-enabled formatted event in the fixed logger ring. */
void record(Channel channel, Level level, std::string_view text) noexcept;

} // namespace internal

/** One immutable structured event copied out of the logger ring. */
class Entry final {
public:
    /** @return Channel that accepted the event. */
    [[nodiscard]] Channel channel() const noexcept;

    /** @return Severity that accepted the event. */
    [[nodiscard]] Level level() const noexcept;

    /**
     * @return Monotonic sequence assigned when the ring stored the event.
     * Sequence numbers survive ring overwrites, so a consumer cursor can
     * detect dropped events between two snapshots.
     */
    [[nodiscard]] std::uint64_t sequence() const noexcept;

    /** @return Bounded formatted event text without the sink line ending. */
    [[nodiscard]] std::string_view text() const noexcept;

private:
    friend void internal::record(Channel channel, Level level, std::string_view text) noexcept;

    Channel channel_{Channel::core};
    Level level_{Level::error};
    std::uint64_t sequence_{};
    std::array<char, kLineCapacity> text_{};
    std::size_t textLength_{};
};

/** Value-owned chronological copy of the bounded logger ring. */
class Snapshot final {
public:
    /** @return Retained entries ordered from oldest to newest. */
    [[nodiscard]] std::span<const Entry> entries() const noexcept;

    /** @return Count of older entries replaced by the fixed ring. */
    [[nodiscard]] std::uint64_t overwritten_count() const noexcept;

    /**
     * @return Oldest retained sequence, or zero while the snapshot is empty.
     * A cursor below this value has lost events to the ring.
     */
    [[nodiscard]] std::uint64_t oldest_sequence() const noexcept;

    /** @return Newest retained sequence, or zero while the snapshot is empty. */
    [[nodiscard]] std::uint64_t newest_sequence() const noexcept;

private:
    friend Snapshot take() noexcept;

    std::array<Entry, kEntryCapacity> entries_{};
    std::size_t count_{};
    std::uint64_t overwrittenCount_{};
};

/** @return A value-owned chronological copy of all retained events. */
[[nodiscard]] Snapshot take() noexcept;

} // namespace sunrise::core::log::snapshot
