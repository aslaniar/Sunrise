#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <utility>

#include "../../../core/logging/log.h"
#include "internal.h"

namespace sunrise::steam::interfaces::tables {

/**
 * INSTRUMENT (FINDINGS 20.42): names every vtable slot the Client calls that this shim does
 * not implement.
 *
 * The serialized-networking trace showed the peer-contact attempt never reaches that table,
 * and the descriptor names a Steam lobby - so the signalling surface may be the lobby or
 * friends tables, whose unimplemented slots currently vanish into a silent shared stub.
 * These thunks answer WHICH slot was asked, rate-limited to the first calls per slot so a
 * polled getter cannot flood the record. Strip with the rest of the instruments once the
 * peer link forms.
 */

/** Times each slot's line is emitted before going quiet. */
inline constexpr std::uint32_t kLoggedEmptyReports = 3;

/** Per-slot call counters, one array per instrumented table. */
template <std::size_t TableId> inline std::array<std::uint32_t, 128> g_loggedEmptyCalls{};

/**
 * The logged stand-in for one unimplemented slot. Mirrors methods::empty exactly - same
 * shape, returns zero - plus one line naming the table and slot on the first calls.
 */
template <std::size_t TableId, std::size_t Slot>
ULONG_PTR empty_logged([[maybe_unused]] void* self) noexcept {
    std::uint32_t& seen = g_loggedEmptyCalls<TableId>[Slot];
    if (seen < kLoggedEmptyReports) {
        ++seen;
        std::array<char, 96> line{};
        const int written = std::snprintf(line.data(),
                                          line.size(),
                                          "ev=steamnet stage=stub table=%zu slot=%zu seen=%u",
                                          TableId,
                                          Slot,
                                          seen);
        if (written > 0) {
            core::log::write(core::log::Channel::client,
                             core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(written)});
        }
    }
    return 0;
}

/** Fills every vtable slot with its per-slot logged do-nothing method. */
template <std::size_t Count, std::size_t TableId>
void fill_logged_empty(std::array<FARPROC, Count>& table) noexcept {
    [&]<std::size_t... Indexes>(std::index_sequence<Indexes...>) {
        ((table[Indexes] = reinterpret_cast<FARPROC>(&empty_logged<TableId, Indexes>)), ...);
    }
    (std::make_index_sequence<Count>{});
}

} // namespace sunrise::steam::interfaces::tables
