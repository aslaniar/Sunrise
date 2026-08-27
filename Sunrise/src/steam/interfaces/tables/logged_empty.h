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
/**
 * Per-slot call counters. Sized for the WIDEST shimmed table, not the widest interface we
 * think exists: the friends table spans 256 slots because destiny2 calls friends offsets up
 * to 0x690 (slot 210) - see steamfriends-vtable-audit.md.
 */
template <std::size_t TableId> inline std::array<std::uint32_t, 256> g_loggedEmptyCalls{};

/**
 * The logged stand-in for one unimplemented slot. Returns zero like methods::empty, and
 * names the table, the slot, AND ITS FIRST FOUR ARGUMENTS on the first calls.
 *
 * WHY THE ARGUMENTS (FINDINGS 20.101 -> 20.102): the friends census told us destiny2 calls
 * slots 3, 5 and 43 - and then we could go no further, because knowing a slot is called
 * says nothing about what it wants. Identifying those three would have cost a whole extra
 * boot purely to add argument logging. Capturing them here means EVERY boot returns call
 * shapes, not just call names, for every unimplemented slot of every instrumented table.
 * That is the difference between a boot that answers one question and a boot that returns
 * a map.
 *
 * READING THE ARGUMENTS: this is the x64 convention, so rcx/rdx/r8/r9 carry `self` plus
 * the first three arguments. Declaring four parameters is safe for slots that take fewer:
 * the registers exist either way, so a short call logs whatever was already in them - junk
 * values, never a fault. Judge an argument by whether it is STABLE across calls and
 * PLAUSIBLE as its supposed type; a value that differs per machine is data, one that does
 * not is probably an index or a flag. Values also repeat: a CSteamID appears as a big
 * 0x0110.. or 0x0109.. constant, a small integer is an index or enum, and a pointer is a
 * large aligned address that VirtualQuery would confirm.
 */
template <std::size_t TableId, std::size_t Slot>
ULONG_PTR empty_logged([[maybe_unused]] void* self,
                       std::uint64_t argument1,
                       std::uint64_t argument2,
                       std::uint64_t argument3) noexcept {
    std::uint32_t& seen = g_loggedEmptyCalls<TableId>[Slot];
    if (seen < kLoggedEmptyReports) {
        ++seen;
        std::array<char, 192> line{};
        const int written = std::snprintf(
            line.data(),
            line.size(),
            "ev=steamnet stage=stub table=%zu slot=%zu seen=%u "
            "a1=0x%016llX a2=0x%016llX a3=0x%016llX",
            TableId,
            Slot,
            seen,
            static_cast<unsigned long long>(argument1),
            static_cast<unsigned long long>(argument2),
            static_cast<unsigned long long>(argument3));
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
