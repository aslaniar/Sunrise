#pragma once
#include <Windows.h>
#include <array>
#include <cstdio>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace sunrise::server::http::presence {

/** One peer's presence keys, keyed by its little-endian xuid string as published. */
inline constexpr std::size_t kMaxPeers = 8;
inline constexpr std::size_t kMaxKeyBytes = 96;
inline constexpr std::size_t kMaxValueBytes = 160;

struct Entry {
    std::uint64_t xuid{};
    char key[kMaxKeyBytes]{};
    char value[kMaxValueBytes]{};
};

/** Stores one key for one xuid. Overwrites same key. @return True when stored. */
bool store(std::uint64_t xuid, std::string_view key, std::string_view value) noexcept;

/** Copies every stored entry flattened as lines "xuid key value\n" into output. */
std::size_t snapshot(char* output, std::size_t capacity) noexcept;

/** Distinct lobby ordinals two clients can pair on in one boot. */
inline constexpr std::size_t kMaxLobbySlots = 8;

/**
 * FIRST-WRITER-WINS claim on one lobby ordinal (FINDINGS 20.101).
 *
 * Both clients create their Nth Steam lobby at roughly the same moment, and each invents
 * its own id, so their managed sessions can never share members. This is the atomic pairing
 * point: the first machine to claim ordinal @p sequence keeps its own id, and every later
 * claimant is told THAT id instead of its own. Doing the compare-and-set on the server is
 * what makes it race-free - a read-then-write from each client would let both see an empty
 * slot and both go on to host.
 *
 * @param sequence Which lobby of the boot this is (1 = first, 2 = second, ...).
 * @param candidate The caller's own invented lobby id.
 * @return The winning lobby id for @p sequence - @p candidate when the caller won.
 */
std::uint64_t claim_lobby(std::uint64_t sequence, std::uint64_t candidate) noexcept;

/** Copies the claim table as lines "sequence lobby\n". */
std::size_t lobby_snapshot(char* output, std::size_t capacity) noexcept;

}
