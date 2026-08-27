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

/** Members recorded against one lobby ordinal. */
inline constexpr std::size_t kMaxLobbyMembers = 4;

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
 * The claimant's xuid is recorded as a MEMBER of that ordinal, and the whole member
 * list comes back with the answer (FINDINGS 20.102): pairing alone did not put the peer
 * on the roster, because neither client ever learned a second member existed. This is how
 * each shim learns the other's xuid - over the same channel, no new transport.
 *
 * @param sequence Which lobby of the boot this is (1 = first, 2 = second, ...).
 * @param candidate The caller's own invented lobby id.
 * @param xuid The claimant, recorded as a member. Zero records nothing.
 * @param members Receives every member xuid known for @p sequence, caller's included.
 * @param memberCapacity Entries available at @p members.
 * @param memberCount Receives how many were written.
 * @return The winning lobby id for @p sequence - @p candidate when the caller won.
 */
std::uint64_t claim_lobby(std::uint64_t sequence,
                          std::uint64_t candidate,
                          std::uint64_t xuid,
                          std::uint64_t* members,
                          std::size_t memberCapacity,
                          std::size_t& memberCount) noexcept;

/** Copies the claim table as lines "sequence lobby\n". */
std::size_t lobby_snapshot(char* output, std::size_t capacity) noexcept;

}
