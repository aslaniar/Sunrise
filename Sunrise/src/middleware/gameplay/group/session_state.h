#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "session_messages.h"

namespace sunrise::middleware::gameplay::group {

/** Bytes of group-session state the membership hash covers, and the whole struct's size. */
inline constexpr std::size_t kSessionStateSize = 28768;

/** One replica of that state. It is large, so it belongs in static or member storage. */
using SessionState = std::array<std::byte, kSessionStateSize>;

/** First player entry in the replica (the HISTORICAL base, confirmed by arm A's 9/9
 *  acceptance and by helper B writing entry+0x108 at state+0x3c68 - see FINDINGS 20.206). */
inline constexpr std::size_t kPlayerTableOffset = 15192;
/** Bytes one player entry occupies. */
inline constexpr std::size_t kPlayerStride = 424;

/**
 * One unresolved choice in the stored profile image (RE_output/claims/
 * session-state-profile-image.md OPEN). Static analysis pinned every offset but two
 * things: whether the client's stored name words are the obfuscated wire words or the
 * deobfuscated plain ones, and where inside the tail's trailing 8 bytes its 5-bit field
 * lands. Both are enumerable, so rather than guess we build every variant and let ONE
 * boot discriminate: the client prints the hash it computed, and exactly one variant
 * reproduces it.
 */
struct ProfileVariant {
    /** True stores the obfuscated wire words; false stores the deobfuscated plain text. */
    bool nameObfuscated{};
    /** Byte offset within the tail's trailing 8 bytes for the 5-bit field's stored value,
     *  or kTailFieldAbsent to write none. */
    std::uint8_t tailFieldOffset{};
};

/** ProfileVariant::tailFieldOffset value meaning "the 5-bit field stores nowhere". */
inline constexpr std::uint8_t kTailFieldAbsent = 0xFF;

/** Tail byte positions the 5-bit field could occupy, plus the absent case. */
inline constexpr std::size_t kTailFieldPositions = 9;

/** Every variant the discriminating boot evaluates: 2 name forms x 9 tail positions. */
inline constexpr std::size_t kProfileVariantCount = 2U * kTailFieldPositions;

/** @return The variant at `index` in the canonical enumeration order. */
[[nodiscard]] ProfileVariant profile_variant(std::size_t index) noexcept;

/**
 * Everything the replica needs about the profile block the encoder is publishing.
 * `publish` false reproduces the pre-profile bytes exactly, which arm A proved correct.
 */
struct ProfileModel {
    /** True when every player row carries a profile block. */
    bool publish{};
    /** Plain name text; the player's slot digit is appended, matching the encoder. */
    std::string_view name{};
    /** Which unresolved variant to build. */
    ProfileVariant variant{};
};

/**
 * Fills a replica of the session state a peer holds after applying one complete snapshot.
 * The peer clears its member and player tables first, so every byte follows from the message.
 * @param body Snapshot the peer will apply.
 * @param output Receives the replica, fully overwritten.
 * @param clientBase See session_state_hash.
 * @param profile The profile block the encoder publishes on each player row. When it
 *                publishes one, the client stores 396 bytes of it INSIDE the hashed player
 *                entry, and the two 0xFFFFFFFF "absent" markers this model writes at +28
 *                and +264 are exactly where the region-A header and region B begin. Not
 *                modelling that is what made every profile-bearing body fail the client's
 *                checksum 1:1 into a force-disconnect (FINDINGS 20.205).
 */
void build_session_state(const MembershipUpdate& body, SessionState& output,
                         bool clientBase, const ProfileModel& profile) noexcept;

/**
 * Computes the state hash a peer will expect for one complete snapshot.
 * @param body Snapshot the peer will apply.
 * @param clientBase Hash the CLIENT's layout, not ours: the client's apply reads the
 *                   player-table header 8 bytes above our model (l9-profile-layout
 *                   ADDENDUM), and a hash over OUR base disagrees with the client's
 *                   own - observed live 2026-08-30 as membership checksum rejections
 *                   escalating to session force-disconnect at peer arrival.
 * @param profile See build_session_state.
 * @return The hash to publish in the message tail.
 */
[[nodiscard]] std::uint32_t session_state_hash(const MembershipUpdate& body,
                                               bool clientBase,
                                               const ProfileModel& profile) noexcept;

} // namespace sunrise::middleware::gameplay::group
