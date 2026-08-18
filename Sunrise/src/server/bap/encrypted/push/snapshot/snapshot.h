#pragma once

#include <array>
#include <cstddef>

#include "../../../../../middleware/datagen/family4/loadout/definition.h"
#include "../../../../../middleware/queuez/queuez_update.h"
#include "../../../../../middleware/queuez/subscription.h"
#include "../../../../../state/account/account_state.h"
#include "../../internal.h"

namespace sunrise::server::bap::encrypted::push::snapshot {

/** Account and selected-character identity take the first two family-four descriptors. */
inline constexpr std::size_t kFamily4IdentityObjectCount = 2;
/**
 * Family four carries both identity objects plus one item record per resolved item, for every
 * character (equipped items and non-equipped storage rows alike). The equip-summary reader
 * looks up an instance with no null check, so no character in the roster may point at a record
 * this snapshot leaves out.
 */
inline constexpr std::size_t kObjectCapacity =
    kFamily4IdentityObjectCount
    + state::kCharacterCapacity * middleware::datagen::family4::loadout::kItemCapacity;

/** Prepared descriptors and scratch extents owned until the update codec copies their bodies. */
struct Prepared {
    std::array<middleware::queuez::Object, kObjectCapacity> objects{};
    middleware::queuez::Family family{};
    std::size_t rawClearSize{};
    std::size_t compressedClearSize{};

    // Default copying would leave family.objects pointing into the source descriptor array.
    Prepared() noexcept = default;
    Prepared(const Prepared&) = delete;
    Prepared& operator=(const Prepared&) = delete;
    Prepared(Prepared&&) = delete;
    Prepared& operator=(Prepared&&) = delete;
};

/**
 * Builds one initial family snapshot from State and build mappings.
 * @param scratch Object and compression storage owned by the lock.
 * @param subscription Family id the Client picked.
 * @param prepared Gets the object descriptors and scratch clear extents.
 * @return True when the asked-for snapshot is valid for the current State and mappings.
 */
[[nodiscard]] bool prepare_initial(Scratch& scratch,
                                   const middleware::queuez::Subscription& subscription,
                                   Prepared& prepared) noexcept;

/**
 * Builds the family-zero banner anchor and the record for the character it names.
 * @param scratch Raw object storage owned by the lock.
 * @param familyRootSoid Root the Client subscribed for the roster.
 * @param version Family version this frame carries.
 * @param previousCharacter Character whose record this frame releases, or zero for the full
 *        snapshot. Nonzero also clears the full-snapshot flag, which retail sets once.
 * @param prepared Gets the descriptors and the scratch clear extent.
 * @return True when a character is selected and every object fits raw storage.
 */
[[nodiscard]] bool prepare_banner(Scratch& scratch,
                                  std::uint64_t familyRootSoid,
                                  std::int32_t version,
                                  std::uint64_t previousCharacter,
                                  Prepared& prepared) noexcept;

/**
 * Builds the family-zero in-place character-record upsert a subclass mutation owes: the
 * resident record's new body at the same key (no release, no anchor, flags 0) — the fork's
 * shape, which refreshes the appearance without tearing down the ship/banner binding.
 */
[[nodiscard]] bool prepare_banner_refresh(Scratch& scratch,
                                          std::uint64_t familyRootSoid,
                                          std::int32_t version,
                                          std::uint64_t characterSoid,
                                          Prepared& prepared) noexcept;

/**
 * Builds one incremental Family-3 character record and its optional changed account roster
 * (the fork's shape — the roster-side appearance copy an equipment mutation owes).
 * @param scratch Object and compression storage owned by the lock.
 * @param refresh Staged family-three after-image and the character key.
 * @param afterCharacter The character's committed after-image.
 * @param characterIndex The character's row in the account.
 * @param prepared Gets the character (+ optional roster) upsert descriptors.
 * @return True when State, mappings, layouts and the installed compression all fit.
 */
[[nodiscard]] bool prepare_roster_appearance_refresh(Scratch& scratch,
                                                     const queuez::RosterAppearanceRefresh& refresh,
                                                     const state::CharacterState& afterCharacter,
                                                     std::size_t characterIndex,
                                                     Prepared& prepared) noexcept;

} // namespace sunrise::server::bap::encrypted::push::snapshot
