#pragma once

#include <cstdint>

#include "../../../../middleware/queuez/queuez_update.h"
#include "../../../../middleware/queuez/subscription.h"
#include "definition.h"

namespace sunrise::server::bap::encrypted::queuez {

/** @return True when one peer queuez state is canonical for the implemented versions. */
[[nodiscard]] bool valid(const SessionState& state) noexcept;

/**
 * Stages publication of one whole Family-4 snapshot.
 * @param before Current queuez state owned by the peer.
 * @param family Prepared Family-4 snapshot whose object payloads stay borrowed.
 * @param after Gets the state published once the snapshot frame is copied.
 * @return True for a first snapshot or an identical version-zero replay.
 */
[[nodiscard]] bool stage_family4_snapshot(const SessionState& before,
                                          const middleware::queuez::Family& family,
                                          SessionState& after) noexcept;

/**
 * Decides whether one family-zero subscription publishes, and as which kind of frame.
 * A repeat naming the character the pair already holds reports no publish and no version bump.
 * Both callers send anyway, so the answer is which frame to build, not whether to answer.
 * @param before Current queuez state owned by the peer.
 * @param selectedCharacter Character the family-zero pair names now.
 * @param publish Gets whether a frame is needed.
 * @param incremental Gets whether that frame is an incremental, not a full snapshot.
 * @param after Gets the state published after the whole response transaction.
 * @return True when the request is canonical for the current state.
 */
[[nodiscard]] bool stage_family0_subscription(const SessionState& before,
                                              std::uint64_t selectedCharacter,
                                              bool& publish,
                                              bool& incremental,
                                              SessionState& after) noexcept;

/**
 * Decides whether one validated Family-3 subscription publishes a snapshot.
 * @param before Current queuez state owned by the peer.
 * @param publish Gets whether a svc-123 frame is needed.
 * @param after Gets the state published after the whole response transaction.
 * @return True when the selector belongs to the active post-change root, where that is needed.
 */
[[nodiscard]] bool stage_family3_subscription(const SessionState& before,
                                              const middleware::queuez::Subscription& subscription,
                                              bool& publish,
                                              SessionState& after) noexcept;

/**
 * Stages the Family-0 refresh a subclass equip owes: the banner record re-encodes from the
 * mutated account even though the character key did not move, so the same-key pair goes out
 * as one increment above the peer's current family-zero version.
 * @param before Current queuez state owned by the peer.
 * @param characterSoid Resident character whose record changed.
 * @param after Gets the state published after the refresh frame is copied.
 * @return True only when the family-zero pair is active and names that character.
 */
[[nodiscard]] bool stage_family0_refresh(const SessionState& before,
                                         std::uint64_t characterSoid,
                                         SessionState& after) noexcept;

/**
 * Stages one in-place Family-3 character refresh and its optional account roster upsert —
 * the fork's shape: the family-three record is a separate copy of the appearance, so the
 * equipment mutation owes it one increment above the peer's family-three version.
 * @param before Current queuez state owned by the peer.
 * @param characterSoid Resident character whose family-three record changed.
 * @param includeRoster True when the roster's slot definitions changed too (the equip moves).
 * @param refresh Gets the staged after-image.
 * @return True only when the family-three store is active and names that root.
 */
[[nodiscard]] bool stage_roster_appearance_refresh(const SessionState& before,
                                                   std::uint64_t characterSoid,
                                                   bool includeRoster,
                                                   RosterAppearanceRefresh& refresh) noexcept;

/**
 * Stages the fixed first opcode-505 transition for one peer.
 * @param before Current queuez state owned by the peer.
 * @param change Gets the version-one after-image and the account definition.
 * @return True only when a version-zero Family-4 manifest is in place.
 */
[[nodiscard]] bool stage_change_character(const SessionState& before,
                                          ChangeCharacter& change) noexcept;

/**
 * Stages the Family-4 increment that moves the character object to the picked character.
 * @param before Current queuez state owned by the peer.
 * @param selectedCharacterSoid Character key the ws-504 request named.
 * @param select Gets the after-image, both object definitions and both character keys.
 * @return True only when an existing manifest names a different resident character.
 */
[[nodiscard]] bool stage_select_character(const SessionState& before,
                                          std::uint64_t selectedCharacterSoid,
                                          SelectCharacter& select) noexcept;

/** Clears state for the active root. Zero or another root leaves the state unchanged. */
void stage_unsubscription(const SessionState& before,
                          std::uint64_t familyRootSoid,
                          SessionState& after) noexcept;

/**
 * Stages the Family-4 increment that republishes the resident character object after a
 * subclass equip. The character object is the only thing that changed; both subclass
 * instances are already resident under their own keys.
 * @param before Current queuez state owned by the peer.
 * @param itemSoid Instance key the opcode-403 request named.
 * @param equip Gets the after-image and the resident character keys.
 * @return True only when a resident character object exists to update.
 */
[[nodiscard]] bool stage_subclass_equip(const SessionState& before,
                                        std::uint64_t itemSoid,
                                        SubclassEquip& equip) noexcept;

/**
 * Stages the opcode-2100 ability change. The family-zero banner record is the only object
 * that moves (the ability buckets live there); the Family-4 version still bumps so the
 * correlated reply carries a fresh peer version.
 * @param before Current queuez state owned by the peer.
 * @param definitionHash Ability definition hash the opcode-2100 request named.
 * @param change Gets the after-image and the resident character keys.
 * @return True only when a resident character object exists to refresh.
 */
[[nodiscard]] bool stage_ability_change(const SessionState& before,
                                        std::uint32_t definitionHash,
                                        AbilityChange& change) noexcept;

/**
 * Stages the opcode-801 subclass selection's after-image. The mutation is State-side; the
 * queuez side only bumps the Family-4 version for the correlated reply and names the resident
 * character whose banner record refreshes.
 * @param before Current queuez state owned by the peer.
 * @param mutation Prepared State mutation the outcome staging commits.
 * @param selection Gets the after-image and the resident character keys.
 * @return True only when a resident character object exists to refresh.
 */
[[nodiscard]] bool stage_subclass_selection(const SessionState& before,
                                            const state::PendingSubclassSelection& mutation,
                                            SubclassSelection& selection) noexcept;

} // namespace sunrise::server::bap::encrypted::queuez
