/**
 * In-process stub for the standalone persistence surface. The client DLL (the in-process
 * server) has no state database, so the shared queuez staging's persist call resolves to a
 * no-op success here — the equip mutation still publishes its frames; nothing is persisted,
 * exactly like every other in-process mutation.
 */

#include "../server/persistence/persistence.h"

namespace sunrise::server::persistence {

/** In-process no-op: the standalone's two-row equip transaction does not exist here. */
bool persist_subclass_equip(std::uint64_t newlyEquippedSoid,
                            std::uint64_t displacedSoid,
                            core::settings::AccountKey key) noexcept {
    (void)newlyEquippedSoid;
    (void)displacedSoid;
    (void)key;
    return true;
}

/** In-process no-op: the ability picks are not persisted without a database. */
bool persist_ability_change(core::settings::AccountKey key) noexcept {
    (void)key;
    return true;
}

} // namespace sunrise::server::persistence
