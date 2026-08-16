#pragma once

namespace sunrise::server::content {

/**
 * Applies the S1-3 Option-B oracle swap at boot.
 *
 * Runs after every State pass (each State pass runs build_data::initialize, which runs
 * cache::load). The five decoded content domains (inventoryBuckets, socketEntryLists,
 * socketEntryTables, abilityBuckets, progressions) replace the cache-loaded runtime rows
 * from the bundled s1_domains_*.json files, applying the S1RD-08 canonicalization so the
 * encode chain sees exactly the rows the cache would have produced. The other eight
 * build-data domains stay cache-driven at this step.
 *
 * The swap is unconditional: once the JSONs parse and validate, they ARE the content source
 * for these five domains, even when a content domain drifted from the cache (the swap line
 * reports the drift as result=mismatch). The one exception is the account-derived
 * abilityBuckets domain: a mismatch against the cache stops the boot with the diff recorded,
 * because force-merging rows computed for different authored characters would corrupt the
 * runtime.
 *
 * @param module Loaded module used to resolve the fallback content directory.
 * @return True when all five domains swapped. A missing or unparseable content file, a
 *         catalog rejection, or a contradictory ability-bucket domain stops the boot.
 */
[[nodiscard]] bool apply_oracle_swap(void* module) noexcept;

} // namespace sunrise::server::content
