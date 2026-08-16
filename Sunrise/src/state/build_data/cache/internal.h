#pragma once

#include <cstdint>

#include "../definition.h"
#include "records/domains.h"

namespace sunrise::state::build_data::cache {

/** Result of opening and checking the one build-data cache file. */
enum class LoadStatus {
    missing,
    loaded,
    stale,
    invalid,
};

/** Final-name rule for one all-or-nothing cache write. */
enum class WriteDisposition {
    createOnly,
    replaceStale,
};

/**
 * Reads the build identity from this process's executable image.
 * @param configuredEquipmentHash Hash of the authored equipment and the score rules.
 * @param identity Receives the PE fields and the configured-equipment hash.
 * @return True when the main executable is a valid Windows PE image.
 */
[[nodiscard]] bool current_build_identity(std::uint64_t configuredEquipmentHash,
                                          BuildIdentity& identity) noexcept;

/**
 * Loads one exact cache file into fixed caller storage.
 * @param path Null-terminated cache path.
 * @param expectedBuild Current executable build identity.
 * @param output Fixed caller storage for all generated domains.
 * @param counts Receives every checked domain count.
 * @return Missing, loaded, stale, or invalid. Never leaves partial counts.
 */
[[nodiscard]] LoadStatus load(const wchar_t* path,
                              const BuildIdentity& expectedBuild,
                              records::MutableDomains output,
                              records::DomainCounts& counts) noexcept;

/**
 * Creates a missing cache, or replaces one marked stale, in one step.
 * @param directory Null-terminated cache directory.
 * @param path Null-terminated final cache path.
 * @param build Current executable build identity.
 * @param domains Complete mapping domains.
 * @param disposition Create only, or replace a stale cache.
 * @return True when the file is on disk under its requested final name.
 */
[[nodiscard]] bool write(const wchar_t* directory,
                         const wchar_t* path,
                         const BuildIdentity& build,
                         records::Domains domains,
                         WriteDisposition disposition) noexcept;

/**
 * Re-stamps the cache header's configured-equipment hash in place (the ts/size stay), used
 * by a persisted equipment mutation so the next boot's gate matches the post-mutation
 * account. Atomic: a same-directory temporary file plus a replace rename.
 * @param hash Configured-equipment hash of the post-mutation account.
 * @return True when the file is on disk under its final name with the new hash.
 */
[[nodiscard]] bool restamp_equipment_hash(std::uint64_t hash) noexcept;

} // namespace sunrise::state::build_data::cache
