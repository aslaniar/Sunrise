#pragma once

namespace sunrise::server::persistence {

/** Verifies the deployed cache against the reader's exact model + prints every check. */
int run_cache_check(void* module) noexcept;

} // namespace sunrise::server::persistence
