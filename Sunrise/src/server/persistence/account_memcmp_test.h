#pragma once

namespace sunrise::server::persistence {

/**
 * Runs the S1 acceptance harness: encode the settings-authored account (when the deployed
 * settings carry a complete account), seed the sqlite state database from the same settings,
 * load the account back, re-encode, and compare the two 96,280-byte native account objects
 * byte-for-byte; compare the family-5 override frame (163 bytes) between the settings, the
 * database rows, and the published State; and encode the selected character's 46,928-byte
 * object from the database account (the summary_matches_loadout gate).
 * @param module Loaded module used to resolve the artifact directory.
 * @return Zero when every active comparison is equal and every DB-driven encode succeeds.
 */
[[nodiscard]] int run_account_memcmp_test(void* module) noexcept;

} // namespace sunrise::server::persistence
