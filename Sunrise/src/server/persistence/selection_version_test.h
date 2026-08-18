#pragma once

namespace sunrise::server::persistence {

/** Runs the family-4 version-discipline test: the subscription replay, two opcode-801
 *  selections, one opcode-403 equip, and the deferred-repush cases — with the delivered
 *  family-4 versions asserted strictly consecutive. Exit 0 = all assertions pass. */
int run_selection_version_test(void* module) noexcept;

} // namespace sunrise::server::persistence
