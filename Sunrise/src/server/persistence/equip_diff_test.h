#pragma once

namespace sunrise::server::persistence {

/** Runs the subclass-equip diff test: the character object pre-equip vs post-equip
 *  through the exact mutation + re-encode the live server's queuez path uses. */
int run_equip_diff_test(void* module) noexcept;

} // namespace sunrise::server::persistence
