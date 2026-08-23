/**
 * Log-only observers on the family-4 item-instance validation chain (FINDINGS 14.23).
 *
 * The client's family-4 event handler FUN_140E06380 runs a WEAPON/ARMOR-only gate
 * (type bytes 1/2 at the store entry's +0x10) that subclasses never touch - the exact
 * asymmetry between working subclasses and broken gear:
 *   cVar1 = FUN_140547800(instance);
 *   if ((cVar1 == 0) || (cVar1 = FUN_140555280(store, instance), cVar1 != 0)) { ...
 *   lVar3 = FUN_140bfa030(index); if ((lVar3 == 0) || (*(char*)(lVar3 + 0xa32) == 1)) {...
 * Every detour calls the original untouched and logs the raw pointers + result + caller
 * RVA. No assumed structure dereference except the caller-proven +0xa32 byte read.
 */
#pragma once

namespace sunrise::client::hooks::item_gate {

/** Attaches the three observers in either server mode. */
bool install() noexcept;

/** Detaches all observers and drops their trampolines. */
bool uninstall() noexcept;

/** @return True while any observer is attached. */
bool is_installed() noexcept;

} // namespace sunrise::client::hooks::item_gate
