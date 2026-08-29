/**
 * Peer ADMISSION: census, and the switch-gated injection behind it (FINDINGS 20.157).
 *
 * WHY THIS IS CLIENT-SIDE. p2(96) censused every message id the group-host pump
 * receives across a full co-located boot: 12, 26, 29, 31, 34, 37, 39, all dispatched,
 * ZERO fallthrough. No id=10. The type-0x0A admission join never reaches our server, so
 * no server-side relay can carry it (route A, closed). Route B - injecting the admission
 * in-process through this DLL - is the only path left to a populated member table.
 *
 * WHAT ADMISSION FEEDS. The roster-caller lane traced `Adding player` to
 * add_candidates(0x141792080), whose peer arm (0x141769A50) reads the peer's xuid ONLY
 * out of the member-record array. That array's address block is written ONLY by ADMIT
 * (0x141777EC0), which our peers never reach - so the array stays empty, count=0, and
 * the roster names only self (20.104). It is also the leading (UNPROVEN) hypothesis for
 * why the public z-leg transition never populates dword[obj+0x524] and stalls.
 *
 * GEOMETRY, all relative to netmgr (which arrives in RCX - the adoption function's own
 * first instruction is `lea r15,[rcx+0x860]`):
 *     peer slots     netmgr + 0x860 + i*0xb8    machine id +0xc8, member count +0xe8,
 *                                               member-index list +0xf0 (int32[])
 *     peer states    netmgr + 0x860 + i*0x120 + 0x1758
 *     member records netmgr + 0x860 + idx*0x1a8
 * The adoption path reads exactly THREE fields from a member record - xuid at the head
 * of the address block (+0x3c00), bit 4 of the flags word (+0x3c30), and the membership
 * byte (+0x3b78) - which is the whole surface an injection has to satisfy.
 *
 * TWO STAGES, ONE BUILD.
 *   census  (client.admission_census, default TRUE)  - observation only. Logs the peer
 *           slots, their states, machine ids and member lists at the adoption entry.
 *           This verifies the geometry above AT RUNTIME (it is currently a static
 *           reading by another lane, and its reserve->admit trigger chain is labelled
 *           INFERRED) and answers the roster lane's open question: which gate actually
 *           blocks - the tick's state==5, or the empty member list.
 *   inject  (client.admission_inject, default FALSE) - the behaviour. Writes the three
 *           fields ADMIT would have written and links the record into the peer slot's
 *           member list.
 *
 * The injection ships DISABLED on purpose. It writes into live netmgr state, and p2(62)
 * is the standing reason not to do that on an unverified reading: it changed six
 * bindings, froze, and its cause is now unknowable. The census boot confirms the
 * geometry and names a safe record index; the switch then flips with no rebuild.
 */
#pragma once

namespace sunrise::client::hooks::admission {

/** Attaches the adoption-path observer. */
bool install() noexcept;

/** Detaches the observer and drops its trampoline. */
bool uninstall() noexcept;

/** @return True while the observer is attached. */
bool is_installed() noexcept;

} // namespace sunrise::client::hooks::admission
