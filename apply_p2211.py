#!/usr/bin/env python3
"""p2-211: the recv_root call counter + server session-lifetime logging."""
import sys

# ============================================================ 1. CLIENT PROBE
F = ("Sunrise/src/client/hooks/milestone_trace/milestone_trace_observer.cpp")
t = open(F).read()

A = "constexpr std::uintptr_t kEntRecvRva = 0x1718510;\n"
NEW = '''/**
 * p2-211: entry 0 of the 14-entry handler table at .rdata RVA 0x1C166A0 - the head
 * of the ONLY chain reaching the ent receive-block ctor. Nine hops, every one a
 * single caller: 0x140B5ECD0 -> 0x1416FCDF0 -> 0x1416F6640 -> 0x141709800 ->
 * 0x141702580 -> 0x141703910 -> 0x1416FF3C0 -> 0x1416CA0B0 -> 0x1416BB1E0.
 *
 * 20.338 measured that the table is REGISTERED AND LIVE at runtime (descriptor
 * object on the heap, the root's address in nine heap records) while the ctor has
 * zero heap references and the four receive blocks are absent in six dumps. A dump
 * cannot separate "never dispatched" from "runs and bails". This counter can, and
 * it is the whole reason for the boot.
 *
 * SAFETY: exact .pdata bounds 0x140B5ECD0..0x140B5F16D starting at offset 0 - a
 * clean detour target, not a fragment. The budget caps EMITS only; the census line
 * reads g_calls, which costs one atomic increment per call.
 */
constexpr std::uintptr_t kRecvRootRva = 0xB5ECD0;
''' + A
assert A in t, "kEntRecvRva anchor missing"
assert "kRecvRootRva" not in t, "already applied"
t = t.replace(A, NEW, 1)

B = '    {"ent_recv",    kEntRecvRva, 24},\n'
NEWB = ('    // p2-211: the construction chain\'s head. calls=0 means nothing dispatches\n'
        '    // entry 0; calls>0 means it runs and bails, and the bail point is then a\n'
        '    // static read of a readable 1181-byte function. Only one of those is a\n'
        '    // dead end, and today we cannot tell which.\n'
        '    {"recv_root",   kRecvRootRva, 12},\n' + B)
assert B in t
t = t.replace(B, NEWB, 1)

C = "constexpr std::size_t kTargetsSize = 68;"
assert C in t, "kTargetsSize anchor missing"
t = t.replace(C, "constexpr std::size_t kTargetsSize = 69;", 1)
open(F, "w").write(t)
print("client: recv_root added, kTargetsSize 68 -> 69")

# ================================================== 2. SERVER SESSION LIFETIME
# 20.338 R4: the mac's activity sessions are short-lived (6-9 wire snapshots each,
# then replaced) while the rig's carries 456. Nothing logs WHY one goes away, so
# the churn cannot be attributed. release_session is the single teardown path -
# state/activity/transactions/activity_session_release.cpp (the staged draft named
# activity_session_lookup.cpp, where the function does not live; the sibling
# activity_session_commit.cpp is the line-style template: Channel::state, ev=activity).
F2 = "Sunrise/src/state/activity/transactions/activity_session_release.cpp"
t2 = open(F2).read()
if "stage=session_release" not in t2:
    ANCHOR = ("    ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);\n"
              "    return released;")
    assert ANCHOR in t2, "release_session tail anchor missing"
    # Logged AFTER the lock is dropped; result= separates a real teardown from a
    # retained (consumer still bound) or not-found record, so the churn readout can
    # tell "someone released it" from "the record never went away".
    log = '''    // p2-211 (20.338 R4): the mac's activity sessions churn - 6-9 wire snapshots
    // each, then replaced - while the rig's carries 456, and that asymmetry is why
    // the mac is fed almost no peer rows. Nothing recorded WHO tears a session down,
    // so the churn could never be attributed. One line per release attempt (rare).
    {
        std::array<char, 128> line{};
        const int n = std::snprintf(line.data(), line.size(),
            "ev=activity stage=session_release session=0x%llX result=%s",
            static_cast<unsigned long long>(sessionId),
            released ? "released" : "kept");
        if (n > 0) {
            core::log::write(core::log::Channel::state,
                             core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(n)});
        }
    }
'''
    t2 = t2.replace(ANCHOR,
                    "    ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);\n"
                    + log + "    return released;", 1)
    INC = '#include "internal.h"\n'
    assert INC in t2, "include anchor missing"
    t2 = t2.replace(INC, INC + '\n#include <array>\n#include <cstdio>\n'
                    '#include "../../../core/logging/log.h"\n', 1)
    open(F2, "w").write(t2)
    print("server: session_release logging added to activity_session_release.cpp")
else:
    print("server: session_release logging already present")
