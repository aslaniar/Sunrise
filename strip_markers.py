# -*- coding: utf-8 -*-
"""Strip the leftover conflict markers from the committed files (the 233c811
resolution missed 7 files). Policy: the both-keep — drop the marker lines, keep
the HEAD and the incoming sides. Any duplicate-definition fallout = the build's
to name, one fix each."""
import io
import re
import sys

FILES = [
    r"Sunrise\src\client\ui\teleport\teleport_panel.cpp",
    r"Sunrise\src\client\teleport\teleport_settings_store.h",
    r"Sunrise\src\client\teleport\teleport_settings_store.cpp",
    r"Sunrise\src\client\hooks\teleport\teleport_move.cpp",
    r"Sunrise\src\client\hooks\noclip\runtime.h",
    r"Sunrise\src\client\hooks\noclip\horizontal_noclip.cpp",
    r"Sunrise\src\client\hooks\sword_skate\sword_skate.cpp",
]


def strip_markers(text):
    out = []
    i = 0
    lines = text.splitlines(True)
    while i < len(lines):
        ln = lines[i]
        if ln.startswith("<<<<<<<"):
            i += 1  # the marker line dropped
            while i < len(lines) and not lines[i].startswith("======="):
                i += 1  # the HEAD side kept
            i += 1  # the ======= dropped
            while i < len(lines) and not lines[i].startswith(">>>>>>>"):
                i += 1  # the incoming side kept
            i += 1  # the >>>>>>> dropped
            continue
        out.append(ln)
        i += 1
    return "".join(out)


for p in FILES:
    try:
        s = io.open(p, encoding="utf-8").read()
    except OSError:
        print("SKIP (missing):", p)
        continue
    before = s.count("<<<<<<<")
    if before == 0:
        print("clean:", p)
        continue
    s = strip_markers(s)
    after = s.count("<<<<<<<")
    io.open(p, "w", encoding="utf-8", newline="").write(s)
    print("resolved %d blocks: %s" % (before, p))
