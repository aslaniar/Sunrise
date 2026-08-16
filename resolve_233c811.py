# -*- coding: utf-8 -*-
"""Resolve the 233c811 vcxproj conflicts: keep both sides' include lists."""
import io

P = r"Sunrise\Sunrise.vcxproj"
s = io.open(P, encoding="utf-8").read()

blocks = [
    (
        '<<<<<<< HEAD\n'
        '    <ClCompile Include="src\\client\\ui\\sword_skate\\sword_skate_panel.cpp" />\n'
        '    <ClCompile Include="src\\client\\teleport\\teleport_settings_store.cpp" />\n'
        '    <ClCompile Include="src\\client\\hooks\\noclip\\horizontal_noclip.cpp" />\n'
        '=======\n'
        '    <ClCompile Include="src\\client\\hooks\\fly\\fly.cpp" />\n'
        '    <ClCompile Include="src\\client\\input\\window_focus.cpp" />\n'
        '>>>>>>> 233c811 (noclip collision fix and fly)',
        '    <ClCompile Include="src\\client\\ui\\sword_skate\\sword_skate_panel.cpp" />\n'
        '    <ClCompile Include="src\\client\\teleport\\teleport_settings_store.cpp" />\n'
        '    <ClCompile Include="src\\client\\hooks\\noclip\\horizontal_noclip.cpp" />\n'
        '    <ClCompile Include="src\\client\\hooks\\fly\\fly.cpp" />\n'
        '    <ClCompile Include="src\\client\\input\\window_focus.cpp" />',
    ),
]

for old, new in blocks:
    if old in s:
        s = s.replace(old, new, 1)
        print("block resolved")
    else:
        print("block NOT FOUND")

# any remaining markers?
remaining = [ln for ln in s.splitlines()
             if ln.startswith(("<<<<<<<", "=======", ">>>>>>>"))]
print("remaining markers:", len(remaining))
for ln in remaining[:8]:
    print("  ", ln)

io.open(P, "w", encoding="utf-8", newline="").write(s)
