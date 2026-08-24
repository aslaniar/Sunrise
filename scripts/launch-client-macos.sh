#!/usr/bin/env bash
# Mac CLIENT launcher - versioned copy of mac-port/launch-sunrise-macos.sh
# hardened after incident FINDINGS 20.8/20.9 (2026-08-23): the WINEDLLOVERRIDES
# export below pins d3d10core + winemetal so the D3D stack cannot silently fall
# back to the WARP software rasterizer (graphics probe driver=warp -> chive/
# centipede at launch). Every Mac boot brief MUST read the probe's driver=
# value; hardware is required before a boot counts.
set -euo pipefail

sunrise_root="${SUNRISE_ROOT:-$HOME/Documents/opencode/sunrise-fork}"
game_root="${GAME_ROOT:-$HOME/Documents/opencode/sunrise-fork/Game}"
# The wintrust shim lives beside the ORIGINAL launcher in mac-port/, not here -
# this versioned copy resolves it through the project root instead.
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
sunrise_root="$(cd "$script_dir/../../.." && pwd)"
wintrust_shim="${WINTRUST_SHIM:-$sunrise_root/mac-port/wintrust.dll}"

# Keep the prefix on APFS in your home directory. Never put it on an exFAT or
# NTFS external volume - same symlink/filename problems as the Linux setup.
prefix="${WINEPREFIX:-$HOME/Library/Application Support/Sunrise/pfx}"

# Point this at whichever Wine you are using:
#   Whisky (GPTK wine-11, D3DMetal-capable, this setup): "$HOME/Library/Application Support/com.franke.Whisky/Libraries/Wine/bin/wine64"
#   CrossOver (x86_64 PEs dead in its wow64 bottles): NOT usable for the client
#   GPTK cask (wine 7.7): /Applications/Game Porting Toolkit.app/Contents/Resources/wine/bin/wine64
wine_bin="${WINE_BIN:-$HOME/Library/Application Support/com.franke.Whisky/Libraries/Wine/bin/wine64}"

for required in "$game_root/destiny2.exe" "$wine_bin" "$wintrust_shim"; do
  if [[ ! -e "$required" ]]; then
    printf 'Required file not found: %s\n' "$required" >&2
    exit 1
  fi
done

export WINEPREFIX="$prefix"
export WINEDEBUG='-all'
export WINEESYNC=1

# CrossOver's wine routes through its bottle system (WINEPREFIX is ignored).
# Point it at the dedicated Sunrise bottle; ignored by every other wine.
export CX_BOTTLE="${CX_BOTTLE:-SunriseClient}"

# The Steam API (real or Sunrise's emulated steam_api64) keys its init on the
# AppID. The Linux/Proton launcher exports these; without them the game halts
# with "The Steam API failed to initialize."
export SteamAppId='1085660'
export SteamGameId='1085660'

# Rosetta advertises no AVX by default. Shadowkeep-era builds generally want it.
# If the client faults immediately on launch, try unsetting this - and note that
# Rosetta provides AVX only, never AVX2 or AVX-512.
export ROSETTA_ADVERTISE_AVX=1

# Set to 1 for a live Metal fps overlay while benchmarking.
export MTL_HUD_ENABLED="${MTL_HUD_ENABLED:-0}"

mkdir -p "$prefix"
cd "$game_root"

system32="$prefix/drive_c/windows/system32"
if [[ ! -d "$system32" ]]; then
  "$wine_bin" wineboot --init
  # wineboot returns before the prefix has finished settling.
  "$wine_bin" wineserver -w || true
fi

# BSD cp has no --remove-destination. The target is normally a symlink into the
# Wine build, so unlink first or you clobber Wine's own copy for every prefix.
rm -f "$system32/wintrust.dll"
cp "$wintrust_shim" "$system32/wintrust.dll"

# Wine on macOS uses your real username for the profile dir, not 'steamuser'.
prefs="$prefix/drive_c/users/$USER/AppData/Roaming/Bungie/DestinyPC/prefs/cvars.xml"
if [[ ! -f "$prefs" ]]; then
  prefs="$prefix/drive_c/users/crossover/AppData/Roaming/Bungie/DestinyPC/prefs/cvars.xml"
fi

if [[ -f "$prefs" ]]; then
  cp -n "$prefs" "$prefs.pre-macos-windowed.xml" 2>/dev/null || true
  # BSD sed requires an explicit backup suffix after -i; '' means no backup.
  sed -i '' \
    -e 's/name="window_mode" value="[0-9]*"/name="window_mode" value="0"/' \
    -e 's/name="hdr_output" value="[0-9]*"/name="hdr_output" value="0"/' \
    -e 's/name="windowed_resolution_width" value="[0-9]*"/name="windowed_resolution_width" value="1280"/' \
    -e 's/name="windowed_resolution_height" value="[0-9]*"/name="windowed_resolution_height" value="720"/' \
    "$prefs"
fi

# No DXVK here - d3d11 and dxgi resolve to D3DMetal instead. d3d9 is dropped
# since it was only in the Linux list to force DXVK's copy. The steam_api64 and
# wintrust overrides are identical to the Proton setup.
# d3d10core + winemetal MUST be pinned here too: when the registry per-app
# section went missing, the D3D stack silently fell back to WARP (driver=warp
# in the graphics probe) - FINDINGS 20.8.
export WINEDLLOVERRIDES='steam_api64=n,b;wintrust=n,b;dxgi=n,b;d3d11=n,b;d3d10core=n,b;winemetal=b'

exec "$wine_bin" "$game_root/destiny2.exe"
