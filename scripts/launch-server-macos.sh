#!/usr/bin/env bash
set -euo pipefail

# Launches the standalone Sunrise dedicated server (sunrise-server.exe) under
# wine on macOS. Deliberately independent of any client/Whisky launch setup:
# the server never renders anything, so it runs under the GPTK cask's
# wine 7.7 (not Whisky) in its own dedicated prefix. This got furthest of any
# tested engine on the TLS/SChannel front and, since it is a separate process
# from the client, there is no requirement that client and server share a
# Wine build or prefix - only that both can reach the configured ports,
# which is plain TCP/IP.
#
# Usage:
#   scripts/launch-server-macos.sh
# (honors the environment variables below; no arguments)
#
# Prerequisites:
#   - Game Porting Toolkit installed at its default location (wine 7.7).
#   - A server home directory laid out per docs/SERVER-QUICKSTART.md:
#     sunrise-server.exe at the root, its Sunrise/ folder next to it
#     (settings.json + cache/build_data.bin), and oo2core_3_win64.dll
#     copied from your own game installation.
#
# Environment variables:
#   SERVER_ROOT  Directory holding sunrise-server.exe.
#                Default: ./s1_accept (relative to your current directory).
#   WINEPREFIX   Wine prefix for the server.
#                Default: ~/Library/Application Support/SunriseServer/pfx
#   WINE_BIN     wine binary to run.
#                Default: Game Porting Toolkit wine64.

server_root="${SERVER_ROOT:-./s1_accept}"
prefix="${WINEPREFIX:-$HOME/Library/Application Support/SunriseServer/pfx}"
wine_bin="${WINE_BIN:-/Applications/Game Porting Toolkit.app/Contents/Resources/wine/bin/wine64}"

for required in "$server_root/sunrise-server.exe" "$wine_bin"; do
  if [[ ! -e "$required" ]]; then
    printf 'Required file not found: %s\n' "$required" >&2
    exit 1
  fi
done

export WINEPREFIX="$prefix"
export WINEDEBUG='fixme-all'

mkdir -p "$prefix"
cd "$server_root"

system32="$prefix/drive_c/windows/system32"
if [[ ! -d "$system32" ]]; then
  "$wine_bin" wineboot --init
  "$wine_bin" wineserver -w || true
fi

exec "$wine_bin" "$server_root/sunrise-server.exe"
