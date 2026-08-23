# Running the client on macOS

The client half of this fork is the modded game running inside a
[Whisky](https://getwhisky.app) bottle. This page walks through that setup end to end.
The server side on macOS runs as a separate process under Game Porting Toolkit wine -
never inside this bottle - and is covered by [SERVER-QUICKSTART.md](SERVER-QUICKSTART.md)
(sections 1 and 6); client and server only need to reach each other over TCP/IP.

One principle explains every step below: **let Whisky manage the wine environment.**
An earlier hand-rolled launch script assembled its own environment and missed roughly
fifteen variables Whisky sets automatically (`WINEMSYNC`, several Darwin-specific
`WINE_MACH_PORT_*` tuning vars, ...) plus the per-app DLL overrides in step 5. That gap -
not a Metal/macOS-version regression - was the actual cause of the original
graphics-init crash.

## Prerequisites

- An Apple Silicon Mac with macOS current enough for Whisky.
- [Whisky](https://getwhisky.app) (`brew install --cask whisky` or download from the site).
- Your own copy of the Season of Arrivals game build. Nothing derived from game data is
  distributed with this fork - bring your own installation (see the ground rules in the
  README).
- The built client mod `steam_api64.dll`, produced per [BUILDING.md](BUILDING.md)
  (Toolchain 2 builds Windows binaries on macOS via llvm-mingw).
- A dedicated server to point at, per [SERVER-QUICKSTART.md](SERVER-QUICKSTART.md).

## Steps

1. **Install and open Whisky**, then let it finish its first-run setup (it downloads a
   wine runtime into the app bundle on first launch):

   ```sh
   brew install --cask whisky
   ```

2. **Create a bottle named e.g. `Sunrise`** (Whisky -> New Bottle). Use one dedicated
   bottle for this game; do not share it with unrelated software.

3. **Install your Arrivals build into the bottle.** Open the bottle's C drive from
   Whisky ("Open C Drive" in the bottle menu) and copy your game folder there, e.g. to
   `C:\Games\Destiny2`. You can copy from Finder; from a shell:

   ```sh
   BOTTLE="<your Sunrise bottle folder>"        # "Open C Drive" reveals the path
   cp -R "/path/to/your/game" "$BOTTLE/drive_c/Games/Destiny2"
   ```

4. **Install the mod DLL** as `Game/bin/x64/steam_api64.dll` inside the bottle's game
   copy, keeping a backup of the original (it is the game's own Steam wrapper):

   ```sh
   GAME="$BOTTLE/drive_c/Games/Destiny2"
   cp "$GAME/bin/x64/steam_api64.dll" "$GAME/bin/x64/steam_api64.dll.orig"
   cp /path/to/build-cmake/steam_api64.dll "$GAME/bin/x64/steam_api64.dll"
   ```

   First launch creates `Game/bin/x64/Sunrise/settings.json` and a logs folder next to it.

5. **Set the per-app DLL overrides in the bottle - required.** Two entries scoped to the
   game executable fix the graphics-init crash:

   | DLL | Value | Meaning |
   |---|---|---|
   | `winemetal` | `b` | builtin only - use wine's own winemetal layer |
   | `d3d10core` | `n,b` | native first, then builtin |

   When Whisky's Metal/DXMT graphics backend is active it applies these itself; verify or
   set them explicitly so any launch method gets them. Per-app overrides live under
   `HKCU\Software\Wine\AppDefaults\<exe>\DllOverrides` - either edit them in Whisky's
   Registry Editor (bottle Config menu), or run this once against the bottle:

   ```sh
   WINE="/Applications/Whisky.app/Contents/Resources/Wine/bin/wine"  # path may vary
   KEY='HKCU\Software\Wine\AppDefaults\destiny2.exe\DllOverrides'
   WINEPREFIX="$BOTTLE" "$WINE" reg add "$KEY" /v winemetal /t REG_SZ /d b /f
   WINEPREFIX="$BOTTLE" "$WINE" reg add "$KEY" /v d3d10core /t REG_SZ /d n,b /f
   ```

6. **Optional: Metal HUD.** For an FPS overlay you can either toggle the HUD per bottle
   in Whisky's Config, or set it machine-wide:

   ```sh
   launchctl setenv MTL_HUD_ENABLED 1
   ```

   After any `launchctl setenv`, **fully quit Whisky and relaunch it** - environment
   variables are inherited at process launch only, so an already-running Whisky never
   picks up a new value. `launchctl setenv` values are session-scoped and reset at
   reboot.

7. **Point the client at your server** - follow
   [SERVER-QUICKSTART.md](SERVER-QUICKSTART.md) section 6 exactly: enable
   `client.external_server`, set `host` to the server's IPv4 address, boot the server
   once and copy its logged manifest guid into `client.external_server.config_guid`,
   and put the identical `bootstrap_token` in both sides' settings. Then launch the game
   via Whisky (Run -> the game's `destiny2.exe`).

For debugging, set `core.logging.file_sink: true` in the client's settings.json - log
lines land in `Game/bin/x64/Sunrise/logs/sunrise.log`. That costs real performance on
this platform, so flip it off again after the session. Boot-log triage lives in
[TROUBLESHOOTING.md](TROUBLESHOOTING.md).

---

> **Known macOS hazards**
>
> - **No persistent MoltenVK shader cache exists on this path**, so the first render of
>   any newly equipped model compiles cold - and character pick is the heaviest renderer
>   moment of the whole boot. Introduce new equipped models sparingly, one change per
>   session, and expect a slow first load after any gear-definition change.
> - **Wine-on-macOS inbound TLS is impossible** (exhaustively tested across GPTK wine,
>   Whisky's wine, and CrossOver): no handshake ever completes. That is why login needs
>   no server TLS here - the client answers the sign-on exchange in-process, and BAP /
>   discovery traffic uses AES-GCM, which never used TLS to begin with. This is a
>   permanent platform limitation, not a bug to chase; see
>   [SERVER-QUICKSTART.md](SERVER-QUICKSTART.md) section 6.
