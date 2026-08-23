# Server Quickstart

How to get this fork's standalone dedicated server (`sunrise-server.exe`) running, and how
to point a modded game client at it. Build instructions live in
[BUILDING.md](BUILDING.md), boot-log triage in [TROUBLESHOOTING.md](TROUBLESHOOTING.md),
and the overall design in [ARCHITECTURE-ROADMAP.md](ARCHITECTURE-ROADMAP.md).

## 1. Requirements

| Platform | Server | Client | Status |
|---|---|---|---|
| Windows (native) | Runs natively as a console process | Native | Confirmed working |
| macOS | Under Game Porting Toolkit wine 7.7 (see `scripts/launch-server-macos.sh`) | Inside a Whisky bottle | Confirmed working |
| Linux | Under Wine | Under Wine/Proton | Hypothesis - untested by us |

Notes:

- On macOS the server deliberately runs under the Game Porting Toolkit's wine 7.7 in its
  own dedicated prefix - not inside the client's Whisky bottle. Client and server never
  need to share a Wine engine or prefix; they only need to reach each other over TCP/IP.
- You need your own copy of the matching game build for the client side. Nothing derived
  from game data is distributed with this fork: package files, caches, and proprietary
  libraries must all be produced or copied from your own installation.
- One machine can host both roles at once. Loopback networking is the default topology.

## 2. Build

Build both targets first: the client mod DLL and `sunrise-server.exe`. See
[BUILDING.md](BUILDING.md) for per-platform toolchains and commands.

## 3. Server home layout

Pick a folder as your `<server-root>` and arrange it like this:

```
<server-root>/
  sunrise-server.exe          the standalone server you built
  oo2core_3_win64.dll         copied from YOUR OWN game installation (see below)
  packages/                   optional: your game's package files (or set server.packages_dir)
  content/                    optional: JSON overrides applied on top of the cache
  Sunrise/
    settings.json             server configuration (created from defaults on first boot)
    cache/
      build_data.bin          generated from your own install - never downloaded
    logs/
      sunrise.log             appears when core.logging.file_sink is true
```

- `oo2core_3_win64.dll` is a proprietary compression library. It is not distributed with
  this project; copy it from your own game's binary directory next to `sunrise-server.exe`.
- `Sunrise/cache/build_data.bin` is produced by the modded client reading your own game
  data. Copy it into the server's `Sunrise/cache/` folder. The server resolves it there
  automatically when `server.build_data_path` is empty.
- Files in `content/` (when `server.content_dir` points at it) override matching catalog
  domains loaded from the cache at boot.

## 4. Minimal settings.json

On first boot the server writes its bundled default document to
`Sunrise/settings.json`; edit that file. A minimal working config:

```json
{
  "version": 6,
  "core": {
    "logging": {
      "file_sink": true,
      "levels": {
        "core": "info",
        "state": "info",
        "server": "info"
      }
    }
  },
  "server": {
    "bap_port": 30975,
    "https_port": 443,
    "bootstrap_token": "<generate 32 hex characters>",
    "packages_dir": "",
    "build_data_path": "",
    "content_dir": ""
  }
}
```

Key points:

- `bootstrap_token` must be exactly 32 hex characters. Generate one, e.g.:
  `python -c "import secrets; print(secrets.token_hex(16))"`. A missing or malformed token
  fails the boot. The same value goes into the client config later (section 6).
- Empty path settings auto-resolve: `packages_dir` to a `packages/` folder next to the
  executable, `build_data_path` to `Sunrise/cache/build_data.bin`, `content_dir` off.
- Unknown keys are skipped silently by the parser - if behavior surprises you, diff your
  config against this template before anything else.

> **CRITICAL: never seed characters from a server config.**
>
> Do NOT put `state.characters` - or any character/equipment seed block - in the SERVER's
> settings.json. A server config carrying one hard-fails the boot during database seeding
> (`seed_equipment_resolve result=fail reason=definition hash not in build data`), because
> item definitions are published by the client-side content pipeline and do not exist yet
> when the standalone server seeds. Character data lives exclusively in the server's local
> database once persistence creates it. See TROUBLESHOOTING.md for the full signature.

## 5. First boot

Run `sunrise-server.exe` from `<server-root>` (on macOS, via
`scripts/launch-server-macos.sh`). A healthy boot ends with lines shaped like:

```
ev=bootstrap stage=token result=ok
ev=transport stage=listen result=ok port=30975
ev=discovery stage=listen result=ok port=3074
ev=discovery stage=listen result=ok port=3075
ev=https stage=listen result=ok port=<your https_port>
ev=admin stage=listen result=ok port=8099
ev=initialize result=ok
```

The final line means every stage started cleanly and the service loop is running. Stop the
server with Ctrl+C; it shuts every stage down in reverse order.

With `core.logging.file_sink` set to true (as in the template above), the same output is
written to `Sunrise/logs/sunrise.log` - that file plus the console are what
[TROUBLESHOOTING.md](TROUBLESHOOTING.md) reasons over.

Two warnings are known-benign and present in healthy boots - do not chase them:

| Warning | Why it looks scary | Why it is safe |
|---|---|---|
| A `build_data stage=identity result=mismatch` line whose `expected_eq` value prints short with trailing garbage | Reads like a corrupted cache identity | The log file itself truncates long values mid-line; the timestamp and size fields match what was cached. Verify identities by computing them, not by reading them back. |
| `s1_loader stage=swap domain=socketEntryLists json=37 cache=14 result=mismatch` | Reads like a failed consistency check | The parsed JSON side wins by design; the mismatch only records that the two sources differ in row count. |

The full benign-vs-fatal table lives in [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

## 6. Point a client at it

The client is the game running the mod DLL, installed as `Game/bin/x64/steam_api64.dll`
(keep a backup of the original file). In the CLIENT's own `Sunrise/settings.json`, add or
edit the external-server block:

```json
{
  "client": {
    "external_server": {
      "enabled": true,
      "host": "127.0.0.1",
      "config_url": "",
      "config_guid": "<the guid synced below>"
    }
  }
}
```

- `host` is an IPv4 dotted quad only (`127.0.0.1` for a server on the same machine);
  hostnames are refused.
- `config_url` optionally overrides where the manifest is fetched from; the default
  already targets the route this server serves.

**Syncing `config_guid`.** The served content manifest carries a computed identity hash,
and the client must quote it exactly:

1. Leave the SERVER's `server.config_guid` setting empty (`""`).
2. Boot the server; it logs its computed manifest guid.
3. Copy that logged value into the CLIENT's `client.external_server.config_guid`.

This value changes whenever the packages/content inputs change, so re-sync after moving
or editing content.

**Shared bootstrap token.** Set the SAME `bootstrap_token` string under
`server.bootstrap_token` in BOTH the server's and the client's `settings.json`. Login does
not need server TLS: the client answers the sign-on exchange in-process, and both sides
derive their session wrap keys deterministically from the shared token - which is why the
values must match exactly.

## 7. Ports

| Port | Protocol | Purpose | Notes |
|---|---|---|---|
| 30975 (`server.bap_port`) | TCP | BAP transport - remote players | Must be identical on both sides |
| 3074 + 3075 | UDP | Discovery | Fixed |
| ~30976 | UDP | Gameplay (DTLS) | Even port required - the join descriptor refuses odd ports |
| your `server.https_port` (default 443) | TCP | HTTPS config-manifest listener | The reference macOS deployment used 8443 instead |
| 8099 | TCP | Admin HTTP | Loopback / local-admin-only today |

All listeners currently bind to loopback. Remote clients are future work; today a second
machine cannot connect even with ports opened.

## 8. Multiplayer status

Right now the server hosts **one account**: destinations load solo, and everything
you equip or swap persists across restarts.

Having a friend connect at the same time isn't supported yet - a second client
would land on the same guardian. That work is underway (per-player accounts,
shared spaces, seeing each other); [ARCHITECTURE-ROADMAP.md](ARCHITECTURE-ROADMAP.md)
tracks where it stands and what's left.
