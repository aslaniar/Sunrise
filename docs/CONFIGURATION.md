# Configuration

Sunrise keeps **one JSON settings file per side**:

| Side | File location |
|---|---|
| Dedicated server | `<server home>/Sunrise/settings.json`, next to `sunrise-server.exe` |
| Game client | `Game/bin/x64/Sunrise/settings.json`, next to the installed `steam_api64.dll` |

Both files share one schema and one `version` field. Each file is created
automatically with built-in defaults on first run; older files are upgraded in
place. Every key below is optional in the sense that a default exists - but see
the [Traps](#traps) section: misspelled keys are ignored silently, so a typo
looks exactly like a default.

---

## Shared keys (both sides)

| Key | Type | Default | Meaning |
|---|---|---|---|
| `version` | integer | current schema version | Settings schema version. Leave as written by the build. |
| `core.logging.debugger_sink` | bool | `true` | Also emit log lines to an attached debugger. |
| `core.logging.file_sink` | bool | `false` | Write `logs/sunrise.log`. Enable while debugging; it costs performance. |
| `core.logging.levels` | object | all `"warn"` | Per-channel log levels. Channels: `core`, `client`, `state`, `server`, `middleware`. Levels follow the usual trace/debug/info/warn/error ladder. |

## Server keys (`server.*`)

Both files carry this block. On the **server** it configures the dedicated
process. On the **client** it configures the built-in embedded server, which
runs whenever `client.external_server.enabled` is `false`; with an external
server enabled the client ignores it.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `server.bap_port` | 1..65535 | `30974` | Main server transport port. **Must match the client side** or the client never reaches the server. |
| `server.https_port` | 1..65535 | `443` | HTTPS listener port. |
| `server.bootstrap_token` | string, <= 32 printable chars | placeholder of zeros | Shared secret between client and server. See [The bootstrap token](#the-bootstrap-token). |
| `server.config_guid` | string | empty | Optional validation override for logging only. The served manifest always carries the server's own computed content GUID; leave empty unless told otherwise by the log. |
| `server.packages_dir` | string path | empty (auto) | Game package directory. Empty = auto-resolved under the server root. |
| `server.build_data_path` | string path | empty (auto) | Extracted-content cache location. Empty = `Sunrise/cache/build_data.bin` under the server root. |
| `server.content_dir` | string path | empty (auto) | Content override directory. Empty = auto-resolved under the server root. |
| `server.world_population` | bool | `false` | Experimental entity scaffolding push. Off by default; leave off unless you are developing it. |
| `server.world_population_carrier` | 0..58 | `7` | Activity-message type used as the carrier for the above. |
| `server.world_population_schema_hash` | 32-bit int | built-in default | Schema tag hash for the same. |

The server also accepts a `server.gameplay` block (transport topology,
bind/advertised addresses, gameplay port) and a `server.entitlements` list.
Both ship with working defaults; you should not need to touch them.

## Client keys (`client.*`)

| Key | Type | Default | Meaning |
|---|---|---|---|
| `client.external_server.enabled` | bool | `false` | Point the client at a separate server process instead of its embedded one. Set `true` when using this fork's dedicated server. |
| `client.external_server.host` | IPv4 string | `127.0.0.1` | Server address. Must be a complete dotted quad - hostnames are refused. |
| `client.external_server.config_url` | URL string | loopback default | Where the client fetches the config manifest from the server. |
| `client.external_server.config_guid` | 36-char GUID | placeholder | Must equal the GUID the server computes for its content set. Copy it verbatim from what the server logs; never hand-type a guess. It changes whenever your packages/content change. |
| `client.region_private` | bool | `false` | `true` = load public destinations solo instead of waiting for an activity-host advertisement that this server does not provide yet. Trades a possible infinite hang for a completed load. |
| `client.pin_replicated_record` | bool | `true` | Keeps the replicated record pinned. Leave at the default. |
| `client.hold_spawn` | bool | `true` | Hold the spawn gate during load-in. |
| `client.spawn_hold_ms` | 1..600000 ms | `30000` | How long the spawn hold lasts. |
| `client.fade_release` | bool | `true` | Release the screen fade on load completion. |
| `client.force_join_request_ready` | bool | `true` | Forces join-request readiness during boot flow. |
| `client.graphics_probe`, `client.graphics_probe_warp`, `client.renderer_hud_always`, `client.renderer_enabled` | bool | see shipped file | Renderer diagnostics switches. **Leave these at their defaults.** |
| `client.ui.enabled` | bool | `true` | In-game mod overlay UI. |
| `client.ui.toggle_key` | named key | `"insert"` | Overlay toggle key. Accepted names: `insert`, `home`, `end`, `delete`, `f1`..`f12`. |

### Steam emulation keys (`steam.*`)

| Key | Type | Default | Meaning |
|---|---|---|---|
| `steam.user.persona_name` | string | `"Player"` | Player name the emulated Steam layer reports. |
| `steam.language` | language token | `"english"` | One of the game's supported Steam language codes. Unknown tokens fall back to English with a startup log line. |

---

## Authored characters and equipment (`state.characters`) - CLIENT ONLY

`state.characters` defines the characters, their appearance, ability picks and
equipped items that the client presents at character select. Each entry carries
identity keys (`soid`, `race`, `gender`, `class`, `level`, ...), the five
ability picks (`movement_ability`, `grenade_ability`, `super_ability`,
`melee_ability`, `class_ability`), and an `equipment` list where every item
must contain exactly five keys: `instance_soid`, `definition_hash`, `level`,
`quantity`, `plugs`.

> **Warning: never copy `state.characters` into a SERVER config.**
> A server config containing `state.characters` hard-fails the boot with
> `persistence stage=seed_equipment_resolve result=fail` - even when every
> referenced definition hash exists in the cache. This is an ordering defect,
> not bad data: item definitions publish after equipment seeding runs, and the
> publishing code only exists in the client-side build. Characters belong in
> the client config only; the server persists them to its database itself.

Related: `state.unlocks` carries the four unlock flag banks. Keep them curated
(the values shipped with the client config). Saturating whole banks with
"everything unlocked" triggers client-side replication rejections - see
[TROUBLESHOOTING.md](TROUBLESHOOTING.md).

### The per-character settings block

Each authored character also carries a `settings` object with six required
groups: `controls`, `audio`, `display`, `interface`, `social`,
`key_bindings`. All six must be present. The `interface` group is the visible
one:

| Key | Range |
|---|---|
| `subtitles_mode` | 0..2 |
| `colorblind_mode` | 0..3 |
| `helmet_mode` | 0..1 |
| `hud_opacity` | 0..3 |
| `display_hints` | bool |
| `background_opacity` | 0..4 |
| `reticle_location` | 0..1 |
| `reticle_color` | 0..6 |
| `text_size` | 0..4 |
| `text_color` | 0..3 |
| `text_background_style` | 0..3 |
| `text_background_opacity` | 0..4 |
| `reserved_text_mode` | pinned `0` |
| `subtitle_options_entry` | pinned `0` |

Note: `helmet_mode` is fully plumbed through validation and encoding, but this
game build contains no code that consumes it - helmet visibility is fixed by
the client regardless of the value.

---

## Validation ranges

Confirmed against `src/state/account/settings/settings_state.cpp`. Values
outside these ranges fail validation and the record is not encoded - the
setting silently stays at whatever the server last published.

| Field | Accepted values |
|---|---|
| Two-choice selectors (`helmet_mode`, `hdr_mode`, team voice channel, reticle location, chat join modes) | `0`..`1` |
| Brightness | `0`..`6` |
| Subtitles mode | `0`..`2` |
| Colorblind mode | `0`..`3` |
| HUD opacity | `0`..`3` |
| Background / text-background opacity | `0`..`4` |
| Reticle color | `0`..`6` |
| Text size | `0`..`4` |
| Text color / text background style | `0`..`3` |
| Mouse look sensitivity | `1`..`100` |
| ADS sensitivity modifier | `0.5`..`1.5` |
| Double-press delay | `0`..`4` |
| Controller button layouts | `{0, 1, 2, 3, 5, 6, 9}` |
| Movement mode / controller sensitivity | `0`..`3` / `0`..`9` |
| Voice output mode | `0`..`2` |
| Chat volume | `0`..`8` |
| Sound / dialogue / music volume | each `0`..`10` |
| Text chat mode | `0`..`3` |
| Renderer calibration floats | pinned: `10000.0` and `0.0` |
| Unidentified text fields | pinned to `0` |
| Audio `migration_version` | must equal `8` |

---

## Traps

Three behaviors that look like bugs and are not:

1. **Unknown settings keys are skipped silently.** There is no error and no
   log line anywhere - not at parse time, not at runtime. A typo'd key simply
   does not exist, and the default applies. If behavior mystifies you, diff
   your config against a known-good copy before anything else.
2. **Content JSON overrides beat cached values by design.** Files in the
   content override directory replace the matching cache domains outright at
   boot; a mismatch between the two only logs a line. If an extracted-cache
   edit "does not take", an override file is winning on purpose.
3. **Never add `state.characters` to a server config.** Covered in the warning
   above: the boot fails at equipment seeding even though the data itself is
   fine.

---

## Minimal external-server setup

The shortest correct path from two default config files to a working client +
dedicated server pair:

1. **Server file** (`<server home>/Sunrise/settings.json`):
   - Set `server.bootstrap_token` to a freshly generated 32-hex string.
   - Leave `server.bap_port` at `30974` (or pick a port and use the same one
     on the client).
   - Leave `server.packages_dir` / `server.build_data_path` /
     `server.content_dir` empty so they auto-resolve under the server home.
2. **Client file** (`Game/bin/x64/Sunrise/settings.json`):
   - Set `client.external_server.enabled` to `true`.
   - Set `client.external_server.host` to the server's IPv4 address
     (`127.0.0.1` for the same machine).
   - Point `client.external_server.config_url` at that same host.
   - Set `server.bootstrap_token` in the client file **identically** to the
     server's value.
   - Set `server.bap_port` identically as well.
3. **Boot once, then sync the GUID**: copy the content GUID from the server's
   log into `client.external_server.config_guid`. This value changes whenever
   your packages/content directory changes - re-sync it after moving content.
4. Optional: set `client.region_private: true` if public destinations hang at
   join (see [TROUBLESHOOTING.md](TROUBLESHOOTING.md)).

---

## The bootstrap token

`server.bootstrap_token` is the shared secret that ties one client to one
server. Sign-on envelope wrap keys are derived deterministically from it on
both sides, so both files must carry **exactly the same value** or the client
cannot authenticate.

Guidance:

- Generate 32 hex characters, e.g.
  `python -c "import secrets; print(secrets.token_hex(16))"`.
- Set the identical value in **both** config files, under
  `server.bootstrap_token`.
- Rotating it is trivial and has no live-server implications: regenerate the
  value and update both files. The token only guards *your* server - there is
  no central service it talks to.
- The compiled default (`000...0`) is a placeholder on purpose. Do not leave
  it if anyone else can reach your server.
