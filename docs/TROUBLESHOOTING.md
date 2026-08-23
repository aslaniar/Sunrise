# Troubleshooting

## Where to look first

Both sides write an application-level log file when
`core.logging.file_sink` is enabled (see [CONFIGURATION.md](CONFIGURATION.md)):

- Server: `<server home>/Sunrise/logs/sunrise.log`
- Client: `Game/bin/x64/Sunrise/logs/sunrise.log`

This log is far more informative than any wrapper/engine-level trace output
for everything past the graphics layer. Enable it, reproduce, then turn it
back off - debug-level file logging has a measurable cost during play.

**Restart the server before blaming persisted state.** Long-lived sessions
produce their own artifact classes, and several documented misdiagnoses came
from blaming the database for what an aged process was doing. A fresh boot is
the cheapest discriminator you have.

---

## Known-benign log lines

All of the following appear in verified healthy boots. Do not chase them.

| Symptom (log line shape) | Verdict | Action |
|---|---|---|
| `ev=build_data stage=identity result=mismatch` warning whose printed `expected_eq` looks suspiciously **short**, possibly with garbage after it | Chronic and benign. Log files truncate lines mid-value; a short hash here is truncation, not a small number. The timestamp/size fields in the same line do match. | None. Never read expected values out of logs - if you need the real value, compute it from disk/database state. |
| `s1_loader stage=swap domain=socketEntryLists json=37 cache=14 result=mismatch` | Benign by design. The content override JSON wins over the cached catalog on a domain mismatch; the line just reports that. | None. |
| A single `queuez ... reason=null_payload` skip line at load time | Expected empty-payload guard trip. | None if it appears once. Repeated occurrences alongside other failures are a different matter - see the fatal table. |
| Client-side `name=DnsQueryRaw result=fail` at attach time | The DNS egress hook reports its attach probe; harmless offline. | None. |

---

## Connectivity and loading problems

The dedicated-server path has three hand-edited coupling points between the
two config files. When a client cannot get into the world, check them in this
order before anything else:

| Symptom | Verdict | Action |
|---|---|---|
| Client never establishes a session; no sign-in progress | `bap_port` differs between the two files. This value drifted silently in real setups and cost a full debugging pass once. | Diff `bap_port` (and `https_port`) across both files; make them identical. |
| Client fails to start connecting at all, immediately | `client.external_server.host` is not a complete IPv4 dotted quad. Hostnames are refused by design. | Use a numeric address such as `127.0.0.1`. |
| Manifest/config fetch misbehaves right after packages or content moved | `config_guid` no longer matches the server's computed content GUID (it changes whenever the content set changes). | Clear the server's `config_guid` override (empty string), boot once, copy the GUID the server logs into the client's `external_server.config_guid`. |
| Loading a public destination hangs forever at join (waiting for a session advertisement that never arrives) | Expected with this server: activity-host advertisement for public spaces is not provided yet. | Set `client.region_private: true` to load public destinations solo. Note the trade-off: some complex multi-bubble destinations still fail to resolve a spawn point even then. |

## Config-file load failures

Settings are read before the logging sinks exist, so config problems surface
as one early line shaped like `ev=settings result=fail reason=<step>`:

| `reason=` | Meaning | Action |
|---|---|---|
| `parse` | The JSON does not parse, or a value fails its key's checks. Remember: unknown *keys* are skipped silently - this failure means malformed structure or bad values, not typos in key names. | Validate the JSON; diff against the freshly generated default. |
| `too_large` | The file exceeds the 1 MiB cap. A bloated config reads exactly like a crash here. | Trim the file. |
| `write_default` / `open` / `reopen` / `path` | The file could not be created or read beside the binary. | Check folder permissions and that the `Sunrise` data folder is writable. |

Related benign lines at startup:

- `ev=settings stage=version result=mismatch file=<n> build=<n>` followed by
  `stage=upgrade` - an older config file being upgraded in place. Harmless;
  the upgraded file replaces the old one only if it parses cleanly.
- `ev=settings stage=language result=fallback token=<x>` - an unsupported
  `steam.language` token falling back to English. Harmless.

## Server self-check without hosting

`sunrise-server.exe --cache-check` runs the extracted-content cache
verification (the same reader model the boot uses) and exits with a verdict,
without bringing up listeners. Use it after any manual cache surgery or exe
replacement to confirm identity and payload health before a real boot.

---

## Fatal signatures

These mean the boot or session is genuinely broken. Act on them.

| Symptom | Verdict | Action |
|---|---|---|
| Server: `persistence stage=seed_equipment_resolve result=fail reason=definition hash not in build data` - even though every referenced definition hash exists in the cache | Your server config contains `state.characters`. Equipment seeding runs before item definitions publish, and the publisher only exists in client-side code, so every lookup fails. It is an ordering defect, not bad data. | Remove `state.characters` from the **server** config. Characters belong in the client config only; the server persists them itself. |
| Server: identity `result=mismatch` followed by **all** content domains reporting `cache=0` and `content_swap` fail | The cache identity no longer matches this `sunrise-server.exe`. Either the exe was rebuilt without refreshing the header, or equipped-item inputs changed without a re-stamp of the stored equipment hash. | After a rebuild: patch the u32 fields at byte offsets 12 and 16 of `cache/build_data.bin` with the `expected_ts` / `expected_size` values from the failing boot log (see [BUILDING.md](BUILDING.md)). Otherwise: make one equipment/ability commit in game - the server re-stamps the equipment hash automatically - or restore the matching exe. |
| Client: `queuez_family_update_begin ignoring family-update due to unhandled replication state` plus failed family-4 update processing, while every server-side check reads healthy | The client is discarding part of the join snapshot. Observed under **blanket unlock-flag saturation** (whole flag banks set to "everything unlocked"). | Keep flag banks curated - use the values shipped with the client config rather than saturating ranges. Revert to the shipped banks and re-test before debugging anything else. |

---

## Crash signature: silent death at character pick

If the game dies silently at character select - no crash dialog, no SEH
record, no minidump, nothing in the OS crash reporter - right after the
application suspends and reactivates:

**Verdict:** the graphics translation layer is cold-compiling shaders for a
newly-seen *equipped* model and dying there. Character pick is the first
heavy renderer work of a session, and there is no persistent shader cache on
this path, so every launch compiles cold. The data can be perfectly correct
and the crash still happens.

**Rule:** changing which items are *equipped* changes what must compile at
pick. When experimenting with loadouts, introduce as few never-before-rendered
models per experiment as possible - one new weapon model is a clean test,
several at once is not, because a crash then cannot be attributed. If a
pick-time crash follows a loadout change, revert the loadout before touching
anything else.

## "My settings change does nothing"

Before suspecting the feature:

| Symptom | Verdict | Action |
|---|---|---|
| Client ignores your server edits entirely, or vice versa | You edited the wrong one of the two config files. They look alike and live in different trees. | Server-side keys go in `<server home>/Sunrise/settings.json`; client-side keys go in `Game/bin/x64/Sunrise/settings.json`. |
| A specific key has no effect anywhere | The key name is misspelled. Unknown keys are skipped silently - no error, no log line (see [CONFIGURATION.md](CONFIGURATION.md) traps). | Diff the key against the parser-documented names; copy-paste rather than retype. |
| Logging stays quiet after enabling `file_sink` | Settings are read once at process start. | Restart the process after any config edit; there is no reload path. |
| Debug-level logging left on from a past session makes everything sluggish | File sink at debug levels is a real, measured cost during play. | Set `file_sink` back to `false` and levels back to `warn` when finished debugging. |

---

## General hygiene

- **Verify raw bytes before concluding.** Log *files* can truncate lines
  mid-value (a NUL byte followed by garbage inside a printed number). Any
  conclusion drawn from a mangled-looking log value should be re-checked
  against the raw file content or recomputed from source data.
- **One change per test.** When a boot fails after multiple config edits,
  revert to the last known-good pair of configs and re-apply edits one at a
  time. Two simultaneous variables cannot be attributed.
- **Back up persistence properly.** The server database uses write-ahead
  logging: copy the database file only while the server is stopped, and take
  its `-wal` and `-shm` siblings along with it. A raw copy taken under a live
  server can miss recent commits.
- **Keep unlock flag banks curated.** The shipped client config's `state.unlocks`
  values are a known-good baseline. "Unlock everything" edits to those banks
  are the one config change with a documented history of breaking the join
  snapshot on an otherwise healthy server (see the fatal table above).
