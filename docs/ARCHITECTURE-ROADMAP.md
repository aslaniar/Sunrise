# Architecture roadmap

This fork extends stanuwu/Sunrise (the GPL-3.0 Destiny 2 Season-of-Arrivals
exploration mod) into a standalone, cross-platform dedicated-server setup with
persistent inventory and equipment. This document maps the tree as it exists
today: what each directory does, what is confirmed working, and where the open
fronts are. Every cited path is in the tree at the time of writing.

---

## 1. Component map

The project splits into six top-level directories under `Sunrise/src/`, split
by responsibility rather than by build target. The client DLL and the standalone
server binary share `src/middleware/` and `src/core/`; everything else is owned
by one side.

### src/client - the in-process mod

Code that lives inside the game process. `src/client/hooking/detour/` holds the
function-hooking machinery; `src/client/patterns/` locates engine code by byte
signature; `src/client/hooks/` applies it: outbound traffic is intercepted in
`src/client/hooks/egress/` (winsock connection/control/discovery layers), the
content-manifest handshake in `src/client/hooks/network/content_config/`,
signon in `src/client/hooks/network/signon/`, and family-4 replication intake
in `src/client/hooks/queuez/`. The same DLL doubles as the extraction tool:
`src/client/content/` (items/packages, scenarios, spawn_sets, vendors,
investment) walks installed game packages and feeds the server's cache.
In-process integration points - answering the TLS-requiring endpoints directly
from inside the client - sit in `src/client/runtime/host/`.

### src/middleware - wire codecs and stateless parsing

Shared protocol layer, safe to use from either side because it owns no global
state. `src/middleware/bap/` implements the BAP service surface (activity host
manager requests/responses, matchmaking, activity messages, account
translation). `src/middleware/datagen/` encodes the replication records:
family3/family4 character and account state, item instances
(`datagen/family4/instance/`), inventory snapshots, loadouts, progression, and
account preferences (`datagen/family4/account/preferences/`).
`src/middleware/content/packages/` reads package containers;
`src/middleware/crypto/` and `src/middleware/secure_channel/` cover session
crypto; `src/middleware/gameplay/` covers DTLS associations and group sessions;
`src/middleware/web_service/messages/` handles the numbered web-service opcodes.

### src/server - the standalone dedicated server

The new capability of this fork. Entry point `src/server/runtime/server_main.cpp`.
Encrypted BAP handling lives under `src/server/bap/encrypted/`: request routing
(`routing/`), reply assembly (`reply/`), server pushes (`push/activity/`,
`push/snapshot/`, `push/queuez/`), transaction staging (`queuez/staging/`),
matchmaking, and activity host management. Gameplay transport (DTLS endpoints,
group/host sessions) sits in `src/server/gameplay/`. Plain HTTP surfaces are
`src/server/http/` (config/manifest listener + TLS) and `src/server/admin/`.
Durable storage is `src/server/persistence/` (sqlite-backed; see section 2).

### src/state - transactional process-owned state

Everything the server asserts about the world, held in memory behind a single
ownership boundary. `src/state/build_data/` is the extracted-content universe:
item details and socket plugs, socket entry lists/buckets, ability buckets,
progressions, scenario catalogs (`build_data/scenarios/`), spawn-set catalogs
(`build_data/spawn_sets/`), vendor tables, and the versioned on-disk cache in
`build_data/cache/` with explicit read/write/validation sublayers.
`src/state/account/` holds account/inventory/settings aggregates;
`src/state/activity/` holds destinations, entity-slot leases, membership, and
bubble authority, each with a `transactions/` sublayer so mutations commit or
roll back as units. `src/state/equipment/light/` computes gear light levels;
`src/state/runtime/` owns boot-time initialization (`runtime.h`) and storage.

### src/steam - platform emulation

A minimal Steamworks stand-in so the client's platform calls resolve against
our environment instead of Valve's back end. Interface methods live in
`src/steam/interfaces/methods/` (apps metadata/DLC, friends, matchmaking,
serialized networking, signon inputs), backed by vtable shims in
`src/steam/interfaces/tables/` and callback dispatch in
`src/steam/runtime/callbacks/`.

### src/core - settings, logging, UI

Cross-cutting infrastructure shared by both binaries. Typed settings trees per
consumer in `src/core/settings/` (`client/external/`, `server/gameplay/`,
`state/`, `steam/`). Logging with snapshot/view helpers in
`src/core/logging/`. The in-game overlay UI (components, HUD modules, themes)
in `src/core/ui/`.

---

## 2. What works today (CONFIRMED by daily use)

These are load-bearing behaviors exercised every session, not aspirations:

- Destination loads through the standalone server (e.g. the Tower) with the
  full activity join sequence served locally.
- Full inventory and equipment persistence in sqlite: items, their plug lanes,
  equipment slots, and instance state survive restarts via
  `src/server/persistence/persistence.cpp`.
- Subclass and ability swapping, committed to persistence and re-stamped into
  the content-cache identity header automatically (see
  `src/server/bap/encrypted/push/queuez/queuez_subclass_equip.cpp`).
- Account-preferences publishing from authored settings
  (`src/middleware/datagen/family4/account/preferences/`). Note this flow is
  one-way by design; there is no in-game write-back path yet.
- The standalone server builds and runs on Windows natively and on macOS under
  wine (see the reference knowledge dump's Mac-port section for the hybrid
  layout that makes macOS work).

---

## 3. Stubs and open fronts

Each front lists its entry-point files. These are honest stubs or bounded
limitations, not hidden features.

### World population / static entities

Destinations load, but they are empty stages: no static actors, props, or
enemies yet. Entry points:

- `src/server/bap/encrypted/push/activity/activity_world_population_push.cpp`
  - the push channel intended to carry world population.
- `src/state/build_data/scenarios/` - scenario catalog (definitions plus
  builder) already extracted from installed data.
- Spawn-set catalogs: `src/state/build_data/spawn_sets/` (server side) and
  `src/client/content/spawn_sets/` (extraction/catalog building, including
  `spawn_set_catalog_builder.cpp`).

The catalogs exist; wiring them into entity creation through the existing
entity pipeline is the next big step, and it is also prerequisite work for
cross-player visibility (section: guest accounts below).

### Multiplayer remote-connect

Transport already supports multiple peers (connection/association/session
tables are sized for several clients), but every listener binds loopback only.
Five bind/config points must become configurable before a second machine can
connect:

- `src/server/admin/admin_http.cpp`
- `src/server/transport/discovery_listener.cpp`
- `src/server/transport/bap_listener.cpp`
- `src/server/http/https_listener.cpp`
- `src/server/http/tls.cpp` - the certificate subject is hardcoded to
  `CN=127.0.0.1` alongside the binds.

Making the bind address configurable (and generating a matching cert subject)
is the smallest complete change here; authentication itself derives from the
shared token and needs no extra infrastructure.

### Guest accounts

The server is currently a one-account system:

- `src/state/runtime/runtime.h` - `initialize()` takes a single
  `initialAccount`, and sign-on returns THE immutable session.
- `src/server/persistence/persistence.cpp` - `seed_account_id()` seeds every
  row (characters, items, flags, entitlements) under one primary SOID.

The good news: the sqlite schema already keys every player-owned table by
`account_id` (with uniqueness scoped per account), so multi-account support is
mostly about per-account state views and SOID ranges, not schema rework.

### Vendor storefronts

Vendor data is extracted and stored (`src/state/build_data/vendors/`), but no
storefront interaction loop is implemented or planned near-term. Parked.

---

---

## 4. Tips for iteration

Protocol work here tends to go better as small experiments than as big
rewrites. A few habits that have paid off:

- Change one thing at a time, and write down what you expect to happen -
  both if it works and if it doesn't - before running it.
- Mark how confident you are in what you wrote. A handful of labels
  (confirmed / inferred from X / hypothesis) keeps notes honest without
  slowing anything down.
- Keep dead ends written down somewhere. Re-running a refuted experiment is
  the most expensive way to learn nothing new - and a negative result only
  rules out what you actually tested.
- If a boot breaks after several changes at once, go back to the last
  known-good pair of configs and re-apply edits one at a time.

The handbook's method chapters are the fullest write-up of this approach.
