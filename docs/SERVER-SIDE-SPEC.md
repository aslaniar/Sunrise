# Destiny 2 (Season of Arrivals) — Server-Side Protocol & Client-Contract Spec

A consolidated reference for the **client–server wire contract** of the Destiny 2
Season-of-Arrivals build (world content 84291.x, 2020-07-16), last revised
2026-08-22, derived from
binary reverse-engineering of `destiny2_unpacked_full.exe` cross-checked against
the working **Sunrise** server implementation (github.com/stanuwu/Sunrise, the
in-process server this project forked). It documents what a compatible private
server must speak, in the order the client expects it.

**Status legend.** Every claim is marked **VERIFIED** (measured against the
client binary, the working server, or live captures) or **INFERRED** (model
built from adjacent evidence; equivalent to the activity-handbook's
CONFIRMED/CURRENT-SOURCE split). Addresses are image VAs of the analyzed client
(base 0x140000000) and are provided as *anchors for further study*, not
requirements.

**Scope.** This is the *protocol and data-contract* side. It deliberately
excludes: game content extraction recipes, the flag/unlock semantics (separate
documents), and any discussion of bypassing authentication to live services.
This project's posture is airtight: our server talks to our client only, never
to Bungie's infrastructure.

---

## 1. Architecture in one page

- The client is a normal Arrivals-era Destiny 2 client. A hook DLL
  (`steam_api64.dll` shim) redirects its outbound network paths to the private
  server: it rewrites the SignOn URL authority, answers the UDP discovery
  probes, and patches the package-trust check so the game accepts its own
  content files.
- The server implements the **Demonware-lineage** stack the client expects:
  - **SignOn** — an HTTPS POST exchange that mints the session tokens.
  - **BAP** — the message protocol over TCP (a Bungie Activision Protocol
    family; the client's code region is named `bap_connection`).
  - **queuez** — the *subscription/object-store* layer on top of BAP. Families:
    **0 = banner**, **3 = roster**, **4 = account/inventory**, **5** and **7** =
    co-registered companion state. All persistent game state travels as
    "family objects" over queuez.
- Message flow: **request (c→s)** → reply (s→c), and **push (s→c)** — pushes
  carry the queuez family-object updates that keep the client's store in sync.

Verified end-to-end: the external-mode server completes the full boot pipeline
(discovery → signon → channel → roster → character select → orbit → Tower walk).

---

## 2. Discovery (UDP 3074/3075)

The client probes for its platform-relay on UDP before anything else.
The private server answers both probe types:

| probe | expected answer |
|---|---|
| **NatProbe** | echo the 4-byte magic + address ^ 0x76C3F6BC (big-endian) + port ^ 0xF6BC (big-endian) |
| **IpDiscovery** | type + v2 (LE) + address (BE) + port (LE) |

VERIFIED. The NAT type must read "open" in-game for the session to proceed.

---

## 3. SignOn (HTTPS POST)

The client POSTs to `SignOn?platform=%s&build=%s` (content type
application/octet-stream) carrying its platform ticket (`cs_signon_token`),
against hosts in the `signon.gravityshavings.net` / `signon.deadorbit.net`
namespaces. The hook rewrites the URL authority to the private server.

The success response is a protobuf with fields 1–7, 12, 14–16: platform token,
session token, channel keys, expiry, relay address, relay port, content
version, plus the environment/bootstrap fields. The working server's response
is ~372 bytes: a varint header + a 220-byte hello (tokens + relay), the
bootstrap token `<shared secret - set your own>`, the platform string `d2legacy`, the relay
`127.0.0.1:<bap_port>`, and the content-config URLs (`http://127.0.0.1/cfg_{a,b,c}/`).

Client-side processing (VERIFIED): a readiness state machine feeds a **4-slot
token store**; success flows into the BAP connection setup. The relay address
is stored as a **network-order-packed varint** — and the client reads it native
little-endian. Known real-world consequence: a packed `127.0.0.1` dials as
**1.0.0.127** (a legendary client bug we reproduce faithfully, not fix).

---

## 4. Secure channel (BAP framing + AES-GCM)

Two message tiers matter:

| tier | form |
|---|---|
| SignOn response envelope (svc 26) | u32BE length + 16-byte IV + 32-byte AES-CBC + 32-byte HMAC-SHA256 |
| BAP frames (after channel setup) | **AES-GCM**, 16-byte tag, 12-byte little-endian nonce (advancing), wire layout `[16B tag][ciphertext]` |

The frame cipher is the client's Windows CNG stack (BCrypt AES-GCM,
`ChainingModeGCM`) — the same crypto the server's implementation uses
(BCRYPT_CHAIN_MODE_GCM). The frame seal/dispatch has a special case: **svc 25
(server hello) crosses in plaintext before the secure channel exists**.

The envelope wrap keys are derived deterministically from the shared
bootstrap token (HMAC-SHA256, domain-separated labels) rather than being
transmitted - so any process holding the token derives agreeing keys,
including an in-process SignOn responder running inside the client.

VERIFIED (imports, call shape; the tag/nonce sizes confirmed against the
working server's implementation).

---

## 5. BAP message layer

### 5.1 Frame format (per message)

```
outer: [0x01 magic][1B message type][u32 BE length]
inner: [u16 BE service][u32 BE task]      (responses add [u16 BE status = 200])
```

### 5.2 Dispatch model

The client dispatch is **table-driven**, not switch-driven (VERIFIED):

- A message-type registry maps each message ID to a handler object.
- Two accessor thunks resolve the arrays: the **receive/class** table
  (`FUN_14106F860`, 8 class descriptors of 18 method slots) and the
  **response/type** table (`FUN_14106F870`, 37+ per-type records of 12 slots).
- Handlers decode inbound payloads via a per-type descriptor, then route to a
  **response** path (pending-request completion) or a **push** path (family
  object apply).

### 5.3 Message space (the documented ID key space)

| ID | name | direction | notes |
|---|---|---|---|
| 6 / 7 | activityHostManager req/rsp | c↔s | |
| 8 / 9 | activityMessage (the svc-8 activity/entity push) | s→c event | entity/simulation content |
| 10 / 11 | webService req/rsp | c→s | the HTTP-ish service calls (see §8) |
| 12 / 13 | subscribeFamily req/rsp | c→s | queuez subscription |
| 14 / 15 | unsubscribe req/rsp | c→s | |
| 16 / 17 | activityHost req/rsp | c→s | |
| 18 / 19 | clientConfig req/rsp | c→s | |
| 21 / 22 | purchasedOffers req/rsp | c→s | |
| 23 / 24 | accountTranslation req/rsp | c→s | |
| 25 / 26 | **serverHello req/rsp** | s→c | plaintext-open; the channel bootstrap |
| 30 / 31 | **start req/rsp** | c→s | channel start |
| 32 / 33 | userMessage req/rsp | c→s | |
| 34 / 35 | skill req/rsp | c→s | matchmaking skill |
| 42 / 43 | matchmaking req/rsp | c→s | |
| 44 / 45 | clan req/rsp | c→s | |
| 110 / 112 | webServiceServer req/rsp | s↔s | |
| 121 / 122 | queuez register req/rsp | c→s | |
| **123** | **queuez update notification** | s→c | **the family object push carrier — the heartbeat of the whole system** |
| 171 | notification171 | s→c | |
| 250 / 251 | echo req/rsp | c↔s | keepalive |
| 300 | irc notification | s→c | relay |
| 302 / 303 | registerRelayClient req/rsp | c↔s | |
| 304 / 305 | signSteamCertificate req/rsp | s↔c | secure-channel setup |
| 306 / 307 | accountFromMembership req/rsp | c↔s | |

Key services a private server must answer to boot a character: **25/26, 30/31,
12/13, 121/122, 123, 250/251**, then the family pushes for 0/3/4/5.

The frame registry also defines request services 36/38/40/48 with matching
response services 37/39/41/49 (unnamed in current source). RULE: a request
service that expects a response must receive one - schema-valid neutral is
fine; silence parks the request in the client's pending ring and can stall
later service work. One-way notifications (9, 123) must never be answered.

---

## 6. queuez — the object-store/subscription layer

### 6.1 Wire format

A family update (carried by svc 123) is:

```
u32 familyCount
per family (21 bytes):
    u32  type              (family id)
    u64  rootSoid
    u32  version
    u8   flags             (bit: full-snapshot)
    u32  objectCount
per object (20 bytes):
    u32  id                (definitionId)
    u64  version
    u32  payloadSize
    u32  encoding          (1=tagReflection, 2=binaryDiff, 3=raw, 4=oodle)
payload ...
```

Raw payloads begin with a **u64 little-endian version prefix** equal to the
header version. Payload size is bounded client-side to ≤0x17818 bytes.

VERIFIED (client decode dispatcher + the working server's encoder).

### 6.2 Families

| family | content |
|---|---|
| 0 | **banner** — the account/character identity banner (record ≈ 3,856 B) |
| 3 | **roster** — one roster object (1,768 B) + one per-character record (3,904 B); Oodle-encoded only (no raw path); after the family-3 snapshot the server appends the family-4 snapshot then the family-0 banner pair ("retail's order") |
| 4 | **account / characters / instances / inventory / loadout / progression** — the persistence family |
| 5 / 7 | companion state (evaluated/derived state; co-register) |

### 6.3 Native object sizes (byte-exact)

| object | native size | notes |
|---|---|---|
| account | **96,280 B** | the whole account record |
| character | **46,928 B** | per-character record |
| item instance | **416 B** | |
| inventory row | **32 B** | defIndex u16 @0, instanceSoid u64 @8, quantity i32 @16, mutationSerial i32 @20, flags u32 @24 |
| roster object | **1,768 B** | accountSoid + a 1,688-byte block (10 character entries × 20 equipment refs) + primary/secondary index tables + flags |
| per-character roster record | **3,904 B** | identity, appearance, summary |

### 6.4 Family-4 account/character field anchors (verified client offsets)

These are the load-bearing offsets a server's family-4 encoder must publish
(native-layout byte offsets):

| offset | field |
|---|---|
| +0x2CC0 | equippedInstanceSoids (the equipped-items list) |
| +0x2BF8..+0x2CC0 | the 16 × 12-byte pending-mutation table |
| +0x2EB8 | summary sub-block (2 × 16-B entries: serial u64, state u8, defIndex u16) |
| +0x2EE0 | gate/definition slot block (u16 defIndex @+8, u8 state @+0x18) |
| +0x43F0 | character progression bank (127 rows, u16 defIndex @ row+0xC, 0xFFFF sentinel) |
| +0x4C18 | 64 × 200-byte record bank |
| +0x742C | **account flag bank: 12,300 bytes** (the diff-apply memcmps the whole region on every push) |
| +0x9348 | acquiredFlags / character-object bank |
| +0xB74C / +0xB74D | **content-change stamp** (2 bytes) |
| +0x10518 | the account's four 256-entry per-character blocks |

VERIFIED (client decompiles; many offsets later confirmed verbatim against the
working server's encoder).

### 6.5 Encodings

| encoding | meaning | client decoder |
|---|---|---|
| 1 | tagReflection (schema-driven field walk against the packed schema key) | `FUN_1404C74D0` |
| 2 | binaryDiff (vcdiff-style delta vs the stored snapshot) | `FUN_14034C190` |
| 3 | raw byte image of the native object (LE u64 version prefix) | `FUN_140351070` |
| 4 | Oodle-compressed snapshot | `FUN_1403512E0` |

Client intake (VERIFIED): svc-123 push → `FUN_1416F17A0` → `FUN_140E0F000` →
family header parse → per-object decode → **fresh apply** (first arrival) or
**diff apply** (byte-compare against the stored snapshot). The store is
partitioned per family (stride 0x81E8), with per-field dirty tracking and a
UI-refresh chain that fires on stamp changes.

**The content stamp (relevant to any server that wants UI state to stay
truthful):** the client compares the 0xB74C/0xB74D stamp between desired and
stored state; on difference it marks its change banks and refreshes the
affected UI lists. A static-zero stamp means the client never observes a
content change — the working server publishes an **FNV-1a-32 over the equipped
SOIDs** (truncated u16, lo/hi), which is loadout-stable and changes exactly
when equipment changes. VERIFIED (patch + live boots).

---

## 7. Content layer (packages)

The client reads its content from **Tiger package files** (`.pkg`):

- Header v38; **pkg_id lives at u16 @0x04** (a classic off-by-2 trap: reading
  @0x02 gets the platform field).
- Entries: `{reference u32, type_info u32, block_info u64}` (16 B each);
  file_type = (type_info >> 9) & 0x7F, subtype = (type_info >> 6) & 0x7;
  block start/offset/size packed in block_info.
- Blocks: 48 B records `{offset, size, patch_id u16, flags u16, 20 B hash,
  16 B GCM tag}`; flags 0x1 = compressed, 0x2 = encrypted, 0x4 = alternate
  cipher. Blocks of a set can live across **multiple patch files** (the
  patch_id field selects the sibling file).
- Decryption: AES-128-GCM with the Shadowkeep build's key pair; a 12-byte
  nonce derived from a fixed base + pkg_id. Decompression: **Oodle**
  (proprietary DLL from the local install).
- Content tags are addressed as `0x80800000 + (packageId << 13) + entryIndex`.

A standalone pure-Python decoder exists for this exact format as a companion
community package; whatever implementation you use, validate it byte-for-byte
against known-good tooling before trusting its output on patch-layer files.

---

## 8. The web-service surface (svc 10/11)

The client's "web service" calls ride the same BAP frames. The response
envelope (VERIFIED): a bit-reader decode → 16-bit opcode tag → schema
resolution → schema-driven field walk → `{u16 tag, payload pointer, u16 len,
schemaId}`. The commit path **gates only on the decode result** — status codes
and values are schema *fields*, not commit gates (a fact that burned several
attempts: the server's `StatusResponse{0, INT32_MIN}` decodes fine and the UI
still rolls back when the *after-image* state machine rejects the change).

---

## 9. World population / spawn recipe (S2)

- Spawn push wire: `{u32 id, u32 type, 132-byte body (0x420 bits), u32 len,
  payload}`; a 8192-slot **lease mask** (1024 B) rides in the payload; the
  client claims/purges entity slots against it.
- Landing zone (client): `FUN_1416F17A0 → FUN_1416F1800 → FUN_140E10C10 →
  FUN_140E0F000`. Slice-set transitions arrive as activity-state commands.
- Hash vocabularies (VERIFIED on 171/171 samples):
  - **tag names** = FNV-1a-32 (basis sentinel 0x811C9DC5 = "unnamed");
  - **spawn/bubble/activity names** = FNV-1-32 (multiply-then-xor, prime
    0x01000193). `fnv1("default") = 0x2EA8FB98`, `fnv1("") = 0x811C9DC5`.
- Spawn sets: tag class `kSpawnSetClass = 0x80809162`; point element class
  `0x80809164`; 48-byte points `{quat@0, position@16, nameHash@32}`. Census:
  386 sets / 8,892 points across 43 of 49 destinations.
- Entity replication schema (the per-property vocabulary from the client's
  string table): `position`, `translational_velocity`, `forward_and_up`,
  `body_vitality`, `shield_vitality`, `region_state`, `damage_sections`,
  `multiplayer_properties`, `parent_vehicle`, and ~30 more.

VERIFIED (client strings, decoders, live server emits).

---

## 10. Telemetry (Dead Orbit upload)

The client periodically uploads telemetry as HTTP "ticket drops" to
`dm-partnernet.upload.deadorbit.net:32556/ticket_drop` (hosts/path/port are
statically compiled: `0x141F16C00`-family config blob, retry counters 5/5/60,
auth tokens). The private server intercepts the URL and answers so the client's
retry loop stays bounded. Non-blocking by design; a private server can sink the
requests.

A fuller static reconstruction lives in the companion knowledge dump ("The
deadorbit telemetry pipeline"): multipart/form-data wire shape with an 18-field
XML metadata sidecar, the complete trigger-to-wire call chain, and a built-in
runtime endpoint-override hook. Two facts matter to server authors: (1)
external-server mode's URL rewrite intercepts these POSTs layout-agnostically;
(2) the embedded/local HTTP branch does NOT serve this route (an op-field
mismatch between builder and handler) - sink or redirect deliberately.

---

## 11. Client quirks a server must know (or faithfully reproduce)

1. **The relay byte-order bug** — packed network-order relayAddress dials
   `1.0.0.127`; the client logs/logs/connects with the byte-reversed address.
   A compatible server just listens on the (fixed) port; the client still
   connects if the dial target is worked around.
2. **Package pkg_id off-by-2** — the header's pkg_id is @0x04, not @0x02.
3. **The 0x6D6D marker sweep** — an encoder that pads record regions with a
   repeated marker corrupts the client's record-bank anchor (observed as a
   headless character model + invisible ship in live boots). Patch the sweep
   away; publish clean zeros + the real stamp.
4. **The content stamp** — static-zero stamps suppress UI refresh (worst
   symptom: the subclass swap cue-then-rollback). Publish the FNV-1a-32 stamp
   over equipped SOIDs.
5. **Commit = decode-only** — status fields are schema data, not gates; if the
   UI rolls back, the store's after-image rejected the change (family-4
   diff-apply), not the commit.
6. **Deployment shapes** - three proven configurations exist: embedded (server
   logic inside the game process; single machine), external with real TLS
   (native Windows host), and hybrid (the client DLL answers the TLS-requiring
   SignOn/config endpoints in-process while BAP/discovery stay external).
   Hybrid is mandatory on wine-on-macOS hosts, where inbound TLS handshakes
   never complete.
7. **Server-side ordering defect (standalone fork)** - never put authored
   characters/equipment (`state.characters`) in a SERVER config: equipment
   seeding runs before item definitions publish (the publisher is client-side
   code only) and the boot hard-fails at equipment seeding even though every
   hash exists in the cache. Characters belong in the client config; the
   standalone server persists them itself.

---

## 12. What a boot looks like (the full pipeline, verified)

1. UDP discovery answered (NAT reports open)
2. Steam shim signin (client-side)
3. SignOn POST → session tokens + relay + config URLs
4. ContentConfig GET → 19 entitlements in settings order + package rows + the
   config guid
5. Package registration (content rights from the entitlement handles)
6. BAP session: hello (25) → channel start (30) → relay/ssc (302–305) →
   subscribe (12/13, 121/122) → families
7. Character select: family-3 roster snapshot + family-4 account
   (96,280 B) + characters (46,928 B each) + family-5/7 companions
8. Join/activity: join burst 4→0→1→54 → roster/membership → queuez →
   destination, spawn sets, slice-set state

The working private server completes all eight stages.

---

## 13. Verification method & sources

- **Primary sources**: decompiles of the Arrivals client binary (all
  addresses bookmarked in the workspace's Ghidra project), cross-checked
  against the working Sunrise server implementation's encoders/decoders
  (queuez_update, roster_snapshot, character_record/layout.h,
  activity_message, secure_channel, family3/family4 datagen).
- **Live proof**: every feature passes byte-exact harness comparisons plus
  real boots (roster renders, world loads, characters persist across
  sessions).
- **Confidence conventions**: VERIFIED = measured/quoted/round-tripped;
  INFERRED = modeled from adjacent evidence and labeled as such.

---

## 14. Contributing / license

This document is a project artifact of a clean-room preservation effort. The
underlying game is © Bungie. It contains **no game content** — only protocol
formats, layouts, and behavior observations. It is released under CC0-1.0. The reference
server implementation is GPL-3.0 (github.com/stanuwu/Sunrise).

Corrections, reproductions on other patches, and implementation reports are
welcome — this spec is the shared basis for building compatible private
servers for the Arrivals build.