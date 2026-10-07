# Ghost Multi-Relay Identity Specification (draft 1)

Companion to `spec.md`. Defines how one account participates in servers hosted on independently operated relays, how identity survives the loss of any single relay, and the object shapes that make it work. Transport-agnostic: §12 binds it to today's HTTPS/WebSocket API; §13 reserves the QUIC/iroh binding.

Status: draft for implementation. Encodings reuse the conventions of `ghost-wire` (big-endian integers, `u16` length-prefixed strings, raw 32-byte keys). Where a shape already exists in code, this document states the file and keeps it unchanged.

---

## 1. Feasibility summary

Everything below composes mechanisms Ghost already ships:

| Needed | Already exists | Where |
|---|---|---|
| Self-certifying, hash-chained, signed identity log with chain validation | yes | `ghost-wire/src/idlog.rs` (`validate_chain`, `validate_entry`) |
| Relay derives active device set from the log and gates requests on it | yes | `ghost-relay/src/storage.rs` `device_keys`, `is_active_device`; `auth.rs` |
| Relay signs an append-only KT tree over log entries and serves inclusion and consistency proofs | yes | `ghost-relay/src/state.rs` `kt_append_and_sign`, `routes/kt.rs`, `ghost-wire/src/merkle.rs` |
| Relay emits external Remove proposals for revoked devices into every group it hosts | yes | `state.rs` `generate_removal_proposals` (requires `ExternalSendersExtension`, already added at group creation) |
| Self-validating MLS credential checked offline | yes | `ghost-core/src/mls/credential.rs`, `wire.rs` `validate_device_credential` |
| Invite tokens, external-commit join, GroupInfo upload | yes | `routes/invite.rs`, `client.rs` `join_by_invite` |
| Passphrase-encrypted recovery blob, pairing offer/response/provision | yes | `identity/export.rs`, `routes/pair.rs` |

New protocol surface: two identity-log entry types, a relay reference object, an "anchored entry" proof object, account registration and import endpoints, replication of two small account blobs to member relays, and a connection pool on the client. No new cryptographic primitives. The parts with the least precedent are the anchoring rule (§6.3) and re-homing (§9); both are small and testable in-process.

---

## 2. Terminology

| Term | Meaning |
|---|---|
| **Account** | An identity: master keypair, fingerprint `account_fp = BLAKE3(master_vk)`, identity log |
| **Device** | One installation with its own Ed25519 signing key, authorized by an identity-log entry |
| **Relay** | One deployment of `ghost-relay`: one process, one signing keypair `relay_vk` |
| **Server** | A community (text and voice channels) hosted on exactly one relay; many servers per relay |
| **Home relay** | The one relay that sequences an account's identity log and signs its KT checkpoints |
| **Member relay** | Any relay hosting a server the account belongs to; the home relay is also a member relay |
| **Mirror** | A member relay's copy of an account's identity log, with the home's proofs |
| **Anchored entry** | A log entry together with the home relay's inclusion proof and signed checkpoint |
| **RelayRef** | The portable reference to a relay: its signing key plus how to reach it |

Invariant: an account has exactly one home relay at any point in the chain. Content (messages, voice) never depends on the home relay being reachable.

---

## 3. Keys

| Key | Type | Derivation | Lives |
|---|---|---|---|
| Master | Ed25519 | `derive_ed25519_seed(seed)` as today | seed in recovery blob; today also on every device (audit C1; removal is independent of this spec) |
| Device signing | Ed25519 | random per device | OS keyring |
| Relay signing | Ed25519 | random at first start | `relay_keypair` table |
| Delegation signature | Ed25519 over `"ghost-delegation-v1:" ‖ device_vk ‖ account_fp ‖ idlog_seq` | unchanged | in credential |
| Transport (QUIC binding only) | Ed25519 | `HKDF-SHA256(ikm = device seed or relay secret, info = "ghost/transport/v1", L = 32)` | reserved, §13 |

Fingerprints and the delegation message are unchanged from `ghost-core/src/identity/mod.rs`.

---

## 4. RelayRef

A relay is identified by `relay_vk`; endpoints are hints that may change.

```
RelayRef:
  [version:1 = 0x01]
  [relay_vk:32]
  [endpoint_count:1]
  endpoint_count × Endpoint

Endpoint:
  [kind:1]           0x01 = HTTPS base URL (UTF-8), 0x02 = iroh EndpointAddr (postcard), 0x03..0xFF reserved
  [len:2]
  [bytes:len]
```

String form: `base64url_nopad(RelayRef)`. Maximum encoded size 512 bytes.

Rules:
- Clients key everything by `relay_vk`. Endpoints are refreshed from `GET /relay` (§12.1) and from any newer RelayRef seen in an invite, pairing code or `SetHomeRelay` entry for the same `relay_vk`.
- A RelayRef with zero endpoints is valid only inside a `SetHomeRelay` entry whose relay is already known to the reader.

Replaces: `relay_url` in invite links, pairing codes, recovery codes, the sealed pairing offer, config, and the `kt_state.relay_url` key.

---

## 5. Identity log v2

### 5.1 Entry envelope

Unchanged from `ghost-wire/src/idlog.rs` `LogEntry::to_bytes`:

```
[seq:8][prev_hash:32][account_fp:32][entry_type:1][timestamp:8][body_len:4][body][signature:64][has_counter:1][counter_signature:64?]
```

Signed message: `"ghost-idlog-v1:" ‖ canonical_bytes(entry)`. `entry_hash = BLAKE3(to_bytes)`.

### 5.2 Entry types

| Type | Code | Body | Signer | Counter-signer | Status |
|---|---|---|---|---|---|
| Genesis | 0x01 | `master_vk:32 ‖ device_vk:32 ‖ label` | master | new device | unchanged |
| AddDevice | 0x02 | `device_vk:32 ‖ label ‖ authorizer_key:32` | master or active device | new device | unchanged |
| RevokeDevice | 0x03 | `device_vk:32 ‖ revoker_key:32` | master or active device (not self) | none | unchanged |
| Recovery | 0x04 | `device_vk:32 ‖ label` | master | new device | unchanged |
| **SetHomeRelay** | **0x05** | `relay_vk:32 ‖ authorizer_key:32 ‖ ref_len:2 ‖ RelayRef` | master or active device | none | **new** |
| DeviceTransportKey | 0x06 | `device_vk:32 ‖ transport_pk:32` | the device itself | none | reserved for §13 |

`label` is `u16`-length-prefixed UTF-8 as today.

### 5.3 Chain rules added by this specification

`validate_entry` gains, in addition to its existing checks:

- **SetHomeRelay.** `authorizer_key` must be the master key or an active device; `signature` verifies under `authorizer_key`; `RelayRef.relay_vk` must equal the body's `relay_vk`. Effect: `state.home_relay_vk = relay_vk`, `state.home_relay_ref = RelayRef`, `state.home_set_at_seq = seq`.
- **Seq 2 rule for v2 accounts.** An account created under this specification MUST have a `SetHomeRelay` at `seq = 2`. A chain without any `SetHomeRelay` is a v1 account whose home is the relay that holds its genesis; relays expose that implicitly (§12.2 `GET /idlog` returns `home_relay_vk` = own key). Enforcement: a relay mirrors only accounts whose chain names a home, so a v1 account can use only its original relay until it appends `SetHomeRelay` there (clients do this on start).
- **Recovery.** Unchanged; a Recovery MAY be immediately followed by a `SetHomeRelay` (the "recover and re-home" batch, §10).
- `LogState` gains `home_relay_vk: Option<[u8;32]>`, `home_relay_ref: Option<Vec<u8>>`, `home_set_at_seq: u64`.

Authority note: `SetHomeRelay` carries the same authority class as `AddDevice` (any active device). It adds no capability an active device does not already have, since an active device can already authorize new devices.

---

## 6. Anchoring: how a mirror knows the home accepted an entry

### 6.1 The problem

Mirrors must never accept an entry the home has not sequenced, or two mirrors could hold divergent chains (device A appends to the home, device B appends to a mirror during a partition). Mirrors also must not need the home online to validate what they receive.

### 6.2 Checkpoint and proof shapes (unchanged, `ghost-wire/src/merkle.rs`)

```
Checkpoint (116 bytes):
  [magic:4][tree_size:8][root_hash:32][timestamp:8][signature:64]   signature by the home relay_vk over the first 52 bytes

InclusionProof (16 + 32·k bytes):
  [leaf_index:8][tree_size:8][path: k × 32]

ConsistencyProof (16 + 32·k bytes):
  [old_size:8][new_size:8][path: k × 32]
```

Leaf hash is `leaf_hash(entry_bytes)` as computed by `kt_append_and_sign` today.

### 6.3 AnchoredEntry

```
AnchoredEntry:
  [entry_len:4][entry: LogEntry bytes]
  [proof_len:2][inclusion_proof]
  [checkpoint:116]
```

Validity (checked by every mirror and every client):

1. `entry` extends the reader's current chain state (`validate_entry`).
2. `checkpoint.signature` verifies under the account's **current** `home_relay_vk` as established by the chain *including this entry* (so a `SetHomeRelay` entry is anchored by the relay it names). Entries before the chain's first `SetHomeRelay` are verified against the relay that first `SetHomeRelay` names, which is where the account was created; only a chain with no `SetHomeRelay` at all uses the serving relay's claimed home.
3. `inclusion_proof.tree_size == checkpoint.tree_size` and `InclusionProof::verify(leaf_hash(entry), checkpoint.root_hash)`.
4. `checkpoint.tree_size` is ≥ the largest tree size previously seen for that `home_relay_vk` in this account's chain (monotonic; equal size requires equal root). Entry checkpoints are taken at append time and are older than the home's current head; a reader talking to the home additionally checks that the newest entry's checkpoint is a prefix of the current head and that the head extends the last head it accepted (§6.5).

An entry that fails any check is rejected and the chain is not advanced. Anchoring is idempotent on `(account_fp, seq, entry_hash)`.

### 6.4 Who produces anchors

Only the home relay, at append time (`kt_append_and_sign` already produces the leaf and checkpoint; it gains "return the inclusion proof for this leaf"). Mirrors store anchors verbatim and serve them pass-through. Mirrors never run their own KT over mirrored accounts; one KT authority per account at a time.

### 6.5 Consistency across time

Clients keep `(home_relay_vk → last Checkpoint)` in `kt_state` and, when the home is reachable, fetch a `ConsistencyProof` between the stored and new tree sizes as today. When only mirrors are reachable, the monotonic rule (6.3 step 4) plus the head-hash gossip in application messages (`kt_head_hash`, extended to include `home_relay_vk` and `tree_size`) is the detection mechanism. There is no resolution protocol; detection surfaces to the user as it does today.

---

## 7. Credentials

Unchanged: the 136-byte self-validating `BasicCredential.identity` (`[account_fp:32][master_vk:32][idlog_seq:8][delegation_sig:64]`).

An earlier draft added `home_relay_vk` as a 32-byte hint. It was dropped (decision 2026-10-06): a receiver already obtains the sender's anchored log from the relay hosting the group, where every member is registered, so the hint locates nothing, and enlarging every credential has a cost.

Validation (`validate_device_credential`, `ghost-core/src/wire.rs`):

1. `BLAKE3(master_vk) == account_fp`.
2. `delegation_sig` verifies under `master_vk` over `"ghost-delegation-v1:" ‖ device_vk ‖ account_fp ‖ idlog_seq`.
3. **Revocation.** If the receiver's cached log for the account lists `device_vk` as revoked, the sender is rejected (application messages, commits, external joins, and added members alike). The delegation signature outlives a revocation, so without this check a revoked device remains valid to receivers until it is removed from every group (audit C2). A device the cache has not seen, for example one added since the last refresh, is not rejected; relays (which refuse revoked devices) and MLS removal are the barriers there.

## 8. Replicated account objects

Stored on the home relay **and** on every member relay. Written by the account's devices (client-driven replication, device-authenticated), never by relays. Last-writer-wins by `generation`; relays reject a lower or equal generation.

### 8.1 RecoveryBundle

```
RecoveryBundle:
  [version:1 = 0x01]
  [generation:8]
  [recovery_blob_len:2][recovery_blob]      today: 125-byte v3 blob from identity/export.rs (seed ‖ sync_key, Argon2id + AES-256-GCM)
  [master_blob_len:2][master_blob]          reserved for the encrypted master key once master_sk leaves devices (audit C1); 0 today
```

Size cap 8 KiB. Replaces the body of `PUT/GET /recovery/{fp}`. `generation` is the writer's clock in milliseconds, raised to one past the newest generation the writer has seen (a passphrase change reads the stored bundle first), so no read is needed before an ordinary write and a device's own writes never collide. A stored bare blob from before bundles is served as generation 0.

### 8.2 SyncSnapshot

Existing encrypted snapshot (`PUT/GET /sync_state/{fp}`, cap 256 KiB) gains an 8-byte `generation` prefix, chosen as for the RecoveryBundle with the device remembering its last written generation. MUST be written to the home; SHOULD be replicated to member relays, coalesced to at most one write per relay per 5 minutes. Loss of the snapshot loses settings, read marks, and the server list a recovering device rejoins from.

### 8.3 Identity log mirror

The anchored log itself (§6.3). Written by devices (push) and refreshed by relays (pull, §12.5). Not generation-versioned; the chain's own `seq` orders it.

---

## 9. Account lifecycle across relays

### 9.1 Account creation

Genesis is posted to the chosen home relay as today (self-authenticating). The device then posts `SetHomeRelay{relay_vk = home.relay_vk, authorizer_key = device_vk, RelayRef = home's ref}` as `seq = 2`. Both are anchored by the home.

### 9.2 Registering an account at a member relay

A relay cannot authenticate a device it has never heard of. Before a device's first authenticated request to relay R, it registers the account by pushing its full anchored chain (seq 1..head) as a self-delimiting sequence of `AnchoredEntry` to `PUT /idlog/{fp}/anchored?invite={token}` (§12.2). The batch authenticates itself through account signatures and home anchors; the credential travels in MLS and is not part of registration.

R validates the chain (§5.3) and every anchor (§6.3), stores the mirror, populates `device_keys` from `LogState.devices`, records `accounts.home_relay_vk`, and from then on treats the account's active devices as authenticatable. R SHOULD begin pulling updates from the home (§12.5).

Spam control: registration of an account R does not know is accepted only with a valid, unexpired invite token for a server on R (`?invite=`); pushes for an account R already holds need none. An invite admits the account's devices to DeviceAuth until the invite expires, long enough to post the first commits, after which mailbox membership keeps them admitted. Rate-limited per account.

### 9.3 Appending an entry (add device, revoke device)

1. Device submits the raw entry to the **home** (`PUT /idlog/{fp}`, device-authenticated, existing route).
2. Home validates, appends, signs a checkpoint, returns the `AnchoredEntry`.
3. Device pushes the `AnchoredEntry` to every member relay it knows (`PUT /idlog/{fp}` on each; mirrors accept only anchored entries).
4. Each mirror validates (§6.3), updates `device_keys`, and on a revocation closes that device's sessions and emits external Remove proposals into every group it hosts for the account (`generate_removal_proposals`, unchanged).
5. Independently, mirrors pull from the home on their refresh interval, so a device that failed step 3 does not leave a mirror stale for long.

Latency of the infrastructure barrier at a mirror is therefore min(client push, pull interval). The cryptographic barrier (remaining devices committing the MLS removals) is unchanged and immediate.

### 9.4 Home temporarily unreachable

Allowed: all messaging and voice; MLS removals by remaining devices; reading mirrors; pairing rendezvous (§9.5 steps 1–4). Blocked until the home returns: appending any entry (hence completing a device add or revoke in the log), recovery entry, sync-snapshot write to the home. Clients MUST surface "home relay unreachable; linking and recovery paused".

### 9.5 Pairing through any member relay

The rendezvous (offer, response, provision) is content-encrypted with the pairing secret and may be hosted by any relay that knows the account. The pairing code becomes:

```
ghost-pair:<base64url(RelayRef)>.<account_fp_hex>.<secret_hex>.<token_hex>
```

where `token` is a fresh 16-byte random value that the existing device registers with the offer. New-device endpoints (`GET /pair/{fp}/{token}`, `POST /pair/{fp}/{token}/respond`, `GET /pair/{fp}/{token}/provision`) are guest endpoints keyed by `(fp, token)`; the token closes the audit's unauthenticated-offer race. Pairing state is persisted in SQLite with a 10-minute TTL (today it is in memory). The final `AddDevice` goes to the home (§9.3). If the home is dead, the user re-homes first (§9.7).

Provision blob (unchanged layout, built in `commands.rs` `check_pairing`): `[master_sk:32][master_vk:32][delegation_sig:64][sync_key:32][gi_len:4][sync GroupInfo][count:2] count × ([len:4][ProvisionPayload]) [sync-state dump]`. `ProvisionPayload` gains the server's RelayRef (§11.2).

### 9.6 Recovery through any member relay

1. New device fetches `RecoveryBundle` from any member relay named in the recovery code `ghost-recover:<base64url(RelayRef)>.<account_fp_hex>` (rate-limited as today; OPAQUE replaces the bare fetch in a later revision).
2. Decrypts seed and sync key; derives master key; verifies fingerprint.
3. Fetches the anchored log from that relay; validates chain and anchors.
4. Creates `Recovery{device_vk, label}` (master-signed, counter-signed by the new device).
5. If the home is reachable: submits to the home (§9.3 steps 1–3), then rejoins groups by external commit as today.
6. If the home is unreachable: §9.7 with the Recovery entry included in the import batch.

### 9.7 Re-homing

Trigger: operator shutdown, prolonged outage, or user choice. Procedure:

```
ImportRequest:
  [version:1 = 0x01]
  [entry_count:2]
  entry_count × AnchoredEntry        existing chain with the OLD home's anchors (fetched from any mirror or the device's idlog_cache)
  [new_count:1]
  new_count × ([len:4][LogEntry])    1 or 2 raw entries: SetHomeRelay{relay_vk = NEW home} [Recovery]?
```

The `SetHomeRelay` comes first so every entry the new home anchors applies after the move that makes it home (§6.3 step 2). In the recovery case it is signed by the master key, which the recovery passphrase unlocks.

New home validation:

1. Validate the anchored prefix against the old `home_relay_vk` established by the prefix's own chain.
2. Validate the new entries extend the chain; the first MUST be `SetHomeRelay` naming the new home's own `relay_vk`, and only a `Recovery` may follow it.
3. Store the prefix with the anchors its previous home issued (they remain the proof for those entries), append only the new entries to the new home's KT tree, and return their `AnchoredEntry` objects.

The device then pushes the new anchored tail (at minimum the `SetHomeRelay` entry, which carries the new home's checkpoint) to every member relay. Each mirror: validates the `SetHomeRelay` entry under the chain, verifies the checkpoint under the relay_vk the entry names, switches `accounts.home_relay_vk`, and re-targets its pull subscription. The old home, if alive, receives the same entry and marks the account as moved (read-only).

Replicated objects (§8) are already on member relays; the device re-writes them to the new home.

KT discontinuity: clients that stored the old home's checkpoint accept the new home's first checkpoint because the `SetHomeRelay` entry that authorizes the new key is itself in the chain they verified. The window in which an old home could equivocate before the move is the same equivocation risk that exists without re-homing.

### 9.8 Server (group) relay disappears

Out of scope for identity; a community dies with its relay unless its creator re-homes the group: new mailboxes on a new relay, GroupInfo upload, a `RelayRef` update distributed inside the group as a metadata control message so members re-dial. Members keep local history. Specified in a later revision.

---

## 10. Membership and authentication at a relay

A relay authenticates a device if and only if:

```
exists accounts row for account_fp
  ∧ device_vk active in that account's mirrored LogState
  ∧ ( relay is the account's home
    ∨ account_fp ∈ mailbox_members for some mailbox on this relay
    ∨ a valid invite token for a server on this relay accompanies the request )
```

This is the same predicate in both bindings: the HTTPS binding evaluates it in `DeviceAuth` (today's `is_active_device` plus the membership clause); the QUIC binding evaluates it once per connection at accept (§13). Per-mailbox membership and creator checks remain per request, as today. A device that is revoked loses authentication at every relay as its anchored revocation arrives (§9.3).

---

## 11. Object changes in existing payloads

### 11.1 Invite link

```
ghost://join?r=<base64url(RelayRef)>&t=<base64url(token:32)>
```

Replaces `relay=<url>`. The unused `gpk` parameter from `spec.md` §11.1 is dropped.

### 11.2 ProvisionPayload and SyncServerMeta

Both gain a trailing field, `ProvisionPayload` after `mailbox_id` and `SyncServerMeta` after its channel list:

```
[relay_ref_len:2][RelayRef]        length 0 = the account's home relay
```

so linked and recovered devices learn which relay hosts each server. The field is last in both, so data written before it existed (stored sync snapshots) decodes with no relay. (`ghost-core/src/wire.rs`.)

### 11.3 InvitePayload

Unchanged; the RelayRef travels in the link, and the joiner records it on the server row.

### 11.4 Application message KT gossip

`kt_head_hash` (32 bytes) becomes `kt_head: [home_relay_vk:32][tree_size:8][root_hash:32]` so receivers can compare heads per home relay.

---

## 12. HTTPS/WebSocket binding (v1 transport)

All existing routes in `spec.md` §13 and `ghost-relay/src/routes/mod.rs` remain. Changes and additions:

### 12.1 Relay identity

```
GET /relay → 200
{ "relay_vk": hex, "protocol": 2, "ref": base64url(RelayRef), "kt_head": base64(Checkpoint) }
```

Replaces `GET /relay_key`. Clients pin `relay_vk` from the RelayRef they were given and reject a mismatch.

### 12.2 Identity log

```
PUT /idlog/{fp}            body: LogEntry (home only; genesis self-authenticating, others DeviceAuth)
                           → 201, body: AnchoredEntry
PUT /idlog/{fp}            → 409 on a relay that only mirrors the account, or for a SetHomeRelay naming another relay
PUT /idlog/{fp}/anchored?invite=
                           body: AnchoredEntry × n back to back (mirror; no credentials, self-authenticating;
                           invite required only for an account this relay does not hold)
                           → 201 { "home_relay_vk", "head_seq", "is_home" } | 403 unknown account without invite
                           | 404 unknown invite | 409 fork at a held seq | 422 chain or anchor fails
GET /idlog/{fp}?after_seq= → { "home_relay_vk": hex, "entries": [ { "seq", "anchored": base64(AnchoredEntry) } ] }
```

The `GET` response replaces today's `{entries[{seq,payload,inclusion_proof}], checkpoint}` with one anchored object per entry; the checkpoint is per entry because, after a re-home, entries carry checkpoints from different homes. Clients decode with one shared decoder in `ghost-core` (replacing the three parsers the code map found).

### 12.3 Account registration and import

```
POST /accounts/{fp}/import                 body: ImportRequest     guest, rate-limited; authenticated by the SetHomeRelay signature → 201, body: AnchoredEntry × n back to back (the newly sequenced entries)
GET  /accounts/{fp}                        → { "home_relay_vk": hex, "head_seq": n, "is_home": bool }   DeviceAuth
```

### 12.4 Replicated objects

```
PUT /recovery/{fp}     body: RecoveryBundle   DeviceAuth; 409 if generation ≤ stored
GET /recovery/{fp}     → RecoveryBundle       guest, rate-limited (5 per 15 min per fp, unchanged)
PUT /sync_state/{fp}   body: [generation:8][snapshot]   DeviceAuth; 409 on stale generation
GET /sync_state/{fp}   → [generation:8][snapshot]       DeviceAuth
```

### 12.5 Relay-to-relay (federation)

Pull only in this revision. A mirror refreshes each mirrored account from its home every `MIRROR_REFRESH_SECS` (default 30) and immediately after any client push for that account:

```
GET /idlog/{fp}?after_seq=   with header X-Ghost-Relay-Auth: <relay_vk_hex>:<timestamp>:<sig_hex>
                            sig over "ghost-relay-auth-v1:GET:/idlog/{fp}:<timestamp>" by the requesting relay's key
```

Implemented as `ghost-relay/src/federation.rs` (`GHOST_MIRROR_REFRESH_SECS`). A relay key alone proves nothing (anyone can make one), so the home serves a relay-authenticated pull only to relays the account granted:

```
PUT /accounts/{fp}/mirrors    body: relay_vk:32 × n    DeviceAuth; replaces the account's grant set
```

Devices keep the set equal to the relays hosting their servers (on join, rejoin and every log replication).

`GET /idlog/{fp}` accepts exactly three readers, because the log lists the account's devices: a device the relay admits (§10); the account's master key (`X-Ghost-Device` = master_vk, signed by it), which is how a recovering device reads the chain before any of its devices is active; and a granted relay via `X-Ghost-Relay-Auth`. Anonymous reads are refused. A new device polling for its `AddDevice` signs with its own key, which the relay starts accepting the moment the entry lands.

The home MAY rate-limit per requesting `relay_vk`. Push subscriptions are reserved for the QUIC binding.

### 12.6 Pairing

```
POST /pair/{fp}                          DeviceAuth; body: [token:16][offer]   → 201
GET  /pair/{fp}/{token}                  guest → offer
POST /pair/{fp}/{token}/respond          guest, body: response → 201
GET  /pair/{fp}/{token}/response         DeviceAuth → response
PUT  /pair/{fp}/{token}/provision        DeviceAuth
GET  /pair/{fp}/{token}/provision        guest
```

State persisted in `pairing` (§14.2), TTL 10 minutes, one active token per account. A second response to the same session is refused with 409, so nobody can replace the new device's answer. The code format implemented is `relay_url#account_fp_hex#secret_hex#token_hex` (16-byte token); the RelayRef form above is the target once codes carry RelayRefs.

### 12.7 Invite join at a foreign relay

Order for a device unknown to relay R: `GET /invite/{t}/join` (guest) → `POST /accounts/{fp}/intro?invite=t` → `POST /box/{mid}` external commits with DeviceAuth (now valid) → `POST /invite/{t}/join` refresh with `X-Ghost-Seq` as today. The relay records `mailbox_members` on commit acceptance as today.

---

## 13. QUIC/iroh binding (reserved)

Defined in `.claude/HYBRID_IMPLEMENTATION.md` §D; summarized here for the identity-relevant parts only.

- Transport keys per §3 are published with `DeviceTransportKey` (0x06) entries so relays map connection key → device → account from the mirrored log. Relays derive their transport key from the relay secret; `RelayRef` endpoint kind 0x02 carries the iroh `EndpointAddr`.
- The §10 predicate is evaluated once per connection in iroh's `after_handshake` hook on the member ALPN; the guest ALPN carries registration, pairing new-device, recovery and import.
- Federation pull (§12.5) becomes a relay-to-relay stream with push of new anchored entries.

Nothing in §§4–11 changes between bindings.

---

## 14. Storage changes

### 14.1 Client (`ghost-core/src/storage/schema.rs`)

```sql
CREATE TABLE relays (
    relay_vk   BLOB PRIMARY KEY,
    ref_bytes  BLOB NOT NULL,            -- latest RelayRef
    last_seen  INTEGER NOT NULL
);
ALTER TABLE servers ADD COLUMN relay_vk BLOB REFERENCES relays(relay_vk);
-- kt_state: PRIMARY KEY relay_url → relay_vk BLOB (migration: resolve each URL via GET /relay, re-key, drop URL)
-- idlog_state: + home_relay_vk BLOB, home_set_at_seq INTEGER
-- idlog_cache: payload becomes the AnchoredEntry bytes (+ anchored INTEGER NOT NULL DEFAULT 0 for legacy rows)
-- device_config: key 'home_relay_vk'
```

### 14.2 Relay (`ghost-relay/src/storage.rs`)

```sql
CREATE TABLE accounts (
    account_fp      BLOB PRIMARY KEY,
    home_relay_vk   BLOB NOT NULL,
    home_relay_ref  BLOB NOT NULL,
    is_home         INTEGER NOT NULL,     -- 1 if this relay is the account's home
    head_seq        INTEGER NOT NULL,
    last_refresh    INTEGER NOT NULL
);
-- identity_log: + inclusion_proof BLOB, checkpoint BLOB (NULL only on the home before anchoring completes)
CREATE TABLE recovery_bundle (
    account_fp BLOB PRIMARY KEY,
    generation INTEGER NOT NULL,
    data       BLOB NOT NULL,
    updated_at INTEGER NOT NULL
);                                        -- replaces recovery_blob
-- sync_state: + generation INTEGER NOT NULL
CREATE TABLE pairing (
    account_fp BLOB NOT NULL,
    token      BLOB NOT NULL,
    offer      BLOB,
    response   BLOB,
    provision  BLOB,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (account_fp, token)
) WITHOUT ROWID;
```

`device_keys` is unchanged and is now populated from mirrored logs as well as the home's own. The KT tables are unchanged and hold only entries this relay anchored as home.

---

## 15. Flows

Layer tags as in `flows.md`, plus `[home]` and `[mirror]` for the two relay roles and `[relay→relay]` for federation.

### Create account

1. `[core]` Generate seed, master key, device key; build Genesis (master-signed, device counter-signed)
2. `[home]` `PUT /idlog/{fp}` Genesis → anchored entry
3. `[core]` Build `SetHomeRelay{home.relay_vk, authorizer = device_vk, home RelayRef}` at seq 2
4. `[home]` `PUT /idlog/{fp}` → anchored entry; account row `is_home = 1`
5. `[core]` Store both anchored entries in `idlog_cache`; `device_config.home_relay_vk`

**On failure at step 4:** account exists without a `SetHomeRelay`; the client retries step 3–4 on next start; relays treat the account as v1-homed here meanwhile.

### Join a server on a foreign relay

1. `[app]` Parse `r` (RelayRef) and `t` from the link; `GET /relay` on an endpoint; pin `relay_vk`
2. `[mirror]` `GET /invite/{t}/join` → InvitePayload
3. `[core]` Read the full anchored chain from `idlog_cache`
4. `[mirror]` `PUT /idlog/{fp}/anchored?invite=t` → validates chain and anchors, creates `accounts` and `device_keys` rows, opens the invite's guest window
5. `[core]` External commit per channel; `POST /box/{mid}` with DeviceAuth
6. `[mirror]` Validates commits, records `mailbox_members`; `[relay→relay]` schedules refresh of the account from its home
7. `[core]` Store server with `relay_vk`; subscribe to its mailboxes on this relay's connection
8. `[sync]` `ServerProvisioned` with the RelayRef to linked devices

**On failure at step 4:** nothing persisted on either side; the invite remains valid.

**Issues:** step 3 can be large for long chains (bounded by entry count × ~300 bytes); a relay that already holds the account skips the entries it has.

### Revoke a device

1. `[core]` Build `RevokeDevice` (signed by this device)
2. `[home]` `PUT /idlog/{fp}` → anchored entry; home closes the revoked device's sessions and emits external Removes for its own groups
3. `[core]` For each known member relay: `PUT /idlog/{fp}` with the anchored entry
4. `[mirror]` Each validates, closes sessions, emits external Removes for its groups
5. `[core]` Remaining devices commit pending removals in every channel group (existing auto-commit path); rotate the sync key
6. `[relay→relay]` Mirrors that missed step 3 pick the entry up on refresh

**On failure at step 2 (home unreachable):** step 5 still runs, so the device loses access to all content; the log entry and session closures wait; the UI reports "revocation pending at home relay".

### Pair a new device through a member relay

1. `[app]` Device A: random secret and token; `POST /pair/{fp}` with sealed offer on any relay R both devices can reach
2. `[app]` Code `ghost-pair:<RelayRef(R)>.<fp>.<secret>.<token>` shown
3. `[app]` Device B: `GET /pair/{fp}/{token}` → offer; generate device key; `POST /pair/{fp}/{token}/respond`
4. `[app]` Device A: `GET /pair/{fp}/{token}/response`; build provision (with RelayRefs); `PUT /pair/{fp}/{token}/provision`
5. `[home]` Device A: `PUT /idlog/{fp}` AddDevice → anchored
6. `[core]` Device A pushes the anchored entry to all member relays
7. `[app]` Device B: `GET /idlog/{fp}` on R until its key is active; `GET /pair/{fp}/{token}/provision`; join groups by external commit on each server's relay

**On failure at step 5 (home unreachable):** provision is stored with a TTL; A retries the append; B waits with a visible status. If the home is dead, A re-homes first.

### Recover (home unreachable)

1. `[app]` Parse `ghost-recover:<RelayRef>.<fp>`; `GET /recovery/{fp}` on that relay → RecoveryBundle
2. `[core]` Decrypt; derive master; verify fingerprint; `GET /idlog/{fp}` → anchored chain; validate
3. `[core]` Build `SetHomeRelay{new home}` (master-signed) then `Recovery{new device}`; new home chosen by the user from relays in the recovered sync snapshot or typed in
4. `[home]` New home: `POST /accounts/{fp}/import` with the anchored prefix plus the two raw entries → anchored tail
5. `[core]` Push the anchored tail to every member relay in the recovered server list; each switches `home_relay_vk`, revokes old devices, emits external Removes
6. `[core]` Rejoin every server by external commit on its relay; re-write RecoveryBundle (generation + 1) and sync snapshot to the new home

**On failure at step 4:** nothing has changed anywhere; retry with another new home.

### Re-home (devices intact)

1. `[core]` Fetch anchored chain from `idlog_cache`; build `SetHomeRelay{new home}` signed by this device
2. `[home]` New home: `POST /accounts/{fp}/import` → anchored tail
3. `[core]` Push the anchored `SetHomeRelay` to every member relay and to the old home if reachable
4. `[mirror]` Each verifies the entry under the chain and the checkpoint under the new relay_vk; switches home; re-targets refresh
5. `[core]` Write RecoveryBundle and sync snapshot to the new home; update `device_config.home_relay_vk`; notify linked devices through the sync group

**Issues:** linked devices that are offline learn of the move from the chain when they next refresh; until then their appends target the old home and fail with 409, which triggers a chain refresh.

---

## 16. Security considerations

- **Enumeration.** Registering an unknown account requires an invite token; `GET /idlog` on mirrors requires DeviceAuth or relay auth; recovery fetch keeps its per-account rate limit.
- **Equivocation by a home.** Detected by anchored-checkpoint monotonicity at every mirror and client, and by `kt_head` gossip in application messages. Not resolved automatically; surfaced to the user. Unchanged class from today, now with more observers.
- **Revoked device with a valid delegation.** Rejected by every receiver whose cached log has the revocation, independent of relays (§7).
- **Hostile re-home.** Requires an active device key or the master key, the same authority that can add a device today. Every device shows a `SetHomeRelay` prominently when it appears in the chain.
- **Rollback of replicated blobs.** Prevented by `generation`; relays reject non-increasing writes.
- **Replay of anchored entries.** Idempotent on `(fp, seq, entry_hash)`.
- **Stale mirrors.** A mirror that misses pushes converges on refresh; clients prefer the home for KT consistency proofs when reachable. A revoked device remains unable to decrypt new content from the moment the remaining devices commit, regardless of mirror staleness.
- **What each party learns.** A member relay learns the account's full device history (already true of the home today). The home learns which relays refresh an account's log (which deployments the account belongs to); a device MAY omit refresh by pushing anchored entries itself, at the cost of staleness when it is offline. Nothing in this specification exposes message content to any relay.
- **No honor-system checks.** Every enforcement point is a signature verification at a relay or an MLS removal; a client that skips a check gains nothing.

---

## 17. Acceptance tests (phase 6 gate)

Named per the convention in `.claude/HYBRID_IMPLEMENTATION.md` §J; all run in-process with two or three relays.

- `accept_p6_sethomerelay_required_at_seq2_for_v2_accounts`
- `accept_p6_anchored_entry_rejected_without_valid_home_checkpoint`
- `accept_p6_anchored_entry_rejected_on_checkpoint_regression`
- `accept_p6_account_intro_requires_invite_token`
- `accept_p6_account_intro_populates_device_keys_and_allows_deviceauth`
- `accept_p6_join_server_on_foreign_relay_end_to_end`
- `accept_p6_linked_device_rejoins_server_on_foreign_relay`
- `accept_p6_recovery_rejoins_servers_on_foreign_relays`
- `accept_p6_revocation_pushed_to_mirror_closes_sessions_and_emits_removes`
- `accept_p6_revocation_pulled_by_mirror_within_refresh_interval`
- `accept_p6_revoked_device_cannot_decrypt_after_remaining_devices_commit_while_home_partitioned`
- `receiver_rejects_messages_from_a_device_its_log_shows_revoked` (replaces the dropped `accept_p6_credential_home_hint_mismatch_rejects_sender`)
- `accept_p6_recovery_bundle_replicated_to_all_member_relays_and_rollback_rejected`
- `accept_p6_pairing_via_member_relay_with_token`
- `accept_p6_rehome_import_anchors_whole_chain_and_mirrors_switch`
- `accept_p6_recover_with_dead_home_via_import_batch`
- `accept_p6_old_home_marks_account_moved_and_rejects_appends`
- `accept_p6_kt_state_migration_from_url_to_relay_vk`

---

## 17a. Implementation notes

- **Client routing.** The client keeps one connection set across relays: views onto other relays share subscriptions, the event stream and a mailbox-to-relay route table, so mailbox-scoped requests from any view reach the relay hosting the mailbox (`ghost-core/src/relay.rs`).
- **Member GroupInfo refresh.** A member that is not a group's creator may publish GroupInfo only when it proves exactly the relay's current group context (same epoch, tree hash and transcript hash, signed by a member leaf). Without this, devices of non-creator members cannot rejoin by external commit after any later commit.
- **Device removal vs account kick.** A receiver distinguishes "this device's leaf was removed while the account remains" from "the account was removed"; only the latter is propagated through the account's sync group.
- **Revocation order.** MLS leaf removal runs before the identity log append, so the cryptographic barrier holds when the home is partitioned; the log entry is retried later.

## 18. Open items

- OPAQUE for recovery-bundle fetch (replaces rate limiting as the only protection).
- Removing `master_sk` from devices (audit C1) and populating `RecoveryBundle.master_blob`.
- Server re-homing (§9.8).
- Push subscriptions for federation (QUIC binding).
- Whether registration should allow partial chains for very long logs.
