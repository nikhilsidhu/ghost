# Ghost Protocol Specification

**Version:** 0.1-draft
**Status:** Pre-implementation draft
**License:** AGPL-3.0

---

## Table of Contents

1. [Overview](#1-overview)
2. [Terminology](#2-terminology)
3. [Cryptographic Primitives](#3-cryptographic-primitives)
4. [Identity](#4-identity)
5. [Mailbox ID Derivation](#5-mailbox-id-derivation)
6. [Message Format](#6-message-format)
7. [Encryption](#7-encryption)
8. [Blob Format](#8-blob-format)
9. [Key Exchange](#9-key-exchange)
10. [Groups & Channels](#10-groups--channels)
11. [Invite Links](#11-invite-links)
12. [Voice Protocol](#12-voice-protocol)
13. [Relay API](#13-relay-api)
14. [Security Considerations](#14-security-considerations)
15. [TBD](#15-tbd)

---

## 1. Overview

Ghost is an encrypted, self-hosted chat protocol. Messages are end-to-end encrypted on the client and delivered through a relay that stores opaque blobs temporarily for text and forwards opaque packets for voice. The relay never has access to plaintext.

Groups, text channels, voice channels, direct messages. A single client can join groups across different relays.

### Design Principles

- **No accounts.** Identity is a keypair.
- **No permanent server state.** Blobs expire after 72 hours. Voice packets are never stored.
- **Forward secrecy.** Compromising current keys does not reveal past messages.
- **Self-hosted.** Single binary, zero dependencies.

---

## 2. Terminology

| Term | Definition |
|------|-----------|
| **Client** | A Ghost application running on a user's device |
| **Relay** | Stores and forwards encrypted blobs (text), forwards encrypted packets (voice) |
| **Group** | Members organized into text and voice channels, backed by a single MLS group |
| **Channel** | A named subdivision within a group (text or voice) |
| **Blob** | An opaque encrypted payload on the relay |
| **Mailbox** | A relay-side queue holding blobs, addressed by a mailbox ID |
| **Mailbox ID** | 32-byte identifier derived from cryptographic material |
| **Identity keypair** | Ed25519 signing key + X25519 agreement key, from the same seed |
| **Fingerprint** | BLAKE3 hash of a user's public signing key (32 bytes) |
| **Epoch** | MLS group state version; increments on membership changes or key updates |
| **SFU** | Selective Forwarding Unit — copies audio packets between participants without decrypting |

---

## 3. Cryptographic Primitives

Signing and key agreement use `ed25519-dalek` and `x25519-dalek`. Symmetric crypto uses `aes-gcm`. Group encryption via OpenMLS.

| Function | Algorithm | Reference |
|----------|-----------|-----------|
| Signing | Ed25519 | RFC 8032, `ed25519-dalek` |
| Key agreement | X25519 | RFC 7748, `x25519-dalek` |
| Symmetric encryption (direct) | AES-256-GCM | NIST SP 800-38D |
| Hashing | BLAKE3 | https://blake3.io |
| Key derivation (high-entropy) | HKDF-SHA-256 | RFC 5869 |
| Key derivation (passphrase) | Argon2id | RFC 9106 |
| Message encryption | MLS (TreeKEM) | RFC 9420, via OpenMLS |
| Audio codec | Opus | RFC 6716 |
| Secure random | OS CSPRNG | `rand::OsRng` |

MLS uses AES-128-GCM internally per the chosen ciphersuite. Direct encryption outside MLS (voice frames, identity export) uses AES-256-GCM.

**KDF selection rule:** HKDF for high-entropy input (seeds, shared secrets). Argon2id for anything derived from a user-typed passphrase.

### Wire Format Conventions

- Multi-byte integers: big-endian
- Strings: UTF-8, length-prefixed with u32

---

## 4. Identity

### 4.1 Key Generation

```
seed = CSPRNG(32)
signing_key = Ed25519_KeyPair::from_seed(seed)
agreement_key = X25519_KeyPair::from(HKDF(seed, info="ghost-x25519"))
```

Both keys derived from the seed. Only the seed needs backup.

### 4.2 Fingerprint

```
fingerprint = BLAKE3(public_signing_key)  // 32 bytes
```

Displayed to users as truncated hex (first 16 characters).

### 4.3 Display Name

UTF-8, max 64 bytes. Distributed via MLS metadata. No cryptographic weight.

### 4.4 Key Storage

The seed is stored in the OS keyring:

| Platform | Backend |
|----------|---------|
| macOS | Keychain Services |
| Windows | DPAPI (Credential Manager) |
| Linux | Secret Service API (via libsecret) |

Service name `ghost`, account name is the hex-encoded fingerprint.

### 4.5 Identity Export

```
export_key = Argon2id(passphrase, salt=CSPRNG(32), m=19MiB, t=2, p=1)
encrypted_seed = AES-256-GCM(export_key, nonce=CSPRNG(12), seed)
export_file = version(1) || salt(32) || nonce(12) || encrypted_seed(48)
```

93 bytes. Passphrase is user-provided. Argon2id provides memory-hard brute-force resistance (OWASP 2023 recommended parameters).

**Export scope:** Only the 32-byte seed is exported. MLS group state (epoch keys, ratchet trees) is NOT included and cannot be derived from the seed. Restoring from an export requires re-joining all groups and re-establishing DM sessions. Sessions are device-local, not transferable.

---

## 5. Mailbox ID Derivation

A mailbox ID is 32 bytes addressing a blob queue on the relay.

### 5.1 Group Mailbox

```
mailbox_id = BLAKE3(mls_group_id || "ghost-mailbox")
```

One mailbox per group. Channel routing happens inside the encrypted payload.

### 5.2 Direct Message Mailbox

```
shared_secret = X3DH(initiator, responder)
mailbox_id = BLAKE3(shared_secret || "ghost-dm-mailbox")
```

### 5.3 URL Encoding

Base64url (RFC 4648 §5, no padding) → 43-character string.

---

## 6. Message Format

### 6.1 Application Message

The plaintext unit before encryption:

| Field | Type | Description |
|-------|------|-------------|
| `version` | u8 | Protocol version (`0x01`) |
| `message_type` | u8 | See §6.2 |
| `channel_id` | 32 bytes | Target channel |
| `sender_fp` | 32 bytes | Sender fingerprint |
| `timestamp` | u64 | Unix milliseconds |
| `message_id` | 32 bytes | `BLAKE3(channel_id \|\| sender_fp \|\| timestamp \|\| content)` |
| `references` | u8 count + N × 32 bytes | Referenced message IDs |
| `content` | length-prefixed bytes | Type-specific payload |

Exact serialization finalized during implementation.

### 6.2 Message Types

| Type | Value | Content | Description |
|------|-------|---------|-------------|
| `TEXT` | 0x01 | UTF-8 string | Text message |
| `FILE` | 0x02 | File metadata + data | File attachment |
| `REACTION` | 0x03 | UTF-8 string (emoji) | Reaction to referenced message |
| `REPLY` | 0x04 | UTF-8 string | Reply to referenced message |
| `SYSTEM` | 0x05 | UTF-8 string | System event (join, leave, etc.) |
| `DELETE` | 0x06 | Empty | Tombstone for referenced message |
| `METADATA` | 0x07 | Metadata payload (§10.6) | Group/channel config update |
| `DM_WELCOME` | 0x08 | MLS Welcome message + target fingerprint | DM session initiation (§9.5) |
| `FRIEND_REQUEST` | 0x09 | Sender X25519 public key | Friend request (§9.6) |
| `FRIEND_ACCEPT` | 0x0A | Responder X25519 public key | Friend request accepted (§9.6) |

### 6.3 File Content

Filename, MIME type, file size, file data. Encrypted inline. Subject to relay blob size limit.

### 6.4 References

`REACTION`, `REPLY`, and `DELETE` reference the target message ID. Other types: typically empty.

---

## 7. Encryption

### 7.1 Group Encryption (MLS)

RFC 9420 via OpenMLS.

**Ciphersuite:** `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (0x0001)

```
plaintext = serialize(ApplicationMessage)
mls_ciphertext = mls_group.encrypt(plaintext)
```

Group operations (add/remove member, update keys) are MLS Commit messages sent through the same group mailbox.

### 7.2 Direct Message Encryption (MLS)

DMs are 2-person MLS groups. Same ciphersuite, same `create_message`/`process_message` API as group messages. Session establishment in §9.5.

```
plaintext = serialize(ApplicationMessage)
mls_ciphertext = dm_group.create_message(plaintext)
```

### 7.3 Voice Encryption

Per-frame AES-256-GCM. Each sender derives their own key from the MLS epoch secret:

```
sender_voice_key = HKDF-SHA256(
  ikm = mls_group.epoch_secret(),
  salt = channel_id,
  info = "ghost-voice" || sender_fp,
  length = 32
)
```

Per-sender keys prevent nonce reuse if a sender disconnects and reconnects within the same epoch (sequence reset is harmless because the key is unique per sender).

Nonce derived from sequence number, zero-padded to 12 bytes:

```
nonce = 0x00000000_00000000 (8 bytes) || sequence_number (4 bytes)
encrypted_frame = AES-256-GCM(sender_voice_key, nonce, opus_frame)
```

New keys on epoch change. ~500ms grace period for decrypting with old key during transition.

---

## 8. Blob Format

### 8.1 Submission (Client → Relay)

Raw ciphertext bytes. Mailbox ID is in the URL path.

```
HTTP:       POST /box/{mailbox_id}  body = ciphertext
WebSocket:  binary frame            data = ciphertext
```

Relay assigns a blob ID (UUID) and records a timestamp.

### 8.2 Delivery (Relay → Client)

Relay wraps payload with: `blob_id`, `received_at` (Unix ms), `payload`. JSON over HTTP, binary over WebSocket.

### 8.3 Size Limits

- Max blob: configurable, default 10 MB
- Max per mailbox: configurable, default 10,000
- Over limit → HTTP 413

---

## 9. Key Exchange

### 9.1 MLS Key Packages

Single-use bundles of public keys allowing group addition. Clients pre-generate a batch for the invite/join flow.

### 9.2 Group Creation

1. Generate random `group_id` (32 bytes)
2. Create MLS group: `mls_group_id = BLAKE3(group_id || "ghost-mls")`
3. Creator is sole initial member
4. Derive mailbox ID (§5.1), connect to relay

### 9.3 Member Addition (Invite + Join)

**Inviter:**
1. Generate invite token (§11), register with relay (§13.4)
2. Share invite link

**Joiner:**
1. Parse invite link → relay address, token, group public key
2. Submit KeyPackage to relay via `POST /join/{token}`
3. Wait for Welcome

**Inviter (on join request):**
1. Create MLS Welcome + Commit adding the new member
2. Commit → group mailbox (existing members update state)
3. Welcome → joiner via relay

**Joiner (on Welcome):**
1. Process Welcome → group state initialized
2. Derive mailbox ID, start listening

### 9.4 Member Removal

1. Creator issues MLS Commit removing the member's leaf
2. Commit includes UpdatePath — new keys from removed leaf to root
3. Remaining members process Commit, rotate state
4. Removed member has no new keys

### 9.5 DM Session Setup

DMs are 2-person MLS groups. Setup is bootstrapped through an existing group or friend connection:

1. Alice creates a 2-person MLS group, adds Bob's KeyPackage
2. Alice sends `DM_WELCOME` (type `0x08`) through the shared MLS group, containing the MLS Welcome message and Bob's fingerprint as target
3. Bob processes the Welcome, initializes the DM group, derives DM mailbox ID (§5.2)
4. Subsequent DMs go through the DM mailbox as MLS application messages

### 9.6 Friend Connections

Friends can DM and call each other independently of shared group membership. Friend list is stored locally on each device.

**Adding via direct link:**

```
ghost://friend?relay=<relay_address>&fp=<fingerprint>&xpk=<x25519_public>
```

1. Alice generates a friend link containing her relay address, fingerprint, and X25519 public key
2. Bob opens the link, performs X25519 DH with Alice's public key from the link to derive a shared secret
3. Bob encrypts a friend request (his fingerprint, X25519 public key, relay address) with AES-256-GCM using the shared secret, and POSTs it to Alice's personal mailbox: `BLAKE3(alice_fingerprint || "ghost-friend")`
4. Alice decrypts, verifies, accepts → encrypts a friend accept with the same shared secret and POSTs it to Bob's personal mailbox
5. Alice creates a 2-person MLS group with Bob's KeyPackage (exchanged in step 3/4), sends Welcome to Bob's friend mailbox
6. Bob processes Welcome, derives DM mailbox (§5.2)

The direct-link flow uses simple DH + AES-256-GCM for the friend handshake. Once keys are exchanged, the DM session is a standard 2-person MLS group. The `FRIEND_REQUEST`/`FRIEND_ACCEPT` message types (§6.2) are only used for the within-group flow.

**Adding within a group:**

1. Alice sends `FRIEND_REQUEST` (0x09) through the MLS group targeting Bob's fingerprint
2. Bob accepts → sends `FRIEND_ACCEPT` (0x0A) through the group, including his KeyPackage
3. Alice creates a 2-person MLS group, sends Welcome to Bob via `DM_WELCOME` through the group
4. Bob processes Welcome, derives DM mailbox (§5.2)

Once friends, DMs and voice calls work through the 2-person MLS group regardless of shared group membership. Removing a friend deletes the local friend entry and MLS group state.

---

## 10. Groups & Channels

### 10.1 Group Structure

- `group_id` — 32 bytes, random
- `name` — max 128 bytes
- `mls_group_id` — derived from `group_id`
- `mailbox_id` — derived from `mls_group_id`
- `creator_fp` — creator's fingerprint
- `channels` — text and voice
- `members` — list

One MLS group per group. All text channels share it. Channel routing via `channel_id` in the message header.

### 10.2 Channels

- `channel_id` — 32 bytes, random
- `name` — max 64 bytes
- `kind` — text or voice
- `position` — display order

Defaults: one text ("general"), one voice ("voice").

### 10.3 Text Channels

Logical divisions. Same mailbox, same MLS group. Clients filter by `channel_id`.

### 10.4 Voice Channels

Separate transport:
- Signaling over relay WebSocket
- Audio over UDP (SFU)
- Encryption key derived from MLS epoch secret + channel ID (§7.3)

No separate MLS operation to join — key material already available to all group members.

### 10.5 Members

- `fingerprint` — 32 bytes
- `display_name` — max 64 bytes
- `role` — creator or member
- `joined_at` — Unix ms

MLS GroupContext extensions carry only what's needed for cryptographic enforcement:

- **Group name** — for display after joining
- **Ban list** — so members can reject joins from banned fingerprints

Everything else (channels, member display names, roles, positions) is distributed via `METADATA` messages (§10.6) at the application layer. This avoids expensive MLS epoch rotations on non-cryptographic changes.

### 10.6 Metadata Updates

`METADATA` messages (type `0x07`) with an action and payload:

| Action | Description |
|--------|-------------|
| `GROUP_RENAME` | New name |
| `CHANNEL_CREATE` | New channel definition |
| `CHANNEL_RENAME` | Channel ID + new name |
| `CHANNEL_DELETE` | Channel ID |
| `CHANNEL_REORDER` | New position ordering |
| `MEMBER_UPDATE` | Updated member info |
| `DISAPPEARING_SET` | Channel ID + message TTL |
| `BAN_ADD` | Fingerprint to ban |
| `BAN_REMOVE` | Fingerprint to unban |

### 10.7 Blocking

**Personal blocks** — client-side only, never leaves the device. After MLS decryption, messages from blocked fingerprints are silently discarded before display. No protocol messages sent. The blocked user has no way to know they are blocked.

**Group bans** — distributed via `METADATA` messages with `BAN_ADD` (fingerprint) and `BAN_REMOVE` (fingerprint) actions. The banned member is removed via MLS Commit (§9.4). All members record the ban locally and reject future join attempts from the banned fingerprint. Creator-only action.

---

## 11. Invite Links

### 11.1 Format

```
ghost://join?relay=<relay_address>&token=<invite_token>&gpk=<group_public_key>
```

| Parameter | Encoding | Description |
|-----------|----------|-------------|
| `relay` | URL-encoded hostname:port | Relay address |
| `token` | base64url, 32 bytes | Invite token |
| `gpk` | base64url, 32 bytes | MLS group public key |

### 11.2 Invite Token

```
token_secret = CSPRNG(32)
token = BLAKE3(token_secret || group_id)
```

Inviter registers with relay (`POST /invite`) and records the hash in the group via a `SYSTEM` message.

### 11.3 Join Flow

```
Joiner                           Relay                         Inviter
  │                                │                              │
  │                                │  POST /invite (register)     │
  │                                │◄─────────────────────────────│
  │                                │                              │
  │  POST /join/{token}            │                              │
  │  Body: KeyPackage              │                              │
  │──────────────────────────────► │                              │
  │                                │  Notify inviter via WS       │
  │                                │─────────────────────────────►│
  │                                │                              │
  │                                │  MLS Welcome + Commit        │
  │                                │◄─────────────────────────────│
  │  Welcome message               │                              │
  │◄────────────────────────────── │                              │
  │                                │                              │
  │  Connect to group mailbox  │                              │
  │──────────────────────────────► │                              │
  │                                │                              │
```

### 11.4 Constraints

| Property | Default | Configurable |
|----------|---------|-------------|
| Single-use | Yes | Multi-use with max count |
| Expiry | 24 hours | Creator-configurable |
| Approval required | No | Creator can enable |

Expired or used → HTTP 410.

---

## 12. Voice Protocol

### 12.1 Signaling

WebSocket at `/voice/{channel_id_b64}`. JSON text frames:

**Client → Relay:**
- **Join** — encrypted presence blob (contains fingerprint, mute/deafen state, display name)
- **Leave** — departure
- **Presence** — updated presence blob (mute/deafen changes)

**Relay → Client:**
- **Assigned** — relay assigns `slot_id` (small integer) and UDP port
- **Welcome** — existing participants' presence blobs (sent on join)
- **Joined** — new participant's slot_id and presence blob
- **Left** — participant's slot_id
- **Speaking** — slot_id and speaking state (from VAD/PTT)

Presence blobs are encrypted with per-sender AES-256-GCM keys derived from the MLS group's shared secret. The relay cannot read them. Receivers trial-decrypt with each known sender's key to identify who sent it.

### 12.1.1 Voice State Broadcast

Voice join/leave/mute state is also broadcast over the mailbox WS so all server members see who's in each voice channel — not just in-call participants.

**Client → Relay (mailbox WS text frame):**
- `{"vs":{"ch":"<b64 channel_id>","p":"<b64 presence_blob>"}}` — join or mute change
- `{"vs":{"ch":"<b64 channel_id>","leave":true}}` — leave

**Relay → Client (mailbox WS text frame):**
- Same format, forwarded to all other mailbox subscribers
- Leave includes last known presence blob so receiver can identify who left
- `{"vs_snap":[...]}` — snapshot of all active voice participants, sent after replay on reconnect

### 12.2 Transport

All voice traffic goes through the relay SFU regardless of participant count. This keeps a single code path and avoids WebRTC NAT-traversal complexity.

### 12.3 Audio Packet Format (SFU)

UDP packets, 45-byte header:

```
[header_len:2][channel_id:32][slot_id:4][flags:1][seq:4][payload_len:2][payload...]
```

**Relay-readable prefix (first 38 bytes):**
- `header_len` — u16, total header size (always 45)
- `channel_id` — 32 bytes, identifies the voice channel
- `slot_id` — u32, relay-assigned per connection (not a fingerprint)

**Remainder of header:**
- `flags` — u8 (reserved)
- `seq` — u32, monotonically increasing sequence number
- `payload_len` — u16, length of encrypted payload

**Payload:**
- Encrypted Opus frame (AES-256-GCM ciphertext + 16-byte authentication tag)

Nonce derived from `seq` zero-padded to 12 bytes (§7.3), not transmitted. Receiver maps `slot_id` to a sender fingerprint (learned from the voice WS presence exchange) and selects the decryption key.

The relay reads only `channel_id` and `slot_id` for routing. Sender fingerprints never appear in the plaintext UDP header.

### 12.4 Audio Parameters

| Parameter | Value |
|-----------|-------|
| Codec | Opus |
| Sample rate | 48 kHz |
| Frame size | 20 ms |
| Channels | Mono |
| Bitrate | 32 kbps (adjustable 16-64) |

~80 byte Opus frame + header + encryption overhead = under 200 bytes per packet. 50 packets/sec/sender.

### 12.5 SFU Behavior

1. Receive packet
2. Read `channel_id` → look up routing table
3. Copy to all endpoints except sender
4. No buffering, reordering, mixing, transcoding, or decryption

Routing table maintained by signaling WebSocket.

---

## 13. Relay API

HTTP, WebSocket, and UDP. Default port 7700. TLS via reverse proxy.

### 13.1 Health

```
GET /health → 200
```

Returns version, uptime, active mailboxes, blob count, memory usage, voice stats.

### 13.2 Blob Mailbox (HTTP)

```
POST /box/{mailbox_id}             → 201 { blob_id }
Content-Type: application/octet-stream

GET /box/{mailbox_id}              → 200 { blobs: [...] }
X-Ghost-Long-Poll: <timeout_ms>     (optional, default 30s)

DELETE /box/{mailbox_id}/{blob_id} → 204
```

### 13.3 Blob Mailbox (WebSocket)

```
WebSocket: /ws/{mailbox_id}
```

- Client sends binary frame → relay acks with blob_id
- Relay pushes blobs as binary frames (blob_id, timestamp, payload)
- Client sends delete confirmation
- Ping/pong heartbeat every 30s, 10s timeout

### 13.4 Invite Management

```
POST /invite                       → 201
Body: { token, mailbox_id, max_uses, expires_at }

POST /join/{invite_token}          → 202 (waiting for inviter)
Body: MLS KeyPackage

POST /welcome/{invite_token}       → 204
Body: MLS Welcome message

GET /welcome/{invite_token}        → 200 (Welcome) or 204 (timeout)
X-Ghost-Long-Poll: 30000
```

Join requests pushed to group mailbox WebSocket.

### 13.5 Voice

```
WebSocket: /voice/{channel_id}     → signaling (§12.1)
UDP: configured port range          → audio packets (§12.3)
```

### 13.6 Error Codes

| Status | Meaning |
|--------|---------|
| 200 | Success with body |
| 201 | Created |
| 202 | Accepted (pending) |
| 204 | No content |
| 400 | Malformed request |
| 404 | Not found |
| 409 | Conflict (duplicate) |
| 410 | Gone (expired/used) |
| 413 | Payload too large |
| 429 | Rate limited (`Retry-After` header) |
| 507 | Storage full |

### 13.7 Rate Limiting

Per-IP on all endpoints. Configurable. Defaults TBD.

### 13.8 Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `GHOST_PORT` | 7700 | Listen port |
| `GHOST_TTL` | 72h | Blob TTL |
| `GHOST_MAX_BLOB_SIZE` | 10 MB | Max blob size |
| `GHOST_MAX_MEMORY` | 512 MB | Memory ceiling |
| `GHOST_VOICE_PORT_RANGE` | 10000-10100 | SFU UDP ports |
| `GHOST_MAX_VOICE_PARTICIPANTS` | 25 | Per-channel cap |

---

## 14. Security Considerations

### 14.1 Relay Visibility

**Sees:** IP addresses, mailbox IDs (opaque hashes), blob sizes and timing, voice channel participation (slot IDs, not fingerprints), activity patterns.

**Cannot see:** message content, audio content, group/channel/member names, which group a mailbox belongs to, who is speaking (slot IDs are opaque to anyone without voice WS context).

### 14.2 Forward Secrecy

- **MLS:** each epoch produces new key material, old secrets deleted
- **Double Ratchet:** each message uses a new key, old keys deleted
- **Voice:** key rotates on epoch change

### 14.3 Post-Compromise Security

- **MLS:** Update Commit re-keys a compromised leaf, restoring confidentiality
- **Double Ratchet:** next DH ratchet step restores security

### 14.4 Replay Protection

- **Text:** MLS and Double Ratchet message counters reject replays
- **Voice:** sliding window on sequence numbers per sender

### 14.5 Denial of Service

Per-IP rate limiting, memory ceiling, mailbox depth limit, blob TTL, voice participant cap. Relay does no computation on payloads.

### 14.6 Metadata Minimization

No accounts, no user database on the relay. Mailbox IDs are opaque hashes. Blobs deleted on confirmation or expiry. Voice packets never stored. No logging by default.

For IP privacy: VPN or Tor.

### 14.7 Device Security

Keys in OS keyring. Local database encrypted (SQLCipher). Optional app-level PIN/biometric. Per-channel disappearing messages.

---

## 15. TBD

Features not yet designed.

### 15.1 Should add

**Message editing** — `EDIT` message type referencing original ID with new content. Original replaced in UI, no edit history preserved.

**@mentions** — Content convention. Clients parse `@<fingerprint_prefix>`, resolve to display name. No protocol change.

**Channel categories** — Collapsible channel groupings. Group metadata. Category field on channels.

**Message formatting** — Markdown rendering in the client. Client-side only.

**Message pinning** — Exempts message from disappearing TTL. Open questions: who can pin, how to display.

**Disappearing messages** — Per-channel TTL for local retention. Open questions: default TTL, minimum floor, silent expiry vs. tombstone.

**Slowmode** — Per-channel cooldown between messages per user. Channel metadata, client-side enforcement.

### 15.2 Worth exploring

**Screen sharing** — Encrypted screen capture through SFU, same key derivation as voice. Heavy: video encoding, bandwidth, frame rate. Post-v1.

**Video calls** — Same as screen sharing but webcam. Same complexity.

**Threads** — `thread_id` reference in application message. Messages with the same thread_id form a thread. Moderate protocol and UI work.

**Audit log (local)** — Local record of moderation actions visible to creator. Not sent to relay.

**Roles and permissions** — Creator → moderator → member. Distributed as member metadata. Adds permission checks to every moderation action. Worth it above ~20 members.

**Bots and integrations** — Every participant must hold MLS group keys. A bot is a full group member with a keypair running ghost-core. Discord-style webhooks (unauthenticated HTTP POST) are impossible without breaking E2E. Integrations are long-lived processes using ghost-core as a library. A bot SDK would lower the barrier.

**P2P voice** — Direct connections for small calls, bypassing the SFU. Lower latency but adds a second voice codepath and requires WebRTC NAT traversal. Not worth the complexity unless SFU latency proves insufficient.

**Audio streaming bots** — Bot joins voice channel, streams audio from external source. Same as any voice participant: MLS member, derives voice key, encrypts Opus frames. Existing Discord music bot patterns adaptable with a ghost-core wrapper.

**Mobile clients** — iOS and Android. ghost-core is a Rust library exposable via FFI. Protocol and encryption are platform-independent. Desktop first, mobile after desktop is solid.

### 15.3 Excluded

**Presence / online status** — Requires continuous state reporting to the relay, leaking user activity patterns.

**Read receipts** — Requires reporting read state back through the relay per message.

**Typing indicators** — Same as presence. Leaks when a user is active.

**Link previews** — Fetching URL metadata leaks which links are shared to the target server.

**Rich user profiles** — No accounts, so no persistent profile. Display name and fingerprint are sufficient.

**Server discovery** — Requires a central index. Ghost is invite-only.
