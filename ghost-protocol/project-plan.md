# Ghost — Project Plan

Open source, self-hosted, encrypted group chat with voice. No accounts, no server-side data, no background activity. Desktop only (macOS, Windows, Linux).

---

## Architecture

```
┌─────────────────────────────────────┐
│        Tauri 2 Desktop App          │
│        SolidJS + TypeScript         │
├─────────────────────────────────────┤
│          Rust Core Library          │
│  ┌──────────┬──────────┬──────────┐ │
│  │ Protocol │  Crypto  │ Storage  │ │
│  │  Logic   │  OpenMLS │ SQLCipher│ │
│  │          │  dalek   │          │ │
│  └──────────┴──────────┴──────────┘ │
├─────────────────────────────────────┤
│            OS Keyring               │
└───────────┬──────────────┬──────────┘
            │              │
      WebSocket (TCP)   Raw UDP
      text, signaling   encrypted voice
            │              │
            ▼              ▼
┌─────────────────────────────────────┐
│             Relay (Rust)            │
│                                     │
│  Persistent Log     Voice Relay     │
│  (text messages)    (copy+forward)  │
│                                     │
│  SQLite + seq log                   │
│  Catch-up replay    No decryption   │
└─────────────────────────────────────┘
```

---

## Tech Stack

| Component | Technology | Reason |
|-----------|-----------|--------|
| Core library | Rust | Crypto libs are Rust-native, shared with relay |
| Relay | Rust (tokio, axum) | Same toolchain as core |
| Message encryption | MLS (OpenMLS) | Forward secrecy, key rotation, groups and DMs |
| Crypto primitives | ed25519-dalek, x25519-dalek, blake3, argon2 | Pure Rust, no OpenSSL |
| Local database | SQLCipher | Encrypted SQLite |
| Key storage | OS keyring | Keychain (macOS), Credential Manager (Windows), Secret Service (Linux) |
| Desktop app | Tauri 2 | Native webview, Rust backend |
| Frontend | SolidJS + TypeScript | Fine-grained reactivity, small runtime |
| Transport (text) | WebSocket over TCP | Persistent connection, reliable delivery |
| Transport (voice) | Raw UDP | Low latency, relay just copies packets |
| Voice codec | Opus | Low latency, adaptive bitrate |
| Noise suppression | nnnoiseless | RNNoise in pure Rust, no C dependencies |
| License | AGPL-3.0 | Copyleft |

---

## User Flow

### First Launch
1. Keypair generated silently, stored in OS keyring
2. Setup screen: choose display name, paste invite link or enter relay URL
3. If invite pasted: join group automatically, land in chat
4. If relay URL entered manually: empty interface, create or join a group

### Joining a Group
1. Receive invite link (contains relay URL + token)
2. Paste in app (or click deep link if registered)
3. App connects to relay, key exchange happens in background
4. You see channels, members, messages

### Sending a Message
1. App encrypts with group key, sends over WebSocket
2. Relay assigns sequence number, persists to log, broadcasts to connected clients
3. Recipients decrypt and display
4. Relay retains messages for catch-up (72h)

### Joining a Voice Channel
1. App opens WebSocket to relay for signaling (join/leave/speaking state)
2. Relay assigns a slot ID and UDP port, app opens UDP socket
4. Voice keys derived from the group's shared secret, audio encrypted per-sender
5. Relay copies your encrypted packets to other participants (cannot decrypt)
6. You receive others' streams, decrypt locally using their per-sender keys

### Kicking a Member
1. Creator removes member
2. Key rotation distributes new keys to everyone except kicked member
3. Kicked member can no longer decrypt text or voice

### Reconnecting After Being Away
1. WebSocket reconnects to relay
2. Client sends last seen sequence number, relay replays all missed messages in order
3. Key updates processed first, then messages decrypted and displayed

---

## Data Model

| Location | Contents | Lifetime |
|----------|----------|----------|
| Device | Messages, keys, contacts, groups, settings | Until user deletes |
| Relay (text) | Encrypted blobs awaiting delivery | 72h max, deleted on delivery |
| Relay (voice) | Nothing — audio packets forwarded immediately, never stored | Instant |

---

## Security Model

### Protected
- **Message content** — E2E encrypted, relay cannot read it
- **Voice audio** — E2E encrypted, relay forwards packets it cannot decrypt
- **Identity** — keypair only, no accounts, no email, no phone
- **Server data** — none stored permanently
- **Forward secrecy** — old keys deleted after use, past messages safe even if current keys compromised

### Visible to relay host
- IP addresses, mailbox activity, timing, blob sizes
- Voice: who is in a call and when (relay forwards their streams)
- Voice UDP header metadata (channel_id, relay-assigned slot ID) visible on wire — content is encrypted
- Message and voice content is never accessible regardless of who runs the relay

### Device security
- App-level PIN / biometric lock
- Disappearing messages (configurable timer per channel)
- Keys stored in OS keyring, not in application memory

### Invite security
- Single-use by default
- Configurable expiry
- Optional: creator must approve join requests

### Friends & DMs
- DMs are 2-person encrypted groups
- No fingerprint lookup on relay
- Invite token flow:
  1. A creates invite → relay returns short token
  2. A shares token out-of-band
  3. B redeems token → uploads key material for this invite only
  4. Relay delivers B's key material to A
  5. A creates 2-person encrypted group, welcome sent to B
- Tokens are one-time, rate-limited, expiring
- Same token system for group invites
- Fingerprints are for verification, not discovery

---

## Relay

Three responsibilities: persistent message log, key update ordering, and voice forwarding.

### Transport

Two transports, two ports:
- **WebSocket over TCP** (axum, default port 7700) — text messages, key updates, voice signaling, invite endpoints
- **Raw UDP** (default port 10000) — encrypted voice packets only

Future: QUIC to unify both onto a single UDP port. Deferred — WS+UDP is simpler to self-host.

### Text — Persistent Log

Every blob is wrapped in a 10-byte plaintext envelope: `[version:1][type:1][epoch:8]`. The relay parses only this envelope, never touches ciphertext.

```
WebSocket /ws/{mailbox_id}        → real-time blob push/pull with sequence numbers
GET /box/{id}?since=N             → catch-up replay from sequence N
GET /health                       → status check
```

Storage: SQLite table with per-mailbox monotonic sequence numbers.

**Key update ordering:** For key updates (type 0x01), the relay checks the epoch matches the current one. All blobs are stored regardless. Concurrent key updates for the same epoch get an `epoch_mismatch` hint; the client catches up and retries.

**Catch-up:** Client sends `last_seen_seq` on reconnect. Server replays all blobs with `seq > last_seen_seq` before switching to live mode.

**Recovery:** When a client falls too far behind (messages expired), it downloads group state from the relay and rejoins at the current epoch.

### Invites — Token Exchange

```
POST   /invites              → create invite (returns token)
POST   /invites/:token/redeem → redeem invite (upload KeyPackage)
GET    /invites/:id/response  → poll for redeemed KeyPackage
DELETE /invites/:id            → cancel invite
```

### Voice Relay

```
WebSocket /voice/{channel_id}  → signaling (join/leave/speaking/mute state)
Raw UDP on GHOST_VOICE_PORT    → encrypted audio packet forwarding
```

Voice signaling flow:
1. Client opens WebSocket to `/voice/{channel_id}`, sends `Join` with an encrypted presence blob
2. Relay assigns a `slot_id` and responds with `Assigned { slot_id, port }`
3. Client opens UDP socket to relay at the assigned port
4. Client sends encrypted Opus frames prefixed with `slot_id`; relay copies to all other participants
5. Participants exchange encrypted presence blobs over the voice WebSocket for key derivation
6. On leave: client sends `Leave`, relay removes from routing table

Voice packet format (45-byte header defined in ghost-wire):
`[header_len:2][channel_id:32][slot_id:4][flags:1][seq:4][payload_len:2] + encrypted Opus payload`

The relay reads the first 38 bytes for routing. The slot_id is relay-assigned, keeping sender fingerprints out of the plaintext header.

**Voice state sync:** Voice join/leave/mute state is broadcast over the mailbox WebSocket to all server members, not just in-call participants. Clients not in a call see who's in each voice channel via encrypted presence snapshots.

### Config (environment variables)

- `GHOST_PORT` — default 7700
- `GHOST_VOICE_PORT` — default 10000
- `GHOST_TTL` — default 72h
- `GHOST_MAX_BLOB_SIZE` — default 10MB
- `GHOST_MAX_VOICE_PARTICIPANTS` — default 25

---

## Repo Structure

```
ghost-protocol/     → protocol spec document (language-agnostic)
ghost-core/         → Rust core library (encryption, storage, protocol logic)
ghost-wire/         → shared wire format types (message envelopes, voice headers)
ghost-relay/        → Rust relay server (message log + voice relay)
ghost-app/          → Tauri desktop app (SolidJS shell around ghost-core)
```

---

### Phase 1: Protocol & Core Library

**1.1 — Protocol Spec**

- [x] Message format (header structure, payload envelope, version field)
- [x] Blob format (how encrypted payloads wrap for relay transport)
- [x] Mailbox ID derivation (how public keys map to mailbox addresses)
- [x] Key exchange flow (MLS group creation, welcome messages, commits — DMs are 2-person groups)
- [x] Invite token format (relay address + one-time token, scoped to friend-add or group-join)
- [x] Channel model (text channels and voice channels as within a group)
- [x] Voice signaling protocol (join/leave over WebSocket)
- [x] Voice packet format (encrypted audio packet envelope for relay forwarding)
- [x] Relay API contract (text endpoints, voice endpoints, request/response shapes, error codes)

Deliverable: `ghost-protocol/spec.md`

**1.2 — Identity & Key Management**

- [x] Keypair generation (Ed25519 for signing, X25519 for key exchange)
- [x] OS keyring integration (macOS Keychain, Windows DPAPI, Linux Secret Service)
- [x] Key serialization/deserialization for storage
- [x] Identity export/import (encrypted file for device migration/backup)
- [x] Unit tests: generate, store, retrieve, export, import

**1.3 — Encryption Engine**

- [x] Encrypted group management via OpenMLS (groups and DMs as 2-person groups)
- [x] Group creation, member add (welcome message), member remove (key rotation)
- [x] Message encrypt/decrypt for groups and DMs
- [x] Audio frame encrypt/decrypt (per-sender keys derived from group shared secret)
- [x] Blob packaging: plaintext → encrypted payload → transport blob
- [x] Unit tests: round-trip encrypt/decrypt for text and audio frames

**1.4 — Local Storage**

- [x] SQLCipher database initialization with device-derived key
- [x] Schema: messages, groups, channels (text + voice), members, key material
- [x] CRUD operations for all entities
- [x] Message query by channel, by time range, full-text search
- [x] Database migration framework for future schema changes
- [x] Unit tests: store and retrieve all entity types, search

**1.5 — Protocol Logic**

- [x] WebSocket client (connect, reconnect with exponential backoff, heartbeat)
- [x] Outbound text pipeline: encrypt → wrap blob → send to relay
- [x] Inbound text pipeline: receive blob → unwrap → decrypt → store locally
- [x] Invite link generation and parsing
- [x] Invite token embeds relay URL so joining user needs zero manual config
- [x] Join flow: parse invite → contact relay → key exchange → receive group state
- [x] Group metadata structure (channel list, member list, display names)
- [x] Voice signaling: join/leave voice channel, relay endpoint assignment
- [x] Integration tests: two core instances exchanging text through a mock relay

**Phase 1 done when:** Two Rust processes can create identities, form a group, exchange encrypted messages through a mock relay, and add/remove members via library API calls. **✓ Complete.**

---

### Phase 2: Relay

**2.1 — Blob Mailbox (text)**

- [x] In-memory hash map: mailbox ID → queue of blobs
- [x] `POST /box/{id}` — accept blob, add to queue, return blob ID
- [x] `GET /box/{id}` — return pending blobs, long-poll until arrival or timeout
- [x] `DELETE /box/{id}/{blob_id}` — remove blob from queue
- [x] `GET /health` — return status
- [x] Max blob size enforcement (configurable, default 10MB)
- [ ] Rate limiting per IP

**2.2 — WebSocket Support (text)**

- [x] Upgrade HTTP connections to persistent WebSocket at `/ws/{id}`
- [x] Push blobs to connected clients immediately on arrival
- [x] Fall back to HTTP long-polling if WebSocket fails

**2.3 — TTL & Storage Management**

- [x] Background task: sweep expired blobs every 60 seconds
- [x] Configurable TTL (default 72h)
- [ ] Disk usage limit: evict oldest blobs when database exceeds configured size

**2.4 — Invite Token Exchange**

- [x] CRUD endpoints: create, redeem (with KeyPackage upload), poll response, cancel
- [x] Configurable expiry (clamped to TTL)
- [ ] One-time use enforcement (currently redeemable multiple times)
- [ ] Rate limiting on invite endpoints

**2.5 — Transport & Reliability**

- [x] WebSocket for text messaging and voice signaling
- [x] Raw UDP for voice packet forwarding
- [x] Persistent sequential log (SQLite)
- [x] Envelope framing: 10-byte plaintext header (version, type, epoch) on every blob
- [x] Key update ordering: all blobs stored, hint on concurrent key updates
- [x] Catch-up: client sends last seen sequence on reconnect, server replays
- [x] Recovery: group state download, client rejoins at current epoch
- [x] Voice packet routing: channel → participant list, copy packets to all others
- [x] Voice state broadcast over mailbox WS (all members see who's in voice)
- [x] Encrypted presence blobs for voice key exchange (per-sender AES-256-GCM)
- [x] Slot-based UDP routing (relay-assigned slot_id replaces fingerprint in header)
- [ ] Voice key rotation when group keys change during active calls
- [ ] Voice key ratcheting: re-derive keys on reconnect, rotate periodically
- [ ] Voice-over-WebSocket fallback when UDP is blocked

**2.6 — Deployment**

- [ ] Single static binary, zero runtime dependencies
- [ ] Dockerfile (FROM scratch, copy binary)
- [ ] docker-compose.yml (relay + optional TLS termination)
- [ ] TLS: relay loads cert + key files directly (or run behind reverse proxy)
- [ ] Future: auto-provision TLS certificates from Let's Encrypt
- [x] All config via environment variables
- [ ] README with setup instructions

**2.7 — CI/CD**

- [ ] GitHub Actions: run `cargo test` on macOS + Windows for ghost-core and ghost-relay
- [ ] GitHub Actions: build relay Docker image, push to container registry on tag
- [ ] GitHub Actions: build Tauri app for macOS + Windows on tag
- [ ] macOS code signing and notarization (required to avoid Gatekeeper blocks)
- [ ] Windows code signing (required to avoid SmartScreen warnings)
- [ ] Automated release artifacts attached to GitHub releases

**Phase 2 done when:** `docker run ghost-relay` works. Core library instances exchange text over WebSocket and audio routes through the relay. CI builds and tests run on every push.

---

### Phase 3: Desktop App

**3.1 — App Shell**

- [x] Tauri 2 project with SolidJS + TypeScript
- [x] Rust core library integrated as Tauri backend (direct Rust calls)
- [x] Frontend calls Rust core through Tauri commands
- [x] CSS variable design system (palette, sizing, animation timing, shadows)
- [x] Persistent config file (config.toml) for relay URL, display name, devices, voice settings
- [ ] Cross-platform builds verified on macOS, Windows, Linux
- [ ] App registers as handler for `ghost://` deep links

**3.2 — Chat UI**

- [x] Group sidebar (list of joined groups, text channels, voice channels)
- [x] Message grouping (consecutive messages from same sender collapsed)
- [x] Command palette with search and actions
- [x] Message input
- [x] Real-time message updates from backend
- [x] Member list panel
- [x] Unread indicators per channel (local count, badge + group dot)
- [ ] Message view with virtual scrolling (render only visible messages)
- [ ] Relay connectivity indicator (connected / reconnecting / offline)
- [ ] Relay topology view: visualize how users connect through relay nodes

**3.3 — Voice UI**

- [x] Join/leave voice channel button
- [x] Voice channel participant list (who's currently in the call)
- [x] Active speaker highlight (ring glow + text brightness)
- [x] Mute and deafen controls (with speaking glow on mic icon)
- [x] Connection quality indicator (signal icon with detail popover)
- [x] Push-to-talk with configurable keybind
- [x] Input mode selector (voice activity / push to talk / continuous)
- [x] Input sensitivity slider (voice activity threshold)
- [x] Input volume slider
- [x] Noise suppression toggle
- [x] Auto volume normalization toggle
- [x] Audio device selection (input + output dropdowns, hot-swap on device change)
- [x] Mic test with loopback and live level meter

**3.4 — Friends & DMs**

- [ ] Generate/redeem invite tokens for friend-add
- [ ] Create 2-person encrypted group on redemption (kind: "dm")
- [ ] Sidebar DM section, rendered by other user's display name

**3.5 — Group Management**

- [x] Create group (name, initial text and voice channels)
- [x] Join via invite token (same token system as friend-add, scoped to group)
- [x] Generate and copy invite tokens (single-use, configurable expiry)
- [x] Create, rename, delete text and voice channels
- [ ] Kick members (triggers key rotation)
- [ ] Optional: require creator approval for new joins

**3.6 — Settings & Security**

- [x] Settings panel with category registry and sidebar navigation
- [x] Settings controls library (toggle, select, input, readonly with copy, slider)
- [x] Appearance settings (font size, compact mode, timestamps) with live preview
- [x] Message settings (enter sends behavior)
- [x] Relay connection settings (relay URL with debounced save)
- [x] Audio input/output device selection (in AV settings)
- [x] Display name (set on first launch, changeable via /rename)
- [x] Avatar (deterministic gradient from fingerprint — no custom upload)
- [ ] App-level PIN / biometric lock
- [ ] Disappearing message timer per channel
- [ ] Export encrypted identity backup
- [ ] Import identity from backup

**3.7 — File Sharing**

- [ ] Drag and drop file/image into chat
- [ ] Files encrypted as blobs, same pipeline as messages
- [ ] Inline image previews in message view
- [ ] File size limit matching relay config

**3.8 — Onboarding & First Launch**

- [x] Setup screen: set display name
- [x] Setup screen: paste invite link or manually enter relay URL
- [x] Invite tokens carry relay URL — invited users skip manual relay config
- [x] First-launch detection (auto-show setup when no display_name in config)
- [ ] Returning user: app loads directly into last-used group/channel
- [ ] Empty state guidance when no groups exist (prompt to create or join)

**3.9 — Discoverability & Help**

- [x] Keyboard shortcut help overlay (hold ? key)
- [x] Tooltips on key UI elements
- [x] `/info` command in palette to show shortcuts and app info
- [ ] Command palette discoverability hint in empty states

**Phase 3 done when:** A complete desktop app on all three platforms. Download, host a relay, click invite, chat and voice call. **This is v0.1 — the first public release.**

---

### Phase 4: Hardening & Quality of Life

**4.1 — Reliability**

- [ ] Offline message queue (encrypt and queue locally, deliver on reconnect)
- [ ] Relay failover (group metadata stores backup relay addresses)
- [ ] Connection status indicator in UI (general, not just voice-call quality)
- [ ] Graceful handling of relay downtime (queue, retry, reconnect)
- [ ] Voice auto-reconnect on connection drop

**4.2 — Quality of Life**

- [ ] Message replies (quote a previous message)
- [ ] Message reactions (emoji)
- [x] Keyboard shortcuts (search, commands, help overlay, push-to-talk keybind)
- [ ] Light theme (currently dark-only, all colors via CSS variables)
- [x] Drag to reorder channels and groups

**4.3 — Voice Polish**

- [x] Silence detection (voice activity probability + energy fallback, configurable threshold)
- [ ] Automatic bitrate adjustment based on connection quality
- [x] Noise suppression (toggleable mid-call)
- [ ] Echo cancellation
- [ ] Per-user volume control
- [x] Adaptive resampling for clock drift between devices

**4.4 — Integrations & Bot SDK**

- [x] Command registry: extensible command/provider system
- [ ] Bot SDK: expose ghost-core as library crate + ghost-bot example/template
- [ ] Bot deployment: separate containers alongside relay via docker-compose
- [ ] Feature toggle system in settings (boolean per integration)
- [ ] Widget slot in channel view (above message input, stacks bottom-up)
- [ ] Music player bot (YouTube/Spotify, queue, /play /skip /pause, now-playing widget)
- [ ] Reminders (/remind, notification within app)
- [ ] Link previews (opt-in, fetched client-side)
- [ ] Polls (/poll, inline widget in channel)

**Phase 4 done when:** Stable, polished, daily-driveable. **This is v0.2.**

---

### Phase 5: Security Audit & Multi-Device → v1.0

**5.1 — Security**

- [ ] Third-party security audit of encryption implementation
- [ ] Reproducible builds (verify distributed binary matches source)
- [ ] Fuzz testing on protocol message parser
- [ ] Penetration testing on relay (message and voice paths)

**5.2 — Multi-Device Support**

- [ ] Device linking flow (QR code or numeric code displayed on new device, confirmed on existing device)
- [ ] Secure channel established between linked devices
- [ ] Existing device transfers group keys and membership to new device
- [ ] New device added as member to all groups
- [ ] Settings → Devices: view all linked devices, unlink any device
- [ ] Unlinking triggers key rotation across all groups
- [ ] Message history sync between linked devices (encrypted, via relay)

**5.3 — Identity Backup & Recovery**

- [ ] Encrypted backup to user-chosen location (local file, USB, NAS)
- [ ] Restore from backup on new device
- [ ] Recovery flow for when all devices are lost (rejoin groups via new invite)

**Phase 5 done when:** Audited, multi-device works, identity is recoverable. **This is v1.0.**

---

## Known Limitations (By Design)

- **No voice presence** — who's in a voice channel is only visible to members of the same server (requires mailbox WS connection)
- **No notifications** — open the app to see what's new
- **No background sync** — nothing happens while the app is closed
- **No server-side search** — search only works on messages your device has
- **No cloud sync** — messages live on device only
- **No link previews by default** — fetching URLs leaks metadata; opt-in client-side fetch planned
- **No message history for new members** — you see messages from when you joined
- **Device loss = history loss** — unless you exported an encrypted backup
- **No mobile** — desktop only until desktop is solid
- **Voice channel cap ~25 people** — relay bandwidth limit for self-hosted setups
- **Bots are opt-in** — a bot is a headless client with its own keypair; group admin invites bot, group can kick it (key rotation locks it out)
- **No webhooks** — encryption prevents server-side message injection; bots are the alternative

---

## Future Considerations

- **QUIC transport** — unify WebSocket + UDP onto a single port. Deferred — current setup is simpler to self-host.
- **UDP header encryption** — channel_id and slot_id are plaintext in the voice header. Encrypting with a session key would hide routing metadata from the wire.
- **Plugin system (WASM)** — sandboxed hot-loadable plugins. Deferred — built-in integrations cover current needs.
- **Relay admin panel** — web UI for managing relay config, bots, monitoring health.
- **Deployment aids** — relay setup wizard, cloud marketplace images.
- **Browser client** — crypto and protocol are pure Rust and WASM-compatible; storage and networking need abstraction.
- **Relay rate limiting** — per-IP throttling when deploying to public internet.
- **Auto TLS** — auto-provision certificates from Let's Encrypt.
