# Ghost — UX Flow Audit

Every user-facing action traced end-to-end. Steps tagged by layer:
- **[app]** — Tauri command handler (ghost-app)
- **[core]** — ghost-core client/storage
- **[relay]** — HTTP/WS to ghost-relay
- **[sync]** — multi-device sync group broadcast
- **[voice]** — voice task / audio pipeline
- **[presence]** — presence state + broadcast

---

## Servers

### Create Server

1. **[core]** Generate random `server_id`, create MLS group with deterministic group ID
2. **[core]** Write 3 rows (not in a transaction): server, default channel ("general"), creator as member
3. **[core]** Cache MLS group + mailbox mapping in memory
4. **[relay]** `PUT /box/{mid}/server_info` — upload GroupInfo for external joins
5. **[relay]** Subscribe to mailbox via WebSocket
6. **[sync]** Broadcast `ServerProvisioned` payload to linked devices
7. **[sync]** Push server metadata to sync state + relay snapshot

**On failure at step 4:** delete local server row — but channels/members may not cascade, leaving orphans. Memory cache (step 3) not cleaned up.

**Issues:** Step 2 not in a transaction (crash = partial state). Sync errors at steps 6-7 silently dropped.

**Refs:** [commands.rs:207](ghost-app/src-tauri/src/commands.rs#L207) → [client.rs:402](ghost-core/src/client.rs#L402)

---

### Create DM

Identical to Create Server except `ServerKind::Dm` and default channel named "messages".

**Refs:** [commands.rs:260](ghost-app/src-tauri/src/commands.rs#L260)

---

### Save Server Order

1. **[core]** Serialize order as JSON, write to sync state KV
2. **[sync]** Broadcast mutation to linked devices
3. **[sync]** Push sync snapshot to relay

**Issues:** If step 2 succeeds but step 3 fails, linked devices see the change via mutation but relay snapshot is stale. On reload, snapshot wins — inconsistent. No validation of duplicate/missing server IDs.

**Refs:** [commands.rs:296](ghost-app/src-tauri/src/commands.rs#L296)

---

## Channels

### Create Channel

1. **[core]** Generate random `channel_id`, compute next position from existing channel count
2. **[core]** INSERT channel row immediately
3. **[core]** Encode `ChannelOpPayload::Create`, encrypt via MLS `send_control()`
4. **[relay]** `POST /box/{mid}` with encrypted blob — **fire-and-forget**
5. **[sync]** Push updated server metadata to linked devices

**On failure at step 4:** silently ignored. Creator sees channel, other members don't. No recovery mechanism.

**Issues:** No idempotency — retry creates duplicate channels. DB insert (step 2) happens before relay confirmation.

**Refs:** [commands.rs:366](ghost-app/src-tauri/src/commands.rs#L366)

---

### Rename Channel

1. **[core]** Verify channel exists, get server_id
2. **[core]** UPDATE channel name in DB
3. **[core]** Encode `ChannelOpPayload::Rename`, encrypt via MLS
4. **[relay]** `POST /box/{mid}` — fire-and-forget
5. **[sync]** Push updated server metadata

**On failure at step 4:** silently ignored. Local rename persists, other members see old name.

**Issues:** No rollback of DB if relay fails.

**Refs:** [commands.rs:417](ghost-app/src-tauri/src/commands.rs#L417)

---

### Delete Channel

1. **[core]** Verify channel exists, get server_id
2. **[core]** DELETE channel row
3. **[core]** Encode `ChannelOpPayload::Delete`, encrypt via MLS
4. **[relay]** `POST /box/{mid}` — fire-and-forget
5. **[sync]** Push updated server metadata

**On failure at step 4:** silently ignored. Creator's channel gone, other members still see it.

**Issues:** No soft-delete for recovery. Retry after failure → "channel not found" error.

**Refs:** [commands.rs:449](ghost-app/src-tauri/src/commands.rs#L449)

---

### Mark Channel Read

1. **[core]** Write read timestamp to `channels` table
2. **[core]** Write to sync state KV (`read:{channel_id}`)
3. **[sync]** Broadcast mutation + push snapshot

**Issues:** Sync errors silently dropped.

**Refs:** [commands.rs:524](ghost-app/src-tauri/src/commands.rs#L524)

---

## Messages

### Send Message

1. **[core]** Build `ApplicationMessage` with content, channel_id, sender fingerprint, timestamp, references
2. **[core]** Encrypt via MLS `seal()`, capture message_id
3. **[core]** INSERT message + reference rows in a transaction (`INSERT OR IGNORE` for idempotency)
4. **[relay]** `POST /box/{mid}` with encrypted blob — **fire-and-forget**

**On failure at step 4:** silently ignored. Message appears "sent" in local UI but never reaches other members. No delivery confirmation.

**Issues:** User has no way to know message didn't send. No retry mechanism.

**Refs:** [commands.rs:337](ghost-app/src-tauri/src/commands.rs#L337) → [client.rs:446](ghost-core/src/client.rs#L446)

---

## Members

### Kick Member

1. **[core]** Verify caller is creator
2. **[core]** Find all MLS leaf indices for target's devices, call `group.remove_members()`
3. **[core]** DELETE member row from DB
4. **[relay]** `POST /box/{mid}` with MLS commit (not fire-and-forget — checks response)
5. **[app]** On success: export + PUT updated GroupInfo to relay
6. **[app]** On epoch conflict: trigger `recover_epoch()` (external commit recovery, up to 3 retries)

**On failure at step 4 (epoch conflict):** recovery loop fetches latest GroupInfo from relay, rebuilds via external commit, retries. If all 3 attempts fail, user gets error.

**Issues:** Step 3 DB delete happens before relay confirmation — if relay fails and recovery fails, DB says member gone but MLS still has them. Step 5 `put_server_info` errors silently dropped.

**Refs:** [commands.rs:480](ghost-app/src-tauri/src/commands.rs#L480) → [client.rs:760](ghost-core/src/client.rs#L760)

---

### Create Invite

1. **[core]** Verify caller is creator
2. **[core]** Export GroupInfo + build `InvitePayload` (server metadata, members, channels)
3. **[core]** Generate random 16-byte token
4. **[relay]** `POST /invite` — register token with 72-hour max lifetime
5. **[relay]** `POST /invite/{token}/join` — upload payload bytes
6. **[app]** Build invite link: `ghost://join?relay={url}&token={token}`

**On failure at step 5:** token registered but payload not uploaded — joiners get empty response.

**Issues:** Steps 4-5 not atomic. GroupInfo and member list are snapshot at creation time — stale if group changes before someone joins.

**Refs:** [commands.rs:543](ghost-app/src-tauri/src/commands.rs#L543) → [client.rs:671](ghost-core/src/client.rs#L671)

---

### Join by Invite

1. **[relay]** `GET /invite/{token}/join` — fetch invite payload
2. **[core]** Deserialize payload, join MLS group via external commit
3. **[core]** Insert server, channels, members into DB (idempotent)
4. **[relay]** `POST /box/{mid}` with external commit blob
5. **[core]** Refresh invite payload with updated GroupInfo
6. **[relay]** `POST /invite/{token}/join` — upload refreshed payload for next joiner
7. **[core]** Set `last_seen_seq` to commit seq (don't replay pre-join messages)
8. **[core]** Send member announcement control message
9. **[relay]** Subscribe to mailbox starting at commit seq
10. **[sync]** Broadcast `ServerProvisioned` to linked devices + push snapshot

**On failure at step 2:** "invalid GroupInfo" if invite is stale — must get creator to re-invite.

**On failure at step 6:** silently ignored. Next joiner gets stale payload.

**Issues:** Step 8 (announcement) errors silently dropped — other members don't learn joiner's display name. Steps 9-10 errors also silent.

**Refs:** [commands.rs:588](ghost-app/src-tauri/src/commands.rs#L588) → [client.rs:699](ghost-core/src/client.rs#L699)

---

## Identity & Profile

### Set Display Name

1. **[app]** Update config on disk
2. **[core]** Update identity + all server member records in storage
3. **[core]** For each server: encode `member_announce`, encrypt via MLS
4. **[relay]** Send control blob to each server mailbox
5. **[sync]** Write to sync state + broadcast mutation + push snapshot
6. **[app]** Emit `display-name-sync` event to frontend

**Issues:** No rollback of local config if relay fails (step 4). Relay errors logged but not returned to caller.

**Refs:** [commands.rs:727](ghost-app/src-tauri/src/commands.rs#L727)

---

### Upload Avatar

1. **[app]** Generate random AES-256 key, encrypt avatar with AES-256-GCM
2. **[app]** Hash encrypted blob with BLAKE3 → `avatar_hash`
3. **[core]** For each server: update member avatar in storage, encode `avatar_update` control
4. **[relay]** For each server: `PUT /avatar/{mid}/{fp}` with encrypted blob
5. **[relay]** For each server: send control blob (contains hash + decryption key)
6. **[app]** Write original avatar to local cache
7. **[presence]** Update presence with `avatar_hash`, broadcast to all servers

**Issues:** AES key generated per-upload and only sent in control message — if message lost, other members have the blob but can't decrypt it. If `put_avatar` succeeds but `send` fails, relay has blob but nobody has the key.

**Refs:** [commands.rs:763](ghost-app/src-tauri/src/commands.rs#L763)

---

### Clear Avatar

1. **[core]** For each server: clear member avatar in storage, encode `avatar_clear` control
2. **[relay]** For each server: `DELETE /avatar/{mid}/{fp}`
3. **[relay]** For each server: send control blob
4. **[app]** Delete local cache files
5. **[presence]** Clear `avatar_hash`

**Issues:** All errors silently logged. If relay delete fails, stale blob remains on relay.

**Refs:** [commands.rs:828](ghost-app/src-tauri/src/commands.rs#L828)

---

### Set Status

1. **[presence]** Update status in memory
2. **[presence]** Broadcast presence to all server mailboxes
3. **[app]** Save to config (skipped if status is Idle)
4. **[sync]** Write to sync state + broadcast + push snapshot (skipped if Idle)

**Issues:** Idle status intentionally skips config/sync — Idle is transient, not persisted.

**Refs:** [commands.rs:1205](ghost-app/src-tauri/src/commands.rs#L1205)

---

### Set Status Message

1. **[presence]** Update status_message + expiry in memory
2. **[presence]** Broadcast presence
3. **[app]** Save to config
4. **[sync]** If message is Some: `sync_set`. If None: `sync_remove`. Then push snapshot.

**Issues:** No background job to clear expired status messages.

**Refs:** [commands.rs:1232](ghost-app/src-tauri/src/commands.rs#L1232)

---

### Set Relay URL

1. **[app]** Save URL to config

**Issues:** Does not reconnect relay client. Change only takes effect on restart.

**Refs:** [commands.rs:896](ghost-app/src-tauri/src/commands.rs#L896)

---

### Set Keybind

1. **[app]** Update keybind config (only "push_to_talk" action supported)
2. **[app]** Save config

**Issues:** Not synced across devices.

**Refs:** [commands.rs:1190](ghost-app/src-tauri/src/commands.rs#L1190)

---

## Devices & Pairing

### Get Devices

1. **[relay]** `GET /idlog/{fp}?after_seq=0` — fetch entire identity log
2. **[core]** Parse entries, validate hash chain
3. **[app]** Map to device DTOs (device_key, label, seq, active, is_current)

**Issues:** Fetches entire log every time (no incremental). No caching.

**Refs:** [commands.rs:1263](ghost-app/src-tauri/src/commands.rs#L1263)

---

### Revoke Device

1. **[relay]** Fetch entire identity log, validate chain
2. **[core]** Create `RevokeDevice` log entry signed by revoker
3. **[relay]** `POST /idlog/{fp}` — append revoke entry (triggers `revocation_tx` → relay deauths device)
4. **[sync]** Remove device from sync MLS group → post commit to sync mailbox (3 retries)
5. **[core]** Remove device leaves from all server MLS groups
6. **[relay]** Post each server commit; on success, update GroupInfo. On epoch conflict, attempt recovery.

**On failure at step 4:** revoked device still in sync group — can decrypt future sync messages. Logs warning and continues.

**On failure at step 6:** epoch recovery attempted (3 retries). If exhausted, logs and continues — revoke entry is in identity log but MLS groups still include the device's leaves.

**Issues:** No atomicity between identity log revocation (step 3) and MLS removal (steps 4-6). If MLS removal fails, device is revoked on paper but still has group access until next epoch change.

**Refs:** [commands.rs:1296](ghost-app/src-tauri/src/commands.rs#L1296)

---

### Start Pairing (Device A)

1. **[app]** Generate random 32-byte pairing secret
2. **[app]** Build offer JSON (relay_url, display_name, avatar_hash, status_message)
3. **[app]** Encrypt offer with `pairing_seal(secret)`
4. **[relay]** `POST /pair/{fp}` — store encrypted offer (5-minute expiry, in-memory only)
5. **[app]** Format pairing code: `{relay_url}#{fp_hex}#{secret_hex}`
6. **[app]** Cache secret in memory

**Issues:** Offer stored in relay memory only — lost on relay restart. 5-minute timeout.

**Refs:** [commands.rs:1639](ghost-app/src-tauri/src/commands.rs#L1639)

---

### Check Pairing (Device A polls)

1. **[relay]** `GET /pair/{fp}/response` — poll for Device B's response
2. **[app]** If no response, return `None` (keep polling)
3. **[app]** Decrypt response → extract new device signing key + label
4. **[relay]** Fetch identity log, validate chain
5. **[core]** Build provision blob: sync_key + sync GroupInfo + all server ProvisionPayloads + sync dump
6. **[app]** Encrypt provision blob with pairing secret
7. **[relay]** `PUT /pair/{fp}/provision` — upload encrypted provision (5-minute expiry, in-memory)
8. **[core]** Create `AddDevice` log entry
9. **[relay]** `POST /idlog/{fp}` — append AddDevice entry
10. **[relay]** Subscribe to sync mailbox if not already
11. **[app]** Clear pairing secret

**On failure at step 9:** provision uploaded but AddDevice not in log. Device B fetches provision and waits forever for log confirmation.

**Issues:** Provision stored in relay memory only. If step 7 succeeds but step 9 fails, Device B is stuck. Genesis re-push at step 4 assumes `genesis.pending` file exists.

**Refs:** [commands.rs:1685](ghost-app/src-tauri/src/commands.rs#L1685)

---

### Cancel Pairing

1. **[app]** Clear pairing secret from memory

**Issues:** Does not notify relay — pairing session remains in relay memory until expiry (5 min).

**Refs:** [commands.rs:1832](ghost-app/src-tauri/src/commands.rs#L1832)

---

### Join as New Device (Device B)

1. **[app]** Parse pairing code → relay_url, account_fp, secret
2. **[relay]** `GET /pair/{fp}` — fetch encrypted offer
3. **[app]** Decrypt offer → get relay_url, display_name, avatar_hash
4. **[app]** Generate new device signing key + label
5. **[app]** Encrypt response (signing key + label), `POST /pair/{fp}/respond`
6. **[relay]** Poll identity log until new device key appears (30 attempts, 0.5s interval)
7. **[app]** Write credentials to disk (debug: file, release: keyring)
8. **[app]** Wipe local databases
9. **[app]** Save config with account metadata from offer
10. **[core]** Create new `GhostClient` with linked identity
11. **[app]** Hot-swap client + auth state + relay connection
12. **[relay]** Fetch provision blob with retries (10 attempts, 1s interval)
13. **[app]** Decrypt provision → sync_key, GroupInfo, server payloads, sync dump
14. **[core]** Join sync MLS group via external commit → post commit to relay
15. **[core]** For each server: join MLS group via external commit, subscribe, update GroupInfo
16. **[core]** Import sync state dump (settings, read marks)
17. **[relay]** Spawn relay task

**On failure at step 6:** timeout — "device not added" error. Credentials not yet written, safe to retry.

**On failure at step 12:** provision blob gone (relay restarted). Device has credentials but can't join groups. Stuck.

**On failure at step 14-15:** device in identity log and has credentials, but not in MLS groups. Must re-pair or wait for recovery mechanism.

**Issues:** Steps 7-8 are irreversible (credentials written, old DBs deleted) — if subsequent steps fail, device is in a half-initialized state with no recovery path. Provision blob in relay memory only.

**Refs:** [commands.rs:1842](ghost-app/src-tauri/src/commands.rs#L1842)

---

## Recovery

### Set Recovery Passphrase

1. **[app]** Validate passphrase (≥12 chars), take seed from state
2. **[core]** `export_recovery_blob()`: Argon2id(passphrase) → AES-256-GCM(seed + sync_key) → v2 blob
3. **[relay]** `PUT /recovery/{fp}` — upload encrypted blob (unauthenticated endpoint)

**On failure at step 3:** seed is restored to state — user can retry.

**Issues:** Recovery endpoint is unauthenticated — anyone can overwrite the blob with garbage.

**Refs:** [commands.rs:2094](ghost-app/src-tauri/src/commands.rs#L2094)

---

### Skip Recovery Setup

1. **[app]** Drop seed from state (zeroized)

**Refs:** [commands.rs:2141](ghost-app/src-tauri/src/commands.rs#L2141)

---

### Get Recovery Code

1. **[app]** Return `{relay_url}#{fp_hex}` (read-only, no side effects)

**Refs:** [commands.rs:2147](ghost-app/src-tauri/src/commands.rs#L2147)

---

### Change Recovery Passphrase

1. **[relay]** `GET /recovery/{fp}` — fetch existing blob (unauthenticated)
2. **[core]** Decrypt with current passphrase via Argon2id
3. **[core]** Re-encrypt with new passphrase
4. **[relay]** `PUT /recovery/{fp}` — upload new blob

**On failure at step 4:** old blob remains. New passphrase doesn't work until PUT succeeds.

**Issues:** No atomic update — race between concurrent passphrase changes. Last writer wins.

**Refs:** [commands.rs:2157](ghost-app/src-tauri/src/commands.rs#L2157)

---

### Has Recovery Blob

1. **[relay]** `GET /recovery/{fp}` — return whether blob exists (unauthenticated)

**Refs:** [commands.rs:2200](ghost-app/src-tauri/src/commands.rs#L2200)

---

### Recover Account

1. **[relay]** `GET /recovery/{fp}` — fetch encrypted blob (unauthenticated)
2. **[core]** Decrypt with passphrase → seed + sync_key
3. **[core]** Derive master key from seed, verify fingerprint matches
4. **[relay]** Fetch identity log, validate chain with master key
5. **[core]** Generate new device key, create Recovery log entry signed by master key
6. **[relay]** `POST /idlog/{fp}` — append Recovery entry (revokes all old devices, unauthenticated)
7. **[app]** Write new credentials to disk, wipe old databases
8. **[core]** Create new `GhostClient`, set sync_key, create sync group
9. **[app]** Hot-swap client + auth + relay connection
10. **[relay]** Fetch + decrypt sync state snapshot → import settings, read marks
11. **[core]** For each server in sync state: rejoin via external commit
12. **[core]** Revoke old device leaves from all server groups
13. **[relay]** Re-upload recovery blob as v2 with same passphrase (includes new sync_key)
14. **[relay]** Push merged sync state to relay
15. **[relay]** Spawn relay task

**On failure at step 6:** old DBs already wiped (step 7 hasn't run yet — actually step 7 is after). Recovery can be retried.

**On failure at step 10:** silently logged, continues. Recovery completes but settings/read marks lost.

**On failure at step 11-12:** device is in identity log but not in MLS groups. Incomplete recovery.

**Issues:** Recovery endpoints unauthenticated — anyone can POST a Recovery entry if they know the account fingerprint (though entry must be signed by master key). Steps 7-9 are irreversible — failure after that point leaves device half-initialized. Step 10 errors silently dropped.

**Refs:** [commands.rs:2307](ghost-app/src-tauri/src/commands.rs#L2307)

---

## Voice

### Join Voice

1. **[sync]** Send `VoiceTakeover` to linked devices (tells them to leave this channel)
2. **[voice]** Build voice WebSocket URL: `ws://.../voice/{channel_b64}`
3. **[core]** Derive presence encryption key from MLS export secret, seal presence blob (AES-256-GCM)
4. **[voice]** Connect WebSocket (10s timeout), send `Join { presence }`
5. **[relay]** Allocate slot, broadcast `Joined` + `Presence` to existing peers
6. **[relay]** Send `Welcome` with slot_id, UDP port, peer list
7. **[voice]** Decrypt each peer's presence blob (trial decryption with all member keys)
8. **[core]** Derive voice encryption key for each peer via MLS export secret
9. **[voice]** Build `AudioPipeline`: open devices, create Opus encoder, nnnoiseless denoiser, jitter buffers, spawn UDP send/recv tasks
10. **[voice]** Broadcast voice state to server mailbox for sidebar visibility
11. **[app]** Emit `voice-state`, `voice-participants`, `voice-mute-state` events

**Issues:** VoiceTakeover (step 1) sent before join completes — if join fails, other devices already left. No Welcome timeout — hangs if relay crashes after handshake.

**Refs:** [commands.rs:907](ghost-app/src-tauri/src/commands.rs#L907)

---

### Leave Voice

1. **[voice]** Send leave presence to server mailbox (sidebar visibility)
2. **[voice]** Send `Leave` to relay WS, close connection
3. **[voice]** Reset state: drop audio session (aborts UDP tasks), clear peers
4. **[relay]** Remove participant, broadcast `Left`, clean up channel if empty
5. **[app]** Emit `voice-state` with connected=false

**Refs:** [commands.rs:963](ghost-app/src-tauri/src/commands.rs#L963)

---

### Set Muted / Set Deafened

1. **[voice]** Update local muted/deafened state (deafen implies mute)
2. **[voice]** If audio session active: update pipeline control atomics
3. **[voice]** If in voice channel: seal + send updated presence blob to relay + mailbox
4. **[app]** Emit `voice-state`

**Issues:** Unmuting while deafened also undeafens — frontend needs to handle this.

**Refs:** [commands.rs:973](ghost-app/src-tauri/src/commands.rs#L973), [commands.rs:983](ghost-app/src-tauri/src/commands.rs#L983)

---

### Audio Settings (NS, AGC, Input Mode, VAD Threshold, Input Gain)

All follow the same pattern:

1. **[app]** Parse + clamp value, save to config
2. **[voice]** Send command to voice task → update pipeline control atomic
3. **[audio]** Next frame reads the atomic and applies new behavior
4. **[sync]** Broadcast setting to linked devices (NS and AGC only — VAD threshold and input gain are NOT synced)

**Issues:**
- VAD threshold and input gain missing sync keys — not synced across devices
- Input gain applied before denoise/AGC — high gain causes clipping before processing
- AGC gain state not reset on toggle — retains previous gain value
- Denoise drops first frame after mode switch (glitch)

**Refs:** [commands.rs:1071](ghost-app/src-tauri/src/commands.rs#L1071), [commands.rs:1092](ghost-app/src-tauri/src/commands.rs#L1092), [commands.rs:1113](ghost-app/src-tauri/src/commands.rs#L1113), [commands.rs:1147](ghost-app/src-tauri/src/commands.rs#L1147), [commands.rs:1164](ghost-app/src-tauri/src/commands.rs#L1164)

---

### Set Input Mode

1. **[app]** Parse mode ("voice_activity" or "push_to_talk"), save to config
2. **[voice]** Update pipeline control atomic
3. **[voice]** If switching to PTT and currently muted: auto-unmute + send presence update
4. **[sync]** Broadcast to linked devices

**Issues:** PTT auto-unmute races with concurrent mute command from another device.

**Refs:** [commands.rs:1113](ghost-app/src-tauri/src/commands.rs#L1113)

---

### Set PTT Active

1. **[voice]** Set `ptt_active` atomic on pipeline
2. **[audio]** Next frame: transmit = `!muted && ptt_active` (when in PTT mode)

**Issues:** No timeout watchdog — if frontend crashes while key held, audio transmits indefinitely.

**Refs:** [commands.rs:1134](ghost-app/src-tauri/src/commands.rs#L1134)

---

### Set Input/Output Device

1. **[app]** Save device name to config

**Issues:** Does NOT restart audio pipeline. Change only takes effect on next voice join. No device validation — any string accepted.

**Refs:** [commands.rs:1051](ghost-app/src-tauri/src/commands.rs#L1051), [commands.rs:1061](ghost-app/src-tauri/src/commands.rs#L1061)

---

### Start Mic Test

1. **[app]** Spawn test thread with input + output device
2. **[test]** Open input stream → ringbuf → output stream (loopback)
3. **[test]** Pre-fill 150ms buffer, then start output
4. **[test]** Poll RMS level every 50ms, emit `mic-level` events
5. **[test]** Loop until `MIC_TESTING` flag cleared

**Issues:** No error recovery if device unplugged. No "test stopped" event — frontend infers from silence.

**Refs:** [commands.rs:993](ghost-app/src-tauri/src/commands.rs#L993)

---

### Stop Mic Test / Play Test Tone

- **Stop:** Set `MIC_TESTING` flag to false. No confirmation event.
- **Tone:** Spawn thread, play 440Hz sine at 0.3 amplitude for 2 seconds.

**Refs:** [commands.rs:1002](ghost-app/src-tauri/src/commands.rs#L1002), [commands.rs:1008](ghost-app/src-tauri/src/commands.rs#L1008)

---

### List Audio Devices

1. **[app]** Query cpal for input/output devices + defaults, return names

**Issues:** Device names not stable across driver updates. No sample rate info exposed.

**Refs:** [commands.rs:1014](ghost-app/src-tauri/src/commands.rs#L1014)

---

## Cross-Cutting Issues

### Fire-and-forget relay sends
Create Channel, Rename Channel, Delete Channel, Send Message all use fire-and-forget `relay.send()`. Failures are silently dropped. User sees success locally while other members never receive the update.

### DB writes before relay confirmation
Most flows write to local DB first, then send to relay. If relay fails, local state diverges from remote. Rollback is incomplete or absent.

### Sync errors silently dropped
All `post_sync_message()` and `push_sync_snapshot()` errors are silently logged or ignored. Multi-device consistency breaks silently.

### Unauthenticated recovery/idlog endpoints
`PUT /recovery/{fp}`, `GET /recovery/{fp}`, and `POST /idlog/{fp}` are unauthenticated. Anyone can overwrite recovery blobs or (if they have the master key) inject identity log entries.

### Pairing state in relay memory only
Offers, responses, and provision blobs are stored in relay memory with 5-minute expiry. Relay restart during pairing = stuck.

### No idempotency
Channel creation, member announcement, and other operations have no idempotency keys. Network retries can cause duplicates.
