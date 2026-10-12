//! Cross-device sync: sealed state changes numbered by each device, sent to the
//! account's sync relays, plus a durable sealed snapshot that carries the whole state
//! and what it covers. State merges per key, so arrival order and copies do not matter.

use std::collections::HashSet;

use ghost_wire::short_id;

use crate::client::GhostClient;
use crate::error::{GhostError, Result};
use crate::relay::RelayClient;
use crate::wire::{
    decode_sync_dump, encode_mutation, encode_sync_dump, sync_open, sync_seal, SyncDump, SyncMessageType, SyncServerMeta,
    MUTATION_REMOVE, MUTATION_SET, SYNC_KEY_AGC, SYNC_KEY_DISPLAY_NAME, SYNC_KEY_INPUT_GAIN, SYNC_KEY_INPUT_MODE,
    SYNC_KEY_NOISE_SUPPRESSION, SYNC_KEY_READ_PREFIX, SYNC_KEY_SERVER_ORDER,
    SYNC_KEY_SERVER_PREFIX, SYNC_KEY_STATUS, SYNC_KEY_STATUS_MESSAGE, SYNC_KEY_VAD_THRESHOLD,
};

use super::{account, now_millis, SharedClient};

/// Relays each sync message and snapshot go to: the home and this many others. Three
/// full copies cost a few hundred bytes a message and need no failover logic; the
/// systems that read from several sources settled in this range.
pub const SYNC_RELAY_COUNT: usize = 3;

/// Copies to relays outside the sync set are refreshed at most this often, so recovery
/// can start from any relay hosting one of the account's servers.
const SNAPSHOT_REPLICATION_INTERVAL_MS: u64 = 5 * 60 * 1000;
/// Rounds of fetch, merge and write when a relay holds a snapshot this device has not seen.
const SNAPSHOT_CONFLICT_ROUNDS: usize = 3;
/// How long sync changes settle before the relays' snapshots are rewritten, so a burst
/// of changes (reading through channels, adjusting settings) costs one write.
pub const SNAPSHOT_SETTLE: std::time::Duration = std::time::Duration::from_secs(2);
const CONFIG_SNAPSHOT_GENERATION: &str = "snapshot_generation";
const CONFIG_SNAPSHOT_REPLICATED_AT: &str = "snapshot_replicated_at";
/// Prefix of the per-relay record of the snapshot hash that relay last accepted.
const CONFIG_SNAPSHOT_WRITTEN_PREFIX: &str = "snapshot_written:";
/// Prefix of the per-relay record that this device took in the snapshot that relay held.
const CONFIG_SNAPSHOT_READ_PREFIX: &str = "snapshot_read:";

/// Addresses of the sync relays other than the home: the lowest relay keys among the
/// relays hosting one of the account's servers. Every device computes the same set from
/// the same servers, and the home is always in it, so devices briefly knowing different
/// servers still share a relay.
pub fn other_sync_relay_urls(client: &GhostClient, home_url: &str) -> Vec<String> {
    let home_vk = client.relay_vk();
    let mut relays = client.store().server_relays().unwrap_or_default();
    relays.sort_by_key(|r| r.relay_vk);
    relays
        .iter()
        .filter(|r| Some(r.relay_vk) != home_vk)
        .filter_map(|r| r.primary_https_url().map(str::to_string))
        .filter(|url| url.trim_end_matches('/') != home_url.trim_end_matches('/'))
        .take(SYNC_RELAY_COUNT - 1)
        .collect()
}

/// Open the sync mailbox on any sync relay it is not open on yet: the set follows the
/// account's servers, so joining one on a new relay can add a relay to it.
pub async fn ensure_sync_relays(client: &SharedClient, relay: &RelayClient) {
    let c = client.lock().await;
    let mailbox = c.account_sync_mailbox();
    let home_url = relay.base_url();
    if !relay.is_subscribed_at(&home_url, &mailbox) {
        let seq = c.store().get_last_seen_seq_at(&mailbox, &home_url).unwrap_or(0);
        relay.subscribe(mailbox, seq);
    }
    for url in other_sync_relay_urls(&c, &home_url) {
        if !relay.is_subscribed_at(&url, &mailbox) {
            let seq = c.store().get_last_seen_seq_at(&mailbox, &url).unwrap_or(0);
            relay.at(&url).subscribe_here_too(mailbox, seq);
        }
    }
}

/// Clients for every sync relay, the home first, signing as this device.
async fn sync_relay_clients(client: &SharedClient, home: &RelayClient) -> Vec<RelayClient> {
    let home_url = home.base_url();
    let others = other_sync_relay_urls(&*client.lock().await, &home_url);
    let mut clients = vec![home.at(&home_url)];
    clients.extend(others.iter().map(|url| home.at(url)));
    clients
}

/// Whether sync is paused: a removal waits for the home, and the removed device still
/// holds the current generation, so nothing is written until it lands.
pub fn paused(c: &GhostClient) -> bool {
    !c.store().pending_revocations().unwrap_or_default().is_empty()
}

/// Send one sync message to the account's other devices through every sync relay. The
/// mailbox is open on each, so one send reaches all; a relay that is unreachable holds
/// its copy until it reconnects. Nothing goes while sync is paused, except the pause.
pub async fn post_message(client: &SharedClient, relay: &RelayClient, msg_type: SyncMessageType, payload: &[u8]) {
    let Some(outbound) = seal_message(client, msg_type, payload).await else { return };
    // A message no relay took is not lost: every device merges the snapshots when it
    // reconnects to the sync mailbox.
    let _ = relay.send(&outbound.mailbox_id, outbound.blob);
}

/// Say `SyncPause` again for every removal still waiting for the home: a pause no relay
/// took would leave the others writing what the removed device can read. Receivers
/// record a pending removal once, so a repeat changes nothing where it already arrived.
pub async fn repeat_pauses(client: &SharedClient, relay: &RelayClient) {
    let pending = client.lock().await.store().pending_revocations().unwrap_or_default();
    for target in pending {
        post_message(client, relay, SyncMessageType::SyncPause, &target).await;
    }
}

/// Send one sync message through every sync relay and wait for each to take it, for a
/// device about to drop its connections: queued on them, it would go down with them.
pub async fn post_message_and_wait(client: &SharedClient, relay: &RelayClient, msg_type: SyncMessageType, payload: &[u8]) {
    let Some(outbound) = seal_message(client, msg_type, payload).await else { return };
    for target in sync_relay_clients(client, relay).await {
        if let Err(e) = target.post_blob_here(&outbound.mailbox_id, outbound.blob.clone()).await {
            tracing::warn!("sync send: relay {} did not take it: {e}", target.base_url());
        }
    }
}

/// Seal a sync message under the current account key generation; `None` while sync is
/// paused, except for the pause and the account's own changes.
async fn seal_message(client: &SharedClient, msg_type: SyncMessageType, payload: &[u8]) -> Option<crate::wire::Outbound> {
    let c = client.lock().await;
    if paused(&c) && !matches!(msg_type, SyncMessageType::SyncPause | SyncMessageType::AccountChanged) {
        return None;
    }
    let mut inner = Vec::with_capacity(1 + payload.len());
    inner.push(msg_type as u8);
    inner.extend_from_slice(payload);
    match c.send_sync(&inner) {
        Ok(outbound) => Some(outbound),
        Err(e) => {
            tracing::warn!("sync send: {e}");
            None
        }
    }
}

fn config_u64(c: &GhostClient, key: &str) -> Option<u64> {
    c.store()
        .get_config_blob(key)
        .ok()
        .flatten()
        .and_then(|v| <[u8; 8]>::try_from(v.as_slice()).ok())
        .map(u64::from_be_bytes)
}

/// This device's whole state, sealed under the current account key generation, and the
/// hash of the state inside, by which a relay's copy is told from it.
struct SealedSnapshot {
    body: Vec<u8>,
    hash: [u8; 32],
}

/// Whether this device may write its state to the relays now: not while sync is paused,
/// nor while the account's current generation is not held or no longer covers it (then a
/// revoked device could still read it).
pub fn snapshot_writable(c: &GhostClient) -> bool {
    !paused(c) && c.sealing_seed().is_ok()
}

/// Seal this device's state. `None` while it may not be written (`snapshot_writable`).
fn sealed_snapshot(c: &GhostClient) -> Result<Option<SealedSnapshot>> {
    if !snapshot_writable(c) {
        return Ok(None);
    }
    let dump = encode_sync_dump(&c.sync_dump()?)?;
    let hash: [u8; 32] = blake3::hash(&dump).into();
    Ok(Some(SealedSnapshot { body: seal_snapshot(c, &dump)?, hash }))
}

fn written_key(relay_url: &str) -> String {
    format!("{CONFIG_SNAPSHOT_WRITTEN_PREFIX}{}", relay_url.trim_end_matches('/'))
}

/// Whether `relay_url` already accepted a snapshot of the state hashing to `hash`.
fn already_written(c: &GhostClient, relay_url: &str, hash: &[u8; 32]) -> bool {
    c.store().get_config_blob(&written_key(relay_url)).ok().flatten().as_deref() == Some(hash.as_slice())
}

fn read_key(relay_url: &str) -> String {
    format!("{CONFIG_SNAPSHOT_READ_PREFIX}{}", relay_url.trim_end_matches('/'))
}

/// Whether this device took in what `relay_url` held, so its writes there lose nothing.
fn already_read(c: &GhostClient, relay_url: &str) -> bool {
    c.store().get_config_blob(&read_key(relay_url)).ok().flatten().is_some()
}

/// Take in what `target` holds before this device first writes there: a write replaces
/// the relay's copy, and a device that never read it (one just recovered or linked)
/// would put its own state in place of the account's. `None` while the copy cannot be
/// read, and the write waits for a later push.
async fn read_before_writing(client: &SharedClient, target: &RelayClient, account_fp: &[u8; 32]) -> Option<SnapshotRead> {
    match merge_snapshot_from(client, target, account_fp).await {
        Ok(read) => {
            read.warn_if_unreadable(&target.base_url());
            Some(read)
        }
        Err(e) => {
            tracing::warn!("sync snapshot: relay {} not written before its copy is read: {e}", target.base_url());
            None
        }
    }
}

/// Add the settings a merge changed to those gathered so far.
fn gather(changed: &mut Option<SyncSettings>, settings: Option<SyncSettings>) {
    let Some(settings) = settings else { return };
    match changed {
        Some(all) => all.absorb(settings),
        None => *changed = Some(settings),
    }
}

/// This device's state sealed for writing, as it is now (a merge may have grown it);
/// `None` when it may not be written now (the push stays asked for) or could not be sealed.
async fn seal_now(client: &SharedClient) -> Option<SealedSnapshot> {
    let mut c = client.lock().await;
    match sealed_snapshot(&c) {
        Ok(Some(fresh)) => Some(fresh),
        Ok(None) => {
            c.request_snapshot_push();
            None
        }
        Err(e) => {
            tracing::warn!("sync snapshot: not written: {e}");
            None
        }
    }
}

/// The generation the next write to a relay carries: past every generation this device
/// has used, and past `held`, the one a relay's refusal showed it holds.
fn next_snapshot_generation(c: &GhostClient, held: Option<u64>) -> u64 {
    let generation = super::next_generation(config_u64(c, CONFIG_SNAPSHOT_GENERATION).max(held));
    let _ = c.store().set_config_blob(CONFIG_SNAPSHOT_GENERATION, &generation.to_be_bytes());
    generation
}

/// Write this device's state to every sync relay whose copy is not already this state,
/// and to the other relays hosting its servers when their copy is older than the
/// replication interval. A relay's copy is taken in before this device first writes
/// there. A relay holding a snapshot this device has not merged refuses the write; the
/// snapshot is then fetched and merged, and the write tried again, past the generation
/// the relay holds, with what the merge changed. A relay that could not be reached is
/// written at the next push, whether or not anything changed meanwhile. A state that may
/// not be written now keeps the push asked for, to go once it may. Returns the settings
/// the merges along the way changed, for applying.
pub async fn push_snapshot(client: &SharedClient, relay: &RelayClient) -> Option<SyncSettings> {
    let now = now_millis();
    let mut sealed = seal_now(client).await?;
    let (account_fp, replicate) = {
        let c = client.lock().await;
        let replicate = config_u64(&c, CONFIG_SNAPSHOT_REPLICATED_AT)
            .is_none_or(|at| now.saturating_sub(at) >= SNAPSHOT_REPLICATION_INTERVAL_MS);
        (*c.fingerprint(), replicate)
    };

    let mut changed = None;
    for target in sync_relay_clients(client, relay).await {
        if already_written(&*client.lock().await, &target.base_url(), &sealed.hash) {
            continue;
        }
        if !already_read(&*client.lock().await, &target.base_url()) {
            let Some(read) = read_before_writing(client, &target, &account_fp).await else { continue };
            gather(&mut changed, read.into_settings());
            match seal_now(client).await {
                Some(fresh) => sealed = fresh,
                None => return changed,
            }
        }
        // The generation this relay's refusal showed it holds, which the next write passes.
        let mut held = None;
        for _ in 0..SNAPSHOT_CONFLICT_ROUNDS {
            let generation = next_snapshot_generation(&*client.lock().await, held);
            match target.put_sync_state(&account_fp, generation, sealed.body.clone()).await {
                Ok(()) => {
                    let _ = client.lock().await.store().set_config_blob(&written_key(&target.base_url()), &sealed.hash);
                    break;
                }
                Err(GhostError::RelayStatus { status: 409, .. }) => {
                    // This relay holds a newer snapshot: take it in before writing ours.
                    match merge_snapshot_from(client, &target, &account_fp).await {
                        Ok(read) => {
                            read.warn_if_unreadable(&target.base_url());
                            held = read.generation();
                            gather(&mut changed, read.into_settings());
                        }
                        Err(e) => {
                            tracing::warn!("sync snapshot: relay {} holds one this device cannot fetch now: {e}", target.base_url());
                            break;
                        }
                    }
                    // The merge may have grown this device's state; the relay's copy lacks
                    // whatever is this device's own either way, so the write goes again.
                    match seal_now(client).await {
                        Some(fresh) => sealed = fresh,
                        None => return changed,
                    }
                }
                Err(e) => {
                    tracing::warn!("sync snapshot: relay {} not updated: {e}", target.base_url());
                    break;
                }
            }
        }
    }

    if !replicate {
        return changed;
    }
    let sync_urls: HashSet<String> = sync_relay_clients(client, relay).await.into_iter().map(|r| r.base_url()).collect();
    let Ok(home_vk) = account::home_relay_vk(client, relay).await else { return changed };
    let Ok(members) = account::member_relay_clients(client, relay, &home_vk).await else { return changed };
    let generation = config_u64(&*client.lock().await, CONFIG_SNAPSHOT_GENERATION).unwrap_or(0);
    for (relay_vk, member) in members {
        if sync_urls.contains(&member.base_url()) {
            continue;
        }
        if !already_read(&*client.lock().await, &member.base_url()) {
            let Some(read) = read_before_writing(client, &member, &account_fp).await else { continue };
            let settings = read.into_settings();
            if settings.is_some() {
                // What only this copy held reaches the sync relays at the next push.
                client.lock().await.request_snapshot_push();
            }
            gather(&mut changed, settings);
            match seal_now(client).await {
                Some(fresh) => sealed = fresh,
                None => return changed,
            }
        }
        match member.put_sync_state(&account_fp, generation, sealed.body.clone()).await {
            Ok(()) | Err(GhostError::RelayStatus { status: 409, .. }) => {}
            Err(e) => tracing::warn!("sync snapshot: relay {} not updated: {e}", short_id(&relay_vk)),
        }
    }
    let c = client.lock().await;
    let _ = c.store().set_config_blob(CONFIG_SNAPSHOT_REPLICATED_AT, &now.to_be_bytes());
    changed
}

/// `[account key generation:4][sealed dump]`, under the generation new data is sealed with.
fn seal_snapshot(c: &GhostClient, dump: &[u8]) -> Result<Vec<u8>> {
    let seed = c.sealing_seed()?;
    let mut body = seed.generation().to_be_bytes().to_vec();
    body.extend_from_slice(&sync_seal(&*seed.sync_key()?, dump)?);
    Ok(body)
}

/// Open a stored snapshot with the account key generation it names. A generation not
/// held yet fails with `AccountKeyUnavailable`; fetch the account's key sets first.
pub fn open_snapshot(c: &GhostClient, body: &[u8]) -> Result<SyncDump> {
    if body.len() < 4 {
        return Err(GhostError::Format("sync snapshot too short".into()));
    }
    let generation = u32::from_be_bytes(body[..4].try_into().unwrap());
    let seed = c
        .account_seed(generation)?
        .ok_or_else(|| GhostError::AccountKeyUnavailable(format!("snapshot generation {generation} is not held")))?;
    decode_sync_dump(&sync_open(&*seed.sync_key()?, &body[4..])?)
}

/// What one relay's snapshot came to.
enum SnapshotRead {
    /// The relay holds none.
    Nothing,
    /// Taken in; `settings` are what it changed, `None` when nothing in it was new.
    Merged { generation: u64, settings: Option<SyncSettings> },
    /// Sealed under a generation no key this device can fetch opens, or damaged: no
    /// device of the account can take it in, so the next write replaces it.
    Unreadable { generation: u64, error: GhostError },
}

impl SnapshotRead {
    /// The generation the relay holds its copy under.
    fn generation(&self) -> Option<u64> {
        match self {
            Self::Nothing => None,
            Self::Merged { generation, .. } | Self::Unreadable { generation, .. } => Some(*generation),
        }
    }

    /// The settings the merge changed, if it changed any.
    fn into_settings(self) -> Option<SyncSettings> {
        match self {
            Self::Merged { settings, .. } => settings,
            Self::Nothing | Self::Unreadable { .. } => None,
        }
    }

    fn warn_if_unreadable(&self, relay_url: &str) {
        if let Self::Unreadable { error, .. } = self {
            tracing::warn!("sync snapshot: relay {relay_url} holds one no key of the account opens ({error}); this device's replaces it");
        }
    }
}

/// Merge the snapshot one relay holds into this device's state, noting that this
/// device read that relay's copy. An error means the relay or the account's keys could
/// not be reached.
async fn merge_snapshot_from(client: &SharedClient, target: &RelayClient, account_fp: &[u8; 32]) -> Result<SnapshotRead> {
    let read = match target.get_sync_state(account_fp).await? {
        None => SnapshotRead::Nothing,
        Some((generation, body)) => {
            let opened = open_snapshot(&*client.lock().await, &body);
            let opened = match opened {
                Err(GhostError::AccountKeyUnavailable(_)) => {
                    // Written under a generation this device has not fetched yet.
                    super::account_keys::refresh(client, target).await?;
                    open_snapshot(&*client.lock().await, &body)
                }
                other => other,
            };
            match opened {
                Ok(dump) => {
                    let c = client.lock().await;
                    let changed = c.sync_import(&dump.entries)?;
                    c.cover_sync(&dump.covered)?;
                    for (_, _, clock) in &changed {
                        let _ = c.sync_observe(*clock);
                    }
                    SnapshotRead::Merged { generation, settings: (!changed.is_empty()).then(|| parse_entries(&changed)) }
                }
                Err(error @ (GhostError::AccountKeyUnavailable(_) | GhostError::Crypto(_) | GhostError::Format(_))) => {
                    SnapshotRead::Unreadable { generation, error }
                }
                Err(e) => return Err(e),
            }
        }
    };
    let _ = client.lock().await.store().set_config_blob(&read_key(&target.base_url()), &[1]);
    Ok(read)
}

/// Catch up from the snapshots on every sync relay, then write the merged state back
/// where it differs. Returns the settings that changed, for applying.
pub async fn merge_snapshots(client: &SharedClient, relay: &RelayClient) -> Result<Option<SyncSettings>> {
    let account_fp = *client.lock().await.fingerprint();
    let mut merged: Option<SyncSettings> = None;
    let mut reached = 0;
    for target in sync_relay_clients(client, relay).await {
        match merge_snapshot_from(client, &target, &account_fp).await {
            Ok(read) => {
                reached += 1;
                read.warn_if_unreadable(&target.base_url());
                gather(&mut merged, read.into_settings());
            }
            Err(e) => tracing::warn!("sync: snapshot not read from {}: {e}", target.base_url()),
        }
    }
    if reached == 0 {
        return Err(GhostError::Network("no sync relay answered".into()));
    }
    gather(&mut merged, push_snapshot(client, relay).await);
    Ok(merged)
}

/// Write a key-value entry locally, broadcast the mutation, and have the session
/// refresh the snapshots once changes settle.
pub async fn set_and_push(client: &SharedClient, relay: &RelayClient, key: &str, value: &[u8]) {
    let ts = {
        let mut c = client.lock().await;
        let Ok(ts) = c.sync_tick() else { return };
        let _ = c.sync_set(key, value, ts);
        c.request_snapshot_push();
        ts
    };
    post_message(client, relay, SyncMessageType::MutationSync, &encode_mutation(MUTATION_SET, ts, key, value)).await;
}

/// Remove a key locally, broadcast the removal, and have the session refresh the
/// snapshots once changes settle.
pub async fn remove_and_push(client: &SharedClient, relay: &RelayClient, key: &str) {
    let ts = {
        let mut c = client.lock().await;
        let Ok(ts) = c.sync_tick() else { return };
        let _ = c.sync_remove(key, ts);
        c.request_snapshot_push();
        ts
    };
    post_message(client, relay, SyncMessageType::MutationSync, &encode_mutation(MUTATION_REMOVE, ts, key, &[])).await;
}

/// Record a server's metadata in sync state and propagate it to linked devices. Carries
/// the account's removal from the server too, once someone removed it.
pub async fn server_entry(client: &SharedClient, relay: &RelayClient, server_id: &[u8; 32]) {
    let value = {
        let c = client.lock().await;
        let Ok(meta) = c.export_server_meta(server_id) else { return };
        meta.to_bytes()
    };
    set_and_push(client, relay, &format!("{}{}", SYNC_KEY_SERVER_PREFIX, hex::encode(server_id)), &value).await;
}

/// Tell linked devices a server was created or joined so they can join it too.
pub async fn post_server_provisioned(client: &SharedClient, relay: &RelayClient, server_id: &[u8; 32]) {
    let payload = {
        let c = client.lock().await;
        match c.export_provision_payload(server_id) {
            Ok(p) => p.to_bytes(),
            Err(_) => return,
        }
    };
    post_message(client, relay, SyncMessageType::ServerProvisioned, &payload).await;
}

/// Settings parsed out of sync state entries, ready for the application to apply.
#[derive(Default, Clone, Debug)]
pub struct SyncSettings {
    pub display_name: Option<String>,
    pub noise_suppression: Option<String>,
    pub agc: Option<String>,
    pub input_mode: Option<String>,
    pub vad_threshold: Option<f32>,
    pub input_gain: Option<f32>,
    pub status: Option<String>,
    /// `Some(None)` means the status message was cleared.
    pub status_message: Option<Option<SyncedStatusMessage>>,
    pub read_marks: Vec<([u8; 32], u64)>,
    pub server_entries: Vec<([u8; 32], SyncServerMeta)>,
    pub server_order_changed: bool,
}

impl SyncSettings {
    /// Combine with settings merged from another snapshot.
    pub(crate) fn absorb(&mut self, other: SyncSettings) {
        self.display_name = other.display_name.or(self.display_name.take());
        self.noise_suppression = other.noise_suppression.or(self.noise_suppression.take());
        self.agc = other.agc.or(self.agc.take());
        self.input_mode = other.input_mode.or(self.input_mode.take());
        self.vad_threshold = other.vad_threshold.or(self.vad_threshold.take());
        self.input_gain = other.input_gain.or(self.input_gain.take());
        self.status = other.status.or(self.status.take());
        self.status_message = other.status_message.or(self.status_message.take());
        self.read_marks.extend(other.read_marks);
        self.server_entries.extend(other.server_entries);
        self.server_order_changed |= other.server_order_changed;
    }
}

fn utf8(value: &Option<Vec<u8>>) -> Option<String> {
    value.as_deref().and_then(|v| std::str::from_utf8(v).ok()).map(str::to_string)
}

/// The status message as synced: its text with its expiry, one value so the two never
/// part, and every device clears it at the same moment.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SyncedStatusMessage {
    pub text: String,
    /// When it expires, in milliseconds by the clock of the device that set it.
    pub expires_at: Option<u64>,
}

impl SyncedStatusMessage {
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("a status message serializes")
    }
}

/// A number written as decimal text, if it is one.
fn number(value: &Option<Vec<u8>>) -> Option<f32> {
    utf8(value)?.parse::<f32>().ok().filter(|n| n.is_finite())
}

fn id_from_hex(hex_str: &str) -> Option<[u8; 32]> {
    hex::decode(hex_str).ok().and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
}

/// Parse sync state entries into settings the application applies.
pub fn parse_entries(entries: &[(String, Option<Vec<u8>>, u64)]) -> SyncSettings {
    let mut s = SyncSettings::default();
    for (key, value, _ts) in entries {
        if key == SYNC_KEY_SERVER_ORDER {
            s.server_order_changed = true;
        } else if let Some(id_hex) = key.strip_prefix(SYNC_KEY_READ_PREFIX) {
            if let (Some(val), Some(cid)) = (value, id_from_hex(id_hex)) {
                if val.len() == 8 {
                    s.read_marks.push((cid, u64::from_be_bytes(val[..8].try_into().unwrap())));
                }
            }
        } else if key == SYNC_KEY_DISPLAY_NAME {
            s.display_name = utf8(value);
        } else if key == SYNC_KEY_NOISE_SUPPRESSION {
            s.noise_suppression = utf8(value);
        } else if key == SYNC_KEY_AGC {
            s.agc = utf8(value);
        } else if key == SYNC_KEY_INPUT_MODE {
            s.input_mode = utf8(value);
        } else if key == SYNC_KEY_VAD_THRESHOLD {
            s.vad_threshold = number(value);
        } else if key == SYNC_KEY_INPUT_GAIN {
            s.input_gain = number(value);
        } else if key == SYNC_KEY_STATUS {
            s.status = utf8(value);
        } else if key == SYNC_KEY_STATUS_MESSAGE {
            // A value this build cannot read is left alone; a tombstone clears it.
            match value {
                Some(bytes) => {
                    if let Ok(message) = serde_json::from_slice::<SyncedStatusMessage>(bytes) {
                        s.status_message = Some(Some(message));
                    }
                }
                None => s.status_message = Some(None),
            }
        } else if let Some(id_hex) = key.strip_prefix(SYNC_KEY_SERVER_PREFIX) {
            if let (Some(val), Some(server_id)) = (value, id_from_hex(id_hex)) {
                if let Ok(meta) = SyncServerMeta::from_bytes(val) {
                    s.server_entries.push((server_id, meta));
                }
            }
        }
    }
    s
}

/// Merge entries into the local store and apply read marks. Returns the settings that
/// changed, so the application can apply display name, preferences and status.
pub async fn import_entries(client: &SharedClient, entries: &[(String, Option<Vec<u8>>, u64)]) -> Result<SyncSettings> {
    let c = client.lock().await;
    let changed = c.sync_import(entries)?;
    for (_, _, clock) in &changed {
        let _ = c.sync_observe(*clock);
    }
    let settings = parse_entries(&changed);
    for (cid, read_ts) in &settings.read_marks {
        let _ = c.store().mark_channel_read(cid, *read_ts);
    }
    Ok(settings)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(key: &str, value: Option<&[u8]>) -> (String, Option<Vec<u8>>, u64) {
        (key.to_string(), value.map(<[u8]>::to_vec), 1)
    }

    #[test]
    fn a_status_message_syncs_with_its_expiry_and_a_tombstone_clears_both() {
        let message = SyncedStatusMessage { text: "lunch".into(), expires_at: Some(1_900_000_000_000) };
        let parsed = parse_entries(&[entry(SYNC_KEY_STATUS_MESSAGE, Some(&message.to_bytes()))]);
        assert_eq!(parsed.status_message, Some(Some(message)));
        let cleared = parse_entries(&[entry(SYNC_KEY_STATUS_MESSAGE, None)]);
        assert_eq!(cleared.status_message, Some(None));
        let unreadable = parse_entries(&[entry(SYNC_KEY_STATUS_MESSAGE, Some(b"lunch"))]);
        assert_eq!(unreadable.status_message, None, "a value this build cannot read is left alone");
    }

    #[test]
    fn audio_levels_sync_as_decimal_numbers() {
        let parsed = parse_entries(&[entry(SYNC_KEY_VAD_THRESHOLD, Some(b"0.6")), entry(SYNC_KEY_INPUT_GAIN, Some(b"NaN"))]);
        assert_eq!(parsed.vad_threshold, Some(0.6));
        assert_eq!(parsed.input_gain, None, "a number that is not one is left alone");
    }
}
