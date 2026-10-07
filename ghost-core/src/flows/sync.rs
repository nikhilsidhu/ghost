//! Cross-device sync: encrypted mutations over the sync MLS group plus a durable
//! encrypted snapshot on the relay.

use crate::error::Result;
use crate::wire::{
    encode_mutation, encode_sync_state_dump, sync_seal, SyncMessageType, SyncServerMeta,
    MUTATION_REMOVE, MUTATION_SET, SYNC_KEY_AGC, SYNC_KEY_DISPLAY_NAME, SYNC_KEY_INPUT_MODE,
    SYNC_KEY_NOISE_SUPPRESSION, SYNC_KEY_READ_PREFIX, SYNC_KEY_SERVER_ORDER,
    SYNC_KEY_SERVER_PREFIX, SYNC_KEY_STATUS, SYNC_KEY_STATUS_MESSAGE,
};

use super::{now_millis, SharedClient, SharedRelay};

/// Send one sync message to all linked devices. No-op without a sync group (single device).
pub async fn post_message(
    client: &SharedClient,
    relay: &SharedRelay,
    msg_type: SyncMessageType,
    payload: &[u8],
) {
    let outbound = {
        let c = client.lock().await;
        if !c.has_sync_group() {
            return;
        }
        let mut inner = Vec::with_capacity(1 + payload.len());
        inner.push(msg_type as u8);
        inner.extend_from_slice(payload);
        match c.send_sync(&inner) {
            Ok(o) => o,
            Err(e) => {
                eprintln!("sync send: {e}");
                return;
            }
        }
    };
    let r = relay.lock().await;
    let _ = r.send(&outbound.mailbox_id, outbound.blob).await;
}

/// Copies to member relays are refreshed at most this often; the home always gets the latest.
const SNAPSHOT_REPLICATION_INTERVAL_MS: u64 = 5 * 60 * 1000;
const CONFIG_SNAPSHOT_GENERATION: &str = "snapshot_generation";
const CONFIG_SNAPSHOT_REPLICATED_AT: &str = "snapshot_replicated_at";

fn config_u64(c: &crate::client::GhostClient, key: &str) -> Option<u64> {
    c.store()
        .get_config_blob(key)
        .ok()
        .flatten()
        .and_then(|v| <[u8; 8]>::try_from(v.as_slice()).ok())
        .map(u64::from_be_bytes)
}

/// Dump local sync state, encrypt it with the sync key and store it on the home relay,
/// and on every member relay when the last copy there is older than the replication
/// interval. The copies let a recovering device find its servers when the home is gone.
pub async fn push_snapshot(client: &SharedClient, relay: &SharedRelay) {
    let now = now_millis();
    let (sync_key, account_fp, dump, generation, replicate) = {
        let c = client.lock().await;
        let Some(key) = c.sync_key() else { return };
        let entries = c.sync_dump().unwrap_or_default();
        let Ok(dump) = encode_sync_state_dump(&entries) else { return };
        let generation = super::next_generation(config_u64(&c, CONFIG_SNAPSHOT_GENERATION));
        let _ = c.store().set_config_blob(CONFIG_SNAPSHOT_GENERATION, &generation.to_be_bytes());
        let replicate = config_u64(&c, CONFIG_SNAPSHOT_REPLICATED_AT)
            .is_none_or(|at| now.saturating_sub(at) >= SNAPSHOT_REPLICATION_INTERVAL_MS);
        (key, *c.fingerprint(), dump, generation, replicate)
    };
    let Ok(sealed) = sync_seal(&sync_key, &dump) else { return };
    {
        let r = relay.lock().await;
        if let Err(e) = r.put_sync_state(&account_fp, generation, sealed.clone()).await {
            eprintln!("sync snapshot: home relay refused: {e}");
            return;
        }
    }
    if !replicate {
        return;
    }
    let Ok(home_vk) = super::account::home_relay_vk(client, relay).await else { return };
    let Ok(members) = super::account::member_relay_clients(client, relay, &home_vk).await else { return };
    for (relay_vk, member) in members {
        if let Err(e) = member.put_sync_state(&account_fp, generation, sealed.clone()).await {
            eprintln!("sync snapshot: relay {} not updated: {e}", hex::encode(&relay_vk[..8]));
        }
    }
    let c = client.lock().await;
    let _ = c.store().set_config_blob(CONFIG_SNAPSHOT_REPLICATED_AT, &now.to_be_bytes());
}

/// Write a key-value entry locally, broadcast the mutation, and refresh the snapshot.
pub async fn set_and_push(client: &SharedClient, relay: &SharedRelay, key: &str, value: &[u8]) {
    let ts = now_millis();
    {
        let c = client.lock().await;
        let _ = c.sync_set(key, value, ts);
    }
    post_message(client, relay, SyncMessageType::MutationSync, &encode_mutation(MUTATION_SET, ts, key, value)).await;
    push_snapshot(client, relay).await;
}

/// Remove a key locally, broadcast the removal, and refresh the snapshot.
pub async fn remove_and_push(client: &SharedClient, relay: &SharedRelay, key: &str) {
    let ts = now_millis();
    {
        let c = client.lock().await;
        let _ = c.sync_remove(key, ts);
    }
    post_message(client, relay, SyncMessageType::MutationSync, &encode_mutation(MUTATION_REMOVE, ts, key, &[])).await;
    push_snapshot(client, relay).await;
}

/// Record a server's metadata in sync state and propagate it to linked devices.
pub async fn server_entry(client: &SharedClient, relay: &SharedRelay, server_id: &[u8; 32]) {
    let (key, value, ts) = {
        let c = client.lock().await;
        let Ok(meta) = c.export_server_meta(server_id) else { return };
        let key = format!("{}{}", SYNC_KEY_SERVER_PREFIX, hex::encode(server_id));
        let value = meta.to_bytes();
        let ts = now_millis();
        let _ = c.sync_set(&key, &value, ts);
        (key, value, ts)
    };
    post_message(client, relay, SyncMessageType::MutationSync, &encode_mutation(MUTATION_SET, ts, &key, &value)).await;
    push_snapshot(client, relay).await;
}

/// Tell linked devices a server was created or joined so they can join it too.
pub async fn post_server_provisioned(client: &SharedClient, relay: &SharedRelay, server_id: &[u8; 32]) {
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
#[derive(Default)]
pub struct SyncSettings {
    pub display_name: Option<String>,
    pub noise_suppression: Option<String>,
    pub agc: Option<String>,
    pub input_mode: Option<String>,
    pub status: Option<String>,
    /// `Some(None)` means the status message was cleared.
    pub status_message: Option<Option<String>>,
    pub read_marks: Vec<([u8; 32], u64)>,
    pub server_entries: Vec<([u8; 32], SyncServerMeta)>,
    pub server_order_changed: bool,
}

fn utf8(value: &Option<Vec<u8>>) -> Option<String> {
    value.as_deref().and_then(|v| std::str::from_utf8(v).ok()).map(str::to_string)
}

fn id_from_hex(hex_str: &str) -> Option<[u8; 32]> {
    hex::decode(hex_str).ok().and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
}

/// Parse sync state entries into typed settings.
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
        } else if key == SYNC_KEY_STATUS {
            s.status = utf8(value);
        } else if key == SYNC_KEY_STATUS_MESSAGE {
            s.status_message = Some(utf8(value));
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

/// Import sync entries into the local store and apply read marks. Returns the parsed settings
/// so the application can apply display name, preferences and status.
pub async fn import_entries(
    client: &SharedClient,
    entries: &[(String, Option<Vec<u8>>, u64)],
) -> Result<SyncSettings> {
    let settings = parse_entries(entries);
    let c = client.lock().await;
    c.sync_import(entries)?;
    for (cid, read_ts) in &settings.read_marks {
        let _ = c.store().mark_channel_read(cid, *read_ts);
    }
    if let Some(ref name) = settings.display_name {
        drop(c);
        let mut c = client.lock().await;
        c.set_display_name(name.clone());
    }
    Ok(settings)
}

/// Replace the sync key after a device removal: the new key travels under the old one,
/// so it must be sent before it is stored.
pub async fn rotate_key(client: &SharedClient, relay: &SharedRelay) {
    let new_key = {
        let mut k = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut k);
        k
    };
    post_message(client, relay, SyncMessageType::SyncKeyRotate, &new_key).await;
    {
        let c = client.lock().await;
        let _ = c.set_sync_key(new_key);
    }
    push_snapshot(client, relay).await;
}
