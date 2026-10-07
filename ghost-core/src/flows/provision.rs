//! Provisioning a linked or recovered device with the account's servers and sync state.

use std::collections::HashMap;

use crate::error::{GhostError, Result};
use crate::wire::{
    channel_mailbox_id, derive_default_channel_id,
    decode_sync_state_dump, encode_member_announce, encode_sync_state_dump, ProvisionPayload,
    SyncServerMeta,
};

use ghost_wire::relay_ref::RelayRef;
use tokio::sync::Mutex;

use super::{account, idlog, publish_server_info, sync, SharedClient, SharedRelay};

const MAX_REJOIN_ATTEMPTS: usize = 3;

/// Everything a new device needs to become a full member of the account.
///
/// Wire layout: `[master_sk:32][master_vk:32][delegation_sig:64][sync_key:32]`
/// `[gi_len:u32][sync GroupInfo][count:u16] count × ([len:u32][ProvisionPayload]) [sync-state dump]`.
pub struct ProvisionBlob {
    pub master_sk: [u8; 32],
    pub master_vk: [u8; 32],
    pub delegation_sig: [u8; 64],
    pub sync_key: [u8; 32],
    pub sync_group_info: Vec<u8>,
    pub servers: Vec<ProvisionPayload>,
    pub sync_entries: Vec<(String, Option<Vec<u8>>, u64)>,
}

const HEADER_LEN: usize = 32 + 32 + 64;

impl ProvisionBlob {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.master_sk);
        buf.extend_from_slice(&self.master_vk);
        buf.extend_from_slice(&self.delegation_sig);
        buf.extend_from_slice(&self.sync_key);
        buf.extend_from_slice(&(self.sync_group_info.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.sync_group_info);
        buf.extend_from_slice(&(self.servers.len() as u16).to_be_bytes());
        for server in &self.servers {
            let bytes = server.to_bytes();
            buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            buf.extend_from_slice(&bytes);
        }
        buf.extend_from_slice(&encode_sync_state_dump(&self.sync_entries)?);
        Ok(buf)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let short = |what: &str| GhostError::Format(format!("provision blob truncated ({what})"));
        if data.len() < HEADER_LEN + 32 + 4 + 2 {
            return Err(short("header"));
        }
        let master_sk: [u8; 32] = data[0..32].try_into().unwrap();
        let master_vk: [u8; 32] = data[32..64].try_into().unwrap();
        let delegation_sig: [u8; 64] = data[64..128].try_into().unwrap();
        let mut pos = HEADER_LEN;

        let sync_key: [u8; 32] = data[pos..pos + 32].try_into().unwrap();
        pos += 32;
        let gi_len = u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        if data.len() < pos + gi_len + 2 {
            return Err(short("group info"));
        }
        let sync_group_info = data[pos..pos + gi_len].to_vec();
        pos += gi_len;
        let count = u16::from_be_bytes(data[pos..pos + 2].try_into().unwrap()) as usize;
        pos += 2;

        let mut servers = Vec::with_capacity(count);
        for _ in 0..count {
            if data.len() < pos + 4 {
                return Err(short("server length"));
            }
            let len = u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            if data.len() < pos + len {
                return Err(short("server payload"));
            }
            servers.push(ProvisionPayload::from_bytes(&data[pos..pos + len])?);
            pos += len;
        }

        let sync_entries = if pos < data.len() {
            decode_sync_state_dump(&data[pos..])?
        } else {
            Vec::new()
        };

        Ok(Self { master_sk, master_vk, delegation_sig, sync_key, sync_group_info, servers, sync_entries })
    }
}

/// Rejoin one server by external commit from each channel's GroupInfo on the relay, with
/// retries. Returns `true` once every channel commit was accepted and the member announced.
/// A relay that refuses a channel's GroupInfo (404 or another client error) ends the attempts.
pub async fn rejoin_server(
    client: &SharedClient,
    relay: &SharedRelay,
    payload: &ProvisionPayload,
    now: u64,
    label: &str,
) -> bool {
    'attempts: for _ in 0..MAX_REJOIN_ATTEMPTS {
        // A channel with an MLS group publishes its GroupInfo under its own mailbox.
        // Channels without one are metadata only; the default channel always has one.
        let default_channel = derive_default_channel_id(&payload.server_id);
        let mut group_infos = HashMap::new();
        for channel in &payload.channels {
            let mailbox_id = channel_mailbox_id(&payload.server_id, &channel.channel_id);
            let fetched = {
                let r = relay.lock().await;
                r.get_server_info(&mailbox_id).await
            };
            match fetched {
                Ok(gi) => {
                    group_infos.insert(channel.channel_id, gi);
                }
                Err(GhostError::RelayStatus { status: 404, .. }) if channel.channel_id != default_channel => {}
                Err(GhostError::RelayStatus { status, .. }) if status >= 500 => continue 'attempts,
                Err(GhostError::RelayStatus { .. }) => break 'attempts,
                Err(_) => continue 'attempts,
            }
        }

        let channel_results = {
            let mut c = client.lock().await;
            match c.join_from_provision(payload, &group_infos, now) {
                Ok(results) => results,
                Err(e) => {
                    eprintln!("{label}: join attempt failed for {}: {e}", hex::encode(&payload.server_id[..8]));
                    continue;
                }
            }
        };

        let mut rejected = 0usize;
        for (channel_id, commit, mailbox_id) in &channel_results {
            let commit_seq = {
                let r = relay.lock().await;
                match r.post_blob(mailbox_id, commit.clone()).await {
                    Ok(res) => res.seq,
                    Err(e) => {
                        eprintln!("{label}: relay rejected commit: {e}");
                        rejected += 1;
                        continue;
                    }
                }
            };
            {
                let c = client.lock().await;
                let _ = c.store().set_last_seen_seq(mailbox_id, commit_seq);
            }
            let mut r = relay.lock().await;
            r.subscribe(*mailbox_id, commit_seq);
            // Voice signaling for the channel goes to the same relay.
            r.add_route(*channel_id);
        }

        if rejected > 0 {
            eprintln!(
                "{label}: {rejected} of {} channels of server {} refused this device's join",
                channel_results.len(),
                hex::encode(&payload.server_id[..8])
            );
            return false;
        }

        for (_channel_id, _commit, mailbox_id) in &channel_results {
            publish_server_info(client, relay, mailbox_id).await;
        }

        let announce = {
            let mut c = client.lock().await;
            let name = c.identity().display_name.clone();
            c.send_control(&payload.server_id, encode_member_announce(&name))
        };
        if let Ok(outbound) = announce {
            let r = relay.lock().await;
            let _ = r.post_blob(&outbound.mailbox_id, outbound.blob).await;
        }

        let member_fps = {
            let c = client.lock().await;
            c.mls_member_fingerprints(&payload.server_id).unwrap_or_default()
        };
        for fp in &member_fps {
            idlog::cache_member(client, relay, fp).await;
        }

        return true;
    }

    eprintln!("{label}: failed to join server {} after retries", hex::encode(&payload.server_id[..8]));
    false
}

/// Rejoin every server listed in a recovered sync snapshot.
/// Client for the relay that hosts a server, or `None` when that is the home.
/// A foreign relay is dialed with this device's credentials, must hold the key
/// the server's record names, and receives the account's chain, which admits
/// this device because another device already made the account known there.
async fn foreign_relay_for(
    client: &SharedClient,
    home: &SharedRelay,
    relay_ref: Option<&RelayRef>,
) -> Result<Option<SharedRelay>> {
    let Some(target) = relay_ref else { return Ok(None) };
    let home_vk = account::home_relay_vk(client, home).await?;
    if target.relay_vk == home_vk {
        return Ok(None);
    }

    let url = target
        .primary_https_url()
        .ok_or_else(|| GhostError::Network("server's relay has no reachable endpoint".into()))?;
    // A view of the home client: its subscriptions join the application's event stream.
    let foreign = Mutex::new(home.lock().await.at(url));
    let info = account::register_at(client, &foreign, None).await?;
    if info.relay_vk != target.relay_vk {
        return Err(GhostError::Network(format!("relay at {url} is not the relay this server lives on")));
    }
    Ok(Some(foreign))
}

/// [`rejoin_server`] on whichever relay hosts the server, recording that relay.
pub async fn rejoin_on_hosting_relay(
    client: &SharedClient,
    home: &SharedRelay,
    payload: &ProvisionPayload,
    now: u64,
    label: &str,
) -> bool {
    match foreign_relay_for(client, home, payload.relay_ref.as_ref()).await {
        Ok(None) => rejoin_server(client, home, payload, now, label).await,
        Ok(Some(foreign)) => {
            let joined = rejoin_server(client, &foreign, payload, now, label).await;
            if let (true, Some(relay_ref)) = (joined, &payload.relay_ref) {
                {
                    let c = client.lock().await;
                    if let Err(e) = c.store().set_server_relay(&payload.server_id, &relay_ref.relay_vk) {
                        eprintln!("{label}: failed to record server relay: {e}");
                    }
                }
                if let Err(e) = account::update_mirror_grants(client, home).await {
                    eprintln!("{label}: mirror grants not updated: {e}");
                }
            }
            joined
        }
        Err(e) => {
            eprintln!("{label}: cannot reach relay for server {}: {e}", hex::encode(&payload.server_id[..8]));
            false
        }
    }
}

fn payload_from_meta(server_id: [u8; 32], meta: &SyncServerMeta) -> ProvisionPayload {
    ProvisionPayload {
        server_id,
        server_name: meta.server_name.clone(),
        kind: meta.kind,
        members: Vec::new(),
        channels: meta.channels.clone(),
        mailbox_id: meta.mailbox_id,
        relay_ref: meta.relay_ref.clone(),
    }
}

/// Rejoin every server listed in a recovered sync snapshot, each on its own relay.
pub async fn rejoin_from_sync(
    client: &SharedClient,
    home: &SharedRelay,
    server_entries: &[([u8; 32], SyncServerMeta)],
    now: u64,
) {
    for (server_id, meta) in server_entries {
        rejoin_on_hosting_relay(client, home, &payload_from_meta(*server_id, meta), now, "recovery").await;
    }
}

/// Join a server found in another device's sync snapshot, unless this device already
/// has it, and record it in this device's sync state. Returns whether it was joined now.
pub async fn join_if_unknown(
    client: &SharedClient,
    home: &SharedRelay,
    server_id: [u8; 32],
    meta: &SyncServerMeta,
    now: u64,
) -> bool {
    join_payload_if_unknown(client, home, &payload_from_meta(server_id, meta), now).await
}

/// Join a server another device announced with its full provision payload, unless this
/// device already has it (a second join would add a duplicate leaf), and record it in this
/// device's sync state. Returns whether it was joined now.
pub async fn join_payload_if_unknown(client: &SharedClient, home: &SharedRelay, payload: &ProvisionPayload, now: u64) -> bool {
    {
        let c = client.lock().await;
        if c.store().get_server(&payload.server_id).is_ok() {
            return false;
        }
    }
    if !rejoin_on_hosting_relay(client, home, payload, now, "sync").await {
        return false;
    }
    let c = client.lock().await;
    if let Ok(meta_out) = c.export_server_meta(&payload.server_id) {
        let key = format!("{}{}", crate::wire::SYNC_KEY_SERVER_PREFIX, hex::encode(payload.server_id));
        let _ = c.sync_set(&key, &meta_out.to_bytes(), now);
    }
    true
}

/// Apply a provision blob on a freshly linked device: store the sync key, join the sync
/// group, rejoin every server, and import sync state. The `client` must already be the
/// new device's identity and `relay` authenticated as it. Returns the parsed settings for
/// the application to apply to its configuration.
pub async fn consume(
    client: &SharedClient,
    relay: &SharedRelay,
    blob: &ProvisionBlob,
    now: u64,
) -> Result<sync::SyncSettings> {
    {
        let c = client.lock().await;
        c.set_sync_key(blob.sync_key)?;
    }

    let (sync_commit, sync_mailbox) = {
        let mut c = client.lock().await;
        c.join_sync_group(&blob.sync_group_info)
            .map_err(|e| GhostError::Mls(format!("join sync group: {e}")))?
    };
    // The other devices only learn about this device through this commit, so a rejection
    // leaves the account's devices permanently out of sync; it is fatal, not logged.
    let sync_commit_seq = {
        let r = relay.lock().await;
        r.post_blob(&sync_mailbox, sync_commit).await?.seq
    };
    {
        let c = client.lock().await;
        let _ = c.store().set_last_seen_seq(&sync_mailbox, sync_commit_seq);
    }
    {
        let mut r = relay.lock().await;
        r.subscribe(sync_mailbox, sync_commit_seq);
    }
    if let Err(e) = super::publish_sync_group_info(client, relay).await {
        eprintln!("provision: sync GroupInfo upload failed: {e}");
    }

    for payload in &blob.servers {
        if rejoin_on_hosting_relay(client, relay, payload, now, "provision").await {
            sync::server_entry(client, relay, &payload.server_id).await;
        }
    }

    if blob.sync_entries.is_empty() {
        return Ok(sync::SyncSettings::default());
    }
    sync::import_entries(client, &blob.sync_entries).await
}
