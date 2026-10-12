//! Provisioning a linked or recovered device with the account's servers and sync state.

use std::collections::HashMap;

use crate::error::{GhostError, Result};
use crate::wire::{
    channel_mailbox_id, derive_default_channel_id,
    decode_sync_dump, encode_member_announce, encode_sync_dump, ProvisionPayload, SyncDump,
    SyncServerMeta,
};

use ghost_wire::bytes::{put_prefixed32, Reader};
use ghost_wire::relay_ref::RelayRef;
use ghost_wire::short_id;

use super::{account, publish_server_info, sync, SharedClient};
use crate::relay::RelayClient;

const MAX_REJOIN_ATTEMPTS: usize = 3;

/// What a new device needs to join the account's servers. It carries no account
/// secrets: the device opens its own copy of the account key from the relay.
///
/// Wire layout: `[version:1][count:u16] count × ([len:u32][ProvisionPayload]) [sync dump]`.
pub struct ProvisionBlob {
    pub servers: Vec<ProvisionPayload>,
    /// The existing device's state and what it covers, so the new device starts from it
    /// and treats the messages it covers as seen when relays replay them.
    pub sync_dump: SyncDump,
}

/// The version a provision blob starts with.
const PROVISION_VERSION: u8 = 0x02;

impl ProvisionBlob {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut buf = vec![PROVISION_VERSION];
        buf.extend_from_slice(&(self.servers.len() as u16).to_be_bytes());
        for server in &self.servers {
            put_prefixed32(&mut buf, &server.to_bytes());
        }
        buf.extend_from_slice(&encode_sync_dump(&self.sync_dump)?);
        Ok(buf)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.first() != Some(&PROVISION_VERSION) {
            return Err(GhostError::Format("provision blob from an older app; update both devices".into()));
        }
        let mut r = Reader::new(&data[1..]);
        let count = r.u16()? as usize;
        let mut servers = Vec::with_capacity(count);
        for _ in 0..count {
            servers.push(ProvisionPayload::from_bytes(r.prefixed32()?)?);
        }
        let sync_dump = decode_sync_dump(r.rest())?;
        Ok(Self { servers, sync_dump })
    }
}

/// Rejoin one server by external commit from each channel's GroupInfo on the relay, with
/// retries. Returns `true` once every channel commit was accepted and the member announced.
/// A relay that refuses a channel's GroupInfo (404 or another client error) ends the attempts.
pub async fn rejoin_server(
    client: &SharedClient,
    relay: &RelayClient,
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
            let fetched = relay.get_server_info(&mailbox_id).await;
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
                    tracing::warn!("{label}: join attempt failed for {}: {e}", short_id(&payload.server_id));
                    continue;
                }
            }
        };

        let mut rejected = 0usize;
        for (channel_id, commit, mailbox_id) in &channel_results {
            let commit_seq = match relay.post_blob(mailbox_id, commit.clone()).await {
                Ok(res) => res.seq,
                Err(e) => {
                    tracing::warn!("{label}: relay rejected commit: {e}");
                    rejected += 1;
                    continue;
                }
            };
            {
                let c = client.lock().await;
                let _ = c.store().set_last_seen_seq(mailbox_id, commit_seq);
            }
            relay.subscribe(*mailbox_id, commit_seq);
            // Voice signaling for the channel goes to the same relay.
            relay.add_route(*channel_id);
        }

        if rejected > 0 {
            tracing::warn!(
                "{label}: {rejected} of {} channels of server {} refused this device's join",
                channel_results.len(),
                short_id(&payload.server_id)
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
            let _ = relay.post_blob(&outbound.mailbox_id, outbound.blob).await;
        }

        return true;
    }

    tracing::error!("{label}: failed to join server {} after retries", short_id(&payload.server_id));
    false
}

/// Rejoin every server listed in a recovered sync snapshot.
/// Client for the relay that hosts a server, or `None` when that is the home.
/// A foreign relay is dialed with this device's credentials, must hold the key
/// the server's record names, and receives the account's chain, which admits
/// this device because another device already made the account known there.
async fn foreign_relay_for(
    client: &SharedClient,
    home: &RelayClient,
    relay_ref: Option<&RelayRef>,
) -> Result<Option<RelayClient>> {
    let Some(target) = relay_ref else { return Ok(None) };
    let home_vk = account::home_relay_vk(client, home).await?;
    if target.relay_vk == home_vk {
        return Ok(None);
    }

    let url = target
        .primary_https_url()
        .ok_or_else(|| GhostError::Network("server's relay has no reachable endpoint".into()))?;
    // A view of the home client: its subscriptions join the application's event stream.
    let foreign = home.at(url);
    let info = account::register_at(client, home, &foreign, None).await?;
    if info.relay_vk != target.relay_vk {
        return Err(GhostError::Network(format!("relay at {url} is not the relay this server lives on")));
    }
    Ok(Some(foreign))
}

/// [`rejoin_server`] on whichever relay hosts the server, recording that relay.
pub async fn rejoin_on_hosting_relay(
    client: &SharedClient,
    home: &RelayClient,
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
                        tracing::error!("{label}: failed to record server relay: {e}");
                    }
                }
                if let Err(e) = account::update_mirror_grants(client, home).await {
                    tracing::warn!("{label}: mirror grants not updated: {e}");
                }
                sync::ensure_sync_relays(client, home).await;
            }
            joined
        }
        Err(e) => {
            tracing::warn!("{label}: cannot reach relay for server {}: {e}", short_id(&payload.server_id));
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
        role_names: meta.role_names.clone(),
    }
}

/// Rejoin every server listed in a recovered sync snapshot, each on its own relay.
pub async fn rejoin_from_sync(
    client: &SharedClient,
    home: &RelayClient,
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
    home: &RelayClient,
    server_id: [u8; 32],
    meta: &SyncServerMeta,
    now: u64,
) -> bool {
    join_payload_if_unknown(client, home, &payload_from_meta(server_id, meta), now).await
}

/// Join a server another device announced with its full provision payload, unless this
/// device already has it (a second join would add a duplicate leaf). The server's sync
/// entry is the announcing device's, which reaches this one with the announcement or
/// came before it; writing one here could only outdate it. Returns whether it was
/// joined now.
pub async fn join_payload_if_unknown(client: &SharedClient, home: &RelayClient, payload: &ProvisionPayload, now: u64) -> bool {
    {
        let c = client.lock().await;
        if c.store().get_server(&payload.server_id).is_ok() {
            return false;
        }
    }
    rejoin_on_hosting_relay(client, home, payload, now, "sync").await
}

/// Apply a provision blob on a freshly linked device: open its copies of the account
/// key, rejoin every server, and import sync state. The `client` must already be the new
/// device's identity and `relay` (the home) authenticated as it. Returns the parsed
/// settings for the application to apply to its configuration.
pub async fn consume(
    client: &SharedClient,
    relay: &RelayClient,
    blob: &ProvisionBlob,
    now: u64,
) -> Result<sync::SyncSettings> {
    super::account_keys::refresh(client, relay).await?;

    for payload in &blob.servers {
        if rejoin_on_hosting_relay(client, relay, payload, now, "provision").await {
            sync::server_entry(client, relay, &payload.server_id).await;
        }
    }

    client.lock().await.cover_sync(&blob.sync_dump.covered)?;
    if blob.sync_dump.entries.is_empty() {
        return Ok(sync::SyncSettings::default());
    }
    sync::import_entries(client, &blob.sync_dump.entries).await
}
