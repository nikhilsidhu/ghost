//! Multi-step protocol flows that combine `GhostClient` state changes with relay
//! round trips: invites, device pairing, account recovery, device revocation,
//! epoch recovery and cross-device sync.
//!
//! Everything here is transport-agnostic above `RelayClient` and free of UI,
//! configuration and credential-storage concerns, which stay in the application.
//! Flows take the shared client and relay handles the application already holds,
//! lock them only for the synchronous work, and never hold a lock across a
//! network round trip.

pub mod account;
pub mod channels;
pub mod devices;
pub mod epoch;
pub mod idlog;
pub mod invite;
pub mod members;
pub mod pairing;
pub mod provision;
pub mod recovery;
pub mod roles;
pub mod server;
pub mod sync;

use tokio::sync::Mutex;

use crate::client::GhostClient;
use crate::relay::RelayClient;

pub type SharedClient = Mutex<GhostClient>;
pub type SharedRelay = Mutex<RelayClient>;

/// Milliseconds since the Unix epoch, used for message and entry timestamps.
pub fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Generation for a replicated object: the clock, but always past the last
/// generation this device knows of, so its own writes never collide.
pub(crate) fn next_generation(known: Option<u64>) -> u64 {
    now_millis().max(known.map_or(0, |g| g.saturating_add(1)))
}

/// Upload the sync group's current GroupInfo under the sync mailbox. The relay validates
/// every commit against the group state it holds for a mailbox, so without this upload it
/// rejects sync-group commits (device joins and removals) outright.
pub(crate) async fn publish_sync_group_info(client: &SharedClient, relay: &SharedRelay) -> crate::error::Result<()> {
    let (mailbox_id, group_info) = {
        let c = client.lock().await;
        let Some(mailbox_id) = c.sync_mailbox_id() else { return Ok(()) };
        (mailbox_id, c.sync_group_info()?)
    };
    let r = relay.lock().await;
    r.put_server_info(&mailbox_id, group_info).await
}

/// Replace the relay's state for the sync mailbox with a freshly created sync group.
/// The sync mailbox id is derived from the account, so a group re-created after recovery
/// collides with the old group's state on the relay, which refuses GroupInfo at a lower
/// epoch. Deleting the mailbox first (creator-only; this account) clears the way. A relay
/// that holds no state for the mailbox answers 403 or 404, which is not an error here.
pub(crate) async fn reset_sync_mailbox(client: &SharedClient, relay: &SharedRelay) -> crate::error::Result<()> {
    let mailbox_id = {
        let c = client.lock().await;
        match c.sync_mailbox_id() {
            Some(id) => id,
            None => return Ok(()),
        }
    };
    {
        let r = relay.lock().await;
        match r.delete_mailbox(&mailbox_id).await {
            Ok(()) => {}
            Err(crate::error::GhostError::RelayStatus { status: 403 | 404, .. }) => {}
            Err(e) => return Err(e),
        }
    }
    publish_sync_group_info(client, relay).await
}

/// Subscribe to every known channel mailbox, each on the relay that hosts its server,
/// plus the sync mailbox on the home relay, resuming from the last seen sequence. Also
/// routes voice channels, so later requests from the home client reach the right relay.
pub fn subscribe_known_mailboxes(client: &GhostClient, relay: &mut RelayClient) {
    let mut views: std::collections::HashMap<String, RelayClient> = std::collections::HashMap::new();
    for (channel_id, mailbox_id) in client.channel_mailboxes() {
        let seq = client.store().get_last_seen_seq(&mailbox_id).unwrap_or(0);
        match hosting_relay_url(client, &mailbox_id).filter(|url| url != relay.base_url()) {
            Some(url) => {
                let view = views.entry(url).or_insert_with_key(|url| relay.at(url));
                view.subscribe(mailbox_id, seq);
                view.add_route(channel_id);
            }
            None => {
                relay.subscribe(mailbox_id, seq);
                relay.add_route(channel_id);
            }
        }
    }
    if let Some(mailbox_id) = client.sync_mailbox_id() {
        let seq = client.store().get_last_seen_seq(&mailbox_id).unwrap_or(0);
        relay.subscribe(mailbox_id, seq);
    }
}

/// URL of the relay hosting the server a mailbox belongs to; `None` for the home relay.
fn hosting_relay_url(client: &GhostClient, mailbox_id: &[u8; 32]) -> Option<String> {
    server_relay_url(client, &client.server_id_for_mailbox(mailbox_id)?)
}

/// URL of the relay hosting a server; `None` when it lives on the home relay.
pub fn server_relay_url(client: &GhostClient, server_id: &[u8; 32]) -> Option<String> {
    let relay_vk = client.store().server_relay(server_id).ok().flatten()?;
    let relay_ref = client.store().get_relay(&relay_vk).ok().flatten()?;
    relay_ref.primary_https_url().map(str::to_string)
}

/// Upload the current GroupInfo of the channel that owns `mailbox_id`, so other devices
/// can join that channel by external commit. Best effort: failures are logged, never
/// fatal, because the group state is already correct locally.
pub async fn publish_server_info(client: &SharedClient, relay: &SharedRelay, mailbox_id: &[u8; 32]) {
    let group_info = {
        let c = client.lock().await;
        let exported = c
            .channel_id_for_mailbox(mailbox_id)
            .ok_or_else(|| crate::error::GhostError::ServerNotLoaded(hex::encode(&mailbox_id[..8])))
            .and_then(|channel_id| c.export_channel_group_info(&channel_id));
        match exported {
            Ok(gi) => gi,
            Err(e) => {
                eprintln!("server_info export for mailbox {}: {e}", hex::encode(&mailbox_id[..8]));
                return;
            }
        }
    };
    let r = relay.lock().await;
    if let Err(e) = r.put_server_info(mailbox_id, group_info).await {
        eprintln!("server_info upload for mailbox {}: {e}", hex::encode(&mailbox_id[..8]));
    }
}
