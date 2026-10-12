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
pub mod account_keys;
pub mod channels;
pub mod devices;
pub mod epoch;
pub mod idlog;
pub mod invite;
pub mod members;
pub mod messages;
pub mod pairing;
pub mod presence;
pub mod profile;
pub mod provision;
pub mod recovery;
pub mod roles;
pub mod server;
pub mod sync;

use std::time::Duration;

use ghost_wire::short_id;
use tokio::sync::Mutex;

use crate::client::GhostClient;
use crate::error::{GhostError, Result};
use crate::relay::RelayClient;
use crate::wire::Outbound;

pub type SharedClient = Mutex<GhostClient>;

pub use ghost_wire::now_millis;

/// How long an op the relay refused as sealed at a stale epoch waits for the session to
/// bring its group up to date before giving up.
const CATCH_UP_WAIT: Duration = Duration::from_secs(5);
/// How often that wait looks at the group's epoch.
const CATCH_UP_POLL: Duration = Duration::from_millis(100);

/// Generation for a replicated object: the clock, but always past the last
/// generation this device knows of, so its own writes never collide.
pub(crate) fn next_generation(known: Option<u64>) -> u64 {
    now_millis().max(known.map_or(0, |g| g.saturating_add(1)))
}

/// Subscribe to every known channel mailbox, each on the relay that hosts its server,
/// plus the sync mailbox on every sync relay, resuming from the last seen sequence. Also
/// routes voice channels, so later requests from the home client reach the right relay.
pub fn subscribe_known_mailboxes(client: &GhostClient, relay: &RelayClient) {
    let mut views: std::collections::HashMap<String, RelayClient> = std::collections::HashMap::new();
    for (channel_id, mailbox_id) in client.channel_mailboxes() {
        // Nothing arrives for a server this account was removed from.
        let removed = client.server_id_for_mailbox(&mailbox_id).is_some_and(|server_id| client.ensure_member(&server_id).is_err());
        if removed {
            continue;
        }
        // A server on a relay this device has no address for is not opened on the home,
        // which would refuse it on every retry; a move link or the owner's record is
        // how it is found again.
        if let Some(server_id) = client.server_id_for_mailbox(&mailbox_id).filter(|server_id| hosting_relay_unreachable(client, server_id)) {
            tracing::warn!("server {}: its relay gives no address to reach it at; not connecting", short_id(&server_id));
            continue;
        }
        let seq = client.store().get_last_seen_seq(&mailbox_id).unwrap_or(0);
        match hosting_relay_url(client, &mailbox_id).filter(|url| *url != relay.base_url()) {
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
    subscribe_sync_mailbox(client, relay);
}

/// Open the sync mailbox on the home and every other sync relay. Each relay numbers the
/// mailbox on its own, so each connection resumes from where this device last saw it.
pub fn subscribe_sync_mailbox(client: &GhostClient, relay: &RelayClient) {
    let sync_mailbox = client.account_sync_mailbox();
    let home_url = relay.base_url();
    let seq = client.store().get_last_seen_seq_at(&sync_mailbox, &home_url).unwrap_or(0);
    relay.subscribe(sync_mailbox, seq);
    for url in sync::other_sync_relay_urls(client, &home_url) {
        let seq = client.store().get_last_seen_seq_at(&sync_mailbox, &url).unwrap_or(0);
        relay.at(&url).subscribe_here_too(sync_mailbox, seq);
    }
}

/// URL of the relay hosting the server a mailbox belongs to; `None` for the home relay.
fn hosting_relay_url(client: &GhostClient, mailbox_id: &[u8; 32]) -> Option<String> {
    server_relay_url(client, &client.server_id_for_mailbox(mailbox_id)?)
}

/// The home relay's key as this device knows it: from the connection, else from the cached
/// copy of its own log.
fn known_home_key(client: &GhostClient) -> Option<[u8; 32]> {
    client.relay_vk().or_else(|| client.store().get_cached_idlog_state(client.fingerprint()).ok().flatten().and_then(|s| s.home_relay_vk))
}

/// Whether the server lives on a relay other than the home that gives no address to
/// reach it at.
pub fn hosting_relay_unreachable(client: &GhostClient, server_id: &[u8; 32]) -> bool {
    let Some(hosting) = client.store().server_relay(server_id).ok().flatten() else { return false };
    let Some(home) = known_home_key(client) else { return false };
    hosting != home && server_relay_url(client, server_id).is_none()
}

/// The key of the relay this device is connected to as its home, asked of the relay when
/// not known yet: every group is made with it as external sender, so that the relay can
/// propose removals in it.
pub(crate) async fn home_key(client: &SharedClient, home: &RelayClient) -> Result<[u8; 32]> {
    if let Some(vk) = client.lock().await.relay_vk() {
        return Ok(vk);
    }
    let info = home.get_relay_info().await.map_err(|e| GhostError::Network(format!("your home relay did not answer: {e}")))?;
    client.lock().await.set_relay_vk(info.relay_vk);
    Ok(info.relay_vk)
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
pub async fn publish_server_info(client: &SharedClient, relay: &RelayClient, mailbox_id: &[u8; 32]) {
    let group_info = {
        let c = client.lock().await;
        let exported = c
            .channel_id_for_mailbox(mailbox_id)
            .ok_or_else(|| crate::error::GhostError::ServerNotLoaded(short_id(mailbox_id)))
            .and_then(|channel_id| c.export_channel_group_info(&channel_id));
        match exported {
            Ok(gi) => gi,
            Err(e) => {
                tracing::warn!("server_info export for mailbox {}: {e}", short_id(mailbox_id));
                return;
            }
        }
    };
    if let Err(e) = relay.put_server_info(mailbox_id, group_info).await {
        tracing::warn!("server_info upload for mailbox {}: {e}", short_id(mailbox_id));
    }
}

/// Seal an op in the group of `group_channel` with `seal`, post it and wait for the
/// relay's answer, so the caller knows it landed. Refused as sealed at a stale epoch
/// (this device two or more commits behind), it is sealed again once the session has
/// applied a newer commit; still behind after `CATCH_UP_WAIT`, it fails with
/// `GroupMoved`. Returns what `seal` gave with the op that landed, and where it landed.
pub(crate) async fn post_op<T>(
    client: &SharedClient,
    relay: &RelayClient,
    group_channel: &[u8; 32],
    mut seal: impl FnMut(&mut GhostClient) -> Result<(Outbound, T)>,
) -> Result<(T, u64)> {
    let deadline = tokio::time::Instant::now() + CATCH_UP_WAIT;
    loop {
        let (outbound, sealed, epoch) = {
            let mut c = client.lock().await;
            let epoch = c.channel_epoch(group_channel)?;
            let (outbound, sealed) = seal(&mut c)?;
            (outbound, sealed, epoch)
        };
        match relay.post_blob(&outbound.mailbox_id, outbound.blob).await {
            Ok(posted) => {
                note_own_server_change(client, group_channel, posted.seq).await;
                return Ok((sealed, posted.seq));
            }
            Err(GhostError::RelayStatus { status: 409, .. }) => {
                if !epoch_passed(client, group_channel, epoch, deadline).await {
                    return Err(GhostError::GroupMoved);
                }
            }
            Err(e) => return Err(e),
        }
    }
}

/// An op of this device's own landed in `group_channel`'s group at `seq`: while this
/// device waits for the server's state, an answer as of before it would undo it.
async fn note_own_server_change(client: &SharedClient, group_channel: &[u8; 32], seq: u64) {
    let c = client.lock().await;
    let Ok(channel) = c.store().get_channel(group_channel) else { return };
    if crate::wire::derive_default_channel_id(&channel.server_id) != *group_channel {
        return;
    }
    if let Err(e) = c.store().note_server_change(&channel.server_id, seq) {
        tracing::warn!("server {}: change not noted: {e}", short_id(&channel.server_id));
    }
}

/// Wait until the group of `channel_id` is past `epoch`; false when `deadline` comes first.
async fn epoch_passed(client: &SharedClient, channel_id: &[u8; 32], epoch: u64, deadline: tokio::time::Instant) -> bool {
    loop {
        if client.lock().await.channel_epoch(channel_id).is_ok_and(|now| now > epoch) {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(CATCH_UP_POLL).await;
    }
}

/// Post each blob over HTTP and wait for the relay's answer, so the caller knows whether
/// the change landed. Every blob is tried; the first failure is the error.
pub async fn post_all(relay: &RelayClient, outbounds: Vec<Outbound>) -> Result<()> {
    let mut first_failure = None;
    for out in outbounds {
        if let Err(e) = relay.post_blob(&out.mailbox_id, out.blob).await {
            first_failure.get_or_insert(e);
        }
    }
    first_failure.map_or(Ok(()), Err)
}
