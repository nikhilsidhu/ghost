//! Listing and revoking the account's devices.

use ghost_wire::idlog::LogState;
use ghost_wire::short_id;

use crate::error::{GhostError, Result};
use crate::identity::batch::BatchBuilder;
use crate::identity::log::{create_rename_device, create_revoke_device};

use super::{account, account_keys, epoch, idlog, now_millis, publish_server_info, sync, SharedClient};
use crate::relay::RelayClient;

/// The account's devices, and whether the list is the home's word now.
pub struct DeviceList {
    pub state: LogState,
    /// `false` when the home could not be reached and this is the log as this device
    /// last verified it, which the account check keeps fresh from the relays mirroring it.
    pub current: bool,
}

/// The account's device list, verified against the home's identity log; with the home
/// out of reach, the log as this device last verified it.
pub async fn list(client: &SharedClient, relay: &RelayClient) -> Result<DeviceList> {
    let account_fp = *client.lock().await.fingerprint();
    match idlog::fetch_and_verify(client, relay, &account_fp).await {
        Ok(state) => Ok(DeviceList { state, current: true }),
        Err(e) if home_unreachable(&e) => match client.lock().await.own_log() {
            Some(cached) => Ok(DeviceList { state: cached.clone(), current: false }),
            None => Err(e),
        },
        Err(e) => Err(e),
    }
}

/// Give a device of this account the label its list shows: an identity log entry any
/// active device may append, which the account's devices and relays all see.
pub async fn rename(client: &SharedClient, relay: &RelayClient, target_vk: &[u8; 32], label: &str) -> Result<()> {
    account::append_built(client, relay, |log_state| Box::pin(async move {
        if !log_state.is_active_device(target_vk) {
            return Err(GhostError::Format("no active device of this account has that key".into()));
        }
        let c = client.lock().await;
        let mut batch = BatchBuilder::new(log_state);
        batch.push(create_rename_device(batch.state(), &c.signing_key_clone(), target_vk, label))?;
        Ok(Some((batch.finish(), ())))
    }))
    .await?;
    account::announce_change(client, relay).await;
    Ok(())
}

/// How far a revocation got.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevokeOutcome {
    /// Out of every group, recorded in the identity log, and pushed to the relays.
    Complete,
    /// Recorded in the identity log and pushed to the relays, but the groups of these
    /// servers refused this device's removal commit: their relays, having learned the
    /// revocation, propose the removal themselves, and a member's device commits it.
    LeavesLeft(Vec<[u8; 32]>),
    /// The home relay was unreachable, so the identity log entry (and relay-side
    /// session closing) waits. This device keeps it and `finish_pending` appends it
    /// once the home is back.
    LogPending,
}

/// Revoke another device of this account. Its MLS leaves go first, from every channel
/// group: that cryptographic barrier needs only the relays hosting each group. Then
/// `RevokeDevice` and an account key generation that leaves the device out are appended
/// at the home together and pushed to the other relays, which close the device's
/// sessions. Nothing the device holds opens sync written under that generation.
pub async fn revoke(client: &SharedClient, relay: &RelayClient, target_vk: &[u8; 32]) -> Result<RevokeOutcome> {
    let own_vk = {
        let c = client.lock().await;
        c.verifying_key_bytes()
    };
    if *target_vk == own_vk {
        return Err(GhostError::PermissionDenied("cannot revoke the current device".into()));
    }

    let leaves_left = remove_device_leaves(client, relay, target_vk).await;

    match append_revocation(client, relay, target_vk).await {
        Ok(()) => {
            client.lock().await.store().remove_pending_revocation(target_vk)?;
            Ok(if leaves_left.is_empty() { RevokeOutcome::Complete } else { RevokeOutcome::LeavesLeft(leaves_left) })
        }
        Err(e) if home_unreachable(&e) => {
            // Until the log revokes it, the device holds the current generation, so every
            // device of the account stops writing sync (it reads nothing it does not get).
            sync::post_message(client, relay, crate::wire::SyncMessageType::SyncPause, target_vk).await;
            client.lock().await.store().add_pending_revocation(target_vk, now_millis())?;
            Ok(RevokeOutcome::LogPending)
        }
        Err(e) => Err(e),
    }
}

/// A waiting removal the home refused, for a reason a retry does not change by itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovalRefused {
    pub device_vk: [u8; 32],
    pub reason: String,
}

/// Append the revocations that waited for the home, oldest first; any active device may,
/// so whichever reaches the home first finishes a removal another device started (a
/// device the log already revokes counts as finished). Stops at the first the home
/// cannot take yet. One refused for another reason stays waiting, and sync paused,
/// with the reason kept for the device list; returns those refused for a reason not
/// told before.
pub async fn finish_pending(client: &SharedClient, relay: &RelayClient) -> Result<Vec<RemovalRefused>> {
    let pending = client.lock().await.store().pending_revocations()?;
    let mut refused = Vec::new();
    for target_vk in pending {
        match append_revocation(client, relay, &target_vk).await {
            Ok(()) => client.lock().await.store().remove_pending_revocation(&target_vk)?,
            Err(e) if home_unreachable(&e) => break,
            Err(e) => {
                let reason = e.to_string();
                tracing::warn!("revoke: the home refused the removal of {}: {reason}", short_id(&target_vk));
                if client.lock().await.store().set_pending_refused(&target_vk, &reason)? {
                    refused.push(RemovalRefused { device_vk: target_vk, reason });
                }
            }
        }
    }
    Ok(refused)
}

/// The relay could not be reached or is temporarily failing, as opposed to refusing.
fn home_unreachable(e: &GhostError) -> bool {
    matches!(e, GhostError::Network(_) | GhostError::RelayStatus { status: 500..=599, .. })
}

/// Append `RevokeDevice` with the next account key generation at the home, and push
/// both to every relay hosting the account's servers. Before the root rotates there is
/// no account key, and the revocation goes alone.
async fn append_revocation(client: &SharedClient, relay: &RelayClient, target_vk: &[u8; 32]) -> Result<()> {
    let appended = account::append_built(client, relay, |log_state| Box::pin(async move {
        if !log_state.is_active_device(target_vk) {
            return Ok(None);
        }
        account_keys::open_missing(client, relay, &log_state).await?;
        let c = client.lock().await;
        let signing_key = c.signing_key_clone();
        let previous = account_keys::newest_held(&c, &log_state)?;
        let mut batch = BatchBuilder::new(log_state);
        batch.push(create_revoke_device(batch.state(), &signing_key, target_vk))?;
        let seed = if batch.state().root_rotated() { Some(batch.push_rekey(&signing_key, previous.as_ref())?) } else { None };
        Ok(Some((batch.finish(), seed)))
    }))
    .await?;
    let Some(seed) = appended else { return Ok(()) };
    if let Some(seed) = seed {
        client.lock().await.store_account_seed(&seed)?;
    }
    // Lets devices that paused for this removal resume, under the new generation.
    account::announce_change(client, relay).await;
    Ok(())
}

/// Remove a device's leaves from every channel group this client belongs to. A rejected
/// commit triggers epoch recovery for that channel and one retry. Returns the servers
/// whose groups still hold a leaf.
pub async fn remove_device_leaves(client: &SharedClient, relay: &RelayClient, target_vk: &[u8; 32]) -> Vec<[u8; 32]> {
    remove_devices_leaves(client, relay, std::slice::from_ref(target_vk)).await
}

/// Remove several devices' leaves from every channel group this client belongs to, one
/// commit per channel, as a recovery does for every device it replaces. Returns the
/// servers whose groups still hold a leaf: their relays propose the removal once they
/// learn the revocation.
pub async fn remove_devices_leaves(client: &SharedClient, relay: &RelayClient, targets: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let outbound = {
        let mut c = client.lock().await;
        c.revoke_devices_leaves(targets)
    };
    let mut left = Vec::new();
    for out in outbound {
        if !remove_leaves_from(client, relay, &out.channel_id, &out.mailbox_id, out.blob, targets).await {
            let server_id = client.lock().await.store().get_channel(&out.channel_id).map(|channel| channel.server_id);
            if let Ok(server_id) = server_id {
                if !left.contains(&server_id) {
                    left.push(server_id);
                }
            }
        }
    }
    left
}

/// Post one channel's removal commit, recovering the epoch and trying once more when the
/// relay refuses it. Whether the group no longer holds the leaves.
async fn remove_leaves_from(
    client: &SharedClient,
    relay: &RelayClient,
    channel_id: &[u8; 32],
    mailbox_id: &[u8; 32],
    commit: Vec<u8>,
    targets: &[[u8; 32]],
) -> bool {
    if post_removal(client, relay, channel_id, mailbox_id, commit).await {
        return true;
    }
    tracing::warn!("revoke: commit rejected for channel {}, recovering epoch", short_id(channel_id));
    match epoch::recover(client, relay, channel_id, mailbox_id, "revoke-retry").await {
        Ok(true) => {}
        Ok(false) | Err(_) => {
            tracing::error!("revoke: epoch recovery failed for channel {}", short_id(channel_id));
            return false;
        }
    }
    let retry = {
        let mut c = client.lock().await;
        let leaves = c.find_devices_leaves(channel_id, targets);
        if leaves.is_empty() {
            return true;
        }
        match c.remove_channel_members(channel_id, &leaves) {
            Ok(blob) => blob,
            Err(e) => {
                tracing::error!("revoke: retry remove_members failed: {e}");
                return false;
            }
        }
    };
    let removed = post_removal(client, relay, channel_id, mailbox_id, retry).await;
    if !removed {
        tracing::error!("revoke: retry also rejected for channel {}", short_id(channel_id));
    }
    removed
}

/// Post one removal commit; merge it locally and republish GroupInfo on success,
/// discard it on rejection. Returns whether the relay accepted it.
async fn post_removal(
    client: &SharedClient,
    relay: &RelayClient,
    channel_id: &[u8; 32],
    mailbox_id: &[u8; 32],
    commit: Vec<u8>,
) -> bool {
    let result = relay.post_blob(mailbox_id, commit).await;
    {
        let mut c = client.lock().await;
        match result {
            Ok(_) => {
                let _ = c.merge_pending_commit_for_channel(channel_id);
            }
            Err(_) => {
                let _ = c.clear_pending_commit_for_channel(channel_id);
                return false;
            }
        }
    }
    publish_server_info(client, relay, mailbox_id).await;
    true
}
