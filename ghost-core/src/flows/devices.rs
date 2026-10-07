//! Listing and revoking the account's devices.

use ghost_wire::idlog::LogState;

use crate::error::{GhostError, Result};
use crate::identity::log::create_revoke_device;

use super::{epoch, idlog, publish_server_info, sync, SharedClient, SharedRelay};

/// The account's device list, verified against the relay's identity log and KT proofs.
pub async fn list(client: &SharedClient, relay: &SharedRelay) -> Result<LogState> {
    let account_fp = {
        let c = client.lock().await;
        *c.fingerprint()
    };
    idlog::fetch_and_verify(client, relay, &account_fp).await
}

/// How far a revocation got.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokeOutcome {
    /// Out of every group, recorded in the identity log, and pushed to the relays.
    Complete,
    /// Out of every group this device could reach, but the home relay was
    /// unreachable, so the identity log entry (and relay-side session closing)
    /// waits; call `revoke` again once the home is back.
    LogPending,
}

/// Revoke another device of this account. Its MLS leaves go first, from the sync group
/// (with a sync key rotation) and every channel group: that cryptographic barrier needs
/// only the relays hosting each group. Then `RevokeDevice` is appended at the home and
/// pushed to the other relays, which close the device's sessions.
pub async fn revoke(client: &SharedClient, relay: &SharedRelay, target_vk: &[u8; 32]) -> Result<RevokeOutcome> {
    let own_vk = {
        let c = client.lock().await;
        c.verifying_key_bytes()
    };
    if *target_vk == own_vk {
        return Err(GhostError::PermissionDenied("cannot revoke the current device".into()));
    }

    remove_from_sync_group(client, relay, target_vk).await;
    remove_device_leaves(client, relay, target_vk).await;

    match append_revocation(client, relay, target_vk).await {
        Ok(()) => Ok(RevokeOutcome::Complete),
        Err(e) if home_unreachable(&e) => Ok(RevokeOutcome::LogPending),
        Err(e) => Err(e),
    }
}

/// The relay could not be reached or is temporarily failing, as opposed to refusing.
fn home_unreachable(e: &GhostError) -> bool {
    matches!(e, GhostError::Network(_) | GhostError::RelayStatus { status: 500..=599, .. })
}

/// Append `RevokeDevice` at the home and push it to every relay hosting the account's servers.
async fn append_revocation(client: &SharedClient, relay: &SharedRelay, target_vk: &[u8; 32]) -> Result<()> {
    let (account_fp, signing_key) = {
        let c = client.lock().await;
        (*c.fingerprint(), c.signing_key_clone())
    };
    let log_state = idlog::fetch_and_verify(client, relay, &account_fp).await?;
    if !log_state.is_active_device(target_vk) {
        return Ok(());
    }
    let entry = create_revoke_device(&log_state, &signing_key, target_vk);
    {
        let r = relay.lock().await;
        r.put_idlog_entry(&account_fp, entry.to_bytes()).await?;
    }
    for (relay_vk, e) in super::account::replicate_own_log(client, relay).await? {
        eprintln!("revoke: relay {} not updated yet: {e}", hex::encode(&relay_vk[..8]));
    }
    Ok(())
}

/// Remove a device from the sync MLS group so it cannot read future sync traffic, then
/// rotate the sync key so stored snapshots are unreadable to it as well.
async fn remove_from_sync_group(client: &SharedClient, relay: &SharedRelay, target_vk: &[u8; 32]) {
    let removal = {
        let mut c = client.lock().await;
        if !c.has_sync_group() {
            return;
        }
        match (c.sync_mailbox_id(), c.remove_device_from_sync_group(target_vk)) {
            (Some(mailbox), Ok(commit)) => Some((mailbox, commit)),
            (_, Err(e)) => {
                eprintln!("revoke: failed to remove from sync group: {e}");
                None
            }
            (None, _) => None,
        }
    };
    let Some((sync_mailbox, commit)) = removal else { return };

    let accepted = {
        let r = relay.lock().await;
        r.post_blob(&sync_mailbox, commit).await
    };
    let mut c = client.lock().await;
    match accepted {
        Ok(_) => {
            let _ = c.merge_pending_commit_for_sync();
            drop(c);
            if let Err(e) = super::publish_sync_group_info(client, relay).await {
                eprintln!("revoke: sync GroupInfo upload failed: {e}");
            }
            sync::rotate_key(client, relay).await;
        }
        Err(e) => {
            eprintln!("revoke: sync group commit rejected: {e}");
            let _ = c.clear_pending_commit_for_sync();
        }
    }
}

/// Remove a device's leaves from every channel group this client belongs to. A rejected
/// commit triggers epoch recovery for that channel and one retry.
pub async fn remove_device_leaves(client: &SharedClient, relay: &SharedRelay, target_vk: &[u8; 32]) {
    let outbound = {
        let mut c = client.lock().await;
        c.revoke_device_leaves(target_vk)
    };
    for out in outbound {
        let accepted = post_removal(client, relay, &out.channel_id, &out.mailbox_id, out.blob).await;
        if accepted {
            continue;
        }
        eprintln!("revoke: commit rejected for channel {}, recovering epoch", hex::encode(&out.channel_id[..8]));
        match epoch::recover(client, relay, &out.channel_id, &out.mailbox_id, "revoke-retry").await {
            Ok(true) => {}
            Ok(false) | Err(_) => {
                eprintln!("revoke: epoch recovery failed for channel {}", hex::encode(&out.channel_id[..8]));
                continue;
            }
        }
        let retry = {
            let mut c = client.lock().await;
            let leaves = c.find_device_leaves(&out.channel_id, target_vk);
            if leaves.is_empty() {
                continue;
            }
            match c.remove_channel_members(&out.channel_id, &leaves) {
                Ok(blob) => blob,
                Err(e) => {
                    eprintln!("revoke: retry remove_members failed: {e}");
                    continue;
                }
            }
        };
        if !post_removal(client, relay, &out.channel_id, &out.mailbox_id, retry).await {
            eprintln!("revoke: retry also rejected for channel {}", hex::encode(&out.channel_id[..8]));
        }
    }
}

/// Post one removal commit; merge it locally and republish GroupInfo on success,
/// discard it on rejection. Returns whether the relay accepted it.
async fn post_removal(
    client: &SharedClient,
    relay: &SharedRelay,
    channel_id: &[u8; 32],
    mailbox_id: &[u8; 32],
    commit: Vec<u8>,
) -> bool {
    let result = {
        let r = relay.lock().await;
        r.post_blob(mailbox_id, commit).await
    };
    let server_id = {
        let mut c = client.lock().await;
        match result {
            Ok(_) => {
                let _ = c.merge_pending_commit_for_channel(channel_id);
                c.server_id_for_mailbox(mailbox_id)
            }
            Err(_) => {
                let _ = c.clear_pending_commit_for_channel(channel_id);
                return false;
            }
        }
    };
    if let Some(sid) = server_id {
        publish_server_info(client, relay, &sid, mailbox_id).await;
    }
    true
}
