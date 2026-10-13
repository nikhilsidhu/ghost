//! Channels: creating open ones, and for private ones creating them, finding and
//! joining the ones this account may enter, changing whom they admit, and clearing out
//! members who lost access; renaming, reordering and deleting them; and marking one read
//! across the account's devices.

use ghost_wire::policy::{ChannelPolicy, MANAGE_CHANNELS};
use ghost_wire::short_id;
use rand::RngCore;

use crate::client::GhostClient;
use crate::error::{GhostError, Result};
use crate::storage::{Channel, ChannelKind, OnConflict};
use crate::wire::{derive_default_channel_id, encode_channel_op, ChannelOpPayload, SYNC_KEY_READ_PREFIX};

use super::{post_op, publish_server_info, sync, SharedClient};
use crate::relay::RelayClient;

/// Mark `channel_id` read up to `ts`, here and on this account's other devices.
pub async fn mark_read(client: &SharedClient, relay: &RelayClient, channel_id: &[u8; 32], ts: u64) -> Result<()> {
    client.lock().await.store().mark_channel_read(channel_id, ts)?;
    let key = format!("{SYNC_KEY_READ_PREFIX}{}", hex::encode(channel_id));
    sync::set_and_push(client, relay, &key, &ts.to_be_bytes()).await;
    Ok(())
}

/// Create a channel open to the whole server, after the last one, telling its members
/// through the server's group and this account's other devices through `relay`. The
/// channel exists here only once the relay took the op, so it is never one that only
/// this device sees. Returns the channel id.
pub async fn create(client: &SharedClient, relay: &RelayClient, server_id: &[u8; 32], name: &str, kind: ChannelKind) -> Result<[u8; 32]> {
    let mut channel_id = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut channel_id);
    // After the last channel as this device knows them when the op is sealed.
    let (position, _) = post_op(client, relay, &derive_default_channel_id(server_id), |c| {
        let position = c.store().next_channel_position(server_id)?;
        let op = ChannelOpPayload::Create { channel_id, name: name.to_string(), kind, position };
        Ok((c.send_control(server_id, encode_channel_op(&op))?, position))
    })
    .await?;
    client
        .lock()
        .await
        .store()
        .insert_channel(&Channel { channel_id, server_id: *server_id, name: name.to_string(), kind, position }, OnConflict::Fail)?;
    sync::server_entry(client, relay, server_id).await;
    Ok(channel_id)
}

/// Put the server's channels in `order`, for every member: each takes its index in the
/// whole order, public ones through the server's group and each private one through its
/// own (only its members know of it), and this account's other devices through sync.
/// Each op that lands moves its channels here as on every member's device; one that
/// fails leaves its channels where they were everywhere, and is the error. Needs the
/// manage channels permission.
pub async fn reorder(client: &SharedClient, relay: &RelayClient, server_id: &[u8; 32], order: &[[u8; 32]]) -> Result<()> {
    let (public, private) = {
        let c = client.lock().await;
        require_manage_channels(&c, server_id, "reordering channels")?;
        let placed = order.iter().enumerate().map(|(position, channel_id)| (*channel_id, position as i32));
        placed.partition::<Vec<_>, _>(|(channel_id, _)| !c.is_private_channel(channel_id))
    };
    let mut first_failure = None;
    let posted = post_op(client, relay, &derive_default_channel_id(server_id), |c| {
        let op = ChannelOpPayload::Reorder { positions: public.clone() };
        Ok((c.send_control(server_id, encode_channel_op(&op))?, ()))
    })
    .await;
    match posted {
        Ok(_) => client.lock().await.store().set_channel_positions(server_id, &public)?,
        Err(e) => {
            first_failure.get_or_insert(e);
        }
    }
    for (channel_id, position) in private {
        let posted = post_op(client, relay, &channel_id, |c| {
            let channel = c.store().get_channel(&channel_id)?;
            let op = ChannelOpPayload::Create { channel_id, name: channel.name, kind: channel.kind, position };
            Ok((c.send_control_in(&channel_id, encode_channel_op(&op))?, ()))
        })
        .await;
        match posted {
            Ok(_) => client.lock().await.store().set_channel_positions(server_id, &[(channel_id, position)])?,
            Err(e) => {
                first_failure.get_or_insert(e);
            }
        }
    }
    sync::server_entry(client, relay, server_id).await;
    first_failure.map_or(Ok(()), Err)
}

/// The group a channel's own ops travel in, after checking this device may manage the
/// server's channels: a private channel's own, else the server's.
async fn managed_channel_group(client: &SharedClient, channel_id: &[u8; 32], what: &str) -> Result<([u8; 32], [u8; 32], bool)> {
    let c = client.lock().await;
    let server_id = c.store().get_channel(channel_id)?.server_id;
    require_manage_channels(&c, &server_id, what)?;
    let private = c.is_private_channel(channel_id);
    let group = if private { *channel_id } else { derive_default_channel_id(&server_id) };
    Ok((server_id, group, private))
}

/// Rename a channel for every member; a private one's name only ever travels inside its
/// own group. Renamed here once the relay took it. Needs the manage channels permission.
pub async fn rename(client: &SharedClient, relay: &RelayClient, channel_id: &[u8; 32], name: &str) -> Result<()> {
    let (server_id, group, _) = managed_channel_group(client, channel_id, "renaming channels").await?;
    let op = encode_channel_op(&ChannelOpPayload::Rename { channel_id: *channel_id, name: name.to_string() });
    post_op(client, relay, &group, |c| Ok((c.send_control_in(&group, op.clone())?, ()))).await?;
    client.lock().await.store().rename_channel(channel_id, name)?;
    sync::server_entry(client, relay, &server_id).await;
    Ok(())
}

/// Delete a channel for every member, here once the relay took it. A private one's
/// members drop it on reading the op inside its group; the relay lists it to everyone it
/// admits until its mailbox goes, so this device remembers it as deleted and deletes the
/// mailbox, again at every discovery until the relay confirms it. Needs the manage
/// channels permission.
pub async fn delete(client: &SharedClient, relay: &RelayClient, channel_id: &[u8; 32]) -> Result<()> {
    let (server_id, group, private) = managed_channel_group(client, channel_id, "deleting channels").await?;
    let op = encode_channel_op(&ChannelOpPayload::Delete { channel_id: *channel_id });
    post_op(client, relay, &group, |c| Ok((c.send_control_in(&group, op.clone())?, ()))).await?;
    if private {
        let mailbox_id = client.lock().await.forget_deleted_private_channel(channel_id, true)?;
        relay.unsubscribe(&mailbox_id);
        finish_channel_deletions(client, relay, &server_id).await;
    } else {
        client.lock().await.store().delete_channel(channel_id)?;
    }
    sync::server_entry(client, relay, &server_id).await;
    Ok(())
}

/// Delete at the relay hosting the server the mailboxes of the private channels this
/// device deleted there and the relay has not confirmed gone. A relay that holds no such
/// mailbox, or no longer lets this account delete it, settles the deletion.
pub async fn finish_channel_deletions(client: &SharedClient, relay: &RelayClient, server_id: &[u8; 32]) {
    let (owed, hosting_url) = {
        let c = client.lock().await;
        match c.store().owed_channel_deletions(server_id) {
            Ok(owed) => (owed, super::server_relay_url(&c, server_id)),
            Err(e) => {
                tracing::warn!("deleted channels of {}: {e}", short_id(server_id));
                return;
            }
        }
    };
    if owed.is_empty() {
        return;
    }
    let hosting = relay.at(&hosting_url.unwrap_or_else(|| relay.base_url()));
    for deletion in owed {
        let settled = match hosting.delete_mailbox(&deletion.mailbox_id).await {
            Ok(()) | Err(GhostError::RelayStatus { status: 404, .. }) => true,
            Err(GhostError::RelayStatus { status: 403, .. }) => {
                tracing::warn!("deleted channel {}: this account may no longer delete its mailbox", short_id(&deletion.mailbox_id));
                true
            }
            Err(e) => {
                tracing::warn!("deleted channel {}: mailbox not deleted yet: {e}", short_id(&deletion.mailbox_id));
                false
            }
        };
        if settled {
            if let Err(e) = client.lock().await.store().settle_channel_deletion(&deletion.mailbox_id) {
                tracing::warn!("deleted channel {}: {e}", short_id(&deletion.mailbox_id));
            }
        }
    }
}

fn require_manage_channels(c: &GhostClient, server_id: &[u8; 32], what: &str) -> Result<()> {
    if c.server_policy(server_id)?.has(c.fingerprint(), MANAGE_CHANNELS) {
        Ok(())
    } else {
        Err(GhostError::PermissionDenied(format!("{what} needs the manage channels permission")))
    }
}

/// Create a private channel on the relay hosting the server (`relay`) and subscribe to
/// it. The relay admits the group only from someone who may manage channels. The
/// account's other devices are told through `home` and join through discovery.
/// Returns the channel id.
#[allow(clippy::too_many_arguments)]
pub async fn create_private(
    client: &SharedClient,
    home: &RelayClient,
    relay: &RelayClient,
    server_id: &[u8; 32],
    name: &str,
    kind: ChannelKind,
    roles: Vec<u8>,
    accounts: Vec<[u8; 32]>,
) -> Result<[u8; 32]> {
    super::home_key(client, home).await?;
    let created = {
        let mut c = client.lock().await;
        let position = c.store().next_channel_position(server_id)?;
        c.create_private_channel(server_id, name, kind, position, roles, accounts)?
    };
    let uploaded = relay.put_server_info(&created.mailbox_id, created.group_info).await;
    if let Err(e) = uploaded {
        client.lock().await.drop_private_channel(&created.channel_id)?;
        return Err(e);
    }
    relay.add_route(created.mailbox_id);
    relay.add_route(created.channel_id);
    // From the mailbox's start: admitted members are told the moment the group
    // exists and may join before the announcement lands, and every join counts.
    relay.subscribe(created.mailbox_id, 0);
    // The channel exists from here. Members who join before or without the announcement
    // ask for its name, which this device answers.
    if let Err(e) = relay.post_blob(&created.announcement.mailbox_id, created.announcement.blob).await {
        tracing::warn!("private channel {}: announcement not posted: {e}", short_id(&created.channel_id));
    }
    sync::post_server_provisioned(client, home, server_id).await;
    Ok(created.channel_id)
}

/// Join every private channel of the server that the relay lists for this account
/// and this device is not yet in, nor knows was deleted, then ask the name of every one
/// still unnamed. Run whenever the connection to the server's mailbox has caught up (at
/// start and after a dropped connection), after server group commits (a role may have
/// been granted), when the relay says a channel became joinable and when a linked device
/// announces a change. First, deletions this device owes the relay are tried again. A
/// channel whose join the relay refuses (another join or commit got in first) is skipped;
/// the relay says when it is joinable again. Returns the channels joined.
pub async fn join_admitted(client: &SharedClient, relay: &RelayClient, server_id: &[u8; 32]) -> Result<Vec<[u8; 32]>> {
    finish_channel_deletions(client, relay, server_id).await;
    let server_mailbox = client.lock().await.server_mailbox(server_id)?;
    let listing = relay.get_admitted_channels(&server_mailbox).await?;
    let mut joined = Vec::new();
    for (mailbox_id, group_info) in listing.0 {
        let staged = {
            let mut c = client.lock().await;
            if c.channel_id_for_mailbox(&mailbox_id).is_some() || c.store().is_deleted_channel(&mailbox_id)? {
                continue;
            }
            c.join_private_channel(server_id, &group_info)
        };
        let (channel_id, mailbox_id, commit) = match staged {
            Ok(staged) => staged,
            Err(e) => {
                tracing::warn!("private channel {}: {e}", short_id(&mailbox_id));
                continue;
            }
        };
        let posted = relay.post_blob(&mailbox_id, commit).await;
        let seq = match posted {
            Ok(result) => result.seq,
            Err(e) => {
                tracing::warn!("private channel {}: join refused: {e}", short_id(&channel_id));
                client.lock().await.drop_private_channel(&channel_id)?;
                continue;
            }
        };
        client.lock().await.store().set_last_seen_seq(&mailbox_id, seq)?;
        relay.add_route(mailbox_id);
        relay.add_route(channel_id);
        relay.subscribe(mailbox_id, seq);
        publish_server_info(client, relay, &mailbox_id).await;
        joined.push(channel_id);
    }
    // A joiner reads nothing from before its join, the channel's name included.
    ask_unnamed(client, relay, server_id).await;
    Ok(joined)
}

/// Ask the members of each of the server's private channels this device holds unnamed,
/// and has not asked in this run, for its name. A request the relay did not take is
/// made again at the next discovery.
async fn ask_unnamed(client: &SharedClient, relay: &RelayClient, server_id: &[u8; 32]) {
    let unnamed = match client.lock().await.unasked_unnamed_channels(server_id) {
        Ok(unnamed) => unnamed,
        Err(e) => {
            tracing::warn!("private channels of {}: {e}", short_id(server_id));
            return;
        }
    };
    for channel_id in unnamed {
        let request = client.lock().await.ask_channel_name(&channel_id);
        let posted = match request {
            Ok(request) => relay.post_blob(&request.mailbox_id, request.blob).await.map(drop),
            Err(e) => Err(e),
        };
        match posted {
            Ok(()) => client.lock().await.channel_name_asked(&channel_id),
            Err(e) => tracing::warn!("private channel {}: name not asked yet: {e}", short_id(&channel_id)),
        }
    }
}

/// Change whom a private channel admits. The relay then proposes removing everyone
/// the new policy excludes. Needs the manage channels permission.
pub async fn set_policy(client: &SharedClient, relay: &RelayClient, channel_id: &[u8; 32], policy: &ChannelPolicy) -> Result<()> {
    let out = client.lock().await.stage_channel_policy(channel_id, policy)?;
    post_and_merge(client, relay, out).await
}

/// Remove everyone a private channel no longer admits, which must happen before this
/// device sends there. Does nothing for public channels or when nobody is excluded.
pub async fn remove_excluded(client: &SharedClient, relay: &RelayClient, channel_id: &[u8; 32]) -> Result<()> {
    let out = client.lock().await.remove_excluded(channel_id)?;
    match out {
        Some(out) => post_and_merge(client, relay, out).await,
        None => Ok(()),
    }
}

/// Post a staged commit, merge it once the relay accepts it (or discard it), and
/// publish the group's fresh GroupInfo.
pub(crate) async fn post_and_merge(client: &SharedClient, relay: &RelayClient, out: crate::wire::Outbound) -> Result<()> {
    let posted = relay.post_blob(&out.mailbox_id, out.blob).await;
    {
        let mut c = client.lock().await;
        match posted {
            Ok(_) => c.merge_pending_commit_for_channel(&out.channel_id)?,
            Err(e) => {
                let _ = c.clear_pending_commit_for_channel(&out.channel_id);
                return Err(match e {
                    GhostError::RelayStatus { status: 409, .. } => GhostError::GroupMoved,
                    other => other,
                });
            }
        }
    }
    publish_server_info(client, relay, &out.mailbox_id).await;
    Ok(())
}
