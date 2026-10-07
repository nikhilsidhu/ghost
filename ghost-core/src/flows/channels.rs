//! Private channels: creating them, finding and joining the ones this account may
//! enter, changing whom they admit, and clearing out members who lost access.

use ghost_wire::policy::ChannelPolicy;

use crate::error::{GhostError, Result};
use crate::storage::ChannelKind;
use crate::wire::{encode_channel_op, ChannelOpPayload};

use super::{publish_server_info, sync, SharedClient, SharedRelay};

/// Create a private channel on the relay hosting the server (`relay`) and subscribe to
/// it. The relay admits the group only from someone who may manage channels. The
/// account's other devices are told through `home` and join through discovery.
/// Returns the channel id.
#[allow(clippy::too_many_arguments)]
pub async fn create_private(
    client: &SharedClient,
    home: &SharedRelay,
    relay: &SharedRelay,
    server_id: &[u8; 32],
    name: &str,
    kind: ChannelKind,
    roles: Vec<u8>,
    accounts: Vec<[u8; 32]>,
) -> Result<[u8; 32]> {
    let created = {
        let mut c = client.lock().await;
        let position = c.store().list_channels(server_id)?.iter().map(|ch| ch.position + 1).max().unwrap_or(0);
        c.create_private_channel(server_id, name, kind, position, roles, accounts)?
    };
    let uploaded = relay.lock().await.put_server_info(&created.mailbox_id, created.group_info).await;
    if let Err(e) = uploaded {
        client.lock().await.drop_private_channel(&created.channel_id)?;
        return Err(e);
    }
    {
        let mut r = relay.lock().await;
        r.add_route(created.mailbox_id);
        r.add_route(created.channel_id);
        // From the mailbox's start: admitted members are told the moment the group
        // exists and may join before the announcement lands, and every join counts.
        r.subscribe(created.mailbox_id, 0);
        r.post_blob(&created.announcement.mailbox_id, created.announcement.blob).await?;
    }
    sync::post_server_provisioned(client, home, server_id).await;
    Ok(created.channel_id)
}

/// Join every private channel of the server that the relay lists for this account
/// and this device is not yet in. Run at start, after server group commits (a role
/// may have been granted) and when a linked device announces a change. A channel
/// whose join the relay refuses is skipped and tried again next time. Returns the
/// channels joined.
pub async fn join_admitted(client: &SharedClient, relay: &SharedRelay, server_id: &[u8; 32]) -> Result<Vec<[u8; 32]>> {
    let server_mailbox = client.lock().await.server_mailbox(server_id)?;
    let listing = relay.lock().await.get_admitted_channels(&server_mailbox).await?;
    let mut joined = Vec::new();
    for (mailbox_id, group_info) in listing.0 {
        let staged = {
            let mut c = client.lock().await;
            if c.channel_id_for_mailbox(&mailbox_id).is_some() {
                continue;
            }
            c.join_private_channel(server_id, &group_info)
        };
        let (channel_id, mailbox_id, commit) = match staged {
            Ok(staged) => staged,
            Err(e) => {
                eprintln!("private channel {}: {e}", hex::encode(&mailbox_id[..8]));
                continue;
            }
        };
        let posted = relay.lock().await.post_blob(&mailbox_id, commit).await;
        let seq = match posted {
            Ok(result) => result.seq,
            Err(e) => {
                eprintln!("private channel {}: join refused: {e}", hex::encode(&channel_id[..8]));
                client.lock().await.drop_private_channel(&channel_id)?;
                continue;
            }
        };
        // A joiner reads nothing from before its join, the channel's name included.
        let request = {
            let mut c = client.lock().await;
            c.store().set_last_seen_seq(&mailbox_id, seq)?;
            c.send_control_in(&channel_id, encode_channel_op(&ChannelOpPayload::InfoRequest { channel_id }))?
        };
        {
            let mut r = relay.lock().await;
            r.add_route(mailbox_id);
            r.add_route(channel_id);
            r.subscribe(mailbox_id, seq);
            r.post_blob(&request.mailbox_id, request.blob).await?;
        }
        publish_server_info(client, relay, &mailbox_id).await;
        joined.push(channel_id);
    }
    Ok(joined)
}

/// Change whom a private channel admits. The relay then proposes removing everyone
/// the new policy excludes. Needs the manage channels permission.
pub async fn set_policy(client: &SharedClient, relay: &SharedRelay, channel_id: &[u8; 32], policy: &ChannelPolicy) -> Result<()> {
    let out = client.lock().await.stage_channel_policy(channel_id, policy)?;
    post_and_merge(client, relay, out).await
}

/// Remove everyone a private channel no longer admits, which must happen before this
/// device sends there. Does nothing for public channels or when nobody is excluded.
pub async fn remove_excluded(client: &SharedClient, relay: &SharedRelay, channel_id: &[u8; 32]) -> Result<()> {
    let out = client.lock().await.remove_excluded(channel_id)?;
    match out {
        Some(out) => post_and_merge(client, relay, out).await,
        None => Ok(()),
    }
}

/// Post a staged commit, merge it once the relay accepts it (or discard it), and
/// publish the group's fresh GroupInfo.
pub(crate) async fn post_and_merge(client: &SharedClient, relay: &SharedRelay, out: crate::wire::Outbound) -> Result<()> {
    let posted = relay.lock().await.post_blob(&out.mailbox_id, out.blob).await;
    {
        let mut c = client.lock().await;
        match posted {
            Ok(_) => c.merge_pending_commit_for_channel(&out.channel_id)?,
            Err(e) => {
                let _ = c.clear_pending_commit_for_channel(&out.channel_id);
                return Err(match e {
                    GhostError::RelayStatus { status: 409, .. } => {
                        GhostError::Network("the group changed meanwhile; catch up and try again".into())
                    }
                    other => other,
                });
            }
        }
    }
    publish_server_info(client, relay, &out.mailbox_id).await;
    Ok(())
}
