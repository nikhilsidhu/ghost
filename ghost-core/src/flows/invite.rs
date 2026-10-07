//! Invite links: creating them as a server creator and joining through them.

use ghost_wire::relay_ref::RelayRef;

use crate::error::{GhostError, Result};
use crate::wire::encode_member_announce;

use super::{account, idlog, publish_server_info, sync, SharedClient, SharedRelay};

pub struct CreatedInvite {
    pub token: String,
    pub relay_url: String,
    /// Identifies the hosting relay by key, so joiners can pin it.
    pub relay_ref: RelayRef,
}

/// Register an invite token on the relay and upload the invite payload for the first joiner.
pub async fn create(
    client: &SharedClient,
    relay: &SharedRelay,
    server_id: &[u8; 32],
    expires_at: u64,
) -> Result<CreatedInvite> {
    let (token, payload) = {
        let c = client.lock().await;
        c.create_invite(server_id)?
    };
    let r = relay.lock().await;
    let relay_ref = r.get_relay_info().await?.relay_ref;
    r.register_invite(&token, expires_at).await?;
    r.put_invite_payload(&token, 0, payload).await?;
    Ok(CreatedInvite { token, relay_url: r.base_url().to_string(), relay_ref })
}

/// Join a server through an invite token on the relay the link names, which may be
/// the account's home or any other relay. `relay` is a client for that relay and
/// `home` for the account's home relay (the same client when they coincide), both
/// authenticated as this device. Returns the server id.
///
/// Registers the account at a foreign relay, posts one external commit per channel,
/// refreshes the invite payload for the next joiner, publishes fresh GroupInfo,
/// announces this member, subscribes to the default mailbox, warms the identity-log
/// cache for existing members, and notifies linked devices through the home relay.
pub async fn join(
    client: &SharedClient,
    home: &SharedRelay,
    relay: &SharedRelay,
    token: &str,
    now: u64,
) -> Result<[u8; 32]> {
    let relay_info = account::register_at(client, relay, Some(token)).await?;

    let (seq, payload_bytes) = {
        let r = relay.lock().await;
        r.get_invite_payload(token)
            .await?
            .ok_or_else(|| GhostError::Network("invite has no payload yet".into()))?
    };

    let (server_id, channel_results) = {
        let mut c = client.lock().await;
        let joined = c.join_by_invite(&payload_bytes, now)?;
        c.store().set_server_relay(&joined.0, &relay_info.relay_vk)?;
        joined
    };
    let (_, _, default_mailbox_id) = *channel_results
        .first()
        .ok_or_else(|| GhostError::Mls("invite produced no channel groups".into()))?;

    let mut default_commit_seq = 0u64;
    for (channel_id, commit, mailbox_id) in &channel_results {
        let r = relay.lock().await;
        // Later requests for this server, from any view, go to the relay hosting it.
        r.add_route(*mailbox_id);
        r.add_route(*channel_id);
        let result = r.post_blob(mailbox_id, commit.clone()).await?;
        if *mailbox_id == default_mailbox_id {
            default_commit_seq = result.seq;
        }
    }

    // The next joiner needs GroupInfo from the epoch our commit just created. A 409 means
    // another joiner refreshed first; their payload is at least as fresh as ours.
    let refreshed = {
        let c = client.lock().await;
        c.refresh_invite_payload(&server_id)?
    };
    {
        let r = relay.lock().await;
        match r.put_invite_payload(token, seq, refreshed).await {
            Ok(()) => {}
            Err(GhostError::RelayStatus { status: 409, .. }) => {}
            Err(e) => return Err(e),
        }
    }

    for (_channel_id, _commit, mailbox_id) in &channel_results {
        publish_server_info(client, relay, mailbox_id).await;
    }

    let announce = {
        let mut c = client.lock().await;
        let _ = c.store().set_last_seen_seq(&default_mailbox_id, default_commit_seq);
        let name = c.identity().display_name.clone();
        c.send_control(&server_id, encode_member_announce(&name))
    };
    {
        let mut r = relay.lock().await;
        r.subscribe(default_mailbox_id, default_commit_seq);
        match announce {
            Ok(outbound) => {
                let _ = r.send(&outbound.mailbox_id, outbound.blob).await;
            }
            Err(e) => eprintln!("join: member announce failed: {e}"),
        }
    }

    let member_fps = {
        let c = client.lock().await;
        c.all_member_fingerprints()
    };
    for fp in &member_fps {
        idlog::cache_member(client, relay, fp).await;
    }

    // The server's relay may now pull this account's log from the home.
    if let Err(e) = account::update_mirror_grants(client, home).await {
        eprintln!("join: mirror grants not updated: {e}");
    }

    // Linked devices and the sync snapshot live on the home relay.
    sync::post_server_provisioned(client, home, &server_id).await;
    sync::server_entry(client, home, &server_id).await;

    Ok(server_id)
}
