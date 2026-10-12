//! Invite links: creating them (with the invite permission) and joining through them.

use std::time::Duration;

use ghost_wire::relay_ref::RelayRef;
use rand::RngCore;

use crate::error::{GhostError, Result};
use crate::wire::{channel_mailbox_id, derive_default_channel_id, encode_member_announce};
use ghost_wire::short_id;

use super::{account, post_op, publish_server_info, sync, SharedClient};
use crate::relay::RelayClient;

/// How many times a join is built afresh on the relay's GroupInfo, when the relay refuses
/// it as stale or its answer is lost.
const JOIN_ATTEMPTS: usize = 3;
/// The pause before building it again: time for a member to publish the GroupInfo of a
/// commit the stale one lacked, the lost join's own included.
const JOIN_RETRY_DELAY: Duration = Duration::from_millis(500);

pub struct CreatedInvite {
    pub token: String,
    /// Opens the payload stored under `token`; it belongs in the link and nowhere else.
    pub key: [u8; 32],
    pub relay_url: String,
    /// Identifies the hosting relay by key, so joiners can pin it.
    pub relay_ref: RelayRef,
    /// When the invite ends: the relay's answer, which the grant inside carries too.
    pub expires_at: u64,
}

/// Register an invite token on the relay and upload the sealed invite payload for the
/// first joiner. `expires_at` is when the creator wants it to end, `None` for as long as
/// the relay allows; the relay may shorten it, and its answer is the invite's expiry.
pub async fn create(
    client: &SharedClient,
    relay: &RelayClient,
    server_id: &[u8; 32],
    expires_at: Option<u64>,
) -> Result<CreatedInvite> {
    let mailbox = client.lock().await.check_may_invite(server_id)?;
    let mut token_bytes = [0u8; ghost_wire::INVITE_TOKEN_LEN];
    rand::rngs::OsRng.fill_bytes(&mut token_bytes);
    let token = hex::encode(token_bytes);
    let relay_ref = relay.get_relay_info().await?.relay_ref;
    let expires_at = relay.register_invite(&token, &mailbox, expires_at).await?;
    let invite = client.lock().await.create_invite(server_id, expires_at)?;
    relay.put_invite_payload(&token, invite.sealed_payload).await?;
    Ok(CreatedInvite { token, key: invite.key, relay_url: relay.base_url(), relay_ref, expires_at })
}

/// Join a server through an invite token on the relay the link names, which may be
/// the account's home or any other relay. `relay` is a client for that relay and
/// `home` for the account's home relay (the same client when they coincide), both
/// authenticated as this device; `key` opens the sealed payload. Returns the server id.
///
/// Registers the account at a foreign relay, reads the server group's current state
/// there (an invite admits its holder to that), posts one external commit per channel,
/// publishes fresh GroupInfo, announces this member, subscribes to the default mailbox,
/// and notifies linked devices through the home relay. A commit the relay refuses as
/// stale, or whose answer is lost, is built again on the GroupInfo read afresh, up to
/// `JOIN_ATTEMPTS` times; a commit that landed unanswered leaves a leaf the next one
/// removes, as an external commit removes any leaf with the joiner's signature key.
pub async fn join(
    client: &SharedClient,
    home: &RelayClient,
    relay: &RelayClient,
    token: &str,
    key: &[u8; 32],
    now: u64,
) -> Result<[u8; 32]> {
    let relay_info = account::register_at(client, home, relay, Some(token)).await?;

    let payload_bytes = relay
        .get_invite_payload(token)
        .await?
        .ok_or_else(|| GhostError::Network("invite has no payload yet".into()))?;
    let payload = client.lock().await.open_invite(&payload_bytes, key)?;
    // The external commit builds on the server group's state as the relay holds it now;
    // the payload is from when the invite was made.
    let server_mailbox = channel_mailbox_id(&payload.server_id, &derive_default_channel_id(&payload.server_id));

    let mut attempt = 0;
    let (server_id, channel_results, rejoining, default_commit_seq) = loop {
        attempt += 1;
        let server_group_info = relay.get_server_info_as_joiner(&server_mailbox, token).await?;
        let (server_id, channel_results, rejoining) = {
            let mut c = client.lock().await;
            let (server_id, channel_results, _) = c.join_by_invite(payload.clone(), server_group_info, now)?;
            c.store().set_server_relay(&server_id, &relay_info.relay_vk)?;
            let rejoining = c.removed_from(&server_id)?.is_some();
            (server_id, channel_results, rejoining)
        };
        match post_join_commits(relay, &channel_results).await {
            Ok(default_commit_seq) => break (server_id, channel_results, rejoining, default_commit_seq),
            Err(e) => {
                // A refused first join leaves nothing behind; a refused rejoin leaves the
                // server as it was, read-only.
                if !rejoining {
                    let _ = client.lock().await.abandon_join(&server_id);
                }
                let stale_or_lost = matches!(e, GhostError::RelayStatus { status: 409, .. } | GhostError::Network(_));
                if !stale_or_lost || attempt == JOIN_ATTEMPTS {
                    return Err(e);
                }
                tracing::warn!("join: commit not taken (attempt {attempt}): {e}; building it again");
                tokio::time::sleep(JOIN_RETRY_DELAY).await;
            }
        }
    };
    let (_, _, default_mailbox_id) = channel_results[0];
    if rejoining {
        client.lock().await.store().clear_server_removed(&server_id)?;
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
    relay.subscribe(default_mailbox_id, default_commit_seq);
    match announce {
        Ok(outbound) => {
            if let Err(e) = relay.send(&outbound.mailbox_id, outbound.blob) {
                tracing::warn!("join: member announce not sent: {e}");
            }
        }
        Err(e) => tracing::warn!("join: member announce failed: {e}"),
    }
    ask_server_state(client, relay, &server_id).await;

    // The server's relay may now pull this account's log from the home, and may now be one
    // of the relays this account syncs through.
    if let Err(e) = account::update_mirror_grants(client, home).await {
        tracing::warn!("join: mirror grants not updated: {e}");
    }
    sync::ensure_sync_relays(client, home).await;

    // Linked devices and the sync snapshot live on the home relay.
    sync::post_server_provisioned(client, home, &server_id).await;
    sync::server_entry(client, home, &server_id).await;

    Ok(server_id)
}

/// Ask the server's members for its current state, which the invite payload a joiner
/// came in with may lack: a member who may manage channels answers. A request the relay
/// did not take is made again at the next start.
pub async fn ask_server_state(client: &SharedClient, relay: &RelayClient, server_id: &[u8; 32]) {
    let asked = post_op(client, relay, &derive_default_channel_id(server_id), |c| Ok((c.ask_server_state(server_id)?, ()))).await;
    let recorded = match asked {
        Ok(((), seq)) => client.lock().await.store().server_state_requested(server_id, seq),
        Err(e) => Err(e),
    };
    if let Err(e) = recorded {
        tracing::warn!("server {}: state not asked yet: {e}", short_id(server_id));
    }
}

/// Ask for the state of every server this device waits for without the relay having
/// taken its request. Run at start.
pub async fn ask_unrequested_server_states(client: &SharedClient, relay: &RelayClient) {
    let servers = match client.lock().await.store().unrequested_server_states() {
        Ok(servers) => servers,
        Err(e) => {
            tracing::warn!("servers waiting for their state not read: {e}");
            return;
        }
    };
    for server_id in servers {
        ask_server_state(client, relay, &server_id).await;
    }
}

/// Post each group's join commit to the relay hosting the server, the server group's
/// first. Returns the sequence of the server group's commit, where its mailbox resumes.
async fn post_join_commits(relay: &RelayClient, channel_results: &[([u8; 32], Vec<u8>, [u8; 32])]) -> Result<u64> {
    let (_, _, default_mailbox_id) = *channel_results.first().ok_or_else(|| GhostError::Mls("invite produced no channel groups".into()))?;
    let mut default_commit_seq = 0;
    for (channel_id, commit, mailbox_id) in channel_results {
        // Later requests for this server, from any view, go to the relay hosting it.
        relay.add_route(*mailbox_id);
        relay.add_route(*channel_id);
        let posted = relay.post_blob(mailbox_id, commit.clone()).await?;
        if *mailbox_id == default_mailbox_id {
            default_commit_seq = posted.seq;
        }
    }
    Ok(default_commit_seq)
}
