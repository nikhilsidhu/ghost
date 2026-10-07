//! Server membership changes initiated by the creator.

use crate::error::Result;

use super::{publish_server_info, SharedClient, SharedRelay};

/// Remove a member from every channel group of a server. Each channel's commit is posted
/// separately; channels whose commit the relay accepted have already advanced their epoch
/// and locked the member out, so the member row is removed even on partial success.
/// Returns `false` when at least one channel commit was rejected (epoch conflict).
pub async fn kick(
    client: &SharedClient,
    relay: &SharedRelay,
    server_id: &[u8; 32],
    member_fp: &[u8; 32],
) -> Result<bool> {
    let outbounds = {
        let mut c = client.lock().await;
        c.kick_member(server_id, member_fp)?
    };

    let mut all_accepted = true;
    for out in &outbounds {
        let result = {
            let r = relay.lock().await;
            r.post_blob(&out.mailbox_id, out.blob.clone()).await
        };
        let mut c = client.lock().await;
        match result {
            Ok(_) => {
                let _ = c.merge_pending_commit_for_channel(&out.channel_id);
            }
            Err(e) => {
                eprintln!("kick: relay rejected commit for channel {}: {e}", hex::encode(&out.channel_id[..8]));
                let _ = c.clear_pending_commit_for_channel(&out.channel_id);
                all_accepted = false;
            }
        }
    }

    let default_mailbox = {
        let c = client.lock().await;
        let _ = c.store().remove_member(server_id, member_fp);
        c.mailbox_id_for_server(server_id)
    };
    if let Some(mailbox_id) = default_mailbox {
        publish_server_info(client, relay, server_id, &mailbox_id).await;
    }
    Ok(all_accepted)
}
