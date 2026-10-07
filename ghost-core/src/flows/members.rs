//! Server membership changes initiated by the creator.

use crate::error::Result;

use super::{publish_server_info, SharedClient, SharedRelay};

/// Kick a member from a server: one commit removing the member's leaves from the server
/// group. The relay then proposes removing the member from the server's private
/// channels, which members' devices commit. Returns `false` when the relay rejected the
/// commit (an epoch conflict); the caller may retry after catching up.
pub async fn kick(
    client: &SharedClient,
    relay: &SharedRelay,
    server_id: &[u8; 32],
    member_fp: &[u8; 32],
) -> Result<bool> {
    let out = {
        let mut c = client.lock().await;
        c.kick_member(server_id, member_fp)?
    };
    let result = {
        let r = relay.lock().await;
        r.post_blob(&out.mailbox_id, out.blob.clone()).await
    };
    {
        let mut c = client.lock().await;
        if let Err(e) = result {
            eprintln!("kick: relay rejected the commit: {e}");
            let _ = c.clear_pending_commit_for_channel(&out.channel_id);
            return Ok(false);
        }
        c.merge_pending_commit_for_channel(&out.channel_id)?;
        let _ = c.store().remove_member(server_id, member_fp);
    }
    // Later external-commit joins need GroupInfo for the new epoch.
    publish_server_info(client, relay, &out.mailbox_id).await;
    Ok(true)
}
