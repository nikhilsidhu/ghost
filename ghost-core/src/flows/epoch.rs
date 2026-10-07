//! Recovery from MLS epoch divergence by rejoining a channel group via external commit.

use crate::error::Result;

use super::{publish_server_info, SharedClient, SharedRelay};

const MAX_ATTEMPTS: usize = 3;

/// Rejoin one channel group at the relay's current epoch. Returns `Ok(true)` when the
/// relay accepted the external commit, `Ok(false)` when every attempt was rejected, and
/// `Err` when the GroupInfo could not be fetched (callers branch on a 404 to detect a
/// relay that has no state for the mailbox).
pub async fn recover(
    client: &SharedClient,
    relay: &SharedRelay,
    channel_id: &[u8; 32],
    mailbox_id: &[u8; 32],
    label: &str,
) -> Result<bool> {
    for attempt in 0..MAX_ATTEMPTS {
        let group_info = {
            let r = relay.lock().await;
            r.get_server_info(mailbox_id).await?
        };
        let commit = {
            let mut c = client.lock().await;
            match c.recover_via_external_commit(channel_id, &group_info) {
                Ok((commit, _)) => commit,
                Err(e) => {
                    eprintln!("{label}: external commit failed (attempt {attempt}): {e}");
                    continue;
                }
            }
        };
        let accepted = {
            let r = relay.lock().await;
            match r.post_blob(mailbox_id, commit).await {
                Ok(_) => true,
                Err(e) => {
                    eprintln!("{label}: relay rejected commit (attempt {attempt}): {e}");
                    false
                }
            }
        };
        if accepted {
            let server_id = {
                let c = client.lock().await;
                c.server_id_for_mailbox(mailbox_id)
            };
            if let Some(sid) = server_id {
                publish_server_info(client, relay, &sid, mailbox_id).await;
            }
            return Ok(true);
        }
    }
    Ok(false)
}
