//! Recovery from MLS epoch divergence by rejoining a channel group via external commit.

use crate::error::Result;

use super::{publish_server_info, SharedClient};
use crate::relay::RelayClient;

const MAX_ATTEMPTS: usize = 3;

/// Rejoin one channel group at the relay's current epoch. Returns `Ok(true)` when the
/// relay accepted the external commit, `Ok(false)` when every attempt was rejected and
/// the group is as it was, and `Err` when the GroupInfo could not be fetched (callers
/// branch on a 404 to detect a relay that has no state for the mailbox).
pub async fn recover(
    client: &SharedClient,
    relay: &RelayClient,
    channel_id: &[u8; 32],
    mailbox_id: &[u8; 32],
    label: &str,
) -> Result<bool> {
    for attempt in 0..MAX_ATTEMPTS {
        let group_info = relay.get_server_info(mailbox_id).await?;
        let commit = {
            let mut c = client.lock().await;
            match c.stage_rejoin(channel_id, &group_info) {
                Ok((commit, _)) => commit,
                Err(e) => {
                    tracing::warn!("{label}: external commit failed (attempt {attempt}): {e}");
                    continue;
                }
            }
        };
        let accepted = match relay.post_blob(mailbox_id, commit).await {
            Ok(_) => true,
            Err(e) => {
                tracing::warn!("{label}: relay rejected commit (attempt {attempt}): {e}");
                false
            }
        };
        // The old group goes, or comes back, by the relay's answer alone.
        let settled = {
            let mut c = client.lock().await;
            if accepted { c.confirm_rejoin(channel_id) } else { c.abandon_rejoin(channel_id) }
        };
        if let Err(e) = settled {
            tracing::error!("{label}: group not settled after the relay's answer: {e}");
        }
        if accepted {
            publish_server_info(client, relay, mailbox_id).await;
            return Ok(true);
        }
    }
    Ok(false)
}
