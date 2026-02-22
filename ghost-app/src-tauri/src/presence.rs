use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ghost_core::client::GhostClient;
use ghost_core::mls::presence::OnlineStatus;
use ghost_core::relay::RelayClient;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct PresenceInfo {
    pub status: OnlineStatus,
    pub status_message: Option<String>,
    pub status_expiry: Option<u64>,
    pub avatar_hash: Option<[u8; 32]>,
}

impl Default for PresenceInfo {
    fn default() -> Self {
        Self {
            status: OnlineStatus::Online,
            status_message: None,
            status_expiry: None,
            avatar_hash: None,
        }
    }
}

/// Seal and send online presence to all server mailboxes.
/// Invisible status sends leave messages to remove existing entries.
pub async fn broadcast_presence(
    client: &Arc<Mutex<GhostClient>>,
    relay: &Arc<Mutex<RelayClient>>,
    info: &PresenceInfo,
) {
    if info.status == OnlineStatus::Invisible {
        // Send leave to each mailbox so relay removes our entry
        let mailboxes = {
            let c = client.lock().await;
            c.server_mailboxes()
        };
        let r = relay.lock().await;
        for (_, mailbox_id) in mailboxes {
            let json = serde_json::json!({ "ps": { "leave": true } });
            let _ = r.send_text(&mailbox_id, json.to_string()).await;
        }
        return;
    }

    // Seal per-server blobs: lock client → seal all → drop
    let blobs: Vec<([u8; 32], Vec<u8>)> = {
        let c = client.lock().await;
        c.server_mailboxes()
            .iter()
            .filter_map(|(server_id, mailbox_id)| {
                c.seal_online_presence_blob(
                    server_id,
                    info.status,
                    info.status_message.clone(),
                    info.status_expiry,
                    info.avatar_hash,
                )
                .ok()
                .map(|blob| (*mailbox_id, blob))
            })
            .collect()
    };

    // Send to relay
    let r = relay.lock().await;
    for (mailbox_id, blob) in blobs {
        let json = serde_json::json!({ "ps": { "p": B64.encode(&blob) } });
        let _ = r.send_text(&mailbox_id, json.to_string()).await;
    }
}

/// Broadcast presence to a single mailbox (used on reconnect).
pub async fn broadcast_presence_to_mailbox(
    client: &Arc<Mutex<GhostClient>>,
    relay: &Arc<Mutex<RelayClient>>,
    mailbox_id: &[u8; 32],
    info: &PresenceInfo,
) {
    if info.status == OnlineStatus::Invisible {
        return;
    }
    let blob = {
        let c = client.lock().await;
        c.server_id_for_mailbox(mailbox_id).and_then(|sid| {
            c.seal_online_presence_blob(
                &sid,
                info.status,
                info.status_message.clone(),
                info.status_expiry,
                info.avatar_hash,
            )
            .ok()
        })
    };
    if let Some(blob) = blob {
        let json = serde_json::json!({ "ps": { "p": B64.encode(&blob) } });
        let r = relay.lock().await;
        let _ = r.send_text(mailbox_id, json.to_string()).await;
    }
}
