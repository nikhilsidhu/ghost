//! Broadcasting this device's online presence (status, status message, avatar) to
//! the servers it belongs to, sealed per server so only members can read it. Presence
//! goes over each server's own mailbox, which every member connects to; a private
//! channel's mailbox carries none.
//!
//! A mailbox connection refuses an announcement only while it is down with its outbox
//! full, or stalled and about to be reopened. Nothing is kept to send later: every
//! connection that comes up is told the presence as it is then.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

use crate::mls::presence::{AvatarRef, OnlineStatus};

use super::SharedClient;
use crate::relay::RelayClient;

/// What this device currently announces as its presence.
#[derive(Clone, Debug)]
pub struct PresenceInfo {
    pub status: OnlineStatus,
    pub status_message: Option<String>,
    pub status_expiry: Option<u64>,
    pub avatar: Option<AvatarRef>,
}

impl Default for PresenceInfo {
    fn default() -> Self {
        Self {
            status: OnlineStatus::Online,
            status_message: None,
            status_expiry: None,
            avatar: None,
        }
    }
}

/// The account's avatar as this device's member records of it name it, for the presence
/// a device starts with.
pub fn own_avatar(client: &crate::client::GhostClient) -> Option<AvatarRef> {
    let own = *client.fingerprint();
    client.server_mailboxes().iter().find_map(|(server_id, _)| {
        let member = client.store().get_member(server_id, &own).ok()?;
        Some(AvatarRef { hash: member.avatar_hash?, key: member.avatar_key? })
    })
}

/// Seal and send online presence to every server's mailbox. Invisible withdraws this
/// device's entry from each instead.
pub async fn broadcast(client: &SharedClient, relay: &RelayClient, info: &PresenceInfo) {
    if info.status == OnlineStatus::Invisible {
        let mailboxes = client.lock().await.server_mailboxes();
        for (_, mailbox_id) in mailboxes {
            announce(relay, &mailbox_id, serde_json::json!({ "ps": { "leave": true } }));
        }
        return;
    }
    let sealed: Vec<([u8; 32], Vec<u8>)> = {
        let c = client.lock().await;
        c.server_mailboxes().into_iter().filter_map(|(server_id, mailbox_id)| seal(&c, &server_id, info).map(|blob| (mailbox_id, blob))).collect()
    };
    for (mailbox_id, blob) in sealed {
        announce(relay, &mailbox_id, serde_json::json!({ "ps": { "p": B64.encode(&blob) } }));
    }
}

/// Announce presence on one mailbox, when its connection comes up or this device's epoch
/// in its group moves. A private channel's mailbox carries none.
pub async fn broadcast_to_mailbox(client: &SharedClient, relay: &RelayClient, mailbox_id: &[u8; 32], info: &PresenceInfo) {
    if info.status == OnlineStatus::Invisible {
        return;
    }
    let blob = {
        let c = client.lock().await;
        c.server_id_for_server_mailbox(mailbox_id).and_then(|server_id| seal(&c, &server_id, info))
    };
    if let Some(blob) = blob {
        announce(relay, mailbox_id, serde_json::json!({ "ps": { "p": B64.encode(&blob) } }));
    }
}

/// The presence sealed for a server; a server whose group is not loaded gets none until
/// its connection comes up or its epoch moves.
fn seal(client: &crate::client::GhostClient, server_id: &[u8; 32], info: &PresenceInfo) -> Option<Vec<u8>> {
    let sealed = client.seal_online_presence_blob(server_id, info.status, info.status_message.clone(), info.status_expiry, info.avatar);
    sealed.inspect_err(|e| tracing::debug!("presence for server {} not sealed: {e}", ghost_wire::short_id(server_id))).ok()
}

fn announce(relay: &RelayClient, mailbox_id: &[u8; 32], announcement: serde_json::Value) {
    if let Err(e) = relay.send_text(mailbox_id, announcement.to_string()) {
        tracing::debug!("presence on mailbox {} waits for its connection: {e}", ghost_wire::short_id(mailbox_id));
    }
}
