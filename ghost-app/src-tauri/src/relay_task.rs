use std::sync::Arc;

use ghost_core::client::GhostClient;
use ghost_core::relay::{RelayClient, RelayEvent};
use tauri::{AppHandle, Emitter};
use tokio::sync::{mpsc, Mutex};

use crate::dto::MessageDto;

pub async fn run(
    app: AppHandle,
    client: Arc<Mutex<GhostClient>>,
    relay: Arc<Mutex<RelayClient>>,
    mut events: mpsc::Receiver<RelayEvent>,
) {
    // Subscribe to all existing group mailboxes with persisted last_seen_seq
    {
        let c = client.lock().await;
        let mailboxes = c.group_mailboxes();
        let mut r = relay.lock().await;
        for (_, mailbox_id) in &mailboxes {
            let seq = c.store().get_last_seen_seq(mailbox_id).unwrap_or(0);
            if let Err(e) = r.subscribe(*mailbox_id, seq).await {
                eprintln!("relay subscribe error: {e}");
            }
        }
    }

    while let Some(event) = events.recv().await {
        let blob = match event {
            RelayEvent::Blob(b) => b,
            RelayEvent::Ack(ack) => {
                if ack.epoch_mismatch {
                    eprintln!("epoch mismatch on seq {}", ack.seq);
                }
                continue;
            }
        };
        let received_at = blob.received_at;
        let mailbox_id = blob.mailbox_id;
        let seq = blob.seq;
        let result = {
            let mut c = client.lock().await;
            match c.group_id_for_mailbox(&mailbox_id) {
                Some(gid) => Some(c.receive_any(&gid, &blob.payload, Some(received_at))),
                None => None,
            }
        };

        match result {
            Some(Ok(Some(msg))) => {
                let dto = MessageDto::from_incoming(&msg, received_at);
                let _ = app.emit("message", &dto);
                let c = client.lock().await;
                let _ = c.store().set_last_seen_seq(&mailbox_id, seq);
            }
            Some(Ok(None)) => {
                // Commit or self-message — still advance seq
                let c = client.lock().await;
                let _ = c.store().set_last_seen_seq(&mailbox_id, seq);
            }
            Some(Err(e)) => eprintln!("relay receive error: {e}"),
            None => {}
        }
    }
}
