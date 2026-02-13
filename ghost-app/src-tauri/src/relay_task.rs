use std::sync::Arc;

use ghost_core::client::GhostClient;
use ghost_core::relay::{IncomingBlob, RelayClient};
use tauri::{AppHandle, Emitter};
use tokio::sync::{mpsc, Mutex};

use crate::dto::MessageDto;

pub async fn run(
    app: AppHandle,
    client: Arc<Mutex<GhostClient>>,
    relay: Arc<Mutex<RelayClient>>,
    mut inbox: mpsc::Receiver<IncomingBlob>,
) {
    // Subscribe to all existing group mailboxes
    let mailboxes = {
        let c = client.lock().await;
        c.group_mailboxes()
    };
    {
        let mut r = relay.lock().await;
        for (_, mailbox_id) in &mailboxes {
            if let Err(e) = r.subscribe(*mailbox_id).await {
                eprintln!("relay subscribe error: {e}");
            }
        }
    }

    while let Some(blob) = inbox.recv().await {
        let received_at = blob.received_at;
        let result = {
            let mut c = client.lock().await;
            match c.group_id_for_mailbox(&blob.mailbox_id) {
                Some(gid) => Some(c.receive_any(&gid, &blob.payload, Some(received_at))),
                None => None,
            }
        };

        match result {
            Some(Ok(Some(msg))) => {
                let dto = MessageDto::from_incoming(&msg, received_at);
                let _ = app.emit("message", &dto);
            }
            Some(Err(e)) => eprintln!("relay receive error: {e}"),
            _ => {}
        }
    }
}
