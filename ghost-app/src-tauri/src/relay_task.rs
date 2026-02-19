use std::sync::Arc;

use ghost_core::client::{GhostClient, ReceiveResult};
use ghost_core::crypto::MessageType;
use ghost_core::relay::{RelayClient, RelayEvent};
use ghost_core::storage::{Channel, Member, MemberRole};
use ghost_core::wire::{decode_metadata, ChannelOpPayload, MetadataPayload};
use tauri::{AppHandle, Emitter};
use tokio::sync::{mpsc, Mutex};

use crate::dto::MessageDto;

pub async fn run(
    app: AppHandle,
    client: Arc<Mutex<GhostClient>>,
    relay: Arc<Mutex<RelayClient>>,
    mut events: mpsc::Receiver<RelayEvent>,
) {
    // Subscribe to all existing server mailboxes with persisted last_seen_seq
    {
        let c = client.lock().await;
        let mailboxes = c.server_mailboxes();
        let mut r = relay.lock().await;
        for (_, mailbox_id) in &mailboxes {
            let seq = c.store().get_last_seen_seq(mailbox_id).unwrap_or(0);
            r.subscribe(*mailbox_id, seq);
        }
    }

    while let Some(event) = events.recv().await {
        match event {
            RelayEvent::Blob(blob) => {
                let received_at = blob.received_at;
                let mailbox_id = blob.mailbox_id;
                let seq = blob.seq;
                let result = {
                    let mut c = client.lock().await;
                    match c.server_id_for_mailbox(&mailbox_id) {
                        Some(sid) => Some((sid, c.receive_any(&sid, &blob.payload, Some(received_at)))),
                        None => None,
                    }
                };

                match result {
                    Some((server_id, Ok(ReceiveResult::Message(msg)))) if msg.message_type == MessageType::Metadata => {
                        match decode_metadata(&msg.content) {
                            Ok(payload) => {
                                let c = client.lock().await;
                                match payload {
                                    MetadataPayload::ChannelOp(ChannelOpPayload::Create { channel_id, name, kind, position }) => {
                                        let _ = c.store().insert_channel(&Channel {
                                            channel_id,
                                            server_id,
                                            name,
                                            kind,
                                            position,
                                        });
                                    }
                                    MetadataPayload::ChannelOp(ChannelOpPayload::Rename { channel_id, name }) => {
                                        let _ = c.store().rename_channel(&channel_id, &name);
                                    }
                                    MetadataPayload::ChannelOp(ChannelOpPayload::Delete { channel_id }) => {
                                        let _ = c.store().delete_channel(&channel_id);
                                    }
                                    MetadataPayload::MemberAnnounce { display_name } => {
                                        let _ = c.store().update_member_name(&server_id, &msg.sender_fp, &display_name);
                                    }
                                }
                                let _ = c.store().set_last_seen_seq(&mailbox_id, seq);
                            }
                            Err(e) => eprintln!("decode metadata: {e}"),
                        }
                        let _ = app.emit("sync", hex::encode(server_id));
                    }
                    Some((_, Ok(ReceiveResult::Message(msg)))) => {
                        let dto = MessageDto::from_incoming(&msg, received_at);
                        let _ = app.emit("message", &dto);
                        let c = client.lock().await;
                        let _ = c.store().set_last_seen_seq(&mailbox_id, seq);
                    }
                    Some((server_id, Ok(ReceiveResult::CommitProcessed))) => {
                        let c = client.lock().await;
                        let _ = c.store().set_last_seen_seq(&mailbox_id, seq);
                        // Add any new MLS members we don't have in the store yet
                        if let Ok(mls_fps) = c.mls_member_fingerprints(&server_id) {
                            let stored: std::collections::HashSet<[u8; 32]> = c.store()
                                .list_members(&server_id)
                                .unwrap_or_default()
                                .iter()
                                .map(|m| m.fingerprint)
                                .collect();
                            for fp in mls_fps {
                                if !stored.contains(&fp) {
                                    let _ = c.store().insert_member(&Member {
                                        server_id,
                                        fingerprint: fp,
                                        display_name: hex::encode(&fp[..8]),
                                        role: MemberRole::Member,
                                        joined_at: received_at,
                                    });
                                }
                            }
                        }
                        // Upload fresh GroupInfo so other clients can recover
                        if let Ok(gi) = c.export_server_info(&server_id) {
                            let r = relay.lock().await;
                            let _ = r.put_server_info(&mailbox_id, gi).await;
                        }
                        let _ = app.emit("sync", hex::encode(server_id));
                    }
                    Some((_, Ok(ReceiveResult::Skipped))) => {
                        let c = client.lock().await;
                        let _ = c.store().set_last_seen_seq(&mailbox_id, seq);
                    }
                    Some((_, Err(e))) => {
                        let msg = e.to_string();
                        if msg.contains("epoch") || msg.contains("Epoch") {
                            // Stale message from wrong epoch — skip and advance seq
                            let c = client.lock().await;
                            let _ = c.store().set_last_seen_seq(&mailbox_id, seq);
                        } else {
                            eprintln!("relay receive error: {e}");
                        }
                    }
                    None => {}
                }
            }
            RelayEvent::Ack(_) => {}
            RelayEvent::Gap { mailbox_id } => {
                handle_gap(&client, &relay, &mailbox_id).await;
            }
        }
    }
}

async fn handle_gap(
    client: &Arc<Mutex<GhostClient>>,
    relay: &Arc<Mutex<RelayClient>>,
    mailbox_id: &[u8; 32],
) {
    // Fetch GroupInfo from relay, rejoin via external commit
    let server_info = {
        let r = relay.lock().await;
        match r.get_server_info(mailbox_id).await {
            Ok(gi) => gi,
            Err(e) => {
                eprintln!("gap recovery: failed to fetch server_info: {e}");
                return;
            }
        }
    };

    let (commit_bytes, server_id) = {
        let mut c = client.lock().await;
        let sid = match c.server_id_for_mailbox(mailbox_id) {
            Some(sid) => sid,
            None => return,
        };
        match c.recover_via_external_commit(&sid, &server_info) {
            Ok((commit, _)) => (commit, sid),
            Err(e) => {
                eprintln!("gap recovery: external commit failed: {e}");
                return;
            }
        }
    };

    // Broadcast the external commit so other members see us rejoin
    {
        let r = relay.lock().await;
        if let Err(e) = r.send(mailbox_id, commit_bytes).await {
            eprintln!("gap recovery: failed to send commit: {e}");
        }
    }

    // Upload fresh GroupInfo
    {
        let c = client.lock().await;
        if let Ok(gi) = c.export_server_info(&server_id) {
            let r = relay.lock().await;
            let _ = r.put_server_info(mailbox_id, gi).await;
        }
    }
}
