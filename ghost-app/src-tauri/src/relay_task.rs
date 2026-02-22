use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ghost_core::client::{GhostClient, ReceiveResult};
use ghost_core::crypto::MessageType;
use ghost_core::mls::presence::OnlineStatus;
use ghost_core::mls::voice::PresenceState;
use ghost_core::relay::{RelayClient, RelayEvent};
use ghost_core::storage::{Channel, Member, MemberRole};
use ghost_core::wire::{decode_metadata, ChannelOpPayload, MetadataPayload};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};
use tokio::sync::{mpsc, Mutex};

use crate::dto::MessageDto;
use crate::presence::{self, PresenceInfo};

async fn rebroadcast_presence(
    client: &Arc<Mutex<GhostClient>>,
    relay: &Arc<Mutex<RelayClient>>,
    mailbox_id: &[u8; 32],
    presence: &Arc<Mutex<PresenceInfo>>,
) {
    let info = presence.lock().await.clone();
    presence::broadcast_presence_to_mailbox(client, relay, mailbox_id, &info).await;
}

pub async fn run(
    app: AppHandle,
    client: Arc<Mutex<GhostClient>>,
    relay: Arc<Mutex<RelayClient>>,
    mut events: mpsc::Receiver<RelayEvent>,
    presence: Arc<Mutex<PresenceInfo>>,
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

    // Per-channel voice members visible to all mailbox subscribers
    let mut voice_members: HashMap<[u8; 32], Vec<PresenceState>> = HashMap::new();
    // Track which channels belong to which mailbox (so snapshots don't clobber other servers)
    let mut mailbox_channels: HashMap<[u8; 32], HashSet<[u8; 32]>> = HashMap::new();
    // Track connected mailboxes for relay connectivity indicator
    let mut connected_mailboxes: HashSet<[u8; 32]> = HashSet::new();
    // Online presence per server: server_id → list of online members
    let mut online_members: HashMap<[u8; 32], Vec<OnlineMember>> = HashMap::new();
    // Presence blobs that failed trial decryption (epoch mismatch), retried after commits
    let mut pending_presence: HashMap<[u8; 32], Vec<Vec<u8>>> = HashMap::new();

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
                        // Discover new members added by this commit (e.g. external join)
                        if let Ok(mls_fps) = c.mls_member_fingerprints(&server_id) {
                            let stored: HashSet<[u8; 32]> = c.store()
                                .list_members(&server_id)
                                .unwrap_or_default()
                                .iter().map(|m| m.fingerprint).collect();
                            for fp in &mls_fps {
                                if !stored.contains(fp) {
                                    let _ = c.store().insert_member(&Member {
                                        server_id,
                                        fingerprint: *fp,
                                        display_name: hex::encode(&fp[..8]),
                                        role: MemberRole::Member,
                                        joined_at: received_at,
                                    });
                                }
                            }
                        }
                        if let Ok(gi) = c.export_server_info(&server_id) {
                            let r = relay.lock().await;
                            let _ = r.put_server_info(&mailbox_id, gi).await;
                        }
                        drop(c);
                        rebroadcast_presence(&client, &relay, &mailbox_id, &presence).await;
                        retry_pending_presence(&app, &client, &server_id, &mut online_members, &mut pending_presence).await;
                        let _ = app.emit("sync", hex::encode(server_id));
                    }
                    Some((server_id, Ok(ReceiveResult::Kicked))) => {
                        let c = client.lock().await;
                        let _ = c.store().set_last_seen_seq(&mailbox_id, seq);
                        drop(c);
                        let _ = app.emit("kicked", hex::encode(server_id));
                    }
                    Some((server_id, Ok(ReceiveResult::MembersRemoved(removed)))) => {
                        let c = client.lock().await;
                        let _ = c.store().set_last_seen_seq(&mailbox_id, seq);
                        for fp in &removed {
                            let _ = c.store().remove_member(&server_id, fp);
                        }
                        if let Ok(gi) = c.export_server_info(&server_id) {
                            let r = relay.lock().await;
                            let _ = r.put_server_info(&mailbox_id, gi).await;
                        }
                        drop(c);
                        rebroadcast_presence(&client, &relay, &mailbox_id, &presence).await;
                        retry_pending_presence(&app, &client, &server_id, &mut online_members, &mut pending_presence).await;
                        let _ = app.emit("sync", hex::encode(server_id));
                    }
                    Some((_, Ok(ReceiveResult::Skipped))) => {
                        let c = client.lock().await;
                        let _ = c.store().set_last_seen_seq(&mailbox_id, seq);
                    }
                    Some((_, Err(e))) => {
                        eprintln!("relay: receive error seq={seq}: {e}");
                        // Advance seq so we don't re-process this blob on reconnect
                        let c = client.lock().await;
                        let _ = c.store().set_last_seen_seq(&mailbox_id, seq);
                    }
                    None => {}
                }
            }
            RelayEvent::Ack(_) => {}
            RelayEvent::Gap { mailbox_id } => {
                handle_gap(&client, &relay, &mailbox_id).await;
            }
            RelayEvent::VoiceState { mailbox_id, json } => {
                handle_voice_state(
                    &app, &client, &mailbox_id, &json, &mut voice_members, &mut mailbox_channels,
                ).await;
            }
            RelayEvent::Presence { mailbox_id, json } => {
                handle_online_presence(
                    &app, &client, &mailbox_id, &json, &mut online_members, &mut pending_presence,
                ).await;
            }
            RelayEvent::ConnectionState { mailbox_id, connected } => {
                if connected {
                    connected_mailboxes.insert(mailbox_id);
                    rebroadcast_presence(&client, &relay, &mailbox_id, &presence).await;
                } else {
                    connected_mailboxes.remove(&mailbox_id);
                }
                let _ = app.emit("relay-connectivity", !connected_mailboxes.is_empty());
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
    let fetch_result = {
        let r = relay.lock().await;
        r.get_server_info(mailbox_id).await
    };
    let server_info = match fetch_result {
        Ok(gi) => gi,
        Err(e) => {
            if e.to_string().contains("404") {
                // Relay was restarted — no server_info exists yet.
                // Our local MLS state is still valid; just reset last_seen
                // and resubscribe from the start of the (now-empty) log.
                eprintln!("gap recovery: relay has no server_info, resetting last_seen");
                let c = client.lock().await;
                let _ = c.store().set_last_seen_seq(mailbox_id, 0);
                drop(c);
                let mut r = relay.lock().await;
                r.subscribe(*mailbox_id, 0);
            } else {
                eprintln!("gap recovery: failed to fetch server_info: {e}");
            }
            return;
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

// --- Voice state via mailbox WS ---

#[derive(Deserialize)]
struct VsMsg {
    ch: String,
    p: Option<String>,
    leave: Option<bool>,
}

#[derive(Serialize, Clone)]
struct VoiceChannelMembersEvent {
    channel_id: String,
    members: Vec<VoiceChannelMember>,
}

#[derive(Serialize, Clone)]
struct VoiceChannelMember {
    fingerprint: String,
    muted: bool,
    deafened: bool,
}

async fn handle_voice_state(
    app: &AppHandle,
    client: &Arc<Mutex<GhostClient>>,
    mailbox_id: &[u8; 32],
    json: &str,
    voice_members: &mut HashMap<[u8; 32], Vec<PresenceState>>,
    mailbox_channels: &mut HashMap<[u8; 32], HashSet<[u8; 32]>>,
) {
    // Try parsing as snapshot first
    if let Ok(snap) = serde_json::from_str::<serde_json::Value>(json) {
        if let Some(arr) = snap.get("vs_snap").and_then(|v| v.as_array()) {
            // Snapshot: clear only channels belonging to this mailbox, then rebuild
            if let Some(old_channels) = mailbox_channels.remove(mailbox_id) {
                for ch_id in &old_channels {
                    if let Some(members) = voice_members.remove(ch_id) {
                        if !members.is_empty() {
                            let empty: Vec<PresenceState> = Vec::new();
                            emit_channel_members(app, ch_id, &empty);
                        }
                    }
                }
            }
            let c = client.lock().await;
            let server_id = match c.server_id_for_mailbox(mailbox_id) {
                Some(sid) => sid,
                None => return,
            };
            for entry in arr {
                let ch_b64 = match entry.get("ch").and_then(|v| v.as_str()) {
                    Some(s) => s,
                    None => continue,
                };
                let p_b64 = match entry.get("p").and_then(|v| v.as_str()) {
                    Some(s) => s,
                    None => continue,
                };
                let channel_id = match decode_channel_id(ch_b64) {
                    Some(id) => id,
                    None => continue,
                };
                let blob = match B64.decode(p_b64) {
                    Ok(b) => b,
                    Err(_) => continue,
                };
                if let Ok(ps) = c.open_presence_blob(&server_id, &channel_id, &blob) {
                    voice_members.entry(channel_id).or_default().push(ps);
                    mailbox_channels.entry(*mailbox_id).or_default().insert(channel_id);
                }
            }
            drop(c);
            // Emit for all channels belonging to this mailbox
            let ch_set = mailbox_channels.get(mailbox_id);
            for (channel_id, members) in voice_members.iter() {
                if ch_set.map_or(false, |s| s.contains(channel_id)) {
                    emit_channel_members(app, channel_id, members);
                }
            }
            return;
        }

        // Single voice state update
        if let Some(vs_val) = snap.get("vs") {
            if let Ok(vs) = serde_json::from_value::<VsMsg>(vs_val.clone()) {
                let channel_id = match decode_channel_id(&vs.ch) {
                    Some(id) => id,
                    None => return,
                };

                if vs.leave == Some(true) {
                    // Leave: decrypt last blob to identify who left
                    if let Some(p_b64) = &vs.p {
                        if let Ok(blob) = B64.decode(p_b64) {
                            let c = client.lock().await;
                            if let Some(server_id) = c.server_id_for_mailbox(mailbox_id) {
                                if let Ok(ps) = c.open_presence_blob(&server_id, &channel_id, &blob) {
                                    drop(c);
                                    if let Some(members) = voice_members.get_mut(&channel_id) {
                                        members.retain(|m| m.fingerprint != ps.fingerprint);
                                        if members.is_empty() {
                                            let empty: Vec<PresenceState> = Vec::new();
                                            emit_channel_members(app, &channel_id, &empty);
                                            voice_members.remove(&channel_id);
                                            // Clean up mailbox_channels tracking
                                            if let Some(chs) = mailbox_channels.get_mut(mailbox_id) {
                                                chs.remove(&channel_id);
                                            }
                                        } else {
                                            emit_channel_members(app, &channel_id, members);
                                        }
                                    }
                                }
                            }
                        }
                    }
                } else if let Some(p_b64) = &vs.p {
                    // Join or presence update
                    if let Ok(blob) = B64.decode(p_b64) {
                        let c = client.lock().await;
                        if let Some(server_id) = c.server_id_for_mailbox(mailbox_id) {
                            if let Ok(ps) = c.open_presence_blob(&server_id, &channel_id, &blob) {
                                drop(c);
                                mailbox_channels.entry(*mailbox_id).or_default().insert(channel_id);
                                let members = voice_members.entry(channel_id).or_default();
                                if let Some(existing) = members.iter_mut().find(|m| m.fingerprint == ps.fingerprint) {
                                    existing.muted = ps.muted;
                                    existing.deafened = ps.deafened;
                                } else {
                                    members.push(ps);
                                }
                                emit_channel_members(app, &channel_id, members);
                            }
                        }
                    }
                }
            }
        }
    }
}

fn decode_channel_id(b64: &str) -> Option<[u8; 32]> {
    B64.decode(b64).ok().and_then(|b| b.try_into().ok())
}

fn emit_channel_members(app: &AppHandle, channel_id: &[u8; 32], members: &[PresenceState]) {
    let event = VoiceChannelMembersEvent {
        channel_id: hex::encode(channel_id),
        members: members
            .iter()
            .map(|m| VoiceChannelMember {
                fingerprint: hex::encode(m.fingerprint),
                muted: m.muted,
                deafened: m.deafened,
            })
            .collect(),
    };
    let _ = app.emit("voice-channel-members", &event);
}

// --- Online presence via mailbox WS ---

#[derive(Clone)]
struct OnlineMember {
    fingerprint: [u8; 32],
    status: &'static str,
    status_message: Option<String>,
}

#[derive(Serialize)]
struct OnlinePresenceEvent {
    server_id: String,
    members: Vec<OnlinePresenceMemberDto>,
}

#[derive(Serialize)]
struct OnlinePresenceMemberDto {
    fingerprint: String,
    status: String,
    status_message: Option<String>,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Strip expired status messages from received presence (handles crashed senders).
fn filter_expired_status(ps: &mut ghost_core::mls::presence::OnlinePresence) {
    if let Some(exp) = ps.status_expiry {
        if now_ms() >= exp {
            ps.status_message = None;
            ps.status_expiry = None;
        }
    }
}

fn status_str(s: OnlineStatus) -> &'static str {
    match s {
        OnlineStatus::Online => "online",
        OnlineStatus::Idle => "idle",
        OnlineStatus::Away => "away",
        OnlineStatus::Invisible => "offline",
    }
}

fn emit_online_presence(app: &AppHandle, server_id: &[u8; 32], members: &[OnlineMember]) {
    let event = OnlinePresenceEvent {
        server_id: hex::encode(server_id),
        members: members
            .iter()
            .map(|m| OnlinePresenceMemberDto {
                fingerprint: hex::encode(m.fingerprint),
                status: m.status.to_string(),
                status_message: m.status_message.clone(),
            })
            .collect(),
    };
    let _ = app.emit("online-presence", &event);
}

/// Try to decrypt a presence blob and upsert into the member list.
/// Returns true if decryption succeeded.
fn try_upsert_presence(
    client: &GhostClient,
    server_id: &[u8; 32],
    blob: &[u8],
    members: &mut Vec<OnlineMember>,
) -> bool {
    match client.open_online_presence_blob(server_id, blob) {
        Ok(mut ps) => {
            filter_expired_status(&mut ps);
            if let Some(existing) = members.iter_mut().find(|m| m.fingerprint == ps.fingerprint) {
                existing.status = status_str(ps.status);
                existing.status_message = ps.status_message;
            } else {
                members.push(OnlineMember {
                    fingerprint: ps.fingerprint,
                    status: status_str(ps.status),
                    status_message: ps.status_message,
                });
            }
            true
        }
        Err(_) => false,
    }
}

/// Retry pending presence blobs after an epoch change (commit processed).
async fn retry_pending_presence(
    app: &AppHandle,
    client: &Arc<Mutex<GhostClient>>,
    server_id: &[u8; 32],
    online_members: &mut HashMap<[u8; 32], Vec<OnlineMember>>,
    pending: &mut HashMap<[u8; 32], Vec<Vec<u8>>>,
) {
    let blobs = match pending.remove(server_id) {
        Some(b) if !b.is_empty() => b,
        _ => return,
    };
    let c = client.lock().await;
    let members = online_members.entry(*server_id).or_default();
    let mut still_pending = Vec::new();
    for blob in blobs {
        if !try_upsert_presence(&c, server_id, &blob, members) {
            still_pending.push(blob);
        }
    }
    drop(c);
    if !still_pending.is_empty() {
        pending.insert(*server_id, still_pending);
    }
    emit_online_presence(app, server_id, members);
}

async fn handle_online_presence(
    app: &AppHandle,
    client: &Arc<Mutex<GhostClient>>,
    mailbox_id: &[u8; 32],
    json: &str,
    online_members: &mut HashMap<[u8; 32], Vec<OnlineMember>>,
    pending_blobs: &mut HashMap<[u8; 32], Vec<Vec<u8>>>,
) {
    let snap: serde_json::Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(_) => return,
    };

    // Snapshot: replace all online members for this server
    if let Some(arr) = snap.get("ps_snap").and_then(|v| v.as_array()) {
        let c = client.lock().await;
        let server_id = match c.server_id_for_mailbox(mailbox_id) {
            Some(sid) => sid,
            None => return,
        };
        let mut members_list = Vec::new();
        let mut failed = Vec::new();
        for entry in arr {
            let p_b64 = match entry.get("p").and_then(|v| v.as_str()) {
                Some(s) => s,
                None => continue,
            };
            let blob = match B64.decode(p_b64) {
                Ok(b) => b,
                Err(_) => continue,
            };
            if !try_upsert_presence(&c, &server_id, &blob, &mut members_list) {
                failed.push(blob);
            }
        }
        drop(c);
        online_members.insert(server_id, members_list);
        if !failed.is_empty() {
            failed.truncate(64);
            pending_blobs.insert(server_id, failed);
        } else {
            pending_blobs.remove(&server_id);
        }
        emit_online_presence(app, &server_id, online_members.get(&server_id).unwrap());
        return;
    }

    // Single update or leave
    if let Some(ps_val) = snap.get("ps") {
        let leave = ps_val.get("leave").and_then(|v| v.as_bool()).unwrap_or(false);
        let p_b64 = match ps_val.get("p").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return,
        };
        let blob = match B64.decode(p_b64) {
            Ok(b) => b,
            Err(_) => return,
        };

        let c = client.lock().await;
        let server_id = match c.server_id_for_mailbox(mailbox_id) {
            Some(sid) => sid,
            None => return,
        };
        if leave {
            // Decrypt just to identify who left
            if let Ok(ps) = c.open_online_presence_blob(&server_id, &blob) {
                drop(c);
                let members = online_members.entry(server_id).or_default();
                members.retain(|m| m.fingerprint != ps.fingerprint);
                emit_online_presence(app, &server_id, members);
            }
        } else {
            let members = online_members.entry(server_id).or_default();
            if try_upsert_presence(&c, &server_id, &blob, members) {
                // Successfully decrypted — also clear any pending blob for this member
                drop(c);
                emit_online_presence(app, &server_id, members);
            } else {
                drop(c);
                // Buffer for retry after next commit (cap at 64 to bound memory)
                let pending = pending_blobs.entry(server_id).or_default();
                if pending.len() < 64 {
                    pending.push(blob);
                }
            }
        }
    }
}
