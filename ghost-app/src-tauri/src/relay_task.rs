use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
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
use ghost_core::wire::{decode_metadata, ChannelOpPayload, MetadataPayload, ProvisionPayload, sync_mailbox_id, sync_open, sync_verify};
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
    data_dir: PathBuf,
) {
    // Compute sync mailbox ID (key is read dynamically — may be created after pairing)
    let sync_mb = {
        let c = client.lock().await;
        sync_mailbox_id(c.fingerprint())
    };

    // Subscribe to all existing server mailboxes with persisted last_seen_seq
    {
        let c = client.lock().await;
        let mailboxes = c.server_mailboxes();
        let mut r = relay.lock().await;
        for (_, mailbox_id) in &mailboxes {
            let seq = c.store().get_last_seen_seq(mailbox_id).unwrap_or(0);
            r.subscribe(*mailbox_id, seq);
        }
        // Subscribe to sync mailbox if key exists
        if c.sync_key().is_some() {
            let seq = c.store().get_last_seen_seq(&sync_mb).unwrap_or(0);
            r.subscribe(sync_mb, seq);
        }
    }

    // Push pending genesis entry to relay (first launch only)
    {
        let genesis_path = data_dir.join("genesis.pending");
        if let Ok(payload) = std::fs::read(&genesis_path) {
            let account_fp = {
                let c = client.lock().await;
                *c.fingerprint()
            };
            let r = relay.lock().await;
            match r.put_idlog_entry(&account_fp, payload).await {
                Ok(()) => { let _ = std::fs::remove_file(&genesis_path); }
                Err(e) => eprintln!("failed to push genesis entry: {e}"),
            }
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

                // Handle sync mailbox blobs before server lookup
                if mailbox_id == sync_mb {
                    let key = { client.lock().await.sync_key() };
                    if let Some(key) = key {
                        handle_sync_blob(
                            &app, &client, &relay, &key, &blob.payload, &data_dir,
                        ).await;
                        let c = client.lock().await;
                        let _ = c.store().set_last_seen_seq(&sync_mb, seq);
                    }
                    continue;
                }

                let result = {
                    let mut c = client.lock().await;
                    match c.server_id_for_mailbox(&mailbox_id) {
                        Some(sid) => Some((sid, c.receive_any(&sid, &blob.payload, Some(received_at)))),
                        None => None,
                    }
                };

                match result {
                    Some((server_id, Ok(ReceiveResult::Message(msg)))) if msg.message_type == MessageType::Metadata => {
                        let mut fetch_avatar = None;
                        let mut own_name_changed = false;
                        match decode_metadata(&msg.content) {
                            Ok(payload) => {
                                let mut c = client.lock().await;
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
                                        if msg.sender_fp == *c.fingerprint() {
                                            c.set_display_name(display_name);
                                            own_name_changed = true;
                                        }
                                    }
                                    MetadataPayload::AvatarUpdate { avatar_hash, avatar_key } => {
                                        let _ = c.store().update_member_avatar(&server_id, &msg.sender_fp, &avatar_hash, &avatar_key);
                                        fetch_avatar = Some((server_id, msg.sender_fp, avatar_hash));
                                    }
                                    MetadataPayload::AvatarClear => {
                                        let _ = c.store().clear_member_avatar(&server_id, &msg.sender_fp);
                                        let fp_hex = hex::encode(msg.sender_fp);
                                        let _ = std::fs::remove_file(data_dir.join("avatars").join(format!("{}.webp", fp_hex)));
                                        let _ = std::fs::remove_file(data_dir.join("avatars").join(format!("{}.hash", fp_hex)));
                                        let _ = app.emit("avatar-cleared", fp_hex);
                                    }
                                }
                                let _ = c.store().set_last_seen_seq(&mailbox_id, seq);
                            }
                            Err(e) => eprintln!("decode metadata: {e}"),
                        }
                        if let Some((sid, fp, hash)) = fetch_avatar {
                            maybe_fetch_avatar(&client, &relay, &app, &data_dir, &sid, &fp, &hash).await;
                        }
                        if own_name_changed {
                            let _ = app.emit("display-name-sync", ());
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
                                        avatar_hash: None,
                                        avatar_key: None,
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
                    &app, &client, &relay, &mailbox_id, &json, &mut online_members, &mut pending_presence, &data_dir,
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

async fn handle_sync_blob(
    app: &AppHandle,
    client: &Arc<Mutex<GhostClient>>,
    relay: &Arc<Mutex<RelayClient>>,
    sync_key: &[u8; 32],
    envelope_blob: &[u8],
    _data_dir: &std::path::Path,
) {
    // Strip envelope header
    if envelope_blob.len() < ghost_wire::ENVELOPE_HEADER_SIZE {
        eprintln!("sync: blob too short for envelope");
        return;
    }
    let sealed = &envelope_blob[ghost_wire::ENVELOPE_HEADER_SIZE..];

    // Decrypt
    let decrypted = match sync_open(sync_key, sealed) {
        Ok(pt) => pt,
        Err(e) => {
            eprintln!("sync: decrypt failed: {e}");
            return;
        }
    };

    if decrypted.is_empty() {
        eprintln!("sync: empty payload");
        return;
    }

    // Verify device signature and check identity log for revocation
    let (device_vk, plaintext) = match sync_verify(&decrypted) {
        Ok(v) => v,
        Err(_) => {
            // Unsigned legacy message — accept during transition
            (Default::default(), decrypted)
        }
    };
    if device_vk != [0u8; 32] {
        let account_fp = {
            let c = client.lock().await;
            *c.fingerprint()
        };
        let is_active = {
            let r = relay.lock().await;
            match r.get_idlog(&account_fp, 0).await {
                Ok(blobs) => {
                    use ghost_core::identity::log::{LogEntry, validate_chain};
                    let entries: Vec<LogEntry> = blobs.iter()
                        .filter_map(|b| LogEntry::from_bytes(&b.payload).ok())
                        .collect();
                    match validate_chain(&entries) {
                        Ok(log_state) => log_state.is_active_device(&device_vk),
                        Err(_) => true, // can't validate — don't block
                    }
                }
                Err(_) => true, // network error — don't block
            }
        };
        if !is_active {
            eprintln!("sync: rejected message from revoked device {}", hex::encode(&device_vk[..8]));
            return;
        }
    }

    let msg_type = plaintext[0];
    let body = &plaintext[1..];

    use ghost_core::wire::SyncMessageType;
    match msg_type {
        x if x == SyncMessageType::ServerProvisioned as u8 => {
            // ServerProvisioned — join via external commit
            let payload = match ProvisionPayload::from_bytes(body) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("sync: bad provision payload: {e}");
                    return;
                }
            };

            // Fetch fresh GroupInfo and join with retry
            let mut joined = false;
            for _ in 0..3 {
                let gi_bytes = {
                    let r = relay.lock().await;
                    match r.get_server_info(&payload.mailbox_id).await {
                        Ok(gi) => gi,
                        Err(_) => break,
                    }
                };

                let result = {
                    let mut c = client.lock().await;
                    c.join_from_provision(&payload, &gi_bytes, now_ms())
                };

                match result {
                    Ok((commit_bytes, mailbox_id)) => {
                        // Broadcast external commit via HTTP POST (not WS — we aren't subscribed yet).
                        // The returned seq lets us subscribe past pre-join history.
                        let commit_seq = {
                            let r = relay.lock().await;
                            match r.post_blob(&mailbox_id, commit_bytes).await {
                                Ok(seq) => seq,
                                Err(e) => {
                                    eprintln!("sync: failed to post external commit: {e}");
                                    continue;
                                }
                            }
                        };

                        // Upload fresh GroupInfo
                        {
                            let c = client.lock().await;
                            if let Ok(gi) = c.export_server_info(&payload.server_id) {
                                let r = relay.lock().await;
                                let _ = r.put_server_info(&mailbox_id, gi).await;
                            }
                        }

                        // Subscribe from the commit seq — skips undecryptable pre-join blobs
                        {
                            let c = client.lock().await;
                            let _ = c.store().set_last_seen_seq(&mailbox_id, commit_seq);
                            drop(c);
                            let mut r = relay.lock().await;
                            r.subscribe(mailbox_id, commit_seq);
                        }

                        // Send member announce
                        let announce = {
                            let mut c = client.lock().await;
                            let name = c.identity().display_name.clone();
                            c.send_control(
                                &payload.server_id,
                                ghost_core::wire::encode_member_announce(&name),
                            )
                        };
                        if let Ok(outbound) = announce {
                            let r = relay.lock().await;
                            let _ = r.send(&outbound.mailbox_id, outbound.blob).await;
                        }

                        joined = true;
                        break;
                    }
                    Err(e) => {
                        eprintln!("sync: join attempt failed for {}: {e}", hex::encode(&payload.server_id[..8]));
                        continue;
                    }
                }
            }

            if !joined {
                eprintln!("sync: failed to join server {} after retries", hex::encode(&payload.server_id[..8]));
                return;
            }

            let _ = app.emit("sync", "all");
        }
        x if x == SyncMessageType::ServerLeft as u8 => {
            // ServerLeft — remove local state, unsubscribe
            if body.len() < 32 {
                eprintln!("sync: ServerLeft body too short");
                return;
            }
            let server_id: [u8; 32] = body[..32].try_into().unwrap();

            let mailbox_id = {
                let c = client.lock().await;
                c.mailbox_id_for_server(&server_id)
            };

            {
                let c = client.lock().await;
                let _ = c.store().delete_server(&server_id);
            }

            if let Some(mb) = mailbox_id {
                let mut r = relay.lock().await;
                r.unsubscribe(&mb);
            }

            let _ = app.emit("kicked", hex::encode(server_id));
        }
        x if x == SyncMessageType::VoiceTakeover as u8 => {
            // VoiceTakeover — other device joined voice, leave if we're in it
            if body.len() < 32 {
                eprintln!("sync: VoiceTakeover body too short");
                return;
            }
            let channel_id: [u8; 32] = body[..32].try_into().unwrap();
            let _ = app.emit("voice-takeover", hex::encode(channel_id));
        }
        _ => {
            eprintln!("sync: unknown message type {msg_type:#04x}");
        }
    }
}

async fn handle_gap(
    client: &Arc<Mutex<GhostClient>>,
    relay: &Arc<Mutex<RelayClient>>,
    mailbox_id: &[u8; 32],
) {
    let server_id = {
        let c = client.lock().await;
        match c.server_id_for_mailbox(mailbox_id) {
            Some(sid) => sid,
            None => return,
        }
    };

    for attempt in 0..3 {
        // Fetch fresh GroupInfo each attempt
        let fetch_result = {
            let r = relay.lock().await;
            r.get_server_info(mailbox_id).await
        };
        let server_info = match fetch_result {
            Ok(gi) => gi,
            Err(e) => {
                if e.to_string().contains("404") {
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

        let commit_bytes = {
            let mut c = client.lock().await;
            match c.recover_via_external_commit(&server_id, &server_info) {
                Ok((commit, _)) => commit,
                Err(e) => {
                    eprintln!("gap recovery: external commit failed (attempt {attempt}): {e}");
                    continue;
                }
            }
        };

        // Post via HTTP so we get a clear success/rejection signal
        match relay.lock().await.post_blob(mailbox_id, commit_bytes).await {
            Ok(_) => {
                // Upload fresh GroupInfo for other joiners
                let c = client.lock().await;
                if let Ok(gi) = c.export_server_info(&server_id) {
                    let r = relay.lock().await;
                    let _ = r.put_server_info(mailbox_id, gi).await;
                }
                return;
            }
            Err(e) => {
                eprintln!("gap recovery: relay rejected commit (attempt {attempt}): {e}");
                continue;
            }
        }
    }
    eprintln!("gap recovery: failed after 3 attempts for mailbox");
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
                                        members.retain(|m| !(m.fingerprint == ps.fingerprint && m.device_vk == ps.device_vk));
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
                                if let Some(existing) = members.iter_mut().find(|m| m.fingerprint == ps.fingerprint && m.device_vk == ps.device_vk) {
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
    avatar_hash: Option<[u8; 32]>,
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
    avatar_hash: Option<String>,
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
                avatar_hash: m.avatar_hash.map(hex::encode),
            })
            .collect(),
    };
    let _ = app.emit("online-presence", &event);
}

/// Try to decrypt a presence blob and upsert into the member list.
/// Returns Some((fingerprint, avatar_hash)) if a new avatar needs fetching, None on failure.
fn try_decrypt_presence(
    client: &GhostClient,
    server_id: &[u8; 32],
    blob: &[u8],
    members: &mut Vec<OnlineMember>,
) -> Option<([u8; 32], Option<[u8; 32]>)> {
    match client.open_online_presence_blob(server_id, blob) {
        Ok(mut ps) => {
            filter_expired_status(&mut ps);
            let avatar_hash = ps.avatar_hash;
            if let Some(existing) = members.iter_mut().find(|m| m.fingerprint == ps.fingerprint) {
                existing.status = status_str(ps.status);
                existing.status_message = ps.status_message;
                existing.avatar_hash = ps.avatar_hash;
            } else {
                members.push(OnlineMember {
                    fingerprint: ps.fingerprint,
                    status: status_str(ps.status),
                    status_message: ps.status_message,
                    avatar_hash: ps.avatar_hash,
                });
            }
            Some((ps.fingerprint, avatar_hash))
        }
        Err(_) => None,
    }
}

/// Fetch, decrypt, and cache an avatar if we have the key but no cached file.
async fn maybe_fetch_avatar(
    client: &Arc<Mutex<GhostClient>>,
    relay: &Arc<Mutex<RelayClient>>,
    app: &AppHandle,
    data_dir: &std::path::Path,
    server_id: &[u8; 32],
    fingerprint: &[u8; 32],
    avatar_hash: &[u8; 32],
) {
    let fp_hex = hex::encode(fingerprint);
    let avatar_dir = data_dir.join("avatars");
    let cache_path = avatar_dir.join(format!("{fp_hex}.webp"));
    let hash_path = avatar_dir.join(format!("{fp_hex}.hash"));
    if let Ok(stored) = std::fs::read(&hash_path) {
        if stored == avatar_hash.as_slice() {
            return; // already have this version
        }
    }

    // Look up the avatar key from the members table
    let avatar_key = {
        let c = client.lock().await;
        c.store().get_member_avatar_key(server_id, fingerprint).ok().flatten()
    };
    let avatar_key = match avatar_key {
        Some(k) => k,
        None => {
            eprintln!("avatar: no key for {fp_hex}, skipping fetch");
            return;
        }
    };

    // Fetch the mailbox_id for this server
    let mailbox_id = {
        let c = client.lock().await;
        c.mailbox_id_for_server(server_id)
    };
    let mailbox_id = match mailbox_id {
        Some(m) => m,
        None => {
            eprintln!("avatar: no mailbox for server {}, skipping fetch for {fp_hex}", hex::encode(server_id));
            return;
        }
    };

    // Fetch encrypted blob from relay
    let encrypted = {
        let r = relay.lock().await;
        r.get_avatar(&mailbox_id, fingerprint).await
    };
    let encrypted = match encrypted {
        Ok(Some(data)) => data,
        Ok(None) => {
            eprintln!("avatar: relay returned no blob for {fp_hex}");
            return;
        }
        Err(e) => {
            eprintln!("avatar: fetch failed for {fp_hex}: {e}");
            return;
        }
    };

    // Decrypt: [nonce:12][ciphertext+tag]
    use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
    use aes_gcm::Nonce;
    if encrypted.len() < 28 {
        eprintln!("avatar: blob too short for {fp_hex} ({} bytes)", encrypted.len());
        return;
    }
    let nonce = Nonce::from_slice(&encrypted[..12]);
    let cipher = Aes256Gcm::new((&avatar_key).into());
    let plaintext = match cipher.decrypt(nonce, &encrypted[12..]) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("avatar: decrypt failed for {fp_hex}: {e}");
            return;
        }
    };

    // Cache to disk
    let _ = std::fs::create_dir_all(&avatar_dir);
    let _ = std::fs::write(&cache_path, &plaintext);
    let _ = std::fs::write(&hash_path, avatar_hash);
    let _ = app.emit("avatar-updated", &fp_hex);
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
        if try_decrypt_presence(&c, server_id, &blob, members).is_none() {
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
    relay: &Arc<Mutex<RelayClient>>,
    mailbox_id: &[u8; 32],
    json: &str,
    online_members: &mut HashMap<[u8; 32], Vec<OnlineMember>>,
    pending_blobs: &mut HashMap<[u8; 32], Vec<Vec<u8>>>,
    data_dir: &std::path::Path,
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
        let mut avatars_to_fetch: Vec<([u8; 32], [u8; 32])> = Vec::new();
        for entry in arr {
            let p_b64 = match entry.get("p").and_then(|v| v.as_str()) {
                Some(s) => s,
                None => continue,
            };
            let blob = match B64.decode(p_b64) {
                Ok(b) => b,
                Err(_) => continue,
            };
            match try_decrypt_presence(&c, &server_id, &blob, &mut members_list) {
                Some((fp, Some(hash))) => avatars_to_fetch.push((fp, hash)),
                Some(_) => {}
                None => failed.push(blob),
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
        for (fp, hash) in avatars_to_fetch {
            maybe_fetch_avatar(client, relay, app, data_dir, &server_id, &fp, &hash).await;
        }
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
            if let Some((fp, hash)) = try_decrypt_presence(&c, &server_id, &blob, members) {
                drop(c);
                emit_online_presence(app, &server_id, members);
                if let Some(h) = hash {
                    maybe_fetch_avatar(client, relay, app, data_dir, &server_id, &fp, &h).await;
                }
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
