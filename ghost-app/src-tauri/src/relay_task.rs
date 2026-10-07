use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ghost_core::client::{GhostClient, ReceiveResult};
use ghost_core::crypto::MessageType;
use ghost_core::mls::presence::OnlineStatus;
use ghost_core::mls::voice::PresenceState;
use ghost_core::relay::{RelayClient, RelayEvent};
use ghost_core::storage::{Channel, Member, MemberRole};
use ghost_core::wire::{decode_metadata, ChannelOpPayload, MetadataPayload, ProvisionPayload, SyncMessageType, SyncReceiveResult, SyncServerMeta};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};
use tokio::sync::{mpsc, Mutex};

use crate::dto::MessageDto;
use crate::presence::{self, PresenceInfo};

fn get_json_str<'a>(obj: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    obj.get(key)?.as_str()
}

fn decode_b64_blob(b64: &str) -> Option<Vec<u8>> {
    B64.decode(b64).ok()
}

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
    config: Arc<Mutex<crate::config::GhostConfig>>,
    config_path: PathBuf,
    voice_cmd_tx: mpsc::Sender<crate::voice_task::VoiceCommand>,
) {
    // Fetch the relay's verifying key so KT checkpoint verification works
    {
        let r = relay.lock().await;
        match r.get_relay_info().await {
            Ok(info) => client.lock().await.set_relay_vk(info.relay_vk),
            Err(e) => eprintln!("failed to fetch relay info: {e}"),
        }
    }

    // Subscribe to every server mailbox on the relay hosting that server, and to the
    // sync mailbox on the home relay, resuming from the persisted last_seen_seq.
    let sync_mb = {
        let c = client.lock().await;
        let mut r = relay.lock().await;
        ghost_core::flows::subscribe_known_mailboxes(&c, &mut r);
        c.sync_mailbox_id()
    };

    // Push genesis entry to relay if relay doesn't have it yet.
    // genesis.pending is kept on disk permanently so it can be re-pushed
    // after relay DB wipes (dev restarts, migrations, server moves).
    {
        let genesis_path = data_dir.join("genesis.pending");
        if let Ok(payload) = std::fs::read(&genesis_path) {
            let account_fp = {
                let c = client.lock().await;
                *c.fingerprint()
            };
            let r = relay.lock().await;
            let needs_push = r.get_idlog(&account_fp, 0).await
                .map(|resp| resp.entries.is_empty())
                .unwrap_or(true);
            if needs_push {
                if let Err(e) = r.put_idlog_entry(&account_fp, payload).await {
                    eprintln!("failed to push genesis entry: {e}");
                }
            }
        }
    }

    // Other relays only register accounts whose log names a home; this also
    // refreshes the cached copy of our own log. Retried on every start.
    if let Err(e) = ghost_core::flows::account::ensure_home_relay(&client, &relay).await {
        eprintln!("failed to record home relay in identity log: {e}");
    }

    // Servers whose relay went away before announcing a move can be found through
    // their creators' home relays.
    {
        let client = client.clone();
        let relay = relay.clone();
        tauri::async_runtime::spawn(async move {
            let moved = ghost_core::flows::server::check_all_locations(&client, &relay).await;
            if moved > 0 {
                eprintln!("{moved} servers moved while this device was away");
            }
        });
    }

    // Cache identity logs for gossip (kt_head_hash) and remove-proposal validation.
    // No longer required for message processing — credentials are self-validating.
    {
        let member_fps = {
            let c = client.lock().await;
            c.all_member_fingerprints()
        };
        for fp in &member_fps {
            ghost_core::flows::idlog::cache_member(&client, &relay, fp).await;
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
    // Consecutive receive errors per mailbox — auto-recover after threshold
    let mut consecutive_errors: HashMap<[u8; 32], u32> = HashMap::new();
    const EPOCH_RECOVERY_ERROR_THRESHOLD: u32 = 3;

    while let Some(event) = events.recv().await {
        match event {
            RelayEvent::Blob(blob) => {
                let received_at = blob.received_at;
                let mailbox_id = blob.mailbox_id;
                let seq = blob.seq;

                // Handle sync mailbox blobs before server lookup
                if let Some(ref smb) = sync_mb {
                    if &mailbox_id == smb {
                        let result = {
                            let mut c = client.lock().await;
                            c.receive_sync(&blob.payload)
                        };
                        match result {
                            Ok(SyncReceiveResult::Application(plaintext)) => {
                                handle_sync_application(
                                    &app, &client, &relay, &plaintext,
                                    &config, &config_path, &presence, &voice_cmd_tx,
                                ).await;
                            }
                            Ok(SyncReceiveResult::CommitProcessed) => {}
                            Ok(SyncReceiveResult::SelfMessage) => {}
                            Err(e) => eprintln!("sync: process failed: {e}"),
                        }
                        let c = client.lock().await;
                        let _ = c.store().set_last_seen_seq(smb, seq);
                        continue;
                    }
                }

                let result = {
                    let mut c = client.lock().await;
                    match (c.channel_id_for_mailbox(&mailbox_id), c.server_id_for_mailbox(&mailbox_id)) {
                        (Some(cid), Some(sid)) => Some((sid, cid, c.receive_any(&cid, &blob.payload, Some(received_at)))),
                        _ => None,
                    }
                };

                // Reset consecutive error counter on any successful receive
                if matches!(&result, Some((_, _, Ok(_)))) {
                    consecutive_errors.remove(&mailbox_id);
                }

                match result {
                    Some((server_id, _channel_id, Ok(ReceiveResult::Message(msg) | ReceiveResult::MessageWithKtWarning(msg)))) if msg.message_type == MessageType::Metadata => {
                        let mut fetch_avatar = None;
                        let mut own_name_changed = false;
                        let mut server_move = None;
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
                                    MetadataPayload::ServerMoved(location) => {
                                        // Only the creator may move a server; the record is verified when followed.
                                        let from_creator = c
                                            .store()
                                            .get_server(&server_id)
                                            .is_ok_and(|s| s.creator_fp == msg.sender_fp);
                                        if from_creator {
                                            server_move = Some(location);
                                        }
                                    }
                                }
                                let _ = c.store().set_last_seen_seq(&mailbox_id, seq);
                            }
                            Err(e) => eprintln!("decode metadata: {e}"),
                        }
                        if let Some((sid, fp, hash)) = fetch_avatar {
                            maybe_fetch_avatar(&client, &relay, &app, &data_dir, &sid, &fp, &hash).await;
                        }
                        if let Some(location) = server_move {
                            match ghost_core::flows::server::follow_move(&client, &relay, &server_id, &location).await {
                                Ok(true) => eprintln!("server {} moved to another relay", hex::encode(&server_id[..8])),
                                Ok(false) => {}
                                Err(e) => eprintln!("server move not followed: {e}"),
                            }
                        }
                        if own_name_changed {
                            let _ = app.emit("display-name-sync", ());
                        }
                        let _ = app.emit("sync", hex::encode(server_id));
                    }
                    Some((_, _, Ok(ReceiveResult::Message(msg)))) | Some((_, _, Ok(ReceiveResult::MessageWithKtWarning(msg)))) => {
                        let dto = MessageDto::from_incoming(&msg, received_at);
                        let _ = app.emit("message", &dto);
                        let c = client.lock().await;
                        let _ = c.store().set_last_seen_seq(&mailbox_id, seq);
                    }
                    Some((server_id, _channel_id, Ok(ReceiveResult::CommitProcessed))) => {
                        let mut new_member_fps = Vec::new();
                        {
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
                                        new_member_fps.push(*fp);
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
                        }
                        // Cache identity logs for gossip enrichment (not required for message processing)
                        for fp in &new_member_fps {
                            ghost_core::flows::idlog::cache_member(&client, &relay, fp).await;
                        }
                        rebroadcast_presence(&client, &relay, &mailbox_id, &presence).await;
                        retry_pending_presence(&app, &client, &server_id, &mut online_members, &mut pending_presence).await;
                        let _ = app.emit("sync", hex::encode(server_id));
                    }
                    Some((server_id, _channel_id, Ok(ReceiveResult::Kicked))) => {
                        use ghost_core::wire::{SyncMessageType, SYNC_KEY_SERVER_PREFIX};
                        let c = client.lock().await;
                        let _ = c.store().set_last_seen_seq(&mailbox_id, seq);
                        let key = format!("{}{}", SYNC_KEY_SERVER_PREFIX, hex::encode(server_id));
                        let _ = c.sync_remove(&key, now_ms());
                        drop(c);
                        ghost_core::flows::sync::post_message(&client, &relay, SyncMessageType::ServerLeft, &server_id).await;
                        ghost_core::flows::sync::push_snapshot(&client, &relay).await;
                        let _ = app.emit("kicked", hex::encode(server_id));
                    }
                    Some((server_id, _channel_id, Ok(ReceiveResult::DeviceRemoved))) => {
                        // This device was revoked; the account's other devices are still
                        // members, so nothing goes to the sync group. Only the UI updates.
                        let c = client.lock().await;
                        let _ = c.store().set_last_seen_seq(&mailbox_id, seq);
                        drop(c);
                        let _ = app.emit("kicked", hex::encode(server_id));
                    }
                    Some((server_id, _channel_id, Ok(ReceiveResult::MembersRemoved(removed)))) => {
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
                    Some((server_id, channel_id, Ok(ReceiveResult::ProposalProcessed))) => {
                        let c = client.lock().await;
                        let _ = c.store().set_last_seen_seq(&mailbox_id, seq);
                        drop(c);

                        // Any member can commit Remove proposals; relay enforces add-only-by-creator
                        {
                            let outbound = {
                                let mut c = client.lock().await;
                                c.commit_pending_proposals(&channel_id)
                            };
                            match outbound {
                                Ok(out) => {
                                    let post_result = {
                                        let r = relay.lock().await;
                                        r.post_blob(&out.mailbox_id, out.blob).await
                                    };
                                    match post_result {
                                        Ok(_) => {
                                            let mut c = client.lock().await;
                                            let _ = c.merge_pending_commit_for_channel(&channel_id);
                                            if let Ok(gi) = c.export_server_info(&server_id) {
                                                let r = relay.lock().await;
                                                let _ = r.put_server_info(&mailbox_id, gi).await;
                                            }
                                            drop(c);
                                            rebroadcast_presence(&client, &relay, &mailbox_id, &presence).await;
                                            let _ = app.emit("sync", hex::encode(server_id));
                                        }
                                        Err(e) => {
                                            eprintln!("relay: failed to post pending commit: {e}");
                                            let mut c = client.lock().await;
                                            let _ = c.clear_pending_commit_for_channel(&channel_id);
                                        }
                                    }
                                }
                                Err(e) => {
                                    eprintln!("relay: failed to build pending commit: {e}");
                                }
                            }
                        }
                    }
                    Some((_, _, Ok(ReceiveResult::Skipped))) => {
                        let c = client.lock().await;
                        let _ = c.store().set_last_seen_seq(&mailbox_id, seq);
                    }
                    Some((_, _, Err(e))) => {
                        eprintln!("relay: receive error seq={seq}: {e}");
                        let c = client.lock().await;
                        let _ = c.store().set_last_seen_seq(&mailbox_id, seq);
                        drop(c);
                        let count = consecutive_errors.entry(mailbox_id).or_insert(0);
                        *count += 1;
                        if *count >= EPOCH_RECOVERY_ERROR_THRESHOLD {
                            eprintln!("relay: {} consecutive errors on {}, triggering epoch recovery",
                                *count, hex::encode(&mailbox_id[..8]));
                            *count = 0;
                            handle_gap(&client, &relay, &mailbox_id).await;
                        }
                    }
                    None => {}
                }
            }
            RelayEvent::Ack(ack) => {
                if ack.epoch_mismatch {
                    eprintln!("relay: epoch mismatch ack on {}, triggering recovery",
                        hex::encode(&ack.mailbox_id[..8]));
                    handle_gap(&client, &relay, &ack.mailbox_id).await;
                }
            }
            RelayEvent::Error { mailbox_id, message } => {
                eprintln!("relay: ws error on {}: {}", hex::encode(&mailbox_id[..8]), message);
            }
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
                    // On sync mailbox connect: fetch durable snapshot for catchup
                    if sync_mb.as_ref() == Some(&mailbox_id) {
                        let app2 = app.clone();
                        let client2 = client.clone();
                        let relay2 = relay.clone();
                        let cfg2 = config.clone();
                        let cfgp2 = config_path.clone();
                        let pres2 = presence.clone();
                        let vcmd2 = voice_cmd_tx.clone();
                        tokio::spawn(async move {
                            fetch_and_merge_sync_state(&app2, &client2, &relay2, &cfg2, &cfgp2, &pres2, &vcmd2).await;
                        });
                    }
                } else {
                    connected_mailboxes.remove(&mailbox_id);
                }
                let _ = app.emit("relay-connectivity", !connected_mailboxes.is_empty());
            }
        }
    }
}

/// Handle a decrypted sync application message (plaintext from MLS group).
async fn handle_sync_application(
    app: &AppHandle,
    client: &Arc<Mutex<GhostClient>>,
    relay: &Arc<Mutex<RelayClient>>,
    plaintext: &[u8],
    config: &Arc<Mutex<crate::config::GhostConfig>>,
    config_path: &PathBuf,
    presence: &Arc<Mutex<PresenceInfo>>,
    voice_cmd_tx: &mpsc::Sender<crate::voice_task::VoiceCommand>,
) {
    if plaintext.is_empty() { return; }

    let msg_type = plaintext[0];
    let body = &plaintext[1..];

    match msg_type {
        x if x == SyncMessageType::ServerProvisioned as u8 => {
            // Another device joined or created a server: join it on the relay hosting it.
            let payload = match ProvisionPayload::from_bytes(body) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("sync: bad provision payload: {e}");
                    return;
                }
            };
            if ghost_core::flows::provision::join_payload_if_unknown(client, relay, &payload, now_ms()).await {
                let _ = app.emit("sync", "all");
            }
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
                use ghost_core::wire::SYNC_KEY_SERVER_PREFIX;
                let c = client.lock().await;
                let _ = c.store().delete_server(&server_id);
                let key = format!("{}{}", SYNC_KEY_SERVER_PREFIX, hex::encode(server_id));
                let _ = c.sync_remove(&key, now_ms());
            }

            if let Some(mb) = mailbox_id {
                let mut r = relay.lock().await;
                r.unsubscribe(&mb);
            }

            // No sync broadcast — this IS the broadcast from the other device
            ghost_core::flows::sync::push_snapshot(&client, &relay).await;
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
        x if x == SyncMessageType::MutationSync as u8 => {
            use ghost_core::wire::{decode_mutation, MUTATION_SET, MUTATION_REMOVE};
            let (op, ts, key, value) = match decode_mutation(body) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("sync: bad mutation: {e}");
                    return;
                }
            };

            let applied = {
                let c = client.lock().await;
                match op {
                    MUTATION_SET => c.sync_set(&key, &value, ts).unwrap_or(false),
                    MUTATION_REMOVE => c.sync_remove(&key, ts).unwrap_or(false),
                    _ => false,
                }
            };
            if !applied { return; }

            let entry = if op == MUTATION_SET {
                vec![(key, Some(value), ts)]
            } else {
                vec![(key, None, ts)]
            };
            let settings = ghost_core::flows::sync::parse_entries(&entry);
            crate::sync_utils::apply_sync_side_effects(
                &settings, app, client, relay, config, config_path, presence, voice_cmd_tx,
            ).await;
            // Join any servers we learned about that we don't have locally.
            for (server_id, meta) in &settings.server_entries {
                join_server_if_unknown(app, client, relay, *server_id, meta).await;
            }
        }
        x if x == SyncMessageType::SyncKeyRotate as u8 => {
            if body.len() != 32 {
                eprintln!("sync: bad SyncKeyRotate payload (expected 32 bytes, got {})", body.len());
                return;
            }
            let new_key: [u8; 32] = body.try_into().unwrap();
            let c = client.lock().await;
            if let Err(e) = c.set_sync_key(new_key) {
                eprintln!("sync: failed to store rotated sync key: {e}");
            }
        }
        _ => {
            eprintln!("sync: unknown message type {msg_type:#04x}");
        }
    }
}

/// On sync mailbox connect: GET durable snapshot, LWW-import, apply side effects, PUT merged state.
async fn fetch_and_merge_sync_state(
    app: &AppHandle,
    client: &Arc<Mutex<GhostClient>>,
    relay: &Arc<Mutex<RelayClient>>,
    config: &Arc<Mutex<crate::config::GhostConfig>>,
    config_path: &PathBuf,
    presence: &Arc<Mutex<PresenceInfo>>,
    voice_cmd_tx: &mpsc::Sender<crate::voice_task::VoiceCommand>,
) {
    use ghost_core::wire::{decode_sync_state_dump, sync_open};

    let (sync_key, account_fp) = {
        let c = client.lock().await;
        let Some(k) = c.sync_key() else { return };
        (k, *c.fingerprint())
    };

    let get_result = {
        let r = relay.lock().await;
        r.get_sync_state(&account_fp).await
    };

    let sealed = match get_result {
        Ok(Some((_generation, data))) => data,
        Ok(None) => {
            // No snapshot yet — push our local state as the initial one
            ghost_core::flows::sync::push_snapshot(client, relay).await;
            return;
        }
        Err(e) => {
            eprintln!("sync: failed to GET sync_state: {e}");
            return;
        }
    };

    let dump_bytes = match sync_open(&sync_key, &sealed) {
        Ok(pt) => pt,
        Err(e) => {
            eprintln!("sync: failed to decrypt sync_state snapshot: {e}");
            return;
        }
    };

    let entries = match decode_sync_state_dump(&dump_bytes) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("sync: failed to decode sync_state snapshot: {e}");
            return;
        }
    };

    {
        let c = client.lock().await;
        c.sync_import(&entries).unwrap_or_default();
    }

    let settings = ghost_core::flows::sync::parse_entries(&entries);
    crate::sync_utils::apply_sync_side_effects(
        &settings, app, client, relay, config, config_path, presence, voice_cmd_tx,
    ).await;
    // Join servers found in snapshot that we don't have locally.
    for (server_id, meta) in &settings.server_entries {
        join_server_if_unknown(app, client, relay, *server_id, meta).await;
    }

    // PUT our merged state back
    ghost_core::flows::sync::push_snapshot(client, relay).await;
}

/// Join a server from its relay-stored GroupInfo if we don't already have it locally.
/// Used for recovery when ServerProvisioned was missed (e.g. epoch mismatch at link time).
async fn join_server_if_unknown(
    app: &AppHandle,
    client: &Arc<Mutex<GhostClient>>,
    relay: &Arc<Mutex<RelayClient>>,
    server_id: [u8; 32],
    meta: &SyncServerMeta,
) {
    if ghost_core::flows::provision::join_if_unknown(client, relay, server_id, meta, now_ms()).await {
        let _ = app.emit("sync", hex::encode(server_id));
    }
}

async fn handle_gap(
    client: &Arc<Mutex<GhostClient>>,
    relay: &Arc<Mutex<RelayClient>>,
    mailbox_id: &[u8; 32],
) {
    let channel_id = {
        let c = client.lock().await;
        let Some(cid) = c.channel_id_for_mailbox(mailbox_id) else { return };
        cid
    };

    match ghost_core::flows::epoch::recover(client, relay, &channel_id, mailbox_id, "gap recovery").await {
        Ok(true) => {}
        Ok(false) => eprintln!("gap recovery: failed after attempts"),
        Err(ghost_core::error::GhostError::RelayStatus { status: 404, .. }) => {
            eprintln!("gap recovery: relay has no server_info, resetting last_seen");
            let c = client.lock().await;
            let _ = c.store().set_last_seen_seq(mailbox_id, 0);
            drop(c);
            let mut r = relay.lock().await;
            r.subscribe(*mailbox_id, 0);
        }
        Err(e) => eprintln!("gap recovery: {e}"),
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
            let Some(_server_id) = c.server_id_for_mailbox(mailbox_id) else { return };
            for entry in arr {
                let Some(ch_b64) = get_json_str(entry, "ch") else { continue };
                let Some(p_b64) = get_json_str(entry, "p") else { continue };
                let Some(channel_id) = decode_channel_id(ch_b64) else { continue };
                let Some(blob) = decode_b64_blob(p_b64) else { continue };
                if let Ok(ps) = c.open_presence_blob(&channel_id, &blob) {
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
                let Some(channel_id) = decode_channel_id(&vs.ch) else { return };

                let Some(p_b64) = &vs.p else { return };
                let Some(blob) = decode_b64_blob(p_b64) else { return };
                let c = client.lock().await;
                let Some(_server_id) = c.server_id_for_mailbox(mailbox_id) else { return };
                let Ok(ps) = c.open_presence_blob(&channel_id, &blob) else { return };
                drop(c);

                if vs.leave == Some(true) {
                    apply_voice_leave(app, &channel_id, &ps, mailbox_id, voice_members, mailbox_channels);
                } else {
                    apply_voice_join(app, &channel_id, ps, mailbox_id, voice_members, mailbox_channels);
                }
            }
        }
    }
}

fn apply_voice_leave(
    app: &AppHandle,
    channel_id: &[u8; 32],
    ps: &PresenceState,
    mailbox_id: &[u8; 32],
    voice_members: &mut HashMap<[u8; 32], Vec<PresenceState>>,
    mailbox_channels: &mut HashMap<[u8; 32], HashSet<[u8; 32]>>,
) {
    let Some(members) = voice_members.get_mut(channel_id) else { return };
    members.retain(|m| !(m.fingerprint == ps.fingerprint && m.device_vk == ps.device_vk));
    if members.is_empty() {
        emit_channel_members(app, channel_id, &[]);
        voice_members.remove(channel_id);
        if let Some(chs) = mailbox_channels.get_mut(mailbox_id) {
            chs.remove(channel_id);
        }
    } else {
        emit_channel_members(app, channel_id, members);
    }
}

fn apply_voice_join(
    app: &AppHandle,
    channel_id: &[u8; 32],
    ps: PresenceState,
    mailbox_id: &[u8; 32],
    voice_members: &mut HashMap<[u8; 32], Vec<PresenceState>>,
    mailbox_channels: &mut HashMap<[u8; 32], HashSet<[u8; 32]>>,
) {
    mailbox_channels.entry(*mailbox_id).or_default().insert(*channel_id);
    let members = voice_members.entry(*channel_id).or_default();
    if let Some(existing) = members.iter_mut().find(|m| m.fingerprint == ps.fingerprint && m.device_vk == ps.device_vk) {
        existing.muted = ps.muted;
        existing.deafened = ps.deafened;
    } else {
        members.push(ps);
    }
    emit_channel_members(app, channel_id, members);
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

fn now_ms() -> u64 { crate::state::now_millis() }

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
        let Some(server_id) = c.server_id_for_mailbox(mailbox_id) else { return };
        let mut members_list = Vec::new();
        let mut failed = Vec::new();
        let mut avatars_to_fetch: Vec<([u8; 32], [u8; 32])> = Vec::new();
        for entry in arr {
            let Some(p_b64) = get_json_str(entry, "p") else { continue };
            let Some(blob) = decode_b64_blob(p_b64) else { continue };
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
        let Some(p_b64) = get_json_str(ps_val, "p") else { return };
        let Some(blob) = decode_b64_blob(p_b64) else { return };

        let c = client.lock().await;
        let Some(server_id) = c.server_id_for_mailbox(mailbox_id) else { return };
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
