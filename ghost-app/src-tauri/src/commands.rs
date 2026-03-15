use base64::Engine;
use rand::RngCore;
use tauri::{Emitter, State};

use ghost_core::storage::{Channel, ChannelKind, ServerKind};
use ghost_core::wire::{encode_avatar_clear, encode_avatar_update, encode_channel_op, encode_member_announce, ChannelOpPayload};

use ghost_core::mls::presence::OnlineStatus;

use crate::constants::{DEFAULT_PAGE_SIZE, INVITE_EXPIRY_MS, SEQ_HEADER};
use crate::config::KeybindConfig;
use crate::dto::{ChannelDto, ConfigDto, DeviceDto, ServerDto, IdentityDto, InviteDto, KeybindConfigDto, MemberDto, MessageDto};
use crate::presence;
use crate::state::{AppState, now_millis};
use crate::voice_task::VoiceCommand;

#[derive(serde::Deserialize)]
struct IdLogEntry {
    payload: String,
}

fn parse_id(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str).map_err(|e| e.to_string())?;
    bytes.try_into().map_err(|_| "invalid 32-byte id".into())
}

/// Sign an HTTP request with the device's cached auth credentials.
fn sign_request(state: &AppState, method: &str, path: &str, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    let auth = state.auth.read().unwrap();
    let h = ghost_wire::auth::sign_request_headers(method, path, &auth.account_fp, &auth.device_vk, &auth.signing_key);
    drop(auth);
    req.header("X-Ghost-Account", &h.account)
        .header("X-Ghost-Device", &h.device)
        .header("X-Ghost-Timestamp", &h.timestamp)
        .header("X-Ghost-Signature", &h.signature)
}

/// Post a sync message to all linked devices. No-op if sync key is not set (single device).
async fn post_sync_message(state: &AppState, msg_type: u8, payload: &[u8]) {
    crate::sync_utils::post_sync_message(&state.client, &state.relay, msg_type, payload).await;
}

async fn push_sync_snapshot(state: &AppState) {
    crate::sync_utils::push_sync_snapshot(&state.client, &state.relay).await;
}

/// Write a server's metadata to sync_state and push to linked devices + relay snapshot.
async fn sync_server_entry(state: &AppState, server_id: &[u8; 32]) {
    use ghost_core::wire::{encode_mutation, MUTATION_SET, SyncMessageType, SYNC_KEY_SERVER_PREFIX};

    let (key, value, ts) = {
        let client = state.client.lock().await;
        let meta = match client.export_server_meta(server_id) {
            Ok(m) => m,
            Err(_) => return,
        };
        let key = format!("{}{}", SYNC_KEY_SERVER_PREFIX, hex::encode(server_id));
        let value = meta.to_bytes();
        let ts = now_millis();
        let _ = client.sync_set(&key, &value, ts);
        (key, value, ts)
    };
    post_sync_message(state, SyncMessageType::MutationSync as u8, &encode_mutation(MUTATION_SET, ts, &key, &value)).await;
    push_sync_snapshot(state).await;
}

/// Write a key-value entry to sync state, broadcast to linked devices, and push snapshot.
async fn sync_set_and_push(state: &AppState, key: &str, value: &[u8]) {
    use ghost_core::wire::{encode_mutation, MUTATION_SET, SyncMessageType};
    let ts = now_millis();
    {
        let client = state.client.lock().await;
        let _ = client.sync_set(key, value, ts);
    }
    post_sync_message(state, SyncMessageType::MutationSync as u8, &encode_mutation(MUTATION_SET, ts, key, value)).await;
    push_sync_snapshot(state).await;
}

/// Fetch an identity log from the relay, verify KT proofs (inclusion + consistency),
/// and cache the validated result. Returns the validated LogState.
async fn fetch_and_verify_idlog(
    state: &AppState,
    account_fp: &[u8; 32],
) -> Result<ghost_wire::idlog::LogState, String> {
    let resp = {
        let relay = state.relay.lock().await;
        relay.get_idlog(account_fp, 0).await.map_err(|e| e.to_string())?
    };

    if resp.entries.is_empty() {
        return Err("identity log is empty".into());
    }

    let relay_url = state.relay_url.lock().await.clone();

    // Fetch consistency proof if we have a previous checkpoint
    let consistency = if !resp.checkpoint.is_empty() {
        let prev_tree_size = {
            let client = state.client.lock().await;
            client.kt_last_tree_size(&relay_url).unwrap_or(0)
        };
        if prev_tree_size > 0 {
            let new_tree_size = ghost_wire::merkle::Checkpoint::from_bytes(&resp.checkpoint)
                .map(|cp| cp.tree_size)
                .unwrap_or(0);
            if new_tree_size > prev_tree_size {
                let relay = state.relay.lock().await;
                Some(relay.get_consistency_proof(prev_tree_size, new_tree_size)
                    .await.map_err(|e| e.to_string())?)
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    // Verify proofs, validate chain, and cache
    let mut client = state.client.lock().await;
    client.cache_identity_log_with_proofs(
        &relay_url,
        account_fp,
        &resp,
        consistency.as_deref(),
    ).map_err(|e| e.to_string())
}

/// Remove a sync state entry, broadcast to linked devices, and push snapshot.
async fn sync_remove_and_push(state: &AppState, key: &str) {
    use ghost_core::wire::{encode_mutation, MUTATION_REMOVE, SyncMessageType};
    let ts = now_millis();
    {
        let client = state.client.lock().await;
        let _ = client.sync_remove(key, ts);
    }
    post_sync_message(state, SyncMessageType::MutationSync as u8, &encode_mutation(MUTATION_REMOVE, ts, key, &[])).await;
    push_sync_snapshot(state).await;
}

/// Abort the running relay task, create a fresh relay client, and swap it into state.
async fn replace_relay(
    state: &AppState,
    relay_url: &str,
) -> tokio::sync::mpsc::Receiver<ghost_core::relay::RelayEvent> {
    if let Some(handle) = state.relay_task_handle.lock().await.take() {
        handle.abort();
    }
    let (mut new_relay, inbox_rx) = ghost_core::relay::RelayClient::new(relay_url);
    {
        let auth = state.auth.read().unwrap();
        new_relay.set_auth(auth.account_fp, auth.device_vk, auth.signing_key.clone());
    }
    *state.relay.lock().await = new_relay;
    *state.relay_url.lock().await = relay_url.to_string();
    inbox_rx
}

/// Subscribe to the sync mailbox (if sync_key is set) and spawn the relay event loop.
async fn spawn_relay_task(
    app: tauri::AppHandle,
    state: &AppState,
    inbox_rx: tokio::sync::mpsc::Receiver<ghost_core::relay::RelayEvent>,
) {
    {
        let client = state.client.lock().await;
        if let Some(sync_mb) = client.sync_mailbox_id() {
            let seq = client.store().get_last_seen_seq(&sync_mb).unwrap_or(0);
            let mut relay = state.relay.lock().await;
            relay.subscribe(sync_mb, seq);
        }
    }
    let data_dir = state.config_path.parent().unwrap().to_path_buf();
    let jh = tauri::async_runtime::spawn(crate::relay_task::run(
        app,
        state.client.clone(),
        state.relay.clone(),
        inbox_rx,
        state.presence.clone(),
        data_dir,
        state.config.clone(),
        state.config_path.clone(),
        state.voice.cmd_tx.clone(),
    ));
    *state.relay_task_handle.lock().await = Some(jh);
}

const MAX_EPOCH_RECOVERY_ATTEMPTS: usize = 3;
const MAX_REJOIN_ATTEMPTS: usize = 3;
const PAIRING_POLL_ATTEMPTS: usize = 90;
const PAIRING_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);
const MAX_PROVISION_FETCH_ATTEMPTS: usize = 5;

/// Recover from an epoch conflict via external commit. Returns true on success.
pub(crate) async fn recover_epoch(
    client: &std::sync::Arc<tokio::sync::Mutex<ghost_core::client::GhostClient>>,
    relay: &std::sync::Arc<tokio::sync::Mutex<ghost_core::relay::RelayClient>>,
    server_id: &[u8; 32],
    mailbox_id: &[u8; 32],
    label: &str,
) -> Result<bool, String> {
    for attempt in 0..MAX_EPOCH_RECOVERY_ATTEMPTS {
        let server_info = {
            let r = relay.lock().await;
            match r.get_server_info(mailbox_id).await {
                Ok(gi) => gi,
                Err(e) => return Err(format!("{label}: fetch GroupInfo: {e}")),
            }
        };
        let commit = {
            let mut c = client.lock().await;
            match c.recover_via_external_commit(server_id, &server_info) {
                Ok((commit, _)) => commit,
                Err(e) => {
                    eprintln!("{label}: external commit failed (attempt {attempt}): {e}");
                    continue;
                }
            }
        };
        let all_ok = match relay.lock().await.post_blob(mailbox_id, commit).await {
            Ok(_) => true,
            Err(e) => {
                eprintln!("{label}: relay rejected commit (attempt {attempt}): {e}");
                false
            }
        };
        if all_ok {
            let c = client.lock().await;
            if let Ok(gi) = c.export_server_info(server_id) {
                let r = relay.lock().await;
                let _ = r.put_server_info(mailbox_id, gi).await;
            }
            return Ok(true);
        }
    }
    Ok(false)
}

#[tauri::command]
pub async fn get_identity(state: State<'_, AppState>) -> Result<IdentityDto, String> {
    let client = state.client.lock().await;
    Ok(IdentityDto::from(client.identity()))
}

#[tauri::command]
pub async fn list_servers(state: State<'_, AppState>) -> Result<Vec<ServerDto>, String> {
    let client = state.client.lock().await;
    let store = client.store();
    let servers = store.list_servers().map_err(|e| e.to_string())?;
    let unread_servers = store.servers_with_unread().map_err(|e| e.to_string())?;
    Ok(servers
        .iter()
        .map(|s| ServerDto::from_server(s, unread_servers.contains(&s.server_id)))
        .collect())
}

async fn create_server_impl(name: &str, kind: ServerKind, state: &AppState) -> Result<ServerDto, String> {
    let (server_dto, server_id, mailbox_id) = {
        let mut client = state.client.lock().await;
        let server_id = client
            .create_server(name, kind, now_millis())
            .map_err(|e| e.to_string())?;
        let server = client
            .store()
            .get_server(&server_id)
            .map_err(|e| e.to_string())?;
        let mid = client.mailbox_id_for_server(&server_id);
        (ServerDto::from_server(&server, false), server_id, mid)
    };

    if let Some(mid) = mailbox_id {
        let upload_ok = {
            let client = state.client.lock().await;
            match client.export_server_info(&server_id) {
                Ok(gi) => {
                    let relay = state.relay.lock().await;
                    relay.put_server_info(&mid, gi).await.map_err(|e| e.to_string())
                }
                Err(e) => Err(e.to_string()),
            }
        };
        if let Err(e) = upload_ok {
            // Roll back local state — server can't exist without relay presence
            let client = state.client.lock().await;
            let _ = client.store().delete_server(&server_id);
            return Err(e);
        }
        let mut relay = state.relay.lock().await;
        relay.subscribe(mid, 0);
    }

    {
        let client = state.client.lock().await;
        if let Ok(payload) = client.export_provision_payload(&server_id) {
            drop(client);
            post_sync_message(state, ghost_core::wire::SyncMessageType::ServerProvisioned as u8, &payload.to_bytes()).await;
        }
    }

    sync_server_entry(state, &server_id).await;
    Ok(server_dto)
}

#[tauri::command]
pub async fn create_server(name: String, state: State<'_, AppState>) -> Result<ServerDto, String> {
    create_server_impl(&name, ServerKind::Server, &state).await
}

#[tauri::command]
pub async fn create_dm(name: String, state: State<'_, AppState>) -> Result<ServerDto, String> {
    create_server_impl(&name, ServerKind::Dm, &state).await
}

#[tauri::command]
pub async fn list_channels(
    server_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<ChannelDto>, String> {
    let sid = parse_id(&server_id)?;
    let client = state.client.lock().await;
    let store = client.store();
    let channels = store.list_channels(&sid).map_err(|e| e.to_string())?;
    let unread = store.get_unread_counts(&sid).map_err(|e| e.to_string())?;
    let unread_map: std::collections::HashMap<[u8; 32], u32> = unread.into_iter().collect();
    Ok(channels
        .iter()
        .map(|c| ChannelDto::from_channel(c, unread_map.get(&c.channel_id).copied().unwrap_or(0)))
        .collect())
}

#[tauri::command]
pub async fn list_members(
    server_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<MemberDto>, String> {
    let sid = parse_id(&server_id)?;
    let client = state.client.lock().await;
    let members = client
        .store()
        .list_members(&sid)
        .map_err(|e| e.to_string())?;
    Ok(members.iter().map(MemberDto::from).collect())
}

#[tauri::command]
pub async fn save_server_order(order: Vec<String>, state: State<'_, AppState>) -> Result<(), String> {
    use ghost_core::wire::{encode_mutation, MUTATION_SET, SyncMessageType, SYNC_KEY_SERVER_ORDER};
    let ts = now_millis();
    let value = serde_json::to_vec(&order).map_err(|e| e.to_string())?;
    {
        let client = state.client.lock().await;
        let _ = client.sync_set(SYNC_KEY_SERVER_ORDER, &value, ts);
    }
    post_sync_message(&state, SyncMessageType::MutationSync as u8, &encode_mutation(MUTATION_SET, ts, SYNC_KEY_SERVER_ORDER, &value)).await;
    push_sync_snapshot(&state).await;
    Ok(())
}

#[tauri::command]
pub async fn get_server_order(state: State<'_, AppState>) -> Result<Vec<String>, String> {
    let client = state.client.lock().await;
    match client.sync_get(ghost_core::wire::SYNC_KEY_SERVER_ORDER) {
        Ok(Some((Some(value), _))) => {
            serde_json::from_slice(&value).map_err(|e| e.to_string())
        }
        _ => Ok(vec![]),
    }
}

#[tauri::command]
pub async fn list_messages(
    channel_id: String,
    before: Option<u64>,
    limit: Option<u32>,
    state: State<'_, AppState>,
) -> Result<Vec<MessageDto>, String> {
    let cid = parse_id(&channel_id)?;
    let client = state.client.lock().await;
    let msgs = client
        .store()
        .get_messages(&cid, before, limit.unwrap_or(DEFAULT_PAGE_SIZE))
        .map_err(|e| e.to_string())?;
    Ok(msgs.iter().map(MessageDto::from).collect())
}

#[tauri::command]
pub async fn send_message(
    server_id: String,
    channel_id: String,
    content: String,
    state: State<'_, AppState>,
) -> Result<MessageDto, String> {
    let sid = parse_id(&server_id)?;
    let cid = parse_id(&channel_id)?;

    let (outbound, dto) = {
        let mut client = state.client.lock().await;
        let (outbound, msg_id) = client
            .send_message(&sid, &cid, content.into_bytes(), vec![], now_millis())
            .map_err(|e| e.to_string())?;
        let stored = client
            .store()
            .get_message(&msg_id)
            .map_err(|e| e.to_string())?;
        (outbound, MessageDto::from(&stored))
    };

    // Forward to relay (best-effort, don't fail the command)
    let relay = state.relay.lock().await;
    let _ = relay.send(&outbound.mailbox_id, outbound.blob).await;

    Ok(dto)
}

#[tauri::command]
pub async fn create_channel(
    server_id: String,
    name: String,
    kind: String,
    state: State<'_, AppState>,
) -> Result<ChannelDto, String> {
    let sid = parse_id(&server_id)?;
    let mut channel_id = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut channel_id);
    let kind = match kind.as_str() {
        "voice" => ChannelKind::Voice,
        _ => ChannelKind::Text,
    };

    let outbound = {
        let mut client = state.client.lock().await;
        let position = client
            .store()
            .list_channels(&sid)
            .map_err(|e| e.to_string())?
            .len() as i32;
        let channel = Channel {
            channel_id,
            server_id: sid,
            name: name.clone(),
            kind,
            position,
        };
        client
            .store()
            .insert_channel(&channel)
            .map_err(|e| e.to_string())?;

        let op = ChannelOpPayload::Create { channel_id, name, kind, position };
        client
            .send_control(&sid, encode_channel_op(&op))
            .map_err(|e| e.to_string())?
    };

    let relay = state.relay.lock().await;
    let _ = relay.send(&outbound.mailbox_id, outbound.blob).await;
    drop(relay);

    sync_server_entry(&state, &sid).await;

    let client = state.client.lock().await;
    let channel = client.store().get_channel(&channel_id).map_err(|e| e.to_string())?;
    Ok(ChannelDto::from_channel(&channel, 0))
}

#[tauri::command]
pub async fn rename_channel(
    channel_id: String,
    name: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let cid = parse_id(&channel_id)?;

    let (outbound, sid) = {
        let mut client = state.client.lock().await;
        let channel = client.store().get_channel(&cid).map_err(|e| e.to_string())?;
        let sid = channel.server_id;
        client
            .store()
            .rename_channel(&cid, &name)
            .map_err(|e| e.to_string())?;

        let op = ChannelOpPayload::Rename { channel_id: cid, name };
        let out = client
            .send_control(&sid, encode_channel_op(&op))
            .map_err(|e| e.to_string())?;
        (out, sid)
    };

    let relay = state.relay.lock().await;
    let _ = relay.send(&outbound.mailbox_id, outbound.blob).await;
    drop(relay);

    sync_server_entry(&state, &sid).await;
    Ok(())
}

#[tauri::command]
pub async fn delete_channel(
    channel_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let cid = parse_id(&channel_id)?;

    let (outbound, sid) = {
        let mut client = state.client.lock().await;
        let channel = client.store().get_channel(&cid).map_err(|e| e.to_string())?;
        let sid = channel.server_id;
        client
            .store()
            .delete_channel(&cid)
            .map_err(|e| e.to_string())?;

        let op = ChannelOpPayload::Delete { channel_id: cid };
        let out = client
            .send_control(&sid, encode_channel_op(&op))
            .map_err(|e| e.to_string())?;
        (out, sid)
    };

    let relay = state.relay.lock().await;
    let _ = relay.send(&outbound.mailbox_id, outbound.blob).await;
    drop(relay);

    sync_server_entry(&state, &sid).await;
    Ok(())
}

#[tauri::command]
pub async fn kick_member(
    server_id: String,
    fingerprint: String,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let sid = parse_id(&server_id)?;
    let fp = parse_id(&fingerprint)?;

    let outbound = {
        let mut client = state.client.lock().await;
        client.kick_member(&sid, &fp).map_err(|e| e.to_string())?
    };

    // Post commit via HTTP (not WebSocket) so we detect epoch conflicts
    let post_result = {
        let relay = state.relay.lock().await;
        relay.post_blob(&outbound.mailbox_id, outbound.blob).await
    };
    match post_result {
        Ok(_) => {
            let mut client = state.client.lock().await;
            let _ = client.merge_pending_commit_for_server(&sid);
            let _ = client.store().remove_member(&sid, &fp);
            if let Ok(gi) = client.export_server_info(&sid) {
                let relay = state.relay.lock().await;
                let _ = relay.put_server_info(&outbound.mailbox_id, gi).await;
            }
            drop(client);
            let _ = app.emit("sync", hex::encode(sid));
        }
        Err(e) => {
            eprintln!("kick: relay rejected commit: {e}, clearing pending commit");
            let mut client = state.client.lock().await;
            let _ = client.clear_pending_commit_for_server(&sid);
            drop(client);
            return Err("epoch conflict — please try again".into());
        }
    }

    Ok(())
}

#[tauri::command]
pub async fn mark_channel_read(
    channel_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    use ghost_core::wire::{encode_mutation, MUTATION_SET, SyncMessageType, SYNC_KEY_READ_PREFIX};
    let cid = parse_id(&channel_id)?;
    let ts = now_millis();
    let key = format!("{SYNC_KEY_READ_PREFIX}{channel_id}");
    {
        let client = state.client.lock().await;
        client.store().mark_channel_read(&cid, ts).map_err(|e| e.to_string())?;
        let _ = client.sync_set(&key, &ts.to_be_bytes(), ts);
    }
    post_sync_message(&state, SyncMessageType::MutationSync as u8, &encode_mutation(MUTATION_SET, ts, &key, &ts.to_be_bytes())).await;
    push_sync_snapshot(&state).await;
    Ok(())
}

#[tauri::command]
pub async fn create_invite(
    server_id: String,
    state: State<'_, AppState>,
) -> Result<InviteDto, String> {
    let sid = parse_id(&server_id)?;

    let relay_url = state.relay_url.lock().await.clone();

    let (token, payload_bytes) = {
        let client = state.client.lock().await;
        client.create_invite(&sid).map_err(|e| e.to_string())?
    };

    let expires_at = now_millis() + INVITE_EXPIRY_MS;
    let reg_path = "/invite";
    sign_request(&state, "POST", reg_path, state.http
        .post(format!("{}{}", relay_url, reg_path))
        .json(&serde_json::json!({ "token": token, "expires_at": expires_at })))
        .send()
        .await
        .map_err(|e| format!("register invite: {e}"))?
        .error_for_status()
        .map_err(|e| format!("register invite: {e}"))?;

    let join_path = format!("/invite/{}/join", token);
    sign_request(&state, "POST", &join_path, state.http
        .post(format!("{}{}", relay_url, join_path))
        .header(SEQ_HEADER, "0")
        .body(payload_bytes))
        .send()
        .await
        .map_err(|e| format!("upload invite payload: {e}"))?
        .error_for_status()
        .map_err(|e| format!("upload invite payload: {e}"))?;

    let mut link = url::Url::parse("ghost://join").expect("valid base URL");
    link.query_pairs_mut()
        .append_pair("relay", &relay_url)
        .append_pair("token", &token);
    let link = link.to_string();

    Ok(InviteDto { token, link })
}

#[tauri::command]
pub async fn join_by_invite(
    relay_url: String,
    token: String,
    state: State<'_, AppState>,
) -> Result<ServerDto, String> {
    let response = state
        .http
        .get(format!("{}/invite/{}/join", relay_url, token))
        .send()
        .await
        .map_err(|e| format!("fetch invite: {e}"))?
        .error_for_status()
        .map_err(|e| format!("fetch invite: {e}"))?;

    let seq: u64 = response
        .headers()
        .get(SEQ_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let payload_bytes = response
        .bytes()
        .await
        .map_err(|e| format!("read invite body: {e}"))?;

    let (server_id, commit, mailbox_id) = {
        let mut client = state.client.lock().await;
        client
            .join_by_invite(&payload_bytes, now_millis())
            .map_err(|e| e.to_string())?
    };

    // Broadcast the external commit so existing members see us
    let mailbox_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mailbox_id);
    #[derive(serde::Deserialize)]
    struct PostBlobResp { seq: u64 }
    let box_path = format!("/box/{}", mailbox_b64);
    let resp = sign_request(&state, "POST", &box_path, state.http
        .post(format!("{}{}", relay_url, box_path))
        .body(commit))
        .send()
        .await
        .map_err(|e| format!("broadcast commit: {e}"))?
        .error_for_status()
        .map_err(|e| format!("broadcast commit: {e}"))?;
    let commit_seq = resp.json::<PostBlobResp>().await
        .map(|r| r.seq).unwrap_or(0);

    // Refresh the invite payload with fresh GroupInfo for the next joiner
    let updated_payload = {
        let client = state.client.lock().await;
        client
            .refresh_invite_payload(&server_id)
            .map_err(|e| e.to_string())?
    };

    let refresh_path = format!("/invite/{}/join", token);
    let resp = sign_request(&state, "POST", &refresh_path, state.http
        .post(format!("{}{}", relay_url, refresh_path))
        .header(SEQ_HEADER, seq.to_string())
        .body(updated_payload))
        .send()
        .await
        .map_err(|e| format!("refresh invite: {e}"))?;

    if !resp.status().is_success() && resp.status() != reqwest::StatusCode::CONFLICT {
        return Err(format!("refresh invite: HTTP {}", resp.status()));
    }

    // Subscribe from the commit seq so we don't replay stale messages
    let announce = {
        let mut client = state.client.lock().await;
        let _ = client.store().set_last_seen_seq(&mailbox_id, commit_seq);
        let name = client.identity().display_name.clone();
        match client.send_control(&server_id, encode_member_announce(&name)) {
            Ok(out) => Some(out),
            Err(e) => {
                eprintln!("send_control failed: {e}");
                None
            }
        }
    };
    {
        let mut relay = state.relay.lock().await;
        relay.subscribe(mailbox_id, commit_seq);
        if let Some(outbound) = announce {
            let _ = relay.send(&outbound.mailbox_id, outbound.blob).await;
        }
    }

    // Notify linked devices
    {
        let client = state.client.lock().await;
        if let Ok(payload) = client.export_provision_payload(&server_id) {
            drop(client);
            post_sync_message(&state, ghost_core::wire::SyncMessageType::ServerProvisioned as u8, &payload.to_bytes()).await;
        }
    }

    sync_server_entry(&state, &server_id).await;

    let client = state.client.lock().await;
    let server = client
        .store()
        .get_server(&server_id)
        .map_err(|e| e.to_string())?;
    Ok(ServerDto::from_server(&server, false))
}

#[tauri::command]
pub async fn get_config(state: State<'_, AppState>) -> Result<ConfigDto, String> {
    let cfg = state.config.lock().await;
    let ns = match cfg.noise_suppression.as_deref() {
        Some("off") => "off",
        _ => "nnnoiseless",
    };
    let agc = match cfg.agc.as_deref() {
        Some("off") => "off",
        _ => "auto",
    };
    let input_mode = cfg.input_mode.as_deref().unwrap_or("voice_activity");
    let status = cfg.status.as_deref().unwrap_or("online");
    Ok(ConfigDto {
        display_name: cfg.display_name.clone(),
        relay_url: cfg.relay_url.clone(),
        input_device: cfg.input_device.clone(),
        output_device: cfg.output_device.clone(),
        noise_suppression: ns.to_string(),
        agc: agc.to_string(),
        input_mode: input_mode.to_string(),
        vad_threshold: cfg.vad_threshold.unwrap_or(crate::constants::VAD_THRESHOLD),
        input_gain: cfg.input_gain.unwrap_or(1.0),
        status: status.to_string(),
        status_message: cfg.status_message.clone(),
    })
}

#[tauri::command]
pub async fn set_display_name(
    name: String,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    use ghost_core::wire::SYNC_KEY_DISPLAY_NAME;

    let mut cfg = state.config.lock().await;
    cfg.display_name = Some(name.clone());
    cfg.save(&state.config_path)?;
    drop(cfg);

    let outbounds = {
        let mut client = state.client.lock().await;
        client.set_display_name(name.clone());
        let payload = encode_member_announce(&name);
        let mut out = Vec::new();
        for (server_id, _) in client.server_mailboxes() {
            if let Ok(o) = client.send_control(&server_id, payload.clone()) {
                out.push(o);
            }
        }
        out
    };
    let relay = state.relay.lock().await;
    for o in outbounds {
        let _ = relay.send(&o.mailbox_id, o.blob).await;
    }
    drop(relay);

    sync_set_and_push(&state, SYNC_KEY_DISPLAY_NAME, name.as_bytes()).await;
    let _ = app.emit("display-name-sync", ());
    Ok(())
}

#[tauri::command]
pub async fn upload_avatar(
    data: Vec<u8>,
    state: State<'_, AppState>,
) -> Result<(), String> {
    use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, AeadCore, OsRng}};

    // Generate random encryption key, encrypt the avatar blob
    let mut avatar_key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut avatar_key);
    let cipher = Aes256Gcm::new((&avatar_key).into());
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, data.as_ref())
        .map_err(|e| format!("encrypt avatar: {e}"))?;
    let mut encrypted = Vec::with_capacity(12 + ciphertext.len());
    encrypted.extend_from_slice(&nonce);
    encrypted.extend_from_slice(&ciphertext);

    let avatar_hash: [u8; 32] = blake3::hash(&encrypted).into();

    // Upload to relay + send MLS metadata for each server
    let (outbounds, fingerprint) = {
        let mut client = state.client.lock().await;
        let fp = *client.fingerprint();
        let payload = encode_avatar_update(&avatar_hash, &avatar_key);
        let mut out = Vec::new();
        for (server_id, _) in client.server_mailboxes() {
            let _ = client.store().update_member_avatar(&server_id, &fp, &avatar_hash, &avatar_key);
            match client.send_control(&server_id, payload.clone()) {
                Ok(o) => out.push(o),
                Err(e) => eprintln!("avatar: send_control failed for server {}: {e}", hex::encode(server_id)),
            }
        }
        (out, fp)
    };
    {
        let relay = state.relay.lock().await;
        for o in &outbounds {
            if let Err(e) = relay.put_avatar(&o.mailbox_id, &fingerprint, encrypted.clone()).await {
                eprintln!("avatar: put_avatar failed for mailbox {}: {e}", hex::encode(o.mailbox_id));
            }
            if let Err(e) = relay.send(&o.mailbox_id, o.blob.clone()).await {
                eprintln!("avatar: send metadata failed for mailbox {}: {e}", hex::encode(o.mailbox_id));
            }
        }
    }

    // Cache locally
    let avatar_dir = state.config_path.parent().unwrap().join("avatars");
    let _ = std::fs::create_dir_all(&avatar_dir);
    let _ = std::fs::write(avatar_dir.join(format!("{}.webp", hex::encode(fingerprint))), &data);

    // Update presence so online members see the new avatar_hash immediately
    {
        let mut p = state.presence.lock().await;
        p.avatar_hash = Some(avatar_hash);
        let info = p.clone();
        drop(p);
        presence::broadcast_presence(&state.client, &state.relay, &info).await;
    }

    Ok(())
}

#[tauri::command]
pub async fn clear_avatar(
    state: State<'_, AppState>,
) -> Result<(), String> {
    let (outbounds, fingerprint) = {
        let mut client = state.client.lock().await;
        let fp = *client.fingerprint();
        let payload = encode_avatar_clear();
        let mut out = Vec::new();
        for (server_id, _) in client.server_mailboxes() {
            let _ = client.store().clear_member_avatar(&server_id, &fp);
            if let Ok(o) = client.send_control(&server_id, payload.clone()) {
                out.push(o);
            }
        }
        (out, fp)
    };
    {
        let relay = state.relay.lock().await;
        for o in &outbounds {
            let _ = relay.delete_avatar(&o.mailbox_id, &fingerprint).await;
            let _ = relay.send(&o.mailbox_id, o.blob.clone()).await;
        }
    }

    // Delete local cache
    let avatar_dir = state.config_path.parent().unwrap().join("avatars");
    let fp_hex = hex::encode(fingerprint);
    let _ = std::fs::remove_file(avatar_dir.join(format!("{}.webp", fp_hex)));
    let _ = std::fs::remove_file(avatar_dir.join(format!("{}.hash", fp_hex)));

    // Clear presence avatar_hash
    {
        let mut p = state.presence.lock().await;
        p.avatar_hash = None;
        let info = p.clone();
        drop(p);
        presence::broadcast_presence(&state.client, &state.relay, &info).await;
    }

    Ok(())
}

#[tauri::command]
pub async fn get_cached_avatar(
    fingerprint_hex: String,
    state: State<'_, AppState>,
) -> Result<Option<String>, String> {
    let avatar_dir = state.config_path.parent().unwrap().join("avatars");
    let path = avatar_dir.join(format!("{}.webp", fingerprint_hex));
    match std::fs::read(&path) {
        Ok(bytes) => {
            let mime = if bytes.starts_with(b"GIF") {
                "image/gif"
            } else if bytes.starts_with(b"\x89PNG") {
                "image/png"
            } else if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xD8 {
                "image/jpeg"
            } else {
                "image/webp"
            };
            let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
            Ok(Some(format!("data:{};base64,{}", mime, b64)))
        }
        Err(_) => Ok(None),
    }
}

#[tauri::command]
pub async fn set_relay_url(
    url: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let mut cfg = state.config.lock().await;
    cfg.relay_url = Some(url);
    cfg.save(&state.config_path)?;
    Ok(())
}

#[tauri::command]
pub async fn join_voice(
    server_id: String,
    channel_id: String,
    muted: bool,
    deafened: bool,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let fingerprint = {
        let client = state.client.lock().await;
        hex::encode(client.fingerprint())
    };
    let default_relay_url = state.relay_url.lock().await.clone();
    let (relay_url, input_device, output_device, ns_mode, agc_mode, vad_threshold, input_gain, input_mode) = {
        let cfg = state.config.lock().await;
        let url = cfg
            .relay_url
            .as_deref()
            .filter(|u| !u.is_empty())
            .map(String::from)
            .unwrap_or(default_relay_url);
        let vad = cfg.vad_threshold.unwrap_or(crate::constants::VAD_THRESHOLD);
        let gain = cfg.input_gain.unwrap_or(1.0);
        let mode = if cfg.input_mode.as_deref() == Some("push_to_talk") {
            crate::audio::INPUT_MODE_PTT
        } else {
            crate::audio::INPUT_MODE_VA
        };
        (url, cfg.input_device.clone(), cfg.output_device.clone(), cfg.noise_suppression_mode(), cfg.agc_mode(), vad, gain, mode)
    };
    // Notify linked devices to leave voice on this channel
    let channel_id_bytes = parse_id(&channel_id)?;
    post_sync_message(&state, ghost_core::wire::SyncMessageType::VoiceTakeover as u8, &channel_id_bytes).await;

    state
        .voice
        .cmd_tx
        .send(VoiceCommand::Join {
            server_id,
            channel_id,
            relay_url,
            fingerprint,
            input_device,
            output_device,
            ns_mode: ns_mode as u8,
            agc_mode: agc_mode as u8,
            vad_threshold: vad_threshold.to_bits(),
            input_gain: input_gain.to_bits(),
            input_mode,
            muted,
            deafened,
        })
        .await
        .map_err(|_| "voice task not running".to_string())
}

#[tauri::command]
pub async fn leave_voice(state: State<'_, AppState>) -> Result<(), String> {
    state
        .voice
        .cmd_tx
        .send(VoiceCommand::Leave)
        .await
        .map_err(|_| "voice task not running".to_string())
}

#[tauri::command]
pub async fn set_muted(muted: bool, state: State<'_, AppState>) -> Result<(), String> {
    state
        .voice
        .cmd_tx
        .send(VoiceCommand::SetMuted(muted))
        .await
        .map_err(|_| "voice task not running".to_string())
}

#[tauri::command]
pub async fn set_deafened(deafened: bool, state: State<'_, AppState>) -> Result<(), String> {
    state
        .voice
        .cmd_tx
        .send(VoiceCommand::SetDeafened(deafened))
        .await
        .map_err(|_| "voice task not running".to_string())
}

#[tauri::command]
pub async fn start_mic_test(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let cfg = state.config.lock().await;
    crate::audio_test::start_mic_test(app, cfg.input_device.clone(), cfg.output_device.clone())
}

#[tauri::command]
pub async fn stop_mic_test() -> Result<(), String> {
    crate::audio_test::stop_mic_test();
    Ok(())
}

#[tauri::command]
pub async fn play_test_tone(state: State<'_, AppState>) -> Result<(), String> {
    let cfg = state.config.lock().await;
    crate::audio_test::play_test_tone(cfg.output_device.clone())
}

#[tauri::command]
pub async fn list_audio_devices() -> Result<AudioDevicesDto, String> {
    use cpal::traits::{DeviceTrait, HostTrait};
    let host = cpal::default_host();

    let default_in = host.default_input_device().and_then(|d| d.name().ok());
    let default_out = host.default_output_device().and_then(|d| d.name().ok());

    let mut inputs = Vec::new();
    if let Ok(devices) = host.input_devices() {
        for d in devices {
            if let Ok(name) = d.name() {
                inputs.push(name);
            }
        }
    }

    let mut outputs = Vec::new();
    if let Ok(devices) = host.output_devices() {
        for d in devices {
            if let Ok(name) = d.name() {
                outputs.push(name);
            }
        }
    }

    Ok(AudioDevicesDto { inputs, outputs, default_input: default_in, default_output: default_out })
}

#[derive(serde::Serialize)]
pub struct AudioDevicesDto {
    pub inputs: Vec<String>,
    pub outputs: Vec<String>,
    pub default_input: Option<String>,
    pub default_output: Option<String>,
}

#[tauri::command]
pub async fn set_input_device(
    name: Option<String>,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let mut cfg = state.config.lock().await;
    cfg.input_device = name;
    cfg.save(&state.config_path)
}

#[tauri::command]
pub async fn set_output_device(
    name: Option<String>,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let mut cfg = state.config.lock().await;
    cfg.output_device = name;
    cfg.save(&state.config_path)
}

#[tauri::command]
pub async fn set_noise_suppression(
    mode: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    use ghost_core::wire::SYNC_KEY_NOISE_SUPPRESSION;

    let ns = match mode.as_str() {
        "off" => crate::audio::NoiseSuppressionMode::Off,
        _ => crate::audio::NoiseSuppressionMode::Nnnoiseless,
    };
    let mut cfg = state.config.lock().await;
    cfg.noise_suppression = Some(mode.clone());
    cfg.save(&state.config_path)?;
    drop(cfg);
    state.voice.cmd_tx.send(VoiceCommand::SetNoiseSuppression(ns as u8)).await
        .map_err(|_| "voice task not running".to_string())?;
    sync_set_and_push(&state, SYNC_KEY_NOISE_SUPPRESSION, mode.as_bytes()).await;
    Ok(())
}

#[tauri::command]
pub async fn set_agc(
    mode: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    use ghost_core::wire::SYNC_KEY_AGC;

    let agc = match mode.as_str() {
        "off" => crate::audio::AgcMode::Off,
        _ => crate::audio::AgcMode::Auto,
    };
    let mut cfg = state.config.lock().await;
    cfg.agc = Some(mode.clone());
    cfg.save(&state.config_path)?;
    drop(cfg);
    state.voice.cmd_tx.send(VoiceCommand::SetAgc(agc as u8)).await
        .map_err(|_| "voice task not running".to_string())?;
    sync_set_and_push(&state, SYNC_KEY_AGC, mode.as_bytes()).await;
    Ok(())
}

#[tauri::command]
pub async fn set_input_mode(
    mode: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    use ghost_core::wire::SYNC_KEY_INPUT_MODE;

    let mode_u8 = match mode.as_str() {
        "voice_activity" => crate::audio::INPUT_MODE_VA,
        "push_to_talk" => crate::audio::INPUT_MODE_PTT,
        _ => return Err(format!("unknown input mode: {mode}")),
    };
    let mut cfg = state.config.lock().await;
    cfg.input_mode = Some(mode.clone());
    cfg.save(&state.config_path)?;
    drop(cfg);
    let _ = state.voice.cmd_tx.send(VoiceCommand::SetInputMode(mode_u8)).await;
    sync_set_and_push(&state, SYNC_KEY_INPUT_MODE, mode.as_bytes()).await;
    Ok(())
}

#[tauri::command]
pub async fn set_ptt_active(
    active: bool,
    state: State<'_, AppState>,
) -> Result<(), String> {
    state
        .voice
        .cmd_tx
        .send(VoiceCommand::SetPttActive(active))
        .await
        .map_err(|_| "voice task not running".to_string())
}

#[tauri::command]
pub async fn set_vad_threshold(
    value: f32,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let clamped = value.clamp(0.0, 1.0);
    let mut cfg = state.config.lock().await;
    cfg.vad_threshold = Some(clamped);
    cfg.save(&state.config_path)?;
    state
        .voice
        .cmd_tx
        .send(VoiceCommand::SetVadThreshold(clamped.to_bits()))
        .await
        .map_err(|_| "voice task not running".to_string())
}

#[tauri::command]
pub async fn set_input_gain(
    value: f32,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let clamped = value.clamp(0.0, 2.0);
    let mut cfg = state.config.lock().await;
    cfg.input_gain = Some(clamped);
    cfg.save(&state.config_path)?;
    state
        .voice
        .cmd_tx
        .send(VoiceCommand::SetInputGain(clamped.to_bits()))
        .await
        .map_err(|_| "voice task not running".to_string())
}

#[tauri::command]
pub async fn get_keybinds(state: State<'_, AppState>) -> Result<KeybindConfigDto, String> {
    let cfg = state.config.lock().await;
    let kb = cfg.keybinds.clone().unwrap_or_default();
    Ok(KeybindConfigDto {
        push_to_talk: kb.push_to_talk,
    })
}

#[tauri::command]
pub async fn set_keybind(
    action: String,
    shortcut: Option<String>,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let mut cfg = state.config.lock().await;
    let kb = cfg.keybinds.get_or_insert_with(KeybindConfig::default);
    match action.as_str() {
        "push_to_talk" => kb.push_to_talk = shortcut,
        _ => return Err(format!("unknown keybind action: {action}")),
    }
    cfg.save(&state.config_path)
}

#[tauri::command]
pub async fn set_status(status: String, state: State<'_, AppState>) -> Result<(), String> {
    use ghost_core::wire::SYNC_KEY_STATUS;

    let os = match status.as_str() {
        "online" => OnlineStatus::Online,
        "idle" => OnlineStatus::Idle,
        "away" => OnlineStatus::Away,
        "invisible" => OnlineStatus::Invisible,
        _ => return Err(format!("unknown status: {status}")),
    };
    let info = {
        let mut p = state.presence.lock().await;
        p.status = os;
        p.clone()
    };
    presence::broadcast_presence(&state.client, &state.relay, &info).await;
    if os != OnlineStatus::Idle {
        let mut cfg = state.config.lock().await;
        cfg.status = Some(status.clone());
        let _ = cfg.save(&state.config_path);
        drop(cfg);
        sync_set_and_push(&state, SYNC_KEY_STATUS, status.as_bytes()).await;
    }
    Ok(())
}

#[tauri::command]
pub async fn set_status_message(
    message: Option<String>,
    expiry: Option<u64>,
    state: State<'_, AppState>,
) -> Result<(), String> {
    use ghost_core::wire::SYNC_KEY_STATUS_MESSAGE;

    let info = {
        let mut p = state.presence.lock().await;
        p.status_message = message.clone();
        p.status_expiry = expiry;
        p.clone()
    };
    presence::broadcast_presence(&state.client, &state.relay, &info).await;
    let mut cfg = state.config.lock().await;
    cfg.status_message = message.clone();
    cfg.status_expiry = expiry;
    let _ = cfg.save(&state.config_path);
    drop(cfg);

    if let Some(ref msg) = message {
        sync_set_and_push(&state, SYNC_KEY_STATUS_MESSAGE, msg.as_bytes()).await;
    } else {
        sync_remove_and_push(&state, SYNC_KEY_STATUS_MESSAGE).await;
    }
    Ok(())
}

// ── Device management ───────────────────────────────────────────────

#[tauri::command]
pub async fn get_devices(state: State<'_, AppState>) -> Result<Vec<DeviceDto>, String> {
    let (account_fp, own_device_vk) = {
        let client = state.client.lock().await;
        (*client.fingerprint(), client.identity().verifying_key.to_bytes())
    };
    let log_state = fetch_and_verify_idlog(&state, &account_fp).await?;
    Ok(log_state
        .devices
        .values()
        .map(|d| DeviceDto {
            device_key: hex::encode(d.verifying_key),
            label: d.label.clone(),
            added_at_seq: d.added_at_seq,
            is_active: d.is_active(),
            is_current: d.verifying_key == own_device_vk,
        })
        .collect())
}

#[tauri::command]
pub async fn revoke_device(
    device_key_hex: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    use ghost_core::identity::log::create_revoke_device;

    let target_key = parse_id(&device_key_hex)?;

    let (account_fp, signing_key_bytes, own_device_vk) = {
        let client = state.client.lock().await;
        (
            *client.fingerprint(),
            client.identity().signing_key.to_bytes(),
            client.identity().verifying_key.to_bytes(),
        )
    };
    if target_key == own_device_vk {
        return Err("cannot revoke current device".into());
    }
    let device_signing_key = ed25519_dalek::SigningKey::from_bytes(&signing_key_bytes);

    let log_state = fetch_and_verify_idlog(&state, &account_fp).await?;

    let revoke_entry = create_revoke_device(&log_state, &device_signing_key, &target_key);
    let payload = revoke_entry.to_bytes();

    {
        let relay = state.relay.lock().await;
        relay.put_idlog_entry(&account_fp, payload).await.map_err(|e| e.to_string())?;
    }

    // Remove from sync MLS group (forward secrecy — revoked device can't decrypt future sync)
    let sync_removal = {
        let mut client = state.client.lock().await;
        if client.has_sync_group() {
            let mb = client.sync_mailbox_id();
            match client.remove_device_from_sync_group(&target_key) {
                Ok(blob) => mb.map(|m| (m, blob)),
                Err(e) => {
                    eprintln!("revoke: failed to remove from sync group: {e}");
                    None
                }
            }
        } else {
            None
        }
    };
    if let Some((sync_mb, commit_blob)) = sync_removal {
        let post_result = {
            let relay = state.relay.lock().await;
            relay.post_blob(&sync_mb, commit_blob).await
        };
        match post_result {
            Ok(_) => {
                let mut client = state.client.lock().await;
                let _ = client.merge_pending_commit_for_sync();
            }
            Err(e) => {
                eprintln!("revoke: sync group POST failed: {e}");
                let mut client = state.client.lock().await;
                let _ = client.clear_pending_commit_for_sync();
            }
        }

        // Rotate sync key so the revoked device can't decrypt future snapshots
        {
            let client_guard = state.client.lock().await;
            if let Ok(new_key) = client_guard.rotate_sync_key() {
                drop(client_guard);
                // Broadcast new key to remaining devices via sync MLS group
                crate::sync_utils::post_sync_message(
                    &state.client,
                    &state.relay,
                    ghost_core::wire::SyncMessageType::SyncKeyRotate as u8,
                    &new_key,
                ).await;
                // Re-encrypt snapshot with new key
                crate::sync_utils::push_sync_snapshot(&state.client, &state.relay).await;
            }
        }
    }

    // Remove leaves via HTTP so we detect epoch conflicts
    let outbound = {
        let mut client = state.client.lock().await;
        client.revoke_device_leaves(&target_key)
    };
    for out in outbound {
        let server_id = {
            let c = state.client.lock().await;
            c.server_id_for_mailbox(&out.mailbox_id)
        };
        let Some(sid) = server_id else { continue };

        let post_result = {
            let relay = state.relay.lock().await;
            relay.post_blob(&out.mailbox_id, out.blob).await
        };
        match post_result {
            Ok(_) => {
                let mut client = state.client.lock().await;
                let _ = client.merge_pending_commit_for_server(&sid);
                if let Ok(gi) = client.export_server_info(&sid) {
                    let relay = state.relay.lock().await;
                    let _ = relay.put_server_info(&out.mailbox_id, gi).await;
                }
            }
            Err(e) => {
                eprintln!("revoke: relay rejected commit for {}: {e}", hex::encode(&sid[..8]));
                let mut client = state.client.lock().await;
                let _ = client.clear_pending_commit_for_server(&sid);
            }
        }
    }

    Ok(())
}

// ── Device pairing ──────────────────────────────────────────────────

fn pairing_seal(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    use aes_gcm::aead::{Aead, AeadCore, OsRng};
    use aes_gcm::{Aes256Gcm, KeyInit};
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ct = cipher.encrypt(&nonce, plaintext)
        .map_err(|e| format!("pairing seal: {e}"))?;
    let mut blob = Vec::with_capacity(12 + ct.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ct);
    Ok(blob)
}

fn pairing_open(key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>, String> {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    if blob.len() < 12 {
        return Err("pairing blob too short".into());
    }
    let nonce = Nonce::from_slice(&blob[..12]);
    let cipher = Aes256Gcm::new(key.into());
    cipher.decrypt(nonce, &blob[12..])
        .map_err(|e| format!("pairing open: {e}"))
}

/// Join a single server via external commit with retries.
/// Posts commits via HTTP (relay WS may not be connected yet), subscribes, uploads
/// GroupInfo, and announces membership. Returns true on success.
async fn rejoin_server(
    state: &AppState,
    relay_url: &str,
    payload: &ghost_core::wire::ProvisionPayload,
    now: u64,
    label: &str,
) -> bool {
    let mailbox_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        &payload.mailbox_id,
    );

    for _ in 0..MAX_REJOIN_ATTEMPTS {
        let si_path = format!("/box/{}/server_info", mailbox_b64);
        let gi_resp = sign_request(state, "GET", &si_path, state.http
            .get(format!("{}{}", relay_url, si_path)))
            .send()
            .await;
        let gi_bytes = match gi_resp {
            Ok(r) if r.status().is_success() => match r.bytes().await {
                Ok(b) => b,
                Err(_) => continue,
            },
            Ok(r) if r.status() == reqwest::StatusCode::NOT_FOUND => break,
            Ok(r) if r.status().is_server_error() => continue,
            Ok(_) => break,
            Err(_) => continue,
        };

        let result = {
            let mut client = state.client.lock().await;
            client.join_from_provision(payload, &gi_bytes, now)
        };

        match result {
            Ok((commit, mailbox_id)) => {
                let commit_seq;
                let box_path = format!("/box/{}", mailbox_b64);
                let resp = sign_request(state, "POST", &box_path, state.http
                    .post(format!("{}{}", relay_url, box_path))
                    .body(commit))
                    .send()
                    .await;
                match resp {
                    Ok(r) if r.status().is_success() => {
                        commit_seq = r.json::<serde_json::Value>().await
                            .ok()
                            .and_then(|v| v["seq"].as_u64())
                            .unwrap_or(0);
                    }
                    Ok(r) => {
                        eprintln!("{label}: relay rejected commit (status {})", r.status());
                        continue;
                    }
                    Err(e) => {
                        eprintln!("{label}: failed to post commit: {e}");
                        continue;
                    }
                }

                {
                    let client = state.client.lock().await;
                    let _ = client.store().set_last_seen_seq(&mailbox_id, commit_seq);
                }
                {
                    let mut relay = state.relay.lock().await;
                    relay.subscribe(mailbox_id, commit_seq);
                }

                // Upload GroupInfo so future joiners see the updated epoch
                {
                    let client = state.client.lock().await;
                    if let Ok(gi) = client.export_server_info(&payload.server_id) {
                        drop(client);
                        let si_put_path = format!("/box/{}/server_info", mailbox_b64);
                        let _ = sign_request(state, "PUT", &si_put_path, state.http
                            .put(format!("{}{}", relay_url, si_put_path))
                            .body(gi))
                            .send()
                            .await;
                    }
                }

                let announce_result = {
                    let mut client = state.client.lock().await;
                    let name = client.identity().display_name.clone();
                    client.send_control(
                        &payload.server_id,
                        ghost_core::wire::encode_member_announce(&name),
                    )
                };
                if let Ok(outbound) = announce_result {
                    let ann_path = format!("/box/{}", mailbox_b64);
                    let _ = sign_request(state, "POST", &ann_path, state.http
                        .post(format!("{}{}", relay_url, ann_path))
                        .body(outbound.blob))
                        .send()
                        .await;
                }

                // Cache identity logs for all group members (warm the AS cache)
                let member_fps = {
                    let client = state.client.lock().await;
                    client.mls_member_fingerprints(&payload.server_id).unwrap_or_default()
                };
                for fp in &member_fps {
                    let _ = fetch_and_verify_idlog(state, fp).await;
                }

                return true;
            }
            Err(e) => {
                eprintln!("{label}: join attempt failed for {}: {e}", hex::encode(&payload.server_id[..8]));
                continue;
            }
        }
    }

    eprintln!("{label}: failed to join server {} after retries", hex::encode(&payload.server_id[..8]));
    false
}

/// Parse and join all servers from a provision blob.
async fn consume_provision(
    state: &AppState,
    relay_url: &str,
    plaintext: &[u8],
) -> Result<(), String> {
    use ghost_core::wire::ProvisionPayload;

    // Parse: [sync_key:32][gi_len:u32][group_info][count:u16][len:u32 + payload]...[sync_dump]
    if plaintext.len() < 38 {
        return Err("provision blob too short".into());
    }

    let sync_key: [u8; 32] = plaintext[..32].try_into().unwrap();
    let gi_len = u32::from_be_bytes(plaintext[32..36].try_into().unwrap()) as usize;
    if plaintext.len() < 36 + gi_len + 2 {
        return Err("provision blob truncated (group info)".into());
    }
    let gi_bytes = &plaintext[36..36 + gi_len];
    let count = u16::from_be_bytes(plaintext[36 + gi_len..38 + gi_len].try_into().unwrap()) as usize;

    let mut pos = 38 + gi_len;
    let mut payloads = Vec::with_capacity(count);
    for _ in 0..count {
        if pos + 4 > plaintext.len() {
            return Err("provision blob truncated".into());
        }
        let len = u32::from_be_bytes(plaintext[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        if pos + len > plaintext.len() {
            return Err("provision payload truncated".into());
        }
        payloads.push(&plaintext[pos..pos + len]);
        pos += len;
    }

    // Store sync_key (used for durable snapshot encryption)
    {
        let client = state.client.lock().await;
        client.set_sync_key(sync_key).map_err(|e| e.to_string())?;
    }

    // Join sync MLS group via external commit
    let (sync_commit, sync_mb) = {
        let mut client = state.client.lock().await;
        client.join_sync_group(gi_bytes).map_err(|e| format!("join sync group: {e}"))?
    };
    {
        let relay = state.relay.lock().await;
        if let Err(e) = relay.post_blob(&sync_mb, sync_commit).await {
            eprintln!("provision: failed to post sync group commit: {e}");
        }
    }

    // Subscribe to sync MLS mailbox
    {
        let client = state.client.lock().await;
        let seq = client.store().get_last_seen_seq(&sync_mb).unwrap_or(0);
        let mut relay = state.relay.lock().await;
        relay.subscribe(sync_mb, seq);
    }

    let now = now_millis();

    for payload_bytes in payloads {
        let payload = ProvisionPayload::from_bytes(payload_bytes).map_err(|e| e.to_string())?;
        if rejoin_server(state, relay_url, &payload, now, "provision").await {
            sync_server_entry(state, &payload.server_id).await;
        }
    }

    // Import sync state if present
    if pos < plaintext.len() {
        if let Ok(sync_entries) = ghost_core::wire::decode_sync_state_dump(&plaintext[pos..]) {
            let settings = crate::sync_utils::parse_sync_entries(&sync_entries);
            let client = state.client.lock().await;
            let _ = client.sync_import(&sync_entries);
            for (cid, read_ts) in &settings.read_marks {
                let _ = client.store().mark_channel_read(cid, *read_ts);
            }
            drop(client);
            let mut cfg = state.config.lock().await;
            crate::sync_utils::apply_sync_to_config(&settings, &mut cfg, &state.config_path);
        }
    }

    Ok(())
}

/// Start pairing: generate secret, post offer, return pairing code.
#[tauri::command]
pub async fn start_pairing(state: State<'_, AppState>) -> Result<String, String> {
    let mut secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret);

    let relay_url = state.relay_url.lock().await.clone();

    // Offer payload: JSON with account config the new device needs
    let (display_name, status_message) = {
        let cfg = state.config.lock().await;
        (cfg.display_name.clone().unwrap_or_default(), cfg.status_message.clone())
    };
    let avatar_hash_hex = {
        let p = state.presence.lock().await;
        p.avatar_hash.map(hex::encode)
    };
    let offer_json = serde_json::json!({
        "relay_url": relay_url,
        "display_name": display_name,
        "avatar_hash": avatar_hash_hex,
        "status_message": status_message,
    });
    let offer_plaintext = serde_json::to_vec(&offer_json).map_err(|e| e.to_string())?;
    let offer_blob = pairing_seal(&secret, &offer_plaintext)?;

    let account_fp = {
        let client = state.client.lock().await;
        *client.fingerprint()
    };

    let relay = state.relay.lock().await;
    relay.post_pairing_offer(&account_fp, offer_blob)
        .await
        .map_err(|e| e.to_string())?;

    let code = format!(
        "{}#{}#{}",
        relay_url,
        hex::encode(account_fp),
        hex::encode(secret),
    );
    *state.pairing_secret.lock().await = Some(zeroize::Zeroizing::new(secret));
    Ok(code)
}

/// Poll for pairing response. Returns the new device label if complete, None if still waiting.
#[tauri::command]
pub async fn check_pairing(state: State<'_, AppState>) -> Result<Option<String>, String> {
    use ghost_core::identity::log::create_add_device;

    let secret = {
        let guard = state.pairing_secret.lock().await;
        match guard.as_deref() {
            Some(s) => *s,
            None => return Err("no active pairing session".into()),
        }
    };

    let account_fp = {
        let client = state.client.lock().await;
        *client.fingerprint()
    };

    let response_blob = {
        let relay = state.relay.lock().await;
        relay.get_pairing_response(&account_fp)
            .await
            .map_err(|e| e.to_string())?
    };

    let response_blob = match response_blob {
        Some(b) => b,
        None => return Ok(None),
    };

    // Decrypt response: [signing_key:32][label_bytes...]
    let plaintext = pairing_open(&secret, &response_blob)?;
    if plaintext.len() < 33 {
        return Err("pairing response too short".into());
    }
    let new_sk_bytes: [u8; 32] = plaintext[..32].try_into().unwrap();
    let new_device_label = String::from_utf8(plaintext[32..].to_vec())
        .map_err(|_| "invalid label in pairing response")?;

    let new_device_key = ed25519_dalek::SigningKey::from_bytes(&new_sk_bytes);

    // Fetch current identity log with KT proof verification
    let log_state = match fetch_and_verify_idlog(&state, &account_fp).await {
        Ok(ls) => ls,
        Err(_) => {
            // Identity log may be empty if relay was restarted — re-push genesis
            let genesis_path = state.config_path.parent()
                .unwrap_or(&state.config_path)
                .join("genesis.pending");
            if let Ok(payload) = std::fs::read(&genesis_path) {
                let relay = state.relay.lock().await;
                relay.put_idlog_entry(&account_fp, payload).await
                    .map_err(|e| format!("re-push genesis: {e}"))?;
            } else {
                return Err("identity log empty on relay and no local genesis available".into());
            }
            fetch_and_verify_idlog(&state, &account_fp).await?
        }
    };

    // Build provision blob BEFORE pushing AddDevice — device B starts
    // fetching provision as soon as it sees AddDevice in the identity log.
    let provision_blob = {
        let client = state.client.lock().await;

        let sync_key = client.sync_key()
            .ok_or_else(|| "sync_key not set — account may not be initialized".to_string())?;

        let gi_bytes = client.sync_group_info()
            .map_err(|e| format!("sync group info: {e}"))?;

        // Export each server's metadata
        let server_mailboxes = client.server_mailboxes();
        let mut payloads: Vec<Vec<u8>> = Vec::new();
        for (sid, _) in &server_mailboxes {
            if let Ok(pp) = client.export_provision_payload(sid) {
                payloads.push(pp.to_bytes());
            }
        }

        // Serialize: [sync_key:32][gi_len:u32][group_info][count:u16][len:u32 + payload]...[sync_dump]
        let mut provision_pt = Vec::new();
        provision_pt.extend_from_slice(&sync_key);
        provision_pt.extend_from_slice(&(gi_bytes.len() as u32).to_be_bytes());
        provision_pt.extend_from_slice(&gi_bytes);
        provision_pt.extend_from_slice(&(payloads.len() as u16).to_be_bytes());
        for p in &payloads {
            provision_pt.extend_from_slice(&(p.len() as u32).to_be_bytes());
            provision_pt.extend_from_slice(p);
        }

        // Append sync_state dump
        let sync_entries = client.sync_dump().unwrap_or_default();
        provision_pt.extend_from_slice(&ghost_core::wire::encode_sync_state_dump(&sync_entries));

        pairing_seal(&secret, &provision_pt)?
    };

    // PUT provision to relay first
    let relay_url = state.relay_url.lock().await.clone();
    let fp_hex = hex::encode(account_fp);
    let prov_path = format!("/pair/{}/provision", fp_hex);
    sign_request(&state, "PUT", &prov_path, state.http
        .put(format!("{}{}", relay_url, prov_path))
        .body(provision_blob))
        .send()
        .await
        .map_err(|e| format!("put provision: {e}"))?
        .error_for_status()
        .map_err(|e| format!("put provision: {e}"))?;

    // Create AddDevice entry (dual-signed) and push AFTER provision is uploaded
    let authorizer_key = {
        let client = state.client.lock().await;
        ed25519_dalek::SigningKey::from_bytes(&client.identity().signing_key.to_bytes())
    };
    let add_entry = create_add_device(&log_state, &authorizer_key, &new_device_key, &new_device_label);
    let payload = add_entry.to_bytes();

    {
        let relay = state.relay.lock().await;
        relay.put_idlog_entry(&account_fp, payload).await.map_err(|e| e.to_string())?;
    }

    // Subscribe to sync MLS mailbox if not already subscribed
    {
        let client = state.client.lock().await;
        if let Some(sync_mb) = client.sync_mailbox_id() {
            let seq = client.store().get_last_seen_seq(&sync_mb).unwrap_or(0);
            let mut relay = state.relay.lock().await;
            relay.subscribe(sync_mb, seq);
        }
    }

    // Zeroizing wrapper handles cleanup on drop
    *state.pairing_secret.lock().await = None;

    Ok(Some(new_device_label))
}

/// Cancel an active pairing session.
#[tauri::command]
pub async fn cancel_pairing(state: State<'_, AppState>) -> Result<(), String> {
    *state.pairing_secret.lock().await = None;
    Ok(())
}

// ── Join as new device ──────────────────────────────────────────────

/// New-device side of pairing: parse code, fetch offer, post response, wait for
/// confirmation, write credentials, hot-swap identity in place.
#[tauri::command]
pub async fn join_as_new_device(
    pairing_code: String,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<String, String> {
    use ghost_core::identity::log::{LogEntry, validate_chain};

    // 1. Parse pairing code: relay_url#account_fp_hex#secret_hex
    let parts: Vec<&str> = pairing_code.splitn(3, '#').collect();
    if parts.len() != 3 {
        return Err("invalid pairing code".into());
    }
    let relay_url = parts[0];
    let account_fp_hex = parts[1];
    let secret_hex = parts[2];

    let account_fp: [u8; 32] = hex::decode(account_fp_hex)
        .map_err(|e| format!("bad fingerprint: {e}"))?
        .try_into()
        .map_err(|_| "fingerprint must be 32 bytes")?;
    let secret: [u8; 32] = hex::decode(secret_hex)
        .map_err(|e| format!("bad secret: {e}"))?
        .try_into()
        .map_err(|_| "secret must be 32 bytes")?;

    let _ = app.emit("link-status", "connecting to relay…");

    // 2. Fetch and decrypt the offer to get account config
    let offer_blob = state
        .http
        .get(format!("{}/pair/{}", relay_url, account_fp_hex))
        .send()
        .await
        .map_err(|e| format!("fetch offer: {e}"))?
        .error_for_status()
        .map_err(|e| format!("fetch offer: {e}"))?
        .bytes()
        .await
        .map_err(|e| format!("read offer: {e}"))?;
    let offer_pt = pairing_open(&secret, &offer_blob)?;
    let offer: serde_json::Value = serde_json::from_slice(&offer_pt)
        .map_err(|e| format!("parse offer: {e}"))?;
    let display_name = offer["display_name"].as_str().unwrap_or("");
    let offer_avatar_hash: Option<[u8; 32]> = offer["avatar_hash"]
        .as_str()
        .and_then(|h| hex::decode(h).ok())
        .and_then(|b| b.try_into().ok());
    let offer_status_message = offer["status_message"].as_str().map(String::from);

    // 3. Generate new device key
    let device_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let device_vk_bytes = device_key.verifying_key().to_bytes();
    let label = crate::setup::device_label();

    let _ = app.emit("link-status", "sending device key…");

    // 4. Encrypt and post response: [signing_key:32][label_bytes]
    let mut response_pt = Vec::with_capacity(32 + label.len());
    response_pt.extend_from_slice(&device_key.to_bytes());
    response_pt.extend_from_slice(label.as_bytes());
    let response_blob = pairing_seal(&secret, &response_pt)?;

    state
        .http
        .post(format!("{}/pair/{}/respond", relay_url, account_fp_hex))
        .body(response_blob)
        .send()
        .await
        .map_err(|e| format!("post pairing response: {e}"))?
        .error_for_status()
        .map_err(|e| format!("post pairing response: {e}"))?;

    let _ = app.emit("link-status", "waiting for other device…");

    // 5. Poll identity log until our device key appears
    for _ in 0..PAIRING_POLL_ATTEMPTS {
        tokio::time::sleep(PAIRING_POLL_INTERVAL).await;

        let resp = state
            .http
            .get(format!("{}/idlog/{}", relay_url, account_fp_hex))
            .send()
            .await
            .map_err(|e| format!("fetch idlog: {e}"))?;
        if !resp.status().is_success() {
            continue;
        }

        let entries: Vec<IdLogEntry> = resp.json().await.map_err(|e| format!("parse idlog: {e}"))?;
        let parsed: std::result::Result<Vec<LogEntry>, _> = entries
            .iter()
            .map(|e| {
                let bytes = base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    &e.payload,
                )
                .map_err(|e| format!("base64: {e}"))?;
                LogEntry::from_bytes(&bytes).map_err(|e| e.to_string())
            })
            .collect();

        if let Ok(log_entries) = parsed {
            if let Ok(log_state) = validate_chain(&log_entries) {
                if log_state.devices.contains_key(&device_vk_bytes) {
                    let _ = app.emit("link-status", "syncing account…");

                    // 6. Write credentials to disk/keyring for next launch
                    let mut db_key = [0u8; 32];
                    let mut mls_db_key = [0u8; 32];
                    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut db_key);
                    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut mls_db_key);

                    let idlog_seq = log_state.devices.get(&device_vk_bytes)
                        .map(|d| d.added_at_seq).unwrap_or(0);
                    write_linked_credentials(
                        &account_fp,
                        &device_key,
                        &db_key,
                        &mls_db_key,
                        idlog_seq,
                    )?;

                    // 7. Delete old DB files
                    crate::setup::wipe_local_databases();

                    // 8. Save config + set presence from offer
                    let relay_url_owned = relay_url.to_string();
                    {
                        let mut cfg = state.config.lock().await;
                        if !display_name.is_empty() {
                            cfg.display_name = Some(display_name.to_string());
                        }
                        cfg.relay_url = Some(relay_url_owned.clone());
                        if let Some(ref sm) = offer_status_message {
                            cfg.status_message = Some(sm.clone());
                        }
                        cfg.save(&state.config_path)?;
                    }
                    {
                        let mut p = state.presence.lock().await;
                        p.avatar_hash = offer_avatar_hash;
                    }

                    // 9. Hot-swap: open new client with linked identity
                    let new_identity = ghost_core::identity::Identity::from_device(
                        account_fp,
                        ed25519_dalek::SigningKey::from_bytes(&device_key.to_bytes()),
                        idlog_seq,
                    );
                    let mut new_client = ghost_core::client::GhostClient::open(
                        new_identity, db_key, mls_db_key, &crate::setup::db_path(),
                    ).map_err(|e| format!("open new client: {e}"))?;
                    if !display_name.is_empty() {
                        new_client.set_display_name(display_name.to_string());
                    }
                    {
                        let mut auth = state.auth.write().unwrap();
                        auth.account_fp = *new_client.fingerprint();
                        auth.device_vk = new_client.verifying_key_bytes();
                        auth.signing_key = new_client.signing_key_clone();
                    }
                    *state.client.lock().await = new_client;

                    // 10. Replace relay
                    let new_inbox_rx = replace_relay(&state, &relay_url_owned).await;

                    // 10b. Fetch provision blob with retries
                    let provision_url = format!("{}/pair/{}/provision", relay_url, account_fp_hex);
                    let mut provision_pt = None;
                    for attempt in 0..MAX_PROVISION_FETCH_ATTEMPTS {
                        if attempt > 0 {
                            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        }
                        match state.http.get(&provision_url).send().await {
                            Ok(resp) if resp.status().is_success() => {
                                match resp.bytes().await {
                                    Ok(enc_blob) => match pairing_open(&secret, &enc_blob) {
                                        Ok(pt) => { provision_pt = Some(pt); break; }
                                        Err(e) => eprintln!("provision decrypt: {e}"),
                                    }
                                    Err(e) => eprintln!("provision read: {e}"),
                                }
                            }
                            Ok(resp) => eprintln!("provision fetch: {}", resp.status()),
                            Err(e) => eprintln!("provision fetch: {e}"),
                        }
                    }

                    if let Some(pt) = provision_pt {
                        consume_provision(&state, relay_url, &pt).await
                            .map_err(|e| format!("provision sync failed: {e}"))?;
                    } else {
                        eprintln!("provision: all retries exhausted, continuing without servers");
                    }

                    // 11. Spawn relay task (subscribes to sync mailbox automatically)
                    spawn_relay_task(app.clone(), &state, new_inbox_rx).await;

                    return Ok(relay_url_owned);
                }
            }
        }
    }

    Err("timed out waiting for device to be added".into())
}

#[cfg(debug_assertions)]
fn write_linked_credentials(
    account_fp: &[u8; 32],
    device_key: &ed25519_dalek::SigningKey,
    db_key: &[u8; 32],
    mls_db_key: &[u8; 32],
    idlog_seq: u64,
) -> Result<(), String> {
    let mut blob = Vec::with_capacity(ghost_core::identity::keyring_store::DEVICE_BLOB_SIZE);
    blob.extend_from_slice(account_fp);
    blob.extend_from_slice(&device_key.to_bytes());
    blob.extend_from_slice(db_key);
    blob.extend_from_slice(mls_db_key);
    blob.extend_from_slice(&idlog_seq.to_be_bytes());
    std::fs::write(crate::setup::device_file(), &blob)
        .map_err(|e| format!("write device.key: {e}"))
}

#[cfg(not(debug_assertions))]
fn write_linked_credentials(
    account_fp: &[u8; 32],
    device_key: &ed25519_dalek::SigningKey,
    db_key: &[u8; 32],
    mls_db_key: &[u8; 32],
    idlog_seq: u64,
) -> Result<(), String> {
    use ghost_core::identity::keyring_store::{self, StoredDevice};
    use ghost_core::crypto::FINGERPRINT_SHORT_BYTES;

    let fp_short = hex::encode(&account_fp[..FINGERPRINT_SHORT_BYTES]);
    let stored = StoredDevice {
        fingerprint: *account_fp,
        signing_key: ed25519_dalek::SigningKey::from_bytes(&device_key.to_bytes()),
        db_key: *db_key,
        mls_db_key: *mls_db_key,
        idlog_seq,
    };
    keyring_store::store(&fp_short, &stored).map_err(|e| format!("keyring store: {e}"))?;
    let fp_file = crate::setup::ghost_dir().join("identity.txt");
    std::fs::write(&fp_file, &fp_short).map_err(|e| format!("write identity.txt: {e}"))
}

// ── Recovery ────────────────────────────────────────────────────────

#[tauri::command]
pub async fn set_recovery_passphrase(
    passphrase: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    use ghost_core::identity::export::export_recovery_blob;

    if passphrase.chars().count() < 12 {
        return Err("passphrase must be at least 12 characters".into());
    }

    let seed = state.recovery_seed.lock().await
        .take()
        .ok_or("recovery seed no longer available — already used or session expired")?;

    let sync_key = {
        let client = state.client.lock().await;
        client.sync_key().ok_or("sync_key not set")?
    };

    let blob = match export_recovery_blob(&*seed, &sync_key, &passphrase) {
        Ok(b) => b,
        Err(e) => {
            // Put seed back so user can retry
            *state.recovery_seed.lock().await = Some(seed);
            return Err(e.to_string());
        }
    };

    let account_fp = {
        let client = state.client.lock().await;
        *client.fingerprint()
    };
    if let Err(e) = {
        let relay = state.relay.lock().await;
        relay.put_recovery_blob(&account_fp, blob).await
    } {
        // Put seed back so user can retry
        *state.recovery_seed.lock().await = Some(seed);
        return Err(e.to_string());
    }
    // seed dropped here — Zeroizing handles cleanup

    let relay_url = state.relay_url.lock().await.clone();
    Ok(format!("{}#{}", relay_url, hex::encode(account_fp)))
}

#[tauri::command]
pub async fn skip_recovery_setup(state: State<'_, AppState>) -> Result<(), String> {
    *state.recovery_seed.lock().await = None;
    Ok(())
}

#[tauri::command]
pub async fn get_recovery_code(state: State<'_, AppState>) -> Result<String, String> {
    let account_fp = {
        let client = state.client.lock().await;
        *client.fingerprint()
    };
    let relay_url = state.relay_url.lock().await.clone();
    Ok(format!("{}#{}", relay_url, hex::encode(account_fp)))
}

#[tauri::command]
pub async fn change_recovery_passphrase(
    current_passphrase: String,
    new_passphrase: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    use ghost_core::identity::export::{import_recovery_blob, export_recovery_blob};

    if new_passphrase.chars().count() < 12 {
        return Err("new passphrase must be at least 12 characters".into());
    }

    let account_fp = {
        let client = state.client.lock().await;
        *client.fingerprint()
    };

    let blob = {
        let relay = state.relay.lock().await;
        relay.get_recovery_blob(&account_fp).await.map_err(|e| e.to_string())?
            .ok_or("no recovery blob found")?
    };

    let recovered = import_recovery_blob(&blob, &current_passphrase).map_err(|e| e.to_string())?;
    // If v1 blob (no sync_key), grab current sync_key for v2 re-export
    let sync_key = match recovered.sync_key {
        Some(k) => k,
        None => {
            let client = state.client.lock().await;
            client.sync_key().ok_or("sync_key not set")?
        }
    };
    let new_blob = export_recovery_blob(&recovered.seed, &sync_key, &new_passphrase)
        .map_err(|e| e.to_string())?;
    drop(recovered);

    {
        let relay = state.relay.lock().await;
        relay.put_recovery_blob(&account_fp, new_blob).await.map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
pub async fn has_recovery_blob(state: State<'_, AppState>) -> Result<bool, String> {
    let account_fp = {
        let client = state.client.lock().await;
        *client.fingerprint()
    };
    let relay = state.relay.lock().await;
    let blob = relay.get_recovery_blob(&account_fp).await.map_err(|e| e.to_string())?;
    Ok(blob.is_some())
}

/// Fetch identity log from relay and validate the hash chain.
async fn fetch_and_validate_idlog(
    http: &reqwest::Client,
    relay_url: &str,
    fp_hex: &str,
) -> Result<(Vec<ghost_core::identity::log::LogEntry>, ghost_core::identity::log::LogState), String> {
    use ghost_core::identity::log::{LogEntry, validate_chain};

    let entries: Vec<IdLogEntry> = http
        .get(format!("{}/idlog/{}", relay_url, fp_hex))
        .send().await.map_err(|e| format!("fetch idlog: {e}"))?
        .error_for_status().map_err(|e| format!("fetch idlog: {e}"))?
        .json().await.map_err(|e| format!("parse idlog: {e}"))?;

    let log_entries: Vec<LogEntry> = entries.iter().map(|e| {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&e.payload).map_err(|e| format!("base64: {e}"))?;
        LogEntry::from_bytes(&bytes).map_err(|e| e.to_string())
    }).collect::<Result<Vec<_>, _>>()?;

    let log_state = validate_chain(&log_entries).map_err(|e| e.to_string())?;
    Ok((log_entries, log_state))
}

/// Rejoin all servers listed in sync state via external commits.
async fn rejoin_servers_from_sync(
    state: &AppState,
    relay_url: &str,
    server_entries: &[([u8; 32], ghost_core::wire::SyncServerMeta)],
    now: u64,
) {
    for (server_id, meta) in server_entries {
        let payload = ghost_core::wire::ProvisionPayload {
            server_id: *server_id,
            server_name: meta.server_name.clone(),
            kind: meta.kind,
            members: Vec::new(),
            channels: meta.channels.clone(),
            mailbox_id: meta.mailbox_id,
        };
        rejoin_server(state, relay_url, &payload, now, "recovery").await;
    }
}

/// Remove revoked device leaves from all MLS groups, with deferred merge.
async fn revoke_old_device_leaves(
    state: &AppState,
    relay_url: &str,
    revoked_keys: &[[u8; 32]],
) {
    for revoked_vk in revoked_keys {
        let outbound = {
            let mut client = state.client.lock().await;
            client.revoke_device_leaves(revoked_vk)
        };
        for out in outbound {
            let sid = {
                let c = state.client.lock().await;
                c.server_id_for_mailbox(&out.mailbox_id)
            };
            let mailbox_b64 = base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                &out.mailbox_id,
            );
            let box_path = format!("/box/{}", mailbox_b64);
            let post_result = sign_request(state, "POST", &box_path, state.http
                .post(format!("{}{}", relay_url, box_path))
                .body(out.blob))
                .send()
                .await;
            match post_result {
                Ok(r) if r.status().is_success() => {
                    if let Some(sid) = sid {
                        let mut client = state.client.lock().await;
                        let _ = client.merge_pending_commit_for_server(&sid);
                        if let Ok(gi) = client.export_server_info(&sid) {
                            drop(client);
                            let si_path = format!("/box/{}/server_info", mailbox_b64);
                            let _ = sign_request(state, "PUT", &si_path, state.http
                                .put(format!("{}{}", relay_url, si_path))
                                .body(gi))
                                .send()
                                .await;
                        }
                    }
                }
                Ok(r) => {
                    eprintln!("recovery: relay rejected revocation commit ({})", r.status());
                    if let Some(sid) = sid {
                        let mut client = state.client.lock().await;
                        let _ = client.clear_pending_commit_for_server(&sid);
                    }
                }
                Err(e) => eprintln!("recovery: failed to post revocation commit: {e}"),
            }
        }
    }
}

#[tauri::command]
pub async fn recover_account(
    recovery_code: String,
    passphrase: String,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<String, String> {
    use ghost_core::identity::export::{import_recovery_blob, export_recovery_blob};
    use ghost_core::identity::log::create_recovery;
    use ghost_core::crypto::keys::derive_ed25519_seed;
    use ghost_core::wire::{SyncServerMeta,
        decode_sync_state_dump, encode_sync_state_dump, sync_open, sync_seal};

    // 1. Parse recovery code: relay_url#fp_hex
    let parts: Vec<&str> = recovery_code.splitn(2, '#').collect();
    if parts.len() != 2 {
        return Err("invalid recovery code".into());
    }
    let relay_url = parts[0];
    let fp_hex = parts[1];

    let account_fp: [u8; 32] = hex::decode(fp_hex)
        .map_err(|e| format!("bad fingerprint: {e}"))?
        .try_into()
        .map_err(|_| "fingerprint must be 32 bytes")?;

    // 2. Fetch and decrypt recovery blob
    let blob_bytes = state.http
        .get(format!("{}/recovery/{}", relay_url, fp_hex))
        .send().await.map_err(|e| format!("fetch recovery blob: {e}"))?
        .error_for_status().map_err(|e| format!("fetch recovery blob: {e}"))?
        .bytes().await.map_err(|e| format!("read recovery blob: {e}"))?;

    let recovered = import_recovery_blob(&blob_bytes, &passphrase).map_err(|e| e.to_string())?;
    let seed = zeroize::Zeroizing::new(recovered.seed);

    // 3. Derive master key and verify fingerprint
    let mut ed_bytes = derive_ed25519_seed(&seed).map_err(|e| e.to_string())?;
    let master_key = ed25519_dalek::SigningKey::from_bytes(&ed_bytes);
    zeroize::Zeroize::zeroize(&mut ed_bytes);
    let expected_fp: [u8; 32] = blake3::hash(master_key.verifying_key().as_bytes()).into();
    if expected_fp != account_fp {
        let mut mk_bytes = master_key.to_bytes();
        drop(master_key);
        zeroize::Zeroize::zeroize(&mut mk_bytes);
        return Err("recovery blob does not match this account".into());
    }

    // 4. Fetch and validate identity log
    let (_log_entries, log_state) = fetch_and_validate_idlog(&state.http, relay_url, fp_hex).await?;

    // 5. Generate new device key + Recovery entry
    let new_device_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let label = crate::setup::device_label();
    let recovery_entry = create_recovery(&log_state, &master_key, &new_device_key, label);
    let mut mk_bytes = master_key.to_bytes();
    drop(master_key);
    zeroize::Zeroize::zeroize(&mut mk_bytes);
    let entry_bytes = recovery_entry.to_bytes();

    // 6. Push Recovery entry to relay
    state.http
        .put(format!("{}/idlog/{}", relay_url, fp_hex))
        .body(entry_bytes)
        .send().await.map_err(|e| format!("push recovery entry: {e}"))?
        .error_for_status().map_err(|e| format!("push recovery entry: {e}"))?;

    // 7. Write credentials for new device
    let mut db_key = [0u8; 32];
    let mut mls_db_key = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut db_key);
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut mls_db_key);

    let recovery_seq = log_state.head_seq + 1;
    write_linked_credentials(&account_fp, &new_device_key, &db_key, &mls_db_key, recovery_seq)?;

    // 8. Delete old DB files
    crate::setup::wipe_local_databases();

    // 9. Set sync_key: from v2 blob or generate random for v1
    let sync_key = match recovered.sync_key {
        Some(k) => k,
        None => {
            let mut k = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut k);
            k
        }
    };

    // 10. Hot-swap client
    let new_identity = ghost_core::identity::Identity::from_device(
        account_fp,
        ed25519_dalek::SigningKey::from_bytes(&new_device_key.to_bytes()),
        recovery_seq,
    );
    let mut new_client = ghost_core::client::GhostClient::open(
        new_identity, db_key, mls_db_key, &crate::setup::db_path(),
    ).map_err(|e| format!("open new client: {e}"))?;
    new_client.set_sync_key(sync_key).map_err(|e| e.to_string())?;
    new_client.create_sync_group().map_err(|e| format!("create sync group: {e}"))?;
    {
        let mut auth = state.auth.write().unwrap();
        auth.account_fp = *new_client.fingerprint();
        auth.device_vk = new_client.verifying_key_bytes();
        auth.signing_key = new_client.signing_key_clone();
    }
    *state.client.lock().await = new_client;

    // 11. Replace relay + save URL in config
    let relay_url_owned = relay_url.to_string();
    let new_inbox_rx = replace_relay(&state, &relay_url_owned).await;
    {
        let mut cfg = state.config.lock().await;
        cfg.relay_url = Some(relay_url_owned.clone());
        let _ = cfg.save(&state.config_path);
    }

    // 12. Fetch and apply sync_state (settings + group list)
    let mut server_entries: Vec<([u8; 32], SyncServerMeta)> = Vec::new();

    if recovered.sync_key.is_some() {
        let entries = async {
            let ss_path = format!("/sync_state/{}", fp_hex);
            let resp = sign_request(&state, "GET", &ss_path, state.http
                .get(format!("{}{}", relay_url, ss_path)))
                .send().await.map_err(|e| format!("fetch: {e}"))?;
            if !resp.status().is_success() {
                return Err(format!("HTTP {}", resp.status()));
            }
            let sealed = resp.bytes().await.map_err(|e| format!("body: {e}"))?;
            let dump_bytes = sync_open(&sync_key, &sealed).map_err(|e| format!("decrypt: {e}"))?;
            decode_sync_state_dump(&dump_bytes).map_err(|e| format!("decode: {e}"))
        }.await;

        if let Ok(entries) = entries {
            let mut settings = crate::sync_utils::parse_sync_entries(&entries);
            server_entries = std::mem::take(&mut settings.server_entries);

            // Import into client (separate lock scope)
            {
                let mut client = state.client.lock().await;
                let _ = client.sync_import(&entries);
                if let Some(ref name) = settings.display_name {
                    client.set_display_name(name.clone());
                }
            }

            // Apply settings to config (separate lock scope)
            {
                let mut cfg = state.config.lock().await;
                crate::sync_utils::apply_sync_to_config(&settings, &mut cfg, &state.config_path);

                // Apply to presence
                let mut p = state.presence.lock().await;
                if let Some(ref status) = cfg.status {
                    p.status = match status.as_str() {
                        "away" => ghost_core::mls::presence::OnlineStatus::Away,
                        "invisible" => ghost_core::mls::presence::OnlineStatus::Invisible,
                        _ => ghost_core::mls::presence::OnlineStatus::Online,
                    };
                }
                p.status_message = cfg.status_message.clone();
            }
        } else if let Err(e) = entries {
            eprintln!("recovery: sync_state failed: {e}");
        }
    }

    // 13. Rejoin groups from sync_state
    rejoin_servers_from_sync(&state, relay_url, &server_entries, now_millis()).await;

    // 13b. Remove old device leaves from groups.
    // log_state is from BEFORE the Recovery entry — all devices that were active
    // at that point are now revoked by the Recovery entry we just pushed.
    let revoked_keys: Vec<[u8; 32]> = log_state.devices.values()
        .filter(|d| d.is_active())
        .map(|d| d.verifying_key)
        .collect();
    revoke_old_device_leaves(&state, relay_url, &revoked_keys).await;

    // 14. Clear old account's recovery seed if present
    *state.recovery_seed.lock().await = None;

    // 15. Re-upload recovery blob as v2 with same passphrase
    let new_blob = export_recovery_blob(&*seed, &sync_key, &passphrase).map_err(|e| e.to_string())?;
    drop(seed);
    {
        let relay = state.relay.lock().await;
        relay.put_recovery_blob(&account_fp, new_blob).await.map_err(|e| e.to_string())?;
    }

    // 16. Push merged sync_state back to relay
    {
        let client = state.client.lock().await;
        let merged = client.sync_dump().unwrap_or_default();
        let dump_blob = encode_sync_state_dump(&merged);
        if let Ok(sealed) = sync_seal(&sync_key, &dump_blob) {
            let relay = state.relay.lock().await;
            let _ = relay.put_sync_state(&account_fp, sealed).await;
        }
    }

    // 17. Spawn relay task (subscribes to sync mailbox automatically)
    spawn_relay_task(app, &state, new_inbox_rx).await;

    Ok(relay_url_owned)
}

#[tauri::command]
pub fn exit_app(app: tauri::AppHandle) {
    app.exit(0);
}

#[tauri::command]
pub fn spawn_dev_instance() -> Result<u32, String> {
    // Grab an OS-assigned free port
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .map_err(|e| format!("find free port: {e}"))?;
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let data_dir = format!("/tmp/ghost-dev-{port}");
    std::fs::create_dir_all(&data_dir).map_err(|e| format!("mkdir: {e}"))?;

    std::process::Command::new("npx")
        .args([
            "tauri", "dev",
            "--config",
            &format!(
                "{{\"identifier\":\"com.ghost.app.dev{port}\",\"build\":{{\"devUrl\":\"http://localhost:{port}\",\"beforeDevCommand\":\"npx vite --port {port}\"}}}}"
            ),
        ])
        .env("GHOST_DATA_DIR", &data_dir)
        .current_dir(
            std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.to_path_buf()))
                .and_then(|d| {
                    let mut cur = d.as_path();
                    while let Some(parent) = cur.parent() {
                        let candidate = parent.join("ghost-app");
                        if candidate.join("package.json").exists() {
                            return Some(candidate);
                        }
                        cur = parent;
                    }
                    None
                })
                .unwrap_or_else(|| std::path::PathBuf::from(".")),
        )
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("spawn: {e}"))?;

    Ok(port as u32)
}
