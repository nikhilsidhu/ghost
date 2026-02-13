use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use rand::RngCore;
use tauri::State;

use ghost_core::storage::{Channel, ChannelKind};

use crate::constants::{DEFAULT_PAGE_SIZE, INVITE_EXPIRY_MS, SEQ_HEADER};
use crate::dto::{ChannelDto, GroupDto, IdentityDto, InviteDto, MemberDto, MessageDto};
use crate::state::AppState;

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn parse_id(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str).map_err(|e| e.to_string())?;
    bytes.try_into().map_err(|_| "invalid 32-byte id".into())
}

#[tauri::command]
pub async fn get_identity(state: State<'_, AppState>) -> Result<IdentityDto, String> {
    let client = state.client.lock().await;
    Ok(IdentityDto::from(client.identity()))
}

#[tauri::command]
pub async fn list_groups(state: State<'_, AppState>) -> Result<Vec<GroupDto>, String> {
    let client = state.client.lock().await;
    let groups = client.store().list_groups().map_err(|e| e.to_string())?;
    Ok(groups.iter().map(GroupDto::from).collect())
}

#[tauri::command]
pub async fn create_group(name: String, state: State<'_, AppState>) -> Result<GroupDto, String> {
    let (group_dto, mailbox_id) = {
        let mut client = state.client.lock().await;
        let group_id = client
            .create_group(&name, now_millis())
            .map_err(|e| e.to_string())?;
        let group = client
            .store()
            .get_group(&group_id)
            .map_err(|e| e.to_string())?;
        let mid = client.mailbox_id_for_group(&group_id);
        (GroupDto::from(&group), mid)
    };

    if let Some(mid) = mailbox_id {
        let mut relay = state.relay.lock().await;
        let _ = relay.subscribe(mid).await;
    }

    Ok(group_dto)
}

#[tauri::command]
pub async fn list_channels(
    group_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<ChannelDto>, String> {
    let gid = parse_id(&group_id)?;
    let client = state.client.lock().await;
    let channels = client
        .store()
        .list_channels(&gid)
        .map_err(|e| e.to_string())?;
    Ok(channels.iter().map(ChannelDto::from).collect())
}

#[tauri::command]
pub async fn list_members(
    group_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<MemberDto>, String> {
    let gid = parse_id(&group_id)?;
    let client = state.client.lock().await;
    let members = client
        .store()
        .list_members(&gid)
        .map_err(|e| e.to_string())?;
    Ok(members.iter().map(MemberDto::from).collect())
}

#[tauri::command]
pub async fn pin_group(group_id: String, state: State<'_, AppState>) -> Result<(), String> {
    let gid = parse_id(&group_id)?;
    let client = state.client.lock().await;
    client
        .store()
        .pin_group(&gid, now_millis())
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn unpin_group(group_id: String, state: State<'_, AppState>) -> Result<(), String> {
    let gid = parse_id(&group_id)?;
    let client = state.client.lock().await;
    client
        .store()
        .unpin_group(&gid)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn list_pinned_groups(state: State<'_, AppState>) -> Result<Vec<String>, String> {
    let client = state.client.lock().await;
    let ids = client
        .store()
        .list_pinned_group_ids()
        .map_err(|e| e.to_string())?;
    Ok(ids.iter().map(hex::encode).collect())
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
    group_id: String,
    channel_id: String,
    content: String,
    state: State<'_, AppState>,
) -> Result<MessageDto, String> {
    let gid = parse_id(&group_id)?;
    let cid = parse_id(&channel_id)?;

    let (outbound, dto) = {
        let mut client = state.client.lock().await;
        let (outbound, msg_id) = client
            .send_message(&gid, &cid, content.into_bytes(), vec![], now_millis())
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
    group_id: String,
    name: String,
    kind: String,
    state: State<'_, AppState>,
) -> Result<ChannelDto, String> {
    let gid = parse_id(&group_id)?;
    let mut channel_id = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut channel_id);
    let kind = match kind.as_str() {
        "voice" => ChannelKind::Voice,
        _ => ChannelKind::Text,
    };
    let client = state.client.lock().await;
    let position = client
        .store()
        .list_channels(&gid)
        .map_err(|e| e.to_string())?
        .len() as i32;
    let channel = Channel {
        channel_id,
        group_id: gid,
        name,
        kind,
        position,
    };
    client
        .store()
        .insert_channel(&channel)
        .map_err(|e| e.to_string())?;
    Ok(ChannelDto::from(&channel))
}

#[tauri::command]
pub async fn rename_channel(
    channel_id: String,
    name: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let cid = parse_id(&channel_id)?;
    let client = state.client.lock().await;
    client
        .store()
        .rename_channel(&cid, &name)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn delete_channel(
    channel_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let cid = parse_id(&channel_id)?;
    let client = state.client.lock().await;
    client
        .store()
        .delete_channel(&cid)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn create_invite(
    group_id: String,
    state: State<'_, AppState>,
) -> Result<InviteDto, String> {
    let gid = parse_id(&group_id)?;

    let (token, payload_bytes) = {
        let client = state.client.lock().await;
        client.create_invite(&gid).map_err(|e| e.to_string())?
    };

    let expires_at = now_millis() + INVITE_EXPIRY_MS;
    state
        .http
        .post(format!("{}/invite", state.relay_url))
        .json(&serde_json::json!({ "token": token, "expires_at": expires_at }))
        .send()
        .await
        .map_err(|e| format!("register invite: {e}"))?
        .error_for_status()
        .map_err(|e| format!("register invite: {e}"))?;

    state
        .http
        .post(format!("{}/invite/{}/join", state.relay_url, token))
        .header(SEQ_HEADER, "0")
        .body(payload_bytes)
        .send()
        .await
        .map_err(|e| format!("upload invite payload: {e}"))?
        .error_for_status()
        .map_err(|e| format!("upload invite payload: {e}"))?;

    let mut link = url::Url::parse("ghost://join").expect("valid base URL");
    link.query_pairs_mut()
        .append_pair("relay", &state.relay_url)
        .append_pair("token", &token);
    let link = link.to_string();

    Ok(InviteDto { token, link })
}

#[tauri::command]
pub async fn join_by_invite(
    relay_url: String,
    token: String,
    state: State<'_, AppState>,
) -> Result<GroupDto, String> {
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

    let (group_id, commit_bytes, mailbox_id) = {
        let mut client = state.client.lock().await;
        client
            .join_by_invite(&payload_bytes, now_millis())
            .map_err(|e| e.to_string())?
    };

    // Broadcast the external commit so existing members see us
    let mailbox_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mailbox_id);
    state
        .http
        .post(format!("{}/box/{}", relay_url, mailbox_b64))
        .body(commit_bytes)
        .send()
        .await
        .map_err(|e| format!("broadcast commit: {e}"))?
        .error_for_status()
        .map_err(|e| format!("broadcast commit: {e}"))?;

    // Refresh the invite payload with fresh GroupInfo for the next joiner
    let updated_payload = {
        let client = state.client.lock().await;
        client
            .refresh_invite_payload(&group_id)
            .map_err(|e| e.to_string())?
    };

    let resp = state
        .http
        .post(format!("{}/invite/{}/join", relay_url, token))
        .header(SEQ_HEADER, seq.to_string())
        .body(updated_payload)
        .send()
        .await
        .map_err(|e| format!("refresh invite: {e}"))?;

    if !resp.status().is_success() && resp.status() != reqwest::StatusCode::CONFLICT {
        return Err(format!("refresh invite: HTTP {}", resp.status()));
    }

    // Subscribe to the new group's mailbox for real-time messages
    {
        let mut relay = state.relay.lock().await;
        let _ = relay.subscribe(mailbox_id).await;
    }

    let client = state.client.lock().await;
    let group = client
        .store()
        .get_group(&group_id)
        .map_err(|e| e.to_string())?;
    Ok(GroupDto::from(&group))
}
