use std::time::{SystemTime, UNIX_EPOCH};

use tauri::State;

use crate::dto::{ChannelDto, GroupDto, IdentityDto, MemberDto, MessageDto};
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
pub fn get_identity(state: State<AppState>) -> Result<IdentityDto, String> {
    let client = state.client.lock().map_err(|e| e.to_string())?;
    Ok(IdentityDto::from(client.identity()))
}

#[tauri::command]
pub fn list_groups(state: State<AppState>) -> Result<Vec<GroupDto>, String> {
    let client = state.client.lock().map_err(|e| e.to_string())?;
    let groups = client.store().list_groups().map_err(|e| e.to_string())?;
    Ok(groups.iter().map(GroupDto::from).collect())
}

#[tauri::command]
pub fn create_group(name: String, state: State<AppState>) -> Result<GroupDto, String> {
    let mut client = state.client.lock().map_err(|e| e.to_string())?;
    let group_id = client
        .create_group(&name, now_millis())
        .map_err(|e| e.to_string())?;
    let group = client
        .store()
        .get_group(&group_id)
        .map_err(|e| e.to_string())?;
    Ok(GroupDto::from(&group))
}

#[tauri::command]
pub fn list_channels(group_id: String, state: State<AppState>) -> Result<Vec<ChannelDto>, String> {
    let gid = parse_id(&group_id)?;
    let client = state.client.lock().map_err(|e| e.to_string())?;
    let channels = client
        .store()
        .list_channels(&gid)
        .map_err(|e| e.to_string())?;
    Ok(channels.iter().map(ChannelDto::from).collect())
}

#[tauri::command]
pub fn list_members(group_id: String, state: State<AppState>) -> Result<Vec<MemberDto>, String> {
    let gid = parse_id(&group_id)?;
    let client = state.client.lock().map_err(|e| e.to_string())?;
    let members = client
        .store()
        .list_members(&gid)
        .map_err(|e| e.to_string())?;
    Ok(members.iter().map(MemberDto::from).collect())
}

#[tauri::command]
pub fn pin_group(group_id: String, state: State<AppState>) -> Result<(), String> {
    let gid = parse_id(&group_id)?;
    let client = state.client.lock().map_err(|e| e.to_string())?;
    client
        .store()
        .pin_group(&gid, now_millis())
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn unpin_group(group_id: String, state: State<AppState>) -> Result<(), String> {
    let gid = parse_id(&group_id)?;
    let client = state.client.lock().map_err(|e| e.to_string())?;
    client
        .store()
        .unpin_group(&gid)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn list_pinned_groups(state: State<AppState>) -> Result<Vec<String>, String> {
    let client = state.client.lock().map_err(|e| e.to_string())?;
    let ids = client
        .store()
        .list_pinned_group_ids()
        .map_err(|e| e.to_string())?;
    Ok(ids.iter().map(hex::encode).collect())
}

#[tauri::command]
pub fn list_messages(
    channel_id: String,
    before: Option<u64>,
    limit: Option<u32>,
    state: State<AppState>,
) -> Result<Vec<MessageDto>, String> {
    let cid = parse_id(&channel_id)?;
    let client = state.client.lock().map_err(|e| e.to_string())?;
    let msgs = client
        .store()
        .get_messages(&cid, before, limit.unwrap_or(50))
        .map_err(|e| e.to_string())?;
    Ok(msgs.iter().map(MessageDto::from).collect())
}

#[tauri::command]
pub fn send_message(
    group_id: String,
    channel_id: String,
    content: String,
    state: State<AppState>,
) -> Result<MessageDto, String> {
    let gid = parse_id(&group_id)?;
    let cid = parse_id(&channel_id)?;
    let mut client = state.client.lock().map_err(|e| e.to_string())?;
    let (_, msg_id) = client
        .send_message(&gid, &cid, content.into_bytes(), vec![], now_millis())
        .map_err(|e| e.to_string())?;
    let stored = client
        .store()
        .get_message(&msg_id)
        .map_err(|e| e.to_string())?;
    Ok(MessageDto::from(&stored))
}
