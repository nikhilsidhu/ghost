use std::time::{SystemTime, UNIX_EPOCH};

use tauri::State;

use crate::dto::{ChannelDto, GroupDto, IdentityDto, MemberDto};
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
