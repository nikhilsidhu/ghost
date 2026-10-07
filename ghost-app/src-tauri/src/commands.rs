use base64::Engine;
use ed25519_dalek::SigningKey;
use rand::RngCore;
use tauri::{Emitter, State};

use ghost_core::client::GhostClient;
use ghost_core::flows;
use ghost_core::flows::pairing::{PairingCode, PairingOffer};
use ghost_core::flows::recovery::RecoveryCode;
use ghost_core::flows::sync::SyncSettings;
use ghost_core::relay::RelayClient;
use ghost_core::storage::{Channel, ChannelKind, ServerKind};
use ghost_core::wire::{
    encode_avatar_clear, encode_avatar_update, encode_channel_op, encode_member_announce,
    ChannelOpPayload, SyncMessageType,
};

use ghost_core::mls::presence::OnlineStatus;

use crate::constants::{DEFAULT_PAGE_SIZE, INVITE_EXPIRY_MS};
use crate::config::KeybindConfig;
use crate::dto::{
    AssignmentDto, ChannelAccessDto, ChannelDto, ConfigDto, DeviceDto, IdentityDto, InviteDto, KeybindConfigDto,
    MemberDto, MessageDto, PolicyDto, RoleDto, ServerDto, ServerRolesDto,
};
use ghost_wire::policy::{ChannelPolicy, Role, ServerPolicy, MANAGE_CHANNELS};
use crate::presence;
use crate::state::{AppState, now_millis};
use crate::voice_task::VoiceCommand;

fn parse_id(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str).map_err(|e| e.to_string())?;
    bytes.try_into().map_err(|_| "invalid 32-byte id".into())
}

/// Refuse early, with a clear message, what every member's device would ignore anyway.
fn require_permission(client: &GhostClient, server_id: &[u8; 32], permission: u32, what: &str) -> Result<(), String> {
    let policy = client.server_policy(server_id).map_err(|e| e.to_string())?;
    if policy.has(client.fingerprint(), permission) {
        Ok(())
    } else {
        Err(format!("{what} needs a permission you do not have"))
    }
}

/// A client for the relay hosting the server, or `None` when it is the home relay.
async fn hosting_relay(state: &AppState, server_id: &[u8; 32]) -> Option<tokio::sync::Mutex<RelayClient>> {
    let url = {
        let client = state.client.lock().await;
        flows::server_relay_url(&client, server_id)
    }?;
    Some(tokio::sync::Mutex::new(state.relay.lock().await.at(&url)))
}

/// Abort the running relay task, create a fresh relay client, and swap it into state.
async fn replace_relay(
    state: &AppState,
    relay_url: &str,
) -> tokio::sync::mpsc::Receiver<ghost_core::relay::RelayEvent> {
    if let Some(handle) = state.relay_task_handle.lock().await.take() {
        handle.abort();
    }
    let (mut new_relay, inbox_rx) = RelayClient::new(relay_url);
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

/// Replace the running identity after linking or recovery: install the new client,
/// refresh the auth material relay clients are built from, and rebuild the relay client.
async fn install_identity(
    state: &AppState,
    new_client: GhostClient,
    relay_url: &str,
) -> tokio::sync::mpsc::Receiver<ghost_core::relay::RelayEvent> {
    {
        let mut auth = state.auth.write().unwrap();
        auth.account_fp = *new_client.fingerprint();
        auth.device_vk = new_client.verifying_key_bytes();
        auth.signing_key = new_client.signing_key_clone();
    }
    *state.client.lock().await = new_client;
    replace_relay(state, relay_url).await
}

/// Persist settings restored from a sync snapshot into config, and optionally presence.
async fn apply_restored_settings(state: &AppState, settings: &SyncSettings, update_presence: bool) {
    let mut cfg = state.config.lock().await;
    crate::sync_utils::apply_sync_to_config(settings, &mut cfg, &state.config_path);
    if update_presence {
        let mut p = state.presence.lock().await;
        crate::sync_utils::apply_config_to_presence(&cfg, &mut p);
    }
}

fn same_relay(a: &str, b: &str) -> bool {
    a.trim_end_matches('/') == b.trim_end_matches('/')
}

const PAIRING_POLL_ATTEMPTS: usize = 90;
const PAIRING_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);
const MAX_PROVISION_FETCH_ATTEMPTS: usize = 5;
const PROVISION_FETCH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

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
        .map(|s| ServerDto::from_server(s, unread_servers.contains(&s.server_id), &client))
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
        (ServerDto::from_server(&server, false, &client), server_id, mid)
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

    flows::sync::post_server_provisioned(&state.client, &state.relay, &server_id).await;
    flows::sync::server_entry(&state.client, &state.relay, &server_id).await;
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
        .map(|c| ChannelDto::from_channel(c, unread_map.get(&c.channel_id).copied().unwrap_or(0), client.is_private_channel(&c.channel_id)))
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
    let policy = client.server_policy(&sid).ok();
    Ok(members
        .iter()
        .map(|m| {
            // In rank order, which is the order the policy lists roles in.
            let roles = policy.as_ref().map_or_else(Vec::new, |p| {
                let assigned = p.roles_of(&m.fingerprint);
                p.roles.iter().filter(|r| assigned.contains(&r.id)).map(|r| r.id).collect()
            });
            MemberDto::from_member(m, roles)
        })
        .collect())
}

#[tauri::command]
pub async fn save_server_order(order: Vec<String>, state: State<'_, AppState>) -> Result<(), String> {
    let value = serde_json::to_vec(&order).map_err(|e| e.to_string())?;
    flows::sync::set_and_push(&state.client, &state.relay, ghost_core::wire::SYNC_KEY_SERVER_ORDER, &value).await;
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

    // A private channel must be rid of members who lost access before anything is sent.
    flows::channels::remove_excluded(&state.client, &state.relay, &cid)
        .await
        .map_err(|e| e.to_string())?;

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
        require_permission(&client, &sid, MANAGE_CHANNELS, "creating channels")?;
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

    flows::sync::server_entry(&state.client, &state.relay, &sid).await;

    let client = state.client.lock().await;
    let channel = client.store().get_channel(&channel_id).map_err(|e| e.to_string())?;
    Ok(ChannelDto::from_channel(&channel, 0, false))
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
        require_permission(&client, &sid, MANAGE_CHANNELS, "renaming channels")?;
        client
            .store()
            .rename_channel(&cid, &name)
            .map_err(|e| e.to_string())?;

        // A private channel's name is only ever sent inside its own group.
        let op = encode_channel_op(&ChannelOpPayload::Rename { channel_id: cid, name });
        let out = if client.is_private_channel(&cid) {
            client.send_control_in(&cid, op)
        } else {
            client.send_control(&sid, op)
        }
        .map_err(|e| e.to_string())?;
        (out, sid)
    };

    let relay = state.relay.lock().await;
    let _ = relay.send(&outbound.mailbox_id, outbound.blob).await;
    drop(relay);

    flows::sync::server_entry(&state.client, &state.relay, &sid).await;
    Ok(())
}

#[tauri::command]
pub async fn delete_channel(
    channel_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let cid = parse_id(&channel_id)?;

    let (outbound, sid, private_mailbox) = {
        let mut client = state.client.lock().await;
        let channel = client.store().get_channel(&cid).map_err(|e| e.to_string())?;
        let sid = channel.server_id;
        require_permission(&client, &sid, MANAGE_CHANNELS, "deleting channels")?;

        let op = encode_channel_op(&ChannelOpPayload::Delete { channel_id: cid });
        if client.is_private_channel(&cid) {
            // Members drop it on reading this inside its group; then the group goes.
            let mailbox_id = client.mailbox_id_for_channel(&cid);
            let out = client.send_control_in(&cid, op).map_err(|e| e.to_string())?;
            client.drop_private_channel(&cid).map_err(|e| e.to_string())?;
            (out, sid, mailbox_id)
        } else {
            client.store().delete_channel(&cid).map_err(|e| e.to_string())?;
            (client.send_control(&sid, op).map_err(|e| e.to_string())?, sid, None)
        }
    };

    let relay = state.relay.lock().await;
    let _ = relay.send(&outbound.mailbox_id, outbound.blob).await;
    drop(relay);
    if let Some(mailbox_id) = private_mailbox {
        let mut relay = state.relay.lock().await;
        relay.unsubscribe(&mailbox_id);
        if let Err(e) = relay.delete_mailbox(&mailbox_id).await {
            eprintln!("delete private channel mailbox: {e}");
        }
    }

    flows::sync::server_entry(&state.client, &state.relay, &sid).await;
    Ok(())
}

/// Create a private channel admitting the given roles and accounts (and always the
/// server's channel managers). Members it does not admit never learn it exists.
#[tauri::command]
pub async fn create_private_channel(
    server_id: String,
    name: String,
    kind: String,
    roles: Vec<u8>,
    accounts: Vec<String>,
    state: State<'_, AppState>,
) -> Result<ChannelDto, String> {
    let sid = parse_id(&server_id)?;
    let kind = match kind.as_str() {
        "voice" => ChannelKind::Voice,
        _ => ChannelKind::Text,
    };
    let accounts = accounts.iter().map(|a| parse_id(a)).collect::<Result<Vec<_>, _>>()?;
    let hosting = hosting_relay(&state, &sid).await;
    let relay = hosting.as_ref().unwrap_or(&state.relay);
    let channel_id = flows::channels::create_private(&state.client, &state.relay, relay, &sid, &name, kind, roles, accounts)
        .await
        .map_err(|e| e.to_string())?;
    let client = state.client.lock().await;
    let channel = client.store().get_channel(&channel_id).map_err(|e| e.to_string())?;
    Ok(ChannelDto::from_channel(&channel, 0, true))
}

/// Who a private channel admits; `None` for a public channel.
#[tauri::command]
pub async fn get_channel_access(channel_id: String, state: State<'_, AppState>) -> Result<Option<ChannelAccessDto>, String> {
    let cid = parse_id(&channel_id)?;
    let client = state.client.lock().await;
    let policy = client.channel_policy(&cid).map_err(|e| e.to_string())?;
    Ok(policy.map(|p| ChannelAccessDto { roles: p.roles, accounts: p.accounts.iter().map(hex::encode).collect() }))
}

/// Change whom a private channel admits. Members it no longer admits are removed.
#[tauri::command]
pub async fn set_channel_access(channel_id: String, access: ChannelAccessDto, state: State<'_, AppState>) -> Result<(), String> {
    let cid = parse_id(&channel_id)?;
    let current = {
        let client = state.client.lock().await;
        client.channel_policy(&cid).map_err(|e| e.to_string())?.ok_or("not a private channel")?
    };
    let accounts = access.accounts.iter().map(|a| parse_id(a)).collect::<Result<Vec<_>, _>>()?;
    let policy = ChannelPolicy { roles: access.roles, accounts, ..current };
    flows::channels::set_policy(&state.client, &state.relay, &cid, &policy)
        .await
        .map_err(|e| e.to_string())
}

/// A server's roles, assignments and what everyone may do, with role names.
#[tauri::command]
pub async fn get_server_roles(server_id: String, state: State<'_, AppState>) -> Result<ServerRolesDto, String> {
    let sid = parse_id(&server_id)?;
    let client = state.client.lock().await;
    let policy = client.server_policy(&sid).map_err(|e| e.to_string())?;
    let names: std::collections::HashMap<u8, String> =
        client.store().list_role_names(&sid).map_err(|e| e.to_string())?.into_iter().collect();
    let explicit = client.server_policy_is_explicit(&sid).map_err(|e| e.to_string())?;
    let missing = client.members_missing_policy_support(&sid).map_err(|e| e.to_string())?;
    Ok(ServerRolesDto {
        my_permissions: policy.permissions(client.fingerprint()),
        policy: PolicyDto {
            owner_fp: hex::encode(policy.owner),
            everyone: policy.everyone,
            roles: policy
                .roles
                .iter()
                .map(|r| RoleDto { id: r.id, name: names.get(&r.id).cloned().unwrap_or_default(), permissions: r.permissions })
                .collect(),
            assignments: policy
                .assignments
                .iter()
                .map(|(account, roles)| AssignmentDto { fingerprint: hex::encode(account), roles: roles.clone() })
                .collect(),
        },
        explicit,
        members_missing_support: missing.iter().map(hex::encode).collect(),
    })
}

/// Replace a server's roles, assignments, everyone permissions or owner, then send the
/// names of roles that are new or renamed. The relay and every member check the change.
#[tauri::command]
pub async fn set_server_roles(server_id: String, policy: PolicyDto, state: State<'_, AppState>) -> Result<(), String> {
    let sid = parse_id(&server_id)?;
    let new_policy = ServerPolicy {
        owner: parse_id(&policy.owner_fp)?,
        everyone: policy.everyone,
        roles: policy.roles.iter().map(|r| Role { id: r.id, permissions: r.permissions }).collect(),
        assignments: policy
            .assignments
            .iter()
            .filter(|a| !a.roles.is_empty())
            .map(|a| Ok((parse_id(&a.fingerprint)?, a.roles.clone())))
            .collect::<Result<Vec<_>, String>>()?,
    };
    flows::roles::set_server_policy(&state.client, &state.relay, &sid, &new_policy)
        .await
        .map_err(|e| e.to_string())?;

    let renamed: Vec<(u8, String)> = {
        let client = state.client.lock().await;
        let known: std::collections::HashMap<u8, String> =
            client.store().list_role_names(&sid).map_err(|e| e.to_string())?.into_iter().collect();
        policy
            .roles
            .iter()
            .filter(|r| known.get(&r.id) != Some(&r.name))
            .map(|r| (r.id, r.name.clone()))
            .collect()
    };
    for (role_id, name) in renamed {
        let out = {
            let mut client = state.client.lock().await;
            client.name_role(&sid, role_id, &name).map_err(|e| e.to_string())?
        };
        let relay = state.relay.lock().await;
        relay.send(&out.mailbox_id, out.blob).await.map_err(|e| e.to_string())?;
    }
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

    let accepted = flows::members::kick(&state.client, &state.relay, &sid, &fp)
        .await
        .map_err(|e| e.to_string())?;
    let _ = app.emit("sync", hex::encode(sid));
    if !accepted {
        return Err("the relay rejected the kick (the server changed meanwhile); try again".into());
    }
    Ok(())
}

#[tauri::command]
pub async fn mark_channel_read(
    channel_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let cid = parse_id(&channel_id)?;
    let ts = now_millis();
    let key = format!("{}{}", ghost_core::wire::SYNC_KEY_READ_PREFIX, channel_id);
    {
        let client = state.client.lock().await;
        client.store().mark_channel_read(&cid, ts).map_err(|e| e.to_string())?;
    }
    flows::sync::set_and_push(&state.client, &state.relay, &key, &ts.to_be_bytes()).await;
    Ok(())
}

#[tauri::command]
pub async fn create_invite(
    server_id: String,
    state: State<'_, AppState>,
) -> Result<InviteDto, String> {
    let sid = parse_id(&server_id)?;
    // Invite tokens live on the relay hosting the server, which joiners will contact.
    let hosting_url = {
        let client = state.client.lock().await;
        flows::server_relay_url(&client, &sid)
    };
    let hosting = match hosting_url {
        Some(url) => Some(tokio::sync::Mutex::new(state.relay.lock().await.at(&url))),
        None => None,
    };
    let relay = hosting.as_ref().unwrap_or(&state.relay);
    let created = flows::invite::create(&state.client, relay, &sid, now_millis() + INVITE_EXPIRY_MS)
        .await
        .map_err(|e| e.to_string())?;

    let mut link = url::Url::parse("ghost://join").expect("valid base URL");
    link.query_pairs_mut()
        .append_pair("relay", &created.relay_url)
        .append_pair("r", &created.relay_ref.encode())
        .append_pair("token", &created.token)
        .append_pair("k", &hex::encode(created.key));

    Ok(InviteDto { token: created.token, link: link.to_string() })
}

/// Move a server this account created to the relay at `relay_url` (normally this
/// account's home). Returns a move link to share with members who cannot reach the
/// old relay any more.
#[tauri::command]
pub async fn move_server(server_id: String, relay_url: String, state: State<'_, AppState>) -> Result<String, String> {
    let sid = parse_id(&server_id)?;
    let location = flows::server::move_server(&state.client, &state.relay, &sid, &relay_url)
        .await
        .map_err(|e| e.to_string())?;
    Ok(flows::server::move_link(&location))
}

/// Follow a server move from a link the server's creator shared.
#[tauri::command]
pub async fn follow_server_move(link: String, state: State<'_, AppState>) -> Result<bool, String> {
    let location = flows::server::parse_move_link(&link).map_err(|e| e.to_string())?;
    flows::server::follow_move(&state.client, &state.relay, &location.server_id, &location)
        .await
        .map_err(|e| e.to_string())
}

/// Join a server through an invite. The server may live on the home relay or any
/// other; `relay_ref`, when the link carries one, pins the relay's key so a link
/// pointing at the wrong relay fails instead of joining it.
#[tauri::command]
pub async fn join_by_invite(
    relay_url: String,
    token: String,
    key: String,
    relay_ref: Option<String>,
    state: State<'_, AppState>,
) -> Result<ServerDto, String> {
    let key = parse_id(&key).map_err(|_| "the invite link's key is malformed".to_string())?;
    let configured = state.relay_url.lock().await.clone();
    // A view of the home client: subscriptions on another relay join the same event stream.
    let target = if same_relay(&relay_url, &configured) {
        None
    } else {
        Some(tokio::sync::Mutex::new(state.relay.lock().await.at(&relay_url)))
    };
    let relay = target.as_ref().unwrap_or(&state.relay);

    if let Some(encoded) = relay_ref {
        let expected = ghost_wire::relay_ref::RelayRef::decode(&encoded).map_err(|e| e.to_string())?;
        let actual = relay.lock().await.get_relay_info().await.map_err(|e| e.to_string())?;
        if actual.relay_vk != expected.relay_vk {
            return Err(format!("the relay at {relay_url} is not the relay this invite was issued by"));
        }
    }

    let server_id = flows::invite::join(&state.client, &state.relay, relay, &token, &key, now_millis())
        .await
        .map_err(|e| e.to_string())?;

    let client = state.client.lock().await;
    let server = client
        .store()
        .get_server(&server_id)
        .map_err(|e| e.to_string())?;
    Ok(ServerDto::from_server(&server, false, &client))
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

    flows::sync::set_and_push(&state.client, &state.relay, SYNC_KEY_DISPLAY_NAME, name.as_bytes()).await;
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
    // Voice runs on the relay hosting the server, which may not be the home relay.
    let (fingerprint, hosting_relay_url) = {
        let client = state.client.lock().await;
        let server = parse_id(&server_id)?;
        (hex::encode(client.fingerprint()), flows::server_relay_url(&client, &server))
    };
    let default_relay_url = state.relay_url.lock().await.clone();
    let (relay_url, input_device, output_device, ns_mode, agc_mode, vad_threshold, input_gain, input_mode) = {
        let cfg = state.config.lock().await;
        let url = hosting_relay_url.unwrap_or_else(|| {
            cfg.relay_url
                .as_deref()
                .filter(|u| !u.is_empty())
                .map(String::from)
                .unwrap_or(default_relay_url)
        });
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
    flows::sync::post_message(&state.client, &state.relay, SyncMessageType::VoiceTakeover, &channel_id_bytes).await;

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
    flows::sync::set_and_push(&state.client, &state.relay, SYNC_KEY_NOISE_SUPPRESSION, mode.as_bytes()).await;
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
    flows::sync::set_and_push(&state.client, &state.relay, SYNC_KEY_AGC, mode.as_bytes()).await;
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
    flows::sync::set_and_push(&state.client, &state.relay, SYNC_KEY_INPUT_MODE, mode.as_bytes()).await;
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
        flows::sync::set_and_push(&state.client, &state.relay, SYNC_KEY_STATUS, status.as_bytes()).await;
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
        flows::sync::set_and_push(&state.client, &state.relay, SYNC_KEY_STATUS_MESSAGE, msg.as_bytes()).await;
    } else {
        flows::sync::remove_and_push(&state.client, &state.relay, SYNC_KEY_STATUS_MESSAGE).await;
    }
    Ok(())
}

// ── Device management ───────────────────────────────────────────────

#[tauri::command]
pub async fn get_devices(state: State<'_, AppState>) -> Result<Vec<DeviceDto>, String> {
    let own_device_vk = {
        let client = state.client.lock().await;
        client.identity().verifying_key.to_bytes()
    };
    let log_state = flows::devices::list(&state.client, &state.relay)
        .await
        .map_err(|e| e.to_string())?;
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

/// Revoke a device. Returns false when the device is out of every group but the home
/// relay was unreachable, so the identity log entry still has to be retried.
#[tauri::command]
pub async fn revoke_device(
    device_key_hex: String,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let target_key = parse_id(&device_key_hex)?;
    let outcome = flows::devices::revoke(&state.client, &state.relay, &target_key)
        .await
        .map_err(|e| e.to_string())?;
    Ok(outcome == flows::devices::RevokeOutcome::Complete)
}

// ── Device pairing ──────────────────────────────────────────────────

/// Start pairing: post a sealed offer and return the code the new device scans.
#[tauri::command]
pub async fn start_pairing(state: State<'_, AppState>) -> Result<String, String> {
    let relay_url = state.relay_url.lock().await.clone();
    let (display_name, status_message) = {
        let cfg = state.config.lock().await;
        (cfg.display_name.clone().unwrap_or_default(), cfg.status_message.clone())
    };
    let avatar_hash = {
        let p = state.presence.lock().await;
        p.avatar_hash.map(hex::encode)
    };
    let offer = PairingOffer { relay_url, display_name, avatar_hash, status_message };

    let code = flows::pairing::start(&state.client, &state.relay, &offer)
        .await
        .map_err(|e| e.to_string())?;
    let encoded = code.encode();
    *state.pairing_code.lock().await = Some(code);
    Ok(encoded)
}

/// Poll for the new device's response. Returns its label once linked, `None` while waiting.
#[tauri::command]
pub async fn check_pairing(app: tauri::AppHandle, state: State<'_, AppState>) -> Result<Option<String>, String> {
    let code = state
        .pairing_code
        .lock()
        .await
        .clone()
        .ok_or_else(|| "no active pairing session".to_string())?;

    // genesis.pending lets the flow re-push the account's genesis if the relay lost its log.
    let genesis = std::fs::read(crate::setup::genesis_pending_path()).ok();
    // Pairing runs on the home relay, so it is also the rendezvous.
    let linked = flows::pairing::check(&state.client, &state.relay, &state.relay, &code, genesis.as_deref())
        .await
        .map_err(|e| e.to_string())?;
    let Some(label) = linked else { return Ok(None) };

    // Restart the relay task so the sync mailbox created during pairing is part of its loop.
    let relay_url = state.relay_url.lock().await.clone();
    let new_inbox_rx = replace_relay(&state, &relay_url).await;
    *state.pairing_code.lock().await = None;
    spawn_relay_task(app, &state, new_inbox_rx).await;

    Ok(Some(label))
}

/// Cancel an active pairing session.
#[tauri::command]
pub async fn cancel_pairing(state: State<'_, AppState>) -> Result<(), String> {
    *state.pairing_code.lock().await = None;
    Ok(())
}

// ── Join as new device ──────────────────────────────────────────────

/// New-device side of pairing: fetch the offer, hand over a fresh device key, wait for the
/// identity log to list it, fetch the provision, then replace the local identity in place.
#[tauri::command]
pub async fn join_as_new_device(
    pairing_code: String,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let code = PairingCode::parse(&pairing_code).map_err(|e| e.to_string())?;

    let _ = app.emit("link-status", "connecting to relay…");
    // The new device has no identity on this relay yet, so the client is unauthenticated.
    let (guest_relay, _unused_events) = RelayClient::new(&code.relay_url);
    let offer = flows::pairing::fetch_offer(&guest_relay, &code).await.map_err(|e| e.to_string())?;

    let device_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let device_vk = device_key.verifying_key().to_bytes();
    let label = crate::setup::device_label();

    let _ = app.emit("link-status", "sending device key…");
    flows::pairing::respond(&guest_relay, &code, &device_key, label).await.map_err(|e| e.to_string())?;

    let _ = app.emit("link-status", "waiting for other device…");
    let log_state = flows::pairing::wait_for_device(
        &guest_relay, &code.account_fp, &device_key, PAIRING_POLL_ATTEMPTS, PAIRING_POLL_INTERVAL,
    ).await.map_err(|e| e.to_string())?;

    let _ = app.emit("link-status", "syncing account…");
    let blob = flows::pairing::fetch_provision(
        &guest_relay, &code, MAX_PROVISION_FETCH_ATTEMPTS, PROVISION_FETCH_INTERVAL,
    ).await.map_err(|e| e.to_string())?;

    // The pairing code may name any relay the account uses; the identity log names the home.
    let home_url = log_state
        .home_relay_ref
        .as_ref()
        .and_then(|r| r.primary_https_url())
        .unwrap_or(&code.relay_url)
        .to_string();

    // From here on the steps are irreversible: credentials written, old databases removed.
    let mut db_key = [0u8; 32];
    let mut mls_db_key = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut db_key);
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut mls_db_key);
    let idlog_seq = log_state.devices.get(&device_vk).map(|d| d.added_at_seq).unwrap_or(0);
    write_linked_credentials(
        &code.account_fp,
        &device_key,
        &db_key,
        &mls_db_key,
        idlog_seq,
        &blob.master_vk,
        &SigningKey::from_bytes(&blob.master_sk),
        &blob.delegation_sig,
    )?;
    crate::setup::wipe_local_databases();

    {
        let mut cfg = state.config.lock().await;
        if !offer.display_name.is_empty() {
            cfg.display_name = Some(offer.display_name.clone());
        }
        cfg.relay_url = Some(home_url.clone());
        if let Some(ref sm) = offer.status_message {
            cfg.status_message = Some(sm.clone());
        }
        cfg.save(&state.config_path)?;
    }
    {
        let mut p = state.presence.lock().await;
        p.avatar_hash = offer.avatar_hash_bytes();
    }

    let identity = flows::pairing::linked_identity(code.account_fp, device_key, &log_state, &blob);
    let mut new_client = GhostClient::open(identity, db_key, mls_db_key, &crate::setup::db_path())
        .map_err(|e| format!("open new client: {e}"))?;
    if !offer.display_name.is_empty() {
        new_client.set_display_name(offer.display_name.clone());
    }
    let new_inbox_rx = install_identity(&state, new_client, &home_url).await;

    let settings = flows::provision::consume(&state.client, &state.relay, &blob, now_millis())
        .await
        .map_err(|e| format!("provision sync failed: {e}"))?;
    apply_restored_settings(&state, &settings, false).await;

    spawn_relay_task(app, &state, new_inbox_rx).await;
    Ok(home_url)
}

#[cfg(debug_assertions)]
fn write_linked_credentials(
    account_fp: &[u8; 32],
    device_key: &ed25519_dalek::SigningKey,
    db_key: &[u8; 32],
    mls_db_key: &[u8; 32],
    idlog_seq: u64,
    master_vk: &[u8; 32],
    master_sk: &ed25519_dalek::SigningKey,
    delegation_sig: &[u8; 64],
) -> Result<(), String> {
    let mut blob = Vec::with_capacity(ghost_core::identity::keyring_store::DEVICE_BLOB_SIZE);
    blob.extend_from_slice(account_fp);
    blob.extend_from_slice(&device_key.to_bytes());
    blob.extend_from_slice(db_key);
    blob.extend_from_slice(mls_db_key);
    blob.extend_from_slice(&idlog_seq.to_be_bytes());
    blob.extend_from_slice(master_vk);
    blob.extend_from_slice(&master_sk.to_bytes());
    blob.extend_from_slice(delegation_sig);
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
    master_vk: &[u8; 32],
    master_sk: &ed25519_dalek::SigningKey,
    delegation_sig: &[u8; 64],
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
        master_vk: *master_vk,
        master_sk: ed25519_dalek::SigningKey::from_bytes(&master_sk.to_bytes()),
        delegation_sig: *delegation_sig,
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
    let seed = state.recovery_seed.lock().await
        .take()
        .ok_or("recovery seed no longer available — already used or session expired")?;

    match flows::recovery::set_passphrase(&state.client, &state.relay, &seed, &passphrase).await {
        Ok(code) => Ok(code.encode()),
        Err(e) => {
            // Put the seed back so the user can retry
            *state.recovery_seed.lock().await = Some(seed);
            Err(e.to_string())
        }
    }
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
    Ok(RecoveryCode { relay_url, account_fp }.encode())
}

#[tauri::command]
pub async fn change_recovery_passphrase(
    current_passphrase: String,
    new_passphrase: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    flows::recovery::change_passphrase(&state.client, &state.relay, &current_passphrase, &new_passphrase)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn has_recovery_blob(state: State<'_, AppState>) -> Result<bool, String> {
    flows::recovery::has_blob(&state.client, &state.relay)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn recover_account(
    recovery_code: String,
    passphrase: String,
    new_passphrase: String,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<String, String> {
    if new_passphrase.chars().count() < flows::recovery::MIN_PASSPHRASE_CHARS {
        return Err(format!("new passphrase must be at least {} characters", flows::recovery::MIN_PASSPHRASE_CHARS));
    }
    let code = RecoveryCode::parse(&recovery_code).map_err(|e| e.to_string())?;

    // No local identity for this account yet, so the relay client is unauthenticated.
    let (guest_relay, _unused_events) = RelayClient::new(&code.relay_url);
    let material = flows::recovery::begin(&guest_relay, code.account_fp, &passphrase, crate::setup::device_label())
        .await
        .map_err(|e| e.to_string())?;

    // From here on the steps are irreversible: credentials written, old databases removed.
    let mut db_key = [0u8; 32];
    let mut mls_db_key = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut db_key);
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut mls_db_key);
    write_linked_credentials(
        &code.account_fp,
        material.device_key(),
        &db_key,
        &mls_db_key,
        material.recovery_seq,
        &material.master_key().verifying_key().to_bytes(),
        material.master_key(),
        &material.delegation_sig(),
    )?;
    crate::setup::wipe_local_databases();

    // v1 blobs carry no sync key; start a fresh one.
    let sync_key = material.sync_key.unwrap_or_else(|| {
        let mut k = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut k);
        k
    });

    let mut new_client = GhostClient::open(material.identity(), db_key, mls_db_key, &crate::setup::db_path())
        .map_err(|e| format!("open new client: {e}"))?;
    new_client.set_sync_key(sync_key).map_err(|e| e.to_string())?;
    new_client.create_sync_group().map_err(|e| format!("create sync group: {e}"))?;
    let new_inbox_rx = install_identity(&state, new_client, &code.relay_url).await;
    {
        let mut cfg = state.config.lock().await;
        cfg.relay_url = Some(code.relay_url.clone());
        let _ = cfg.save(&state.config_path);
    }

    let settings = flows::recovery::finish(&state.client, &state.relay, &material, sync_key, &new_passphrase)
        .await
        .map_err(|e| e.to_string())?;
    apply_restored_settings(&state, &settings, true).await;

    *state.recovery_seed.lock().await = None;
    spawn_relay_task(app, &state, new_inbox_rx).await;
    Ok(code.relay_url)
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
