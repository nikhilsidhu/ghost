use ed25519_dalek::SigningKey;
use tauri::{Emitter, State};

use crate::error::{CommandError, CommandResult, ErrorCode};

use ghost_core::account_keys::{DeviceEncryptionKey, RecoveryKey};
use ghost_core::client::GhostClient;
use ghost_core::flows::{self, now_millis};
use ghost_core::flows::pairing::{PairingCode, PairingOffer};
use ghost_core::flows::recovery::RecoveryMaterial;
use ghost_core::flows::sync::SyncSettings;
use ghost_core::identity::keyring_store::StoredDevice;
use ghost_core::identity::Identity;
use ghost_core::relay::{RelayClient, RelayInfo};
use ghost_core::storage::ServerKind;

use crate::constants::{DEFAULT_PAGE_SIZE, INPUT_GAIN_MAX};
use crate::config::KeybindConfig;
use crate::dto::{
    setting_name, AccountPhaseDto, AccountStatusDto, AgcDto, AssignmentDto, ChannelAccessDto, ChannelDto, ChannelKindDto,
    ConfigDto, DeviceDto, IdentityDto, InputModeDto, InviteDto, KeptOutDto, KeybindConfigDto, MemberDto, MessageDto,
    NoiseSuppressionDto, OnlineStatusDto, PairingStageDto, PairingStatusDto, PolicyDto, ProfileReachDto, RecoveryOutcomeDto,
    RecoveryOutcomeKindDto, RevokeOutcomeDto, RevokeOutcomeKindDto, RoleDto, ServerDto, ServerRolesDto, SnapshotRestoreDto,
    DeviceListDto, KeyCheckDto, UnfinishedOutcomeDto, UnfinishedOutcomeKindDto,
};
use ghost_wire::policy::{ChannelPolicy, Role, ServerPolicy, MANAGE_CHANNELS};
use ghost_core::flows::presence;
use crate::state::{
    AccountPhase, AppState, PendingCreation, PendingNewKey, PendingPairing, PendingRecovery,
};

fn parse_id(hex_str: &str) -> CommandResult<[u8; 32]> {
    let bytes = hex::decode(hex_str).map_err(|e| CommandError::input(format!("not a hex id: {e}")))?;
    bytes.try_into().map_err(|_| CommandError::input("an id must be 32 bytes"))
}

/// Refuse early, with a clear message, what every member's device would ignore anyway.
fn require_permission(client: &GhostClient, server_id: &[u8; 32], permission: u32, what: &str) -> CommandResult<()> {
    let policy = client.server_policy(server_id)?;
    if policy.has(client.fingerprint(), permission) {
        Ok(())
    } else {
        Err(CommandError::new(ErrorCode::PermissionDenied, format!("{what} needs a permission you do not have")))
    }
}

/// A relay URL as the user typed it, normalized; refused unless it is an http(s) URL.
fn relay_url_input(url: &str) -> CommandResult<String> {
    let url = url.trim().trim_end_matches('/');
    let parsed = url::Url::parse(url).map_err(|e| CommandError::input(format!("not a relay url: {e}")))?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host().is_none() {
        return Err(CommandError::input("a relay url starts with http:// or https:// and names a host"));
    }
    Ok(url.to_string())
}

/// How long a replaced session loop gets to finish what it was doing.
const SESSION_STOP_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// A client for the relay hosting the server, or `None` when it is the home relay.
async fn hosting_relay(state: &AppState, server_id: &[u8; 32]) -> Option<RelayClient> {
    let url = {
        let client = state.client.lock().await;
        flows::server_relay_url(&client, server_id)
    }?;
    Some(state.relay.at(&url))
}

/// Point the relay client at `relay_url` with the current device credentials and start
/// its event stream over. Closing the connections ends the stream the running session
/// loop reads, so that loop returns once it has handled what already arrived; one that
/// takes too long is cut off.
async fn replace_relay(state: &AppState, relay_url: &str) -> tokio::sync::mpsc::Receiver<ghost_core::relay::RelayEvent> {
    {
        let auth = state.auth.read().unwrap();
        state.relay.set_auth(auth.account_fp, auth.device_vk, auth.signing_key.clone());
    }
    state.relay.set_base_url(relay_url);
    let inbox_rx = state.relay.restart();
    if let Some(mut handle) = state.relay_task_handle.lock().await.take() {
        if tokio::time::timeout(SESSION_STOP_WAIT, &mut handle).await.is_err() {
            tracing::warn!("the session loop did not stop in time; cutting it off");
            handle.abort();
        }
    }
    inbox_rx
}

/// Spawn the session loop; it subscribes to every mailbox itself.
async fn spawn_relay_task(
    app: tauri::AppHandle,
    state: &AppState,
    inbox_rx: tokio::sync::mpsc::Receiver<ghost_core::relay::RelayEvent>,
) {
    let jh = tauri::async_runtime::spawn(crate::relay_task::run(app, state.handles(), inbox_rx));
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

const PAIRING_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);
/// The new device polls for as long as the existing one can still add it.
const PAIRING_POLL_ATTEMPTS: usize = (flows::pairing::NEW_DEVICE_WAIT.as_secs() / PAIRING_POLL_INTERVAL.as_secs()) as usize;
const MAX_PROVISION_FETCH_ATTEMPTS: usize = 5;
const PROVISION_FETCH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn get_identity(state: State<'_, AppState>) -> CommandResult<IdentityDto> {
    let client = state.client.lock().await;
    Ok(IdentityDto::from(client.identity()))
}

#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn list_servers(state: State<'_, AppState>) -> CommandResult<Vec<ServerDto>> {
    let client = state.client.lock().await;
    let store = client.store();
    let servers = store.list_servers()?;
    let unread_servers = store.servers_with_unread()?;
    Ok(servers
        .iter()
        .map(|s| ServerDto::from_server(s, unread_servers.contains(&s.server_id), &client))
        .collect())
}

async fn create_server_impl(name: &str, kind: ServerKind, state: &AppState) -> CommandResult<ServerDto> {
    let server_id = flows::server::create(&state.client, &state.relay, name, kind, now_millis())
        .await
        ?;
    let client = state.client.lock().await;
    let server = client.store().get_server(&server_id)?;
    Ok(ServerDto::from_server(&server, false, &client))
}

#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn create_server(name: String, state: State<'_, AppState>) -> CommandResult<ServerDto> {
    create_server_impl(&name, ServerKind::Server, &state).await
}

#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn create_dm(name: String, state: State<'_, AppState>) -> CommandResult<ServerDto> {
    create_server_impl(&name, ServerKind::Dm, &state).await
}

#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn list_channels(
    server_id: String,
    state: State<'_, AppState>,
) -> CommandResult<Vec<ChannelDto>> {
    let sid = parse_id(&server_id)?;
    let client = state.client.lock().await;
    let store = client.store();
    let channels = store.list_channels(&sid)?;
    let unread = store.get_unread_counts(&sid)?;
    let unread_map: std::collections::HashMap<[u8; 32], u32> = unread.into_iter().collect();
    Ok(channels
        .iter()
        .map(|c| ChannelDto::from_channel(c, unread_map.get(&c.channel_id).copied().unwrap_or(0), client.is_private_channel(&c.channel_id)))
        .collect())
}

#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn list_members(
    server_id: String,
    state: State<'_, AppState>,
) -> CommandResult<Vec<MemberDto>> {
    let sid = parse_id(&server_id)?;
    let client = state.client.lock().await;
    let members = client
        .store()
        .list_members(&sid)
        ?;
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
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn save_server_order(order: Vec<String>, state: State<'_, AppState>) -> CommandResult<()> {
    let value = serde_json::to_vec(&order).map_err(|e| CommandError::internal(e.to_string()))?;
    flows::sync::set_and_push(&state.client, &state.relay, ghost_core::wire::SYNC_KEY_SERVER_ORDER, &value).await;
    Ok(())
}

#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn get_server_order(state: State<'_, AppState>) -> CommandResult<Vec<String>> {
    let client = state.client.lock().await;
    match client.sync_get(ghost_core::wire::SYNC_KEY_SERVER_ORDER) {
        Ok(Some((Some(value), _))) => serde_json::from_slice(&value).map_err(|e| CommandError::internal(e.to_string())),
        _ => Ok(vec![]),
    }
}

#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn list_messages(
    channel_id: String,
    before: Option<u64>,
    limit: Option<u32>,
    state: State<'_, AppState>,
) -> CommandResult<Vec<MessageDto>> {
    let cid = parse_id(&channel_id)?;
    let client = state.client.lock().await;
    let msgs = client
        .store()
        .get_messages(&cid, before, limit.unwrap_or(DEFAULT_PAGE_SIZE))
        ?;
    Ok(msgs.iter().map(MessageDto::from).collect())
}

#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn send_message(
    server_id: String,
    channel_id: String,
    content: String,
    state: State<'_, AppState>,
) -> CommandResult<MessageDto> {
    let sid = parse_id(&server_id)?;
    let cid = parse_id(&channel_id)?;
    // Shown as pending at once; the session reports when the relay takes or refuses it.
    let sent = flows::messages::send_text(&state.client, &state.relay, &sid, &cid, content.into_bytes())
        .await
        ?;
    Ok(MessageDto::from(&sent.message))
}

/// Send a message the relay refused once more, sealed afresh.
#[tauri::command]
pub async fn retry_message(message_id: String, state: State<'_, AppState>) -> CommandResult<MessageDto> {
    let id = parse_id(&message_id)?;
    {
        let client = state.client.lock().await;
        client.store().set_delivery(&id, ghost_core::storage::Delivery::Pending)?;
    }
    flows::messages::resend(&state.client, &state.relay, id).await?;
    let stored = state.client.lock().await.store().get_message(&id)?;
    Ok(MessageDto::from(&stored))
}

#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn create_channel(
    server_id: String,
    name: String,
    kind: ChannelKindDto,
    state: State<'_, AppState>,
) -> CommandResult<ChannelDto> {
    let sid = parse_id(&server_id)?;
    require_permission(&*state.client.lock().await, &sid, MANAGE_CHANNELS, "creating channels")?;
    let channel_id = flows::channels::create(&state.client, &state.relay, &sid, &name, kind.into())
        .await
        ?;

    let client = state.client.lock().await;
    let channel = client.store().get_channel(&channel_id)?;
    Ok(ChannelDto::from_channel(&channel, 0, false))
}

#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn rename_channel(channel_id: String, name: String, state: State<'_, AppState>) -> CommandResult<()> {
    flows::channels::rename(&state.client, &state.relay, &parse_id(&channel_id)?, &name).await?;
    Ok(())
}

#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn delete_channel(channel_id: String, state: State<'_, AppState>) -> CommandResult<()> {
    flows::channels::delete(&state.client, &state.relay, &parse_id(&channel_id)?).await?;
    Ok(())
}

/// Create a private channel admitting the given roles and accounts (and always the
/// server's channel managers). Members it does not admit never learn it exists.
#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn reorder_channels(server_id: String, channel_ids: Vec<String>, state: State<'_, AppState>) -> CommandResult<()> {
    let sid = parse_id(&server_id)?;
    let order = channel_ids.iter().map(|id| parse_id(id)).collect::<CommandResult<Vec<_>>>()?;
    Ok(flows::channels::reorder(&state.client, &state.relay, &sid, &order).await?)
}

#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn create_private_channel(
    server_id: String,
    name: String,
    kind: ChannelKindDto,
    roles: Vec<u8>,
    accounts: Vec<String>,
    state: State<'_, AppState>,
) -> CommandResult<ChannelDto> {
    let sid = parse_id(&server_id)?;
    let accounts = accounts.iter().map(|a| parse_id(a)).collect::<Result<Vec<_>, _>>()?;
    let hosting = hosting_relay(&state, &sid).await;
    let relay = hosting.as_ref().unwrap_or(state.relay.as_ref());
    let channel_id = flows::channels::create_private(&state.client, &state.relay, relay, &sid, &name, kind.into(), roles, accounts)
        .await
        ?;
    let client = state.client.lock().await;
    let channel = client.store().get_channel(&channel_id)?;
    Ok(ChannelDto::from_channel(&channel, 0, true))
}

/// Who a private channel admits; `None` for a public channel.
#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn get_channel_access(channel_id: String, state: State<'_, AppState>) -> CommandResult<Option<ChannelAccessDto>> {
    let cid = parse_id(&channel_id)?;
    let client = state.client.lock().await;
    let policy = client.channel_policy(&cid)?;
    Ok(policy.map(|p| ChannelAccessDto { roles: p.roles, accounts: p.accounts.iter().map(hex::encode).collect() }))
}

/// Change whom a private channel admits. Members it no longer admits are removed.
#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn set_channel_access(channel_id: String, access: ChannelAccessDto, state: State<'_, AppState>) -> CommandResult<()> {
    let cid = parse_id(&channel_id)?;
    let current = {
        let client = state.client.lock().await;
        client.channel_policy(&cid)?.ok_or_else(|| CommandError::state("not a private channel"))?
    };
    let accounts = access.accounts.iter().map(|a| parse_id(a)).collect::<Result<Vec<_>, _>>()?;
    let policy = ChannelPolicy { roles: access.roles, accounts, ..current };
    Ok(flows::channels::set_policy(&state.client, &state.relay, &cid, &policy).await?)
}

/// A server's roles, assignments and what everyone may do, with role names.
#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn get_server_roles(server_id: String, state: State<'_, AppState>) -> CommandResult<ServerRolesDto> {
    let sid = parse_id(&server_id)?;
    let client = state.client.lock().await;
    let policy = client.server_policy(&sid)?;
    let names: std::collections::HashMap<u8, String> =
        client.store().list_role_names(&sid)?.into_iter().collect();
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
    })
}

/// Replace a server's roles, assignments, everyone permissions or owner, then send the
/// names of roles that are new or renamed. The relay and every member check the change.
#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn set_server_roles(server_id: String, policy: PolicyDto, state: State<'_, AppState>) -> CommandResult<()> {
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
            .collect::<CommandResult<Vec<_>>>()?,
    };
    // Saving again after only the names failed sends the names alone.
    let current = state.client.lock().await.server_policy(&sid)?;
    if new_policy != current {
        flows::roles::set_server_policy(&state.client, &state.relay, &sid, &new_policy).await?;
    }

    let renamed: Vec<(u8, String)> = {
        let client = state.client.lock().await;
        let known: std::collections::HashMap<u8, String> =
            client.store().list_role_names(&sid)?.into_iter().collect();
        policy
            .roles
            .iter()
            .filter(|r| known.get(&r.id) != Some(&r.name))
            .map(|r| (r.id, r.name.clone()))
            .collect()
    };
    if !renamed.is_empty() {
        flows::roles::name_roles(&state.client, &state.relay, &sid, &renamed)
            .await
            .map_err(|e| CommandError::from(e).context("the roles were saved, but their names did not reach the members; save again to send them"))?;
    }
    Ok(())
}

/// Accounts the server keeps from rejoining, for those who may let them back in.
#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn kept_out(server_id: String, state: State<'_, AppState>) -> CommandResult<Vec<KeptOutDto>> {
    let sid = parse_id(&server_id)?;
    let client = state.client.lock().await;
    let kept = client.kept_out(&sid)?;
    Ok(kept
        .into_iter()
        .map(|(entry, display_name)| KeptOutDto { fingerprint: hex::encode(entry.account), display_name, removed_at: entry.removed_at })
        .collect())
}

/// Let an account the server keeps out back in, so it may rejoin with an invite.
#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn let_back_in(server_id: String, fingerprint: String, app: tauri::AppHandle, state: State<'_, AppState>) -> CommandResult<()> {
    let (sid, fp) = (parse_id(&server_id)?, parse_id(&fingerprint)?);
    let let_in = flows::members::let_back_in(&state.client, &state.relay, &sid, &fp).await;
    let _ = app.emit("sync", hex::encode(sid));
    Ok(let_in?)
}

/// Forget a server this account was removed from, with its history.
#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn forget_server(server_id: String, state: State<'_, AppState>) -> CommandResult<()> {
    let sid = parse_id(&server_id)?;
    Ok(state.client.lock().await.forget_server(&sid)?)
}

/// Take the relay's version of a halted server after all: rejoin its groups at the
/// relay's epoch and follow it again.
#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn accept_relay_state(server_id: String, state: State<'_, AppState>) -> CommandResult<()> {
    let sid = parse_id(&server_id)?;
    Ok(flows::server::accept_relay_state(&state.client, &state.relay, &sid).await?)
}

/// Kick a member, who is kept from rejoining until someone who may kick lets them back.
#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn kick_member(
    server_id: String,
    fingerprint: String,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> CommandResult<()> {
    let sid = parse_id(&server_id)?;
    let fp = parse_id(&fingerprint)?;
    let kicked = flows::members::kick(&state.client, &state.relay, &sid, &fp).await;
    let _ = app.emit("sync", hex::encode(sid));
    Ok(kicked?)
}

#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn mark_channel_read(
    channel_id: String,
    state: State<'_, AppState>,
) -> CommandResult<()> {
    let cid = parse_id(&channel_id)?;
    Ok(flows::channels::mark_read(&state.client, &state.relay, &cid, now_millis()).await?)
}

/// An invite to `sid`, registered on the relay hosting it, which joiners will contact,
/// open for as long as that relay allows.
pub(crate) async fn issue_invite(state: &AppState, sid: &[u8; 32]) -> CommandResult<flows::invite::CreatedInvite> {
    let hosting_url = {
        let client = state.client.lock().await;
        flows::server_relay_url(&client, sid)
    };
    let hosting = match hosting_url {
        Some(url) => Some(state.relay.at(&url)),
        None => None,
    };
    let relay = hosting.as_ref().unwrap_or(state.relay.as_ref());
    Ok(flows::invite::create(&state.client, relay, sid, None).await?)
}

#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn create_invite(
    server_id: String,
    state: State<'_, AppState>,
) -> CommandResult<InviteDto> {
    let sid = parse_id(&server_id)?;
    let created = issue_invite(&state, &sid).await?;

    let mut link = url::Url::parse("ghost://join").expect("valid base URL");
    link.query_pairs_mut()
        .append_pair("relay", &created.relay_url)
        .append_pair("r", &created.relay_ref.encode())
        .append_pair("token", &created.token)
        .append_pair("k", &hex::encode(created.key));

    Ok(InviteDto { token: created.token, link: link.to_string(), expires_at: created.expires_at })
}

/// Move a server this account created to the relay at `relay_url` (normally this
/// account's home). Returns a move link to share with members who cannot reach the
/// old relay any more.
#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn move_server(server_id: String, relay_url: String, state: State<'_, AppState>) -> CommandResult<String> {
    let sid = parse_id(&server_id)?;
    let location = flows::server::move_server(&state.client, &state.relay, &sid, &relay_url)
        .await
        ?;
    Ok(flows::server::move_link(&location))
}

/// Follow a server move from a link the server's creator shared.
#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn follow_server_move(link: String, state: State<'_, AppState>) -> CommandResult<bool> {
    let location = flows::server::parse_move_link(&link)?;
    flows::server::follow_move_link(&state.client, &state.relay, &location).await.map_err(|e| match CommandError::from(e) {
        unreachable if unreachable.code == ErrorCode::Network => unreachable.context("not followed yet; ghost keeps the link and tries again on its own"),
        other => other,
    })
}

/// Join a server through an invite. The server may live on the home relay or any
/// other; `relay_ref`, when the link carries one, pins the relay's key so a link
/// pointing at the wrong relay fails instead of joining it.
#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn join_by_invite(
    relay_url: String,
    token: String,
    key: String,
    relay_ref: Option<String>,
    state: State<'_, AppState>,
) -> CommandResult<ServerDto> {
    let key = parse_id(&key).map_err(|_| CommandError::input("the invite link's key is malformed"))?;
    let relay_url = relay_url_input(&relay_url)?;
    let expected = relay_ref
        .map(|encoded| ghost_wire::relay_ref::RelayRef::decode(&encoded))
        .transpose()
        .map_err(|e| CommandError::input(format!("the invite link's relay is malformed: {e}")))?;
    // The home relay's own client serves an invite from the home; any other relay is a
    // view of it, whose subscriptions join the same event stream. Which one the link
    // names is decided by relay key, so a link spelling the home's address differently
    // still joins through the home.
    let home_vk = state.client.lock().await.relay_vk();
    let issued_by_home = match (&expected, home_vk) {
        (Some(expected), Some(home_vk)) => expected.relay_vk == home_vk,
        _ => relay_url == state.relay_url(),
    };
    let view = if issued_by_home { None } else { Some(state.relay.at(&relay_url)) };
    let relay = view.as_ref().unwrap_or(state.relay.as_ref());

    if let Some(expected) = expected {
        let actual = relay.get_relay_info().await?;
        if actual.relay_vk != expected.relay_vk {
            return Err(CommandError::new(ErrorCode::WrongRelay, format!("the relay at {relay_url} is not the relay this invite was issued by")));
        }
    }

    let server_id = flows::invite::join(&state.client, &state.relay, relay, &token, &key, now_millis())
        .await
        ?;

    let client = state.client.lock().await;
    let server = client
        .store()
        .get_server(&server_id)
        ?;
    Ok(ServerDto::from_server(&server, false, &client))
}

#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn get_config(state: State<'_, AppState>) -> CommandResult<ConfigDto> {
    let relay_url = state.relay_url();
    let cfg = state.config.lock().await;
    Ok(ConfigDto {
        display_name: cfg.display_name.clone(),
        relay_url,
        input_device: cfg.input_device.clone(),
        output_device: cfg.output_device.clone(),
        noise_suppression: cfg.noise_suppression(),
        agc: cfg.agc(),
        input_mode: cfg.input_mode(),
        vad_threshold: cfg.vad_threshold(),
        input_gain: cfg.input_gain(),
        auto_mute_on_idle: cfg.auto_mute_on_idle(),
        status: cfg.status(),
        status_message: cfg.status_message.clone(),
        status_expiry: cfg.status_expiry,
    })
}

/// Whether going idle mutes a call; this device's own setting.
#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn set_auto_mute_on_idle(enabled: bool, state: State<'_, AppState>) -> CommandResult<()> {
    let mut cfg = state.config.lock().await;
    cfg.auto_mute_on_idle = Some(enabled);
    cfg.save(&state.config_path)?;
    Ok(())
}

#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn set_display_name(
    name: String,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> CommandResult<ProfileReachDto> {
    let mut cfg = state.config.lock().await;
    cfg.display_name = Some(name.clone());
    cfg.save(&state.config_path)?;
    drop(cfg);

    let reach = flows::profile::set_display_name(&state.client, &state.relay, &state.data_dir(), &name).await;
    let _ = app.emit("display-name-sync", ());
    Ok(reach?.into())
}

/// Most bytes an avatar image may have; the crop keeps stills small, animations less so.
const MAX_AVATAR_BYTES: usize = 2 * 1024 * 1024;

#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn upload_avatar(request: tauri::ipc::Request<'_>, state: State<'_, AppState>) -> CommandResult<ProfileReachDto> {
    let data = match request.body() {
        tauri::ipc::InvokeBody::Raw(bytes) => bytes.clone(),
        tauri::ipc::InvokeBody::Json(_) => return Err(CommandError::input("the avatar must be sent as raw bytes")),
    };
    if data.len() > MAX_AVATAR_BYTES {
        return Err(CommandError::input("the avatar image is too large"));
    }
    let (avatar, reach) = flows::profile::set_avatar(&state.client, &state.relay, &state.data_dir(), &data).await?;
    // Online members see the new avatar at once; its key rides along in the presence.
    announce_avatar(&state, Some(avatar)).await;
    Ok(reach.into())
}

#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn clear_avatar(
    state: State<'_, AppState>,
) -> CommandResult<ProfileReachDto> {
    let reach = flows::profile::clear_avatar(&state.client, &state.relay, &state.data_dir()).await?;
    announce_avatar(&state, None).await;
    Ok(reach.into())
}

/// Announce the account's avatar as it is now in this device's presence.
async fn announce_avatar(state: &AppState, avatar: Option<ghost_core::mls::presence::AvatarRef>) {
    let info = {
        let mut p = state.presence.lock().await;
        p.avatar = avatar;
        p.clone()
    };
    presence::broadcast(&state.client, &state.relay, &info).await;
}

#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
/// A member's cached avatar as raw image bytes; empty when none is cached.
pub async fn get_cached_avatar(fingerprint_hex: String, state: State<'_, AppState>) -> CommandResult<tauri::ipc::Response> {
    let fingerprint = parse_id(&fingerprint_hex)?;
    let bytes = std::fs::read(ghost_core::session::avatars::cache_path(&state.data_dir(), &fingerprint)).unwrap_or_default();
    Ok(tauri::ipc::Response::new(bytes))
}

#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
/// Connect to the account's home relay at another address. The relay there must be the
/// home the account's log names; moving the home is `move_home`. Without an account
/// yet, it is simply the relay the setup screens use.
pub async fn set_relay_url(url: String, app: tauri::AppHandle, state: State<'_, AppState>) -> CommandResult<()> {
    let url = relay_url_input(&url)?;
    if url == state.relay_url() {
        return Ok(());
    }
    let (probe, _events) = RelayClient::new(&url);
    let info = probe.get_relay_info().await.map_err(|e| CommandError::from(e).context("that relay did not answer"))?;
    let has_account = *state.phase.lock().await != AccountPhase::None;
    if has_account {
        // The home the account's log names, as kept on this device even before this run
        // fetched it.
        let home = {
            let mut client = state.client.lock().await;
            let fingerprint = *client.fingerprint();
            client.cached_identity_log(&fingerprint)?.and_then(|log| log.home_relay_vk)
        };
        match home {
            Some(home) if home != info.relay_vk => {
                return Err(CommandError::new(ErrorCode::WrongRelay, "that relay is not this account's home; to move the account there, move its home"));
            }
            Some(_) => {}
            None => return Err(CommandError::state("this device does not know its account's home yet; connect to the current one first")),
        }
    }
    {
        let mut cfg = state.config.lock().await;
        cfg.relay_url = Some(url.clone());
        cfg.save(&state.config_path)?;
    }
    let inbox_rx = replace_relay(&state, &url).await;
    if has_account {
        spawn_relay_task(app, &state, inbox_rx).await;
    }
    Ok(())
}

#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn join_voice(
    server_id: String,
    channel_id: String,
    muted: bool,
    deafened: bool,
    state: State<'_, AppState>,
) -> CommandResult<()> {
    let (server_id, channel_id) = (parse_id(&server_id)?, parse_id(&channel_id)?);
    {
        let cfg = state.config.lock().await;
        state.devices.choose(cfg.device_choice());
        cfg.apply_audio(&state.audio);
    }
    // The call takes the microphone; the test ends without touching the call's track.
    crate::audio_test::stop_mic_test();
    Ok(state.voice.join(server_id, channel_id, muted, deafened).await?)
}

#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn leave_voice(state: State<'_, AppState>) -> CommandResult<()> {
    Ok(state.voice.leave().await?)
}

#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn set_muted(muted: bool, state: State<'_, AppState>) -> CommandResult<()> {
    // The user's mute now, which the return from idle leaves alone.
    state.idle_mute.store(false, std::sync::atomic::Ordering::SeqCst);
    Ok(state.voice.set_muted(muted).await?)
}

#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn set_deafened(deafened: bool, state: State<'_, AppState>) -> CommandResult<()> {
    state.idle_mute.store(false, std::sync::atomic::Ordering::SeqCst);
    Ok(state.voice.set_deafened(deafened).await?)
}

#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn start_mic_test(app: tauri::AppHandle, state: State<'_, AppState>) -> CommandResult<()> {
    if state.voice.in_call() {
        return Err(CommandError::state("the microphone is in a call"));
    }
    crate::audio_test::start_mic_test(app, state.audio.clone()).map_err(CommandError::internal)
}

#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn stop_mic_test() -> CommandResult<()> {
    crate::audio_test::stop_mic_test();
    Ok(())
}

#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn play_test_tone(state: State<'_, AppState>) -> CommandResult<()> {
    let cfg = state.config.lock().await;
    crate::audio_test::play_test_tone(cfg.output_device.clone()).map_err(CommandError::internal)
}

#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn list_audio_devices() -> CommandResult<AudioDevicesDto> {
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
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "AudioDevices"))]
pub struct AudioDevicesDto {
    pub inputs: Vec<String>,
    pub outputs: Vec<String>,
    pub default_input: Option<String>,
    pub default_output: Option<String>,
}

#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn set_input_device(
    name: Option<String>,
    state: State<'_, AppState>,
) -> CommandResult<()> {
    let mut cfg = state.config.lock().await;
    cfg.input_device = name;
    cfg.save(&state.config_path)?;
    // A call or mic test running now switches to it.
    state.devices.choose(cfg.device_choice());
    Ok(())
}

#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn set_output_device(
    name: Option<String>,
    state: State<'_, AppState>,
) -> CommandResult<()> {
    let mut cfg = state.config.lock().await;
    cfg.output_device = name;
    cfg.save(&state.config_path)?;
    // A call or mic test running now switches to it.
    state.devices.choose(cfg.device_choice());
    Ok(())
}

#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn set_noise_suppression(mode: NoiseSuppressionDto, state: State<'_, AppState>) -> CommandResult<()> {
    use ghost_core::wire::SYNC_KEY_NOISE_SUPPRESSION;

    let mut cfg = state.config.lock().await;
    cfg.noise_suppression = Some(mode);
    cfg.save(&state.config_path)?;
    drop(cfg);
    state.audio.set_noise_suppression(mode.into());
    flows::sync::set_and_push(&state.client, &state.relay, SYNC_KEY_NOISE_SUPPRESSION, setting_name(&mode).as_bytes()).await;
    Ok(())
}

#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn set_agc(mode: AgcDto, state: State<'_, AppState>) -> CommandResult<()> {
    use ghost_core::wire::SYNC_KEY_AGC;

    let mut cfg = state.config.lock().await;
    cfg.agc = Some(mode);
    cfg.save(&state.config_path)?;
    drop(cfg);
    state.audio.set_agc(mode.into());
    flows::sync::set_and_push(&state.client, &state.relay, SYNC_KEY_AGC, setting_name(&mode).as_bytes()).await;
    Ok(())
}

#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn set_input_mode(mode: InputModeDto, state: State<'_, AppState>) -> CommandResult<()> {
    use ghost_core::wire::SYNC_KEY_INPUT_MODE;

    let mut cfg = state.config.lock().await;
    cfg.input_mode = Some(mode);
    cfg.save(&state.config_path)?;
    drop(cfg);
    crate::sync_utils::apply_input_mode(&state.audio, &state.voice, mode.into()).await;
    flows::sync::set_and_push(&state.client, &state.relay, SYNC_KEY_INPUT_MODE, setting_name(&mode).as_bytes()).await;
    Ok(())
}

#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn set_ptt_active(
    active: bool,
    state: State<'_, AppState>,
) -> CommandResult<()> {
    state.audio.set_ptt_active(active);
    Ok(())
}

#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn set_vad_threshold(
    value: f32,
    state: State<'_, AppState>,
) -> CommandResult<()> {
    use ghost_core::wire::SYNC_KEY_VAD_THRESHOLD;

    let clamped = value.clamp(0.0, 1.0);
    let mut cfg = state.config.lock().await;
    cfg.vad_threshold = Some(clamped);
    cfg.save(&state.config_path)?;
    drop(cfg);
    state.audio.set_vad_threshold(clamped);
    flows::sync::set_and_push(&state.client, &state.relay, SYNC_KEY_VAD_THRESHOLD, clamped.to_string().as_bytes()).await;
    Ok(())
}

#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn set_input_gain(
    value: f32,
    state: State<'_, AppState>,
) -> CommandResult<()> {
    use ghost_core::wire::SYNC_KEY_INPUT_GAIN;

    let clamped = value.clamp(0.0, INPUT_GAIN_MAX);
    let mut cfg = state.config.lock().await;
    cfg.input_gain = Some(clamped);
    cfg.save(&state.config_path)?;
    drop(cfg);
    state.audio.set_input_gain(clamped);
    flows::sync::set_and_push(&state.client, &state.relay, SYNC_KEY_INPUT_GAIN, clamped.to_string().as_bytes()).await;
    Ok(())
}

#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn get_keybinds(state: State<'_, AppState>) -> CommandResult<KeybindConfigDto> {
    let cfg = state.config.lock().await;
    let kb = cfg.keybinds.clone().unwrap_or_default();
    Ok(KeybindConfigDto {
        push_to_talk: kb.push_to_talk,
    })
}

#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn set_keybind(
    action: String,
    shortcut: Option<String>,
    state: State<'_, AppState>,
) -> CommandResult<()> {
    let mut cfg = state.config.lock().await;
    let kb = cfg.keybinds.get_or_insert_with(KeybindConfig::default);
    match action.as_str() {
        "push_to_talk" => kb.push_to_talk = shortcut,
        _ => return Err(CommandError::input(format!("unknown keybind action: {action}"))),
    }
    Ok(cfg.save(&state.config_path)?)
}

#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn set_status(status: OnlineStatusDto, state: State<'_, AppState>) -> CommandResult<()> {
    use ghost_core::wire::SYNC_KEY_STATUS;

    let info = {
        let mut p = state.presence.lock().await;
        p.status = status.into();
        p.clone()
    };
    presence::broadcast(&state.client, &state.relay, &info).await;
    // Idle follows inactivity; only a status the user chose is kept and shared.
    if status != OnlineStatusDto::Idle {
        let mut cfg = state.config.lock().await;
        cfg.status = Some(status);
        cfg.save(&state.config_path)?;
        drop(cfg);
        flows::sync::set_and_push(&state.client, &state.relay, SYNC_KEY_STATUS, setting_name(&status).as_bytes()).await;
    }
    Ok(())
}

#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn set_status_message(
    message: Option<String>,
    expiry: Option<u64>,
    state: State<'_, AppState>,
) -> CommandResult<()> {
    use ghost_core::wire::SYNC_KEY_STATUS_MESSAGE;

    let info = {
        let mut p = state.presence.lock().await;
        p.status_message = message.clone();
        p.status_expiry = expiry;
        p.clone()
    };
    presence::broadcast(&state.client, &state.relay, &info).await;
    let mut cfg = state.config.lock().await;
    cfg.status_message = message.clone();
    cfg.status_expiry = expiry;
    cfg.save(&state.config_path)?;
    drop(cfg);

    match message {
        Some(text) => {
            let synced = flows::sync::SyncedStatusMessage { text, expires_at: expiry };
            flows::sync::set_and_push(&state.client, &state.relay, SYNC_KEY_STATUS_MESSAGE, &synced.to_bytes()).await;
        }
        None => flows::sync::remove_and_push(&state.client, &state.relay, SYNC_KEY_STATUS_MESSAGE).await,
    }
    Ok(())
}

// ── Device management ───────────────────────────────────────────────

#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn get_devices(state: State<'_, AppState>) -> CommandResult<DeviceListDto> {
    let list = flows::devices::list(&state.client, &state.relay).await?;
    let (own_device_vk, pending) = {
        let client = state.client.lock().await;
        (client.identity().verifying_key.to_bytes(), client.store().pending_removals()?)
    };
    let devices = list
        .state
        .devices
        .values()
        .map(|d| {
            let removal = pending.iter().find(|p| p.device_vk == d.verifying_key);
            DeviceDto {
                device_key: hex::encode(d.verifying_key),
                label: d.label.clone(),
                added_at_seq: d.added_at_seq,
                is_active: d.is_active(),
                is_current: d.verifying_key == own_device_vk,
                removal_pending: removal.is_some() && d.is_active(),
                removal_refused: removal.and_then(|p| p.refused.clone()),
            }
        })
        .collect();
    Ok(DeviceListDto { devices, current: list.current })
}

/// Remove a device of this account.
#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn revoke_device(device_key_hex: String, state: State<'_, AppState>) -> CommandResult<RevokeOutcomeDto> {
    use flows::devices::RevokeOutcome;
    let target_key = parse_id(&device_key_hex)?;
    let outcome = flows::devices::revoke(&state.client, &state.relay, &target_key).await?;
    Ok(match outcome {
        RevokeOutcome::Complete => RevokeOutcomeDto { outcome: RevokeOutcomeKindDto::Complete, servers: Vec::new() },
        RevokeOutcome::LeavesLeft(server_ids) => {
            let client = state.client.lock().await;
            let servers = server_ids.iter().filter_map(|id| client.store().get_server(id).ok().map(|s| s.name)).collect();
            RevokeOutcomeDto { outcome: RevokeOutcomeKindDto::LeavesLeft, servers }
        }
        RevokeOutcome::LogPending => RevokeOutcomeDto { outcome: RevokeOutcomeKindDto::LogPending, servers: Vec::new() },
    })
}

#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn rename_device(device_key_hex: String, label: String, state: State<'_, AppState>) -> CommandResult<()> {
    let target_key = parse_id(&device_key_hex)?;
    let label = label.trim();
    if label.is_empty() {
        return Err(CommandError::input("a device needs a name"));
    }
    Ok(flows::devices::rename(&state.client, &state.relay, &target_key, label).await?)
}

// ── Account ─────────────────────────────────────────────────────────

#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn get_account_status(state: State<'_, AppState>) -> CommandResult<AccountStatusDto> {
    let phase = match *state.phase.lock().await {
        AccountPhase::None => AccountPhaseDto::None,
        AccountPhase::Ready => AccountPhaseDto::Ready,
    };
    Ok(AccountStatusDto { phase, relay_url: state.relay_url(), device_label: crate::setup::device_label() })
}

/// Whether `typed` is the key shown, by its bytes: the user types it back in full before
/// anything leaves the device.
fn typed_matches(shown: &RecoveryKey, typed: &str) -> CommandResult<()> {
    let typed = RecoveryKey::parse(typed)?;
    let same = shown.root()?.verifying_key() == typed.root()?.verifying_key();
    if same {
        Ok(())
    } else {
        Err(CommandError::new(ErrorCode::WrongKey, "that is not the key shown; type it exactly as displayed"))
    }
}

/// The device label the user chose, or the machine's name when they left it empty.
fn chosen_device_label(label: &str) -> String {
    let label = label.trim();
    if label.is_empty() { crate::setup::device_label() } else { label.to_string() }
}

/// The databases of a device about to hold another account's data go first, so a fresh
/// client opens on nothing. The device record is kept only once the account is fully
/// set up, so a failure part way leaves a device without an account, not an account
/// without its state.
fn fresh_databases() {
    crate::setup::wipe_local_databases();
}

fn fresh_db_keys() -> ([u8; 32], [u8; 32]) {
    let mut keys = [[0u8; 32]; 2];
    for key in &mut keys {
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, key);
    }
    (keys[0], keys[1])
}

/// Make an account at `relay_url` for `display_name` and show its recovery key. Nothing
/// is sent until `confirm_new_account` sees the key typed back.
#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn begin_create_account(
    display_name: String,
    relay_url: String,
    device_label: String,
    state: State<'_, AppState>,
) -> CommandResult<String> {
    if *state.phase.lock().await != AccountPhase::None {
        return Err(CommandError::state("this device already has an account"));
    }
    let display_name = display_name.trim().to_string();
    if display_name.is_empty() {
        return Err(CommandError::input("a display name is needed"));
    }
    let relay_url = relay_url_input(&relay_url)?;
    let (guest, _events) = RelayClient::new(&relay_url);
    let info = guest.get_relay_info().await.map_err(|e| CommandError::from(e).context("that relay did not answer"))?;
    let recovery_key = RecoveryKey::generate();
    let account = Identity::create_account(&info.relay_ref, &chosen_device_label(&device_label), &recovery_key)?;
    let shown = recovery_key.encode();
    *state.pending_creation.lock().await = Some(PendingCreation { account, recovery_key, display_name, relay_url });
    Ok(shown)
}

/// The user typed the recovery key back: publish the account and run it. The device
/// record is filed as unfinished before anything is sent, so a crash before the relay's
/// answer leaves what the next start finishes from (`resume_unfinished_account`). Until
/// the relay has the account, a failure keeps the pending account, so the key the user
/// wrote down is still the one to type.
#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn confirm_new_account(typed: String, app: tauri::AppHandle, state: State<'_, AppState>) -> CommandResult<()> {
    let pending = state.pending_creation.lock().await.take().ok_or_else(|| CommandError::state("no account is being made"))?;
    if let Err(e) = typed_matches(&pending.recovery_key, &typed) {
        *state.pending_creation.lock().await = Some(pending);
        return Err(e);
    }
    let identity = &pending.account.identity;
    let unfinished = crate::setup::UnfinishedAccount {
        device: StoredDevice {
            fingerprint: identity.fingerprint,
            signing_key: identity.signing_key.clone(),
            encryption_key: identity.encryption_key.clone(),
            db_key: pending.account.db_key,
            mls_db_key: pending.account.mls_db_key,
            added_at: identity.added_at,
        },
        relay_url: pending.relay_url.clone(),
        display_name: pending.display_name.clone(),
    };
    if let Err(e) = crate::setup::save_unfinished(&unfinished) {
        *state.pending_creation.lock().await = Some(pending);
        return Err(CommandError::from(e).context("this device could not keep the account's key, so nothing was sent"));
    }
    let info = match publish_account(&pending).await {
        Ok(info) => info,
        Err(e) => {
            *state.pending_creation.lock().await = Some(pending);
            return Err(e);
        }
    };
    let PendingCreation { account, display_name, relay_url, .. } = pending;
    crate::setup::finish_unfinished(&unfinished.device)
        .map_err(|e| CommandError::from(e).context("the account was made, but this device could not keep its key; restart Ghost to finish setting it up"))?;
    let mut new_client = open_fresh_account(&unfinished.device, &display_name, &relay_url, &state).await?;
    new_client.set_relay_vk(info.relay_vk);
    new_client.store_account_seed(&account.account_seed)?;
    let inbox_rx = install_identity(&state, new_client, &relay_url).await;
    *state.phase.lock().await = AccountPhase::Ready;
    spawn_relay_task(app, &state, inbox_rx).await;
    Ok(())
}

/// Open the client of an account this device just made, on fresh databases, and keep
/// its name and home in the config.
async fn open_fresh_account(device: &StoredDevice, display_name: &str, relay_url: &str, state: &AppState) -> CommandResult<GhostClient> {
    fresh_databases();
    let mut client = GhostClient::open(device.identity(), device.db_key, device.mls_db_key, &crate::setup::db_path())
        .map_err(|e| CommandError::from(e).context("the account is made and kept on this device; restart Ghost to open it"))?;
    client.set_display_name(display_name.to_string());
    let mut cfg = state.config.lock().await;
    cfg.display_name = Some(display_name.to_string());
    cfg.relay_url = Some(relay_url.to_string());
    cfg.save(&state.config_path)?;
    Ok(client)
}

/// Whether the relay an unfinished account was posted to holds it: `Some(true)` when it
/// admits the device, `Some(false)` when it does not know it, `None` when it did not
/// answer.
async fn relay_holds(unfinished: &crate::setup::UnfinishedAccount) -> Option<bool> {
    let (relay, _events) = RelayClient::new(&unfinished.relay_url);
    let device = &unfinished.device;
    relay.set_auth(device.fingerprint, device.signing_key.verifying_key().to_bytes(), device.signing_key.clone());
    match relay.get_account(&device.fingerprint).await {
        Ok(_) => Some(true),
        Err(ghost_core::error::GhostError::RelayStatus { status: 401 | 404, .. }) => Some(false),
        Err(_) => None,
    }
}

/// At setup, finish an account whose batch reached the relay before this device kept
/// its record (the app closed in between): the relay holding it makes the filed record
/// this device's, and the account runs. One the relay does not know is forgotten.
#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn resume_unfinished_account(app: tauri::AppHandle, state: State<'_, AppState>) -> CommandResult<UnfinishedOutcomeDto> {
    if *state.phase.lock().await != AccountPhase::None {
        return Ok(UnfinishedOutcomeDto::none());
    }
    let Some(unfinished) = crate::setup::load_unfinished() else { return Ok(UnfinishedOutcomeDto::none()) };
    match relay_holds(&unfinished).await {
        Some(true) => {}
        Some(false) => {
            crate::setup::discard_unfinished();
            return Ok(UnfinishedOutcomeDto::none());
        }
        None => return Ok(UnfinishedOutcomeDto { outcome: UnfinishedOutcomeKindDto::Waiting, relay_url: Some(unfinished.relay_url) }),
    }
    crate::setup::finish_unfinished(&unfinished.device)?;
    // Its account key is fetched by the session's account check: the key set holds a copy for it.
    let mut client = open_fresh_account(&unfinished.device, &unfinished.display_name, &unfinished.relay_url, &state).await?;
    if let Ok(info) = RelayClient::new(&unfinished.relay_url).0.get_relay_info().await {
        client.set_relay_vk(info.relay_vk);
    }
    let inbox_rx = install_identity(&state, client, &unfinished.relay_url).await;
    *state.phase.lock().await = AccountPhase::Ready;
    spawn_relay_task(app, &state, inbox_rx).await;
    Ok(UnfinishedOutcomeDto { outcome: UnfinishedOutcomeKindDto::Finished, relay_url: Some(unfinished.relay_url) })
}

/// Make the relay hold the account: its key, then the genesis batch. Nothing of the
/// pending account is consumed, so a failure leaves it to try again.
async fn publish_account(pending: &PendingCreation) -> CommandResult<RelayInfo> {
    let (relay, _events) = RelayClient::new(&pending.relay_url);
    let identity = &pending.account.identity;
    relay.set_auth(identity.fingerprint, identity.verifying_key.to_bytes(), identity.signing_key.clone());
    let info = relay.get_relay_info().await.map_err(|e| CommandError::from(e).context("that relay did not answer"))?;
    relay
        .post_idlog_batch(&identity.fingerprint, &pending.account.batch)
        .await
        .map_err(|e| CommandError::from(e).context("the relay refused the account"))?;
    Ok(info)
}

#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn cancel_create_account(state: State<'_, AppState>) -> CommandResult<()> {
    *state.pending_creation.lock().await = None;
    // A batch sent may have landed though its answer never came: that account stays
    // filed, for the next start to finish.
    if let Some(unfinished) = crate::setup::load_unfinished() {
        if relay_holds(&unfinished).await == Some(false) {
            crate::setup::discard_unfinished();
        }
    }
    Ok(())
}

// ── Device pairing ──────────────────────────────────────────────────

/// Start pairing: post a sealed offer and return the code the new device scans.
#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn start_pairing(state: State<'_, AppState>) -> CommandResult<String> {
    let relay_url = state.relay_url();
    let display_name = state.config.lock().await.display_name.clone().unwrap_or_default();
    let avatar = state.presence.lock().await.avatar;
    let offer = PairingOffer {
        relay_url,
        display_name,
        avatar_hash: avatar.map(|a| hex::encode(a.hash)),
        avatar_key: avatar.map(|a| hex::encode(a.key)),
    };

    let code = flows::pairing::start(&state.client, &state.relay, &offer)
        .await
        ?;
    let encoded = code.encode();
    *state.pending_pairing.lock().await = Some(PendingPairing { code, device: None, draft: None });
    Ok(encoded)
}

/// Where the pairing stands. Polled: while waiting for the new device to answer; then,
/// after `confirm_pairing`, while waiting for it to sign the addition.
#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn check_pairing(state: State<'_, AppState>) -> CommandResult<PairingStatusDto> {
    let mut guard = state.pending_pairing.lock().await;
    let pending = guard.as_mut().ok_or_else(|| CommandError::state("no active pairing session"))?;
    match check_pending_pairing(&state, pending).await {
        Ok(status) => {
            if status.stage == PairingStageDto::Linked {
                *guard = None;
            }
            Ok(status)
        }
        // The relay ended the session (it expired, or another replaced it): nothing more
        // can come of this one.
        Err(e) if e.code == ErrorCode::NotFound => {
            *guard = None;
            Err(CommandError::new(ErrorCode::NotFound, "the pairing session ended. start again on both devices."))
        }
        Err(e) => Err(e),
    }
}

/// One poll of the pairing in progress.
async fn check_pending_pairing(state: &AppState, pending: &mut PendingPairing) -> CommandResult<PairingStatusDto> {
    let status = |stage: PairingStageDto, code: Option<String>, label: Option<String>| PairingStatusDto { stage, code, label };

    // Pairing runs on the home relay, so it is also the rendezvous.
    let Some(device) = &pending.device else {
        return match flows::pairing::await_response(&state.relay, &pending.code).await? {
            Some(answered) => {
                let code = answered.code.clone();
                pending.device = Some(answered);
                Ok(status(PairingStageDto::Confirm, Some(code), None))
            }
            None => Ok(status(PairingStageDto::Waiting, None, None)),
        };
    };
    let Some(draft) = pending.draft.as_mut() else {
        return Ok(status(PairingStageDto::Confirm, Some(device.code.clone()), None));
    };
    match flows::pairing::complete(&state.client, &state.relay, &state.relay, &pending.code, device, draft).await? {
        Some(label) => Ok(status(PairingStageDto::Linked, None, Some(label))),
        None => Ok(status(PairingStageDto::Signing, Some(device.code.clone()), None)),
    }
}

/// The user compared the codes and they match: draft the addition for the new device to sign.
#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn confirm_pairing(state: State<'_, AppState>) -> CommandResult<()> {
    let mut guard = state.pending_pairing.lock().await;
    let pending = guard.as_mut().ok_or_else(|| CommandError::state("no active pairing session"))?;
    let device = pending.device.as_ref().ok_or_else(|| CommandError::state("the new device has not answered yet"))?;
    let draft = flows::pairing::post_draft(&state.client, &state.relay, &state.relay, &pending.code, device).await?;
    pending.draft = Some(draft);
    Ok(())
}

/// Cancel an active pairing session, also when the codes did not match. The relay ends
/// it too, so the new device stops waiting and the code answers nobody.
#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn cancel_pairing(state: State<'_, AppState>) -> CommandResult<()> {
    let Some(pending) = state.pending_pairing.lock().await.take() else { return Ok(()) };
    if let Err(e) = state.relay.close_pairing(&pending.code.account_fp, &pending.code.token).await {
        // It expires on its own; until then nobody holding the code gets anything from it.
        tracing::warn!("pairing: the session not ended on the relay: {e}");
    }
    Ok(())
}

// ── Join as new device ──────────────────────────────────────────────

/// New-device side of pairing: fetch the offer, answer with fresh keys, show the code
/// for the user to compare (the `link-code` event), sign the addition the other device
/// drafts, wait for the log to list this device, fetch the provision, then replace the
/// local identity in place.
#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn join_as_new_device(
    pairing_code: String,
    device_label: String,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> CommandResult<String> {
    if *state.phase.lock().await == AccountPhase::Ready {
        return Err(CommandError::state("this device already has an account"));
    }
    let code = PairingCode::parse(&pairing_code)?;

    let _ = app.emit("link-status", "connecting to relay…");
    // The new device has no identity on this relay yet, so the client is unauthenticated.
    let (guest_relay, _unused_events) = RelayClient::new(&code.relay_url);
    let offer = flows::pairing::fetch_offer(&guest_relay, &code).await?;

    let device_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let encryption_key = DeviceEncryptionKey::generate();
    let label = chosen_device_label(&device_label);

    let _ = app.emit("link-status", "sending device keys…");
    let shown = flows::pairing::respond(&guest_relay, &code, &device_key, &encryption_key, &label).await.map_err(|e| match e {
        // The relay keeps the first answer only.
        ghost_core::error::GhostError::RelayStatus { status: 409, .. } => {
            CommandError::new(ErrorCode::Conflict, "this pairing code was already used. generate a new code on your other device.")
        }
        e => e.into(),
    })?;
    let _ = app.emit("link-code", &shown);

    let _ = app.emit("link-status", "waiting for your other device to confirm…");
    let (log_state, added_at) = flows::pairing::wait_for_device(
        &guest_relay, &code, &device_key, &label, PAIRING_POLL_ATTEMPTS, PAIRING_POLL_INTERVAL,
    ).await?;

    // The pairing code may name any relay the account uses; the identity log names the home.
    let home_url = log_state
        .home_relay_ref
        .as_ref()
        .and_then(|r| r.primary_https_url())
        .unwrap_or(&code.relay_url)
        .to_string();

    // This device is active in the account's log from here, with a generation sealed to
    // it: its record comes first, so nothing that fails after can leave the account with
    // a device that holds nothing.
    let (db_key, mls_db_key) = fresh_db_keys();
    let device = StoredDevice {
        fingerprint: code.account_fp,
        signing_key: device_key.clone(),
        encryption_key: encryption_key.clone(),
        db_key,
        mls_db_key,
        added_at,
    };
    crate::setup::save_device(&device)
        .map_err(|e| CommandError::from(e).context("this device was added to the account but could not keep its key; remove it from your other device and link again"))?;
    {
        let mut cfg = state.config.lock().await;
        if !offer.display_name.is_empty() {
            cfg.display_name = Some(offer.display_name.clone());
        }
        cfg.relay_url = Some(home_url.clone());
        cfg.save(&state.config_path)?;
    }
    fresh_databases();
    let identity = flows::pairing::linked_identity(code.account_fp, device_key, encryption_key, added_at);
    let mut new_client = GhostClient::open(identity, db_key, mls_db_key, &crate::setup::db_path())
        .map_err(|e| CommandError::from(e).context("this device is linked and kept; restart Ghost to open it"))?;
    if !offer.display_name.is_empty() {
        new_client.set_display_name(offer.display_name.clone());
    }
    if let Ok(info) = guest_relay.get_relay_info().await {
        new_client.set_relay_vk(info.relay_vk);
    }
    let new_inbox_rx = install_identity(&state, new_client, &home_url).await;

    // The provision brings the servers now; without it the running session's account check
    // opens the account keys and its snapshot merge joins the servers.
    let _ = app.emit("link-status", "syncing account…");
    let restored = match flows::pairing::fetch_provision(&guest_relay, &code, MAX_PROVISION_FETCH_ATTEMPTS, PROVISION_FETCH_INTERVAL).await {
        Ok(blob) => flows::provision::consume(&state.client, &state.relay, &blob, now_millis()).await,
        Err(e) => Err(e),
    };
    let settings = match restored {
        Ok(settings) => settings,
        Err(e) => {
            tracing::warn!("link: the account's servers were not restored now, the session joins them: {e}");
            flows::sync::SyncSettings::default()
        }
    };
    {
        let mut p = state.presence.lock().await;
        p.avatar = offer.avatar();
    }
    apply_restored_settings(&state, &settings, false).await;

    *state.phase.lock().await = AccountPhase::Ready;
    spawn_relay_task(app, &state, new_inbox_rx).await;
    Ok(home_url)
}

// ── Recovery ────────────────────────────────────────────────────────

/// Find the account behind a recovery key through `relay_url` and show the new key every
/// recovery sets. Nothing changes until `confirm_recovery` sees it typed back.
#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn begin_recovery(
    recovery_key: String,
    relay_url: String,
    device_label: String,
    state: State<'_, AppState>,
) -> CommandResult<String> {
    if *state.phase.lock().await == AccountPhase::Ready {
        return Err(CommandError::state("this device already has an account"));
    }
    let key = RecoveryKey::parse(&recovery_key)?;
    let relay_url = relay_url_input(&relay_url)?;
    let (guest, _events) = RelayClient::new(&relay_url);
    let located = flows::recovery::locate(&guest, &key)
        .await
        .map_err(|e| match CommandError::from(e) {
            unreachable if unreachable.code == ErrorCode::Network => unreachable.context("that relay did not answer"),
            refused => refused,
        })?
        .ok_or_else(|| CommandError::new(ErrorCode::NotFound, "no account with this recovery key is known to that relay"))?;
    let new_key = RecoveryKey::generate();
    let shown = new_key.encode();
    *state.pending_recovery.lock().await = Some(PendingRecovery {
        relay_url,
        located,
        recovery_key: key,
        new_key,
        device_label: chosen_device_label(&device_label),
    });
    Ok(shown)
}

/// The user typed the new key back: recover through the account's home. When the home
/// does not answer, nothing is done and the outcome says so; `recover_through_relay`
/// then recovers through the relay given, making it the home.
#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn confirm_recovery(typed: String, app: tauri::AppHandle, state: State<'_, AppState>) -> CommandResult<RecoveryOutcomeDto> {
    let pending = state.pending_recovery.lock().await.take().ok_or_else(|| CommandError::state("no recovery is in progress"))?;
    if let Err(e) = typed_matches(&pending.new_key, &typed) {
        *state.pending_recovery.lock().await = Some(pending);
        return Err(e);
    }
    let home_url = match (&pending.located.relay_is_home, pending.located.home.as_ref().and_then(|h| h.primary_https_url())) {
        (true, _) => pending.relay_url.clone(),
        (false, Some(url)) => url.to_string(),
        (false, None) => return Err(CommandError::state("the account's log names a home this app cannot reach by address")),
    };
    let (home, _events) = RelayClient::new(&home_url);
    if home.get_relay_info().await.is_err() {
        let outcome = RecoveryOutcomeDto { outcome: RecoveryOutcomeKindDto::HomeUnreachable, home_url: Some(home_url), restore: None };
        *state.pending_recovery.lock().await = Some(pending);
        return Ok(outcome);
    }
    let begun = flows::recovery::begin(&home, pending.located.account_fp, &pending.recovery_key, &pending.new_key, &pending.device_label).await;
    // Nothing landed: the key shown is still the one to type back.
    let material = match begun {
        Ok(material) => material,
        Err(e) => {
            *state.pending_recovery.lock().await = Some(pending);
            return Err(e.into());
        }
    };
    let restore = finish_recovery(app, &state, material, &home_url).await?;
    Ok(RecoveryOutcomeDto::recovered(restore))
}

/// The home did not answer and the user chose to go on: recover through the relay given
/// and make it the account's home.
#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn recover_through_relay(app: tauri::AppHandle, state: State<'_, AppState>) -> CommandResult<RecoveryOutcomeDto> {
    let pending = state.pending_recovery.lock().await.take().ok_or_else(|| CommandError::state("no recovery is in progress"))?;
    let (source, _events) = RelayClient::new(&pending.relay_url);
    let begun =
        flows::recovery::begin_with_new_home(&source, &source, pending.located.account_fp, &pending.recovery_key, &pending.new_key, &pending.device_label)
            .await;
    let material = match begun {
        Ok(material) => material,
        Err(e) => {
            *state.pending_recovery.lock().await = Some(pending);
            return Err(e.into());
        }
    };
    let restore = finish_recovery(app, &state, material, &pending.relay_url).await?;
    Ok(RecoveryOutcomeDto::recovered(restore))
}

#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn cancel_recovery(state: State<'_, AppState>) -> CommandResult<()> {
    *state.pending_recovery.lock().await = None;
    Ok(())
}

/// Run the recovered device: keep its record, open its database at `home_url`, restore
/// what the account's snapshots hold, and start the session. The record comes first:
/// the batch has landed, so this device is the account's only one, and whatever fails
/// after the record is fetched again as the device runs. Returns what became of the
/// snapshot, which the user is told when it restored nothing.
async fn finish_recovery(app: tauri::AppHandle, state: &AppState, material: RecoveryMaterial, home_url: &str) -> CommandResult<SnapshotRestoreDto> {
    let (db_key, mls_db_key) = fresh_db_keys();
    let device = StoredDevice {
        fingerprint: material.account_fp,
        signing_key: material.device_key.clone(),
        encryption_key: material.encryption_key.clone(),
        db_key,
        mls_db_key,
        added_at: material.added_at,
    };
    crate::setup::save_device(&device)
        .map_err(|e| CommandError::from(e).context("the account was recovered, but this device could not keep its key; recover it again with the new key"))?;
    {
        let mut cfg = state.config.lock().await;
        cfg.relay_url = Some(home_url.to_string());
        cfg.save(&state.config_path)?;
    }
    fresh_databases();
    let (home, _events) = RelayClient::new(home_url);
    let mut new_client = GhostClient::open(material.identity(), db_key, mls_db_key, &crate::setup::db_path())
        .map_err(|e| CommandError::from(e).context("the account is recovered and kept on this device; restart Ghost to open it"))?;
    if let Ok(info) = home.get_relay_info().await {
        new_client.set_relay_vk(info.relay_vk);
    }
    let new_inbox_rx = install_identity(state, new_client, home_url).await;

    // What the snapshot holds is restored now when it can be; otherwise the running
    // session fetches it from the account's relays.
    let (settings, restore) = match flows::recovery::finish(&state.client, &state.relay, &material).await {
        Ok(finished) => (finished.settings, finished.snapshot.into()),
        Err(e) => {
            tracing::warn!("recovery: the account's data was not restored now, the session fetches it: {e}");
            (flows::sync::SyncSettings::default(), SnapshotRestoreDto::NotReached)
        }
    };
    apply_restored_settings(state, &settings, true).await;

    *state.phase.lock().await = AccountPhase::Ready;
    spawn_relay_task(app, state, new_inbox_rx).await;
    Ok(restore)
}

// ── Recovery key ────────────────────────────────────────────────────

/// Whether `recovery_key` is this account's current one. Nothing is sent.
#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn check_recovery_key(recovery_key: String, state: State<'_, AppState>) -> CommandResult<KeyCheckDto> {
    let key = RecoveryKey::parse(&recovery_key)?;
    let check = flows::account::check_recovery_key(&state.client, &state.relay, &key).await?;
    Ok(KeyCheckDto { matches: check.matches, current: check.current })
}

/// Replacing the key needs the current one. Shows the new key; `confirm_new_recovery_key`
/// makes the change once it is typed back.
#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn begin_replace_recovery_key(current: String, state: State<'_, AppState>) -> CommandResult<String> {
    let current = RecoveryKey::parse(&current)?;
    if !flows::account::check_recovery_key(&state.client, &state.relay, &current).await?.matches {
        return Err(CommandError::new(ErrorCode::WrongKey, "that is not this account's current recovery key"));
    }
    let new_key = RecoveryKey::generate();
    let shown = new_key.encode();
    *state.pending_new_key.lock().await = Some(PendingNewKey { current, new_key });
    Ok(shown)
}

/// The user typed the new key back: replace the current key.
#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn confirm_new_recovery_key(typed: String, state: State<'_, AppState>) -> CommandResult<()> {
    let pending = state.pending_new_key.lock().await.take().ok_or_else(|| CommandError::state("no new recovery key is being set"))?;
    if let Err(e) = typed_matches(&pending.new_key, &typed) {
        *state.pending_new_key.lock().await = Some(pending);
        return Err(e);
    }
    // Nothing changed when this fails: the key shown is still the one to type back.
    if let Err(e) = flows::account::replace_recovery_key(&state.client, &state.relay, &pending.current, &pending.new_key).await {
        *state.pending_new_key.lock().await = Some(pending);
        return Err(e.into());
    }
    Ok(())
}

#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn cancel_new_recovery_key(state: State<'_, AppState>) -> CommandResult<()> {
    *state.pending_new_key.lock().await = None;
    Ok(())
}

// ── Home relay ──────────────────────────────────────────────────────

/// Move the account's home to `relay_url`, which the recovery key authorises, and
/// connect there. Servers made on the old home stay where they are.
#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn move_home(recovery_key: String, relay_url: String, app: tauri::AppHandle, state: State<'_, AppState>) -> CommandResult<()> {
    let key = RecoveryKey::parse(&recovery_key)?;
    let relay_url = relay_url_input(&relay_url)?;
    let new_home = state.relay.at(&relay_url);
    flows::account::rehome(&state.client, &new_home, Some(state.relay.as_ref()), &key).await?;
    {
        let mut cfg = state.config.lock().await;
        cfg.relay_url = Some(relay_url.clone());
        cfg.save(&state.config_path)?;
    }
    let inbox_rx = replace_relay(&state, &relay_url).await;
    spawn_relay_task(app, &state, inbox_rx).await;
    Ok(())
}

/// Forget this device's account, after another device removed it: its record and
/// databases go, and the app restarts into setup.
#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub async fn reset_device(app: tauri::AppHandle, state: State<'_, AppState>) -> CommandResult<()> {
    // The app restarts into setup; the session is cut off with the process.
    if let Some(handle) = state.relay_task_handle.lock().await.take() {
        handle.abort();
    }
    if let Err(e) = state.voice.leave().await {
        tracing::warn!("reset: the call not left: {e}");
    }
    {
        let mut cfg = state.config.lock().await;
        cfg.forget_account();
        cfg.save(&state.config_path)?;
    }
    crate::setup::delete_device();
    crate::setup::wipe_local_databases();
    crate::setup::wipe_account_files();
    app.restart();
}

#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub fn exit_app(app: tauri::AppHandle) {
    app.exit(0);
}

/// The latest relay connectivity, online presence and voice rosters, for a front end
/// that starts after the session reported them.
#[tauri::command]
pub async fn live_state(state: State<'_, AppState>) -> CommandResult<crate::relay_task::LiveStateDto> {
    let status = state.presence.lock().await.status.into();
    Ok(state.live.lock().unwrap().snapshot(status))
}

/// The user acted in this window: an idle device is back online at once, rather than at
/// the idle task's next poll.
#[tauri::command]
pub async fn note_activity(app: tauri::AppHandle, state: State<'_, AppState>) -> CommandResult<()> {
    crate::idle_task::back_from_idle(&app, &state.handles()).await;
    Ok(())
}

/// The user dismissed an account alert, so a reload does not show it again.
#[tauri::command]
pub fn dismiss_alert(id: u64, state: State<'_, AppState>) -> CommandResult<()> {
    state.live.lock().unwrap().dismiss_alert(id);
    Ok(())
}
