use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use rand::RngCore;
use tauri::State;

use ghost_core::storage::{Channel, ChannelKind, Group, Member, MemberRole, StoredMessage};
use ghost_core::wire::{encode_channel_op, encode_member_announce, ChannelOpPayload};

use crate::constants::{DEFAULT_PAGE_SIZE, INVITE_EXPIRY_MS, SEQ_HEADER};
use crate::config::KeybindConfig;
use crate::dto::{ChannelDto, ConfigDto, GroupDto, IdentityDto, InviteDto, KeybindConfigDto, MemberDto, MessageDto};
use crate::state::AppState;
use crate::voice_task::VoiceCommand;

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
    let store = client.store();
    let groups = store.list_groups().map_err(|e| e.to_string())?;
    let unread_groups = store.groups_with_unread().map_err(|e| e.to_string())?;
    Ok(groups
        .iter()
        .map(|g| GroupDto::from_group(g, unread_groups.contains(&g.group_id)))
        .collect())
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
        (GroupDto::from_group(&group, false), mid)
    };

    if let Some(mid) = mailbox_id {
        let mut relay = state.relay.lock().await;
        relay.subscribe(mid, 0);
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
    let store = client.store();
    let channels = store.list_channels(&gid).map_err(|e| e.to_string())?;
    let unread = store.get_unread_counts(&gid).map_err(|e| e.to_string())?;
    let unread_map: std::collections::HashMap<[u8; 32], u32> = unread.into_iter().collect();
    Ok(channels
        .iter()
        .map(|c| ChannelDto::from_channel(c, unread_map.get(&c.channel_id).copied().unwrap_or(0)))
        .collect())
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

    let outbound = {
        let mut client = state.client.lock().await;
        let position = client
            .store()
            .list_channels(&gid)
            .map_err(|e| e.to_string())?
            .len() as i32;
        let channel = Channel {
            channel_id,
            group_id: gid,
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
            .send_control(&gid, encode_channel_op(&op))
            .map_err(|e| e.to_string())?
    };

    let relay = state.relay.lock().await;
    let _ = relay.send(&outbound.mailbox_id, outbound.blob).await;

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

    let outbound = {
        let mut client = state.client.lock().await;
        let channel = client.store().get_channel(&cid).map_err(|e| e.to_string())?;
        client
            .store()
            .rename_channel(&cid, &name)
            .map_err(|e| e.to_string())?;

        let op = ChannelOpPayload::Rename { channel_id: cid, name };
        client
            .send_control(&channel.group_id, encode_channel_op(&op))
            .map_err(|e| e.to_string())?
    };

    let relay = state.relay.lock().await;
    let _ = relay.send(&outbound.mailbox_id, outbound.blob).await;
    Ok(())
}

#[tauri::command]
pub async fn delete_channel(
    channel_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let cid = parse_id(&channel_id)?;

    let outbound = {
        let mut client = state.client.lock().await;
        let channel = client.store().get_channel(&cid).map_err(|e| e.to_string())?;
        client
            .store()
            .delete_channel(&cid)
            .map_err(|e| e.to_string())?;

        let op = ChannelOpPayload::Delete { channel_id: cid };
        client
            .send_control(&channel.group_id, encode_channel_op(&op))
            .map_err(|e| e.to_string())?
    };

    let relay = state.relay.lock().await;
    let _ = relay.send(&outbound.mailbox_id, outbound.blob).await;
    Ok(())
}

#[tauri::command]
pub async fn mark_channel_read(
    channel_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let cid = parse_id(&channel_id)?;
    let client = state.client.lock().await;
    client
        .store()
        .mark_channel_read(&cid, now_millis())
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
    #[derive(serde::Deserialize)]
    struct PostBlobResp { seq: u64 }
    let commit_resp = state
        .http
        .post(format!("{}/box/{}", relay_url, mailbox_b64))
        .body(commit_bytes)
        .send()
        .await
        .map_err(|e| format!("broadcast commit: {e}"))?
        .error_for_status()
        .map_err(|e| format!("broadcast commit: {e}"))?;
    let commit_seq = commit_resp.json::<PostBlobResp>().await
        .map(|r| r.seq).unwrap_or(0);

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

    // Subscribe from the commit seq so we don't replay stale messages
    let announce = {
        let mut client = state.client.lock().await;
        let _ = client.store().set_last_seen_seq(&mailbox_id, commit_seq);
        let name = client.identity().display_name.clone();
        match client.send_control(&group_id, encode_member_announce(&name)) {
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

    let client = state.client.lock().await;
    let group = client
        .store()
        .get_group(&group_id)
        .map_err(|e| e.to_string())?;
    Ok(GroupDto::from_group(&group, false))
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
    Ok(ConfigDto {
        display_name: cfg.display_name.clone(),
        relay_url: cfg.relay_url.clone(),
        input_device: cfg.input_device.clone(),
        output_device: cfg.output_device.clone(),
        noise_suppression: ns.to_string(),
        agc: agc.to_string(),
        input_mode: input_mode.to_string(),
    })
}

#[tauri::command]
pub async fn set_display_name(
    name: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let mut cfg = state.config.lock().await;
    cfg.display_name = Some(name.clone());
    cfg.save(&state.config_path)?;

    let mut client = state.client.lock().await;
    client.set_display_name(name);
    Ok(())
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
    group_id: String,
    channel_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let fingerprint = {
        let client = state.client.lock().await;
        hex::encode(client.fingerprint())
    };
    let (relay_url, input_device, output_device, ns_mode, agc_mode) = {
        let cfg = state.config.lock().await;
        let url = cfg
            .relay_url
            .as_deref()
            .filter(|u| !u.is_empty())
            .map(String::from)
            .unwrap_or_else(|| state.relay_url.clone());
        (url, cfg.input_device.clone(), cfg.output_device.clone(), cfg.noise_suppression_mode(), cfg.agc_mode())
    };
    state
        .voice
        .cmd_tx
        .send(VoiceCommand::Join {
            group_id,
            channel_id,
            relay_url,
            fingerprint,
            input_device,
            output_device,
            ns_mode: ns_mode as u8,
            agc_mode: agc_mode as u8,
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
pub async fn seed_test_data(state: State<'_, AppState>) -> Result<(), String> {
    let client = state.client.lock().await;
    let store = client.store();
    let own_fp = *client.fingerprint();
    let now = now_millis();

    let mut rng = rand::rngs::OsRng;
    let mut id = || -> [u8; 32] {
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        b
    };

    // Fake member fingerprints
    let alice_fp = id();
    let bob_fp = id();
    let carol_fp = id();
    let dave_fp = id();
    let eve_fp = id();

    // --- Group 1: ghost-dev (3 text, 1 voice, 4 members) ---
    let g1 = id();
    store.insert_group(&Group { group_id: g1, name: "ghost-dev".into(), creator_fp: own_fp, created_at: now - 86_400_000 }).map_err(|e| e.to_string())?;
    let g1_general = id();
    let g1_random = id();
    let g1_bugs = id();
    let g1_voice = id();
    store.insert_channel(&Channel { channel_id: g1_general, group_id: g1, name: "general".into(), kind: ChannelKind::Text, position: 0 }).map_err(|e| e.to_string())?;
    store.insert_channel(&Channel { channel_id: g1_random, group_id: g1, name: "random".into(), kind: ChannelKind::Text, position: 1 }).map_err(|e| e.to_string())?;
    store.insert_channel(&Channel { channel_id: g1_bugs, group_id: g1, name: "bugs".into(), kind: ChannelKind::Text, position: 2 }).map_err(|e| e.to_string())?;
    store.insert_channel(&Channel { channel_id: g1_voice, group_id: g1, name: "standup".into(), kind: ChannelKind::Voice, position: 3 }).map_err(|e| e.to_string())?;
    store.insert_member(&Member { group_id: g1, fingerprint: own_fp, display_name: client.identity().display_name.clone(), role: MemberRole::Creator, joined_at: now - 86_400_000 }).map_err(|e| e.to_string())?;
    store.insert_member(&Member { group_id: g1, fingerprint: alice_fp, display_name: "alice".into(), role: MemberRole::Member, joined_at: now - 82_000_000 }).map_err(|e| e.to_string())?;
    store.insert_member(&Member { group_id: g1, fingerprint: bob_fp, display_name: "bob".into(), role: MemberRole::Member, joined_at: now - 80_000_000 }).map_err(|e| e.to_string())?;
    store.insert_member(&Member { group_id: g1, fingerprint: carol_fp, display_name: "carol".into(), role: MemberRole::Member, joined_at: now - 78_000_000 }).map_err(|e| e.to_string())?;

    // Messages in #general — conversation about the project
    let msgs: &[(&[u8; 32], &str)] = &[
        (&alice_fp, "hey, just pushed the new sidebar refactor"),
        (&bob_fp, "nice, pulling now"),
        (&bob_fp, "the view transitions are smooth"),
        (&own_fp, "thanks! the icon morph was the tricky part"),
        (&alice_fp, "yeah I noticed that. how did you handle the text transition?"),
        (&own_fp, "stripped the text transitions entirely — bitmap scaling looked bad"),
        (&own_fp, "just morphing the icons now, text swaps instantly"),
        (&carol_fp, "makes sense. discord does the same thing"),
        (&bob_fp, "are we keeping the collapsible channel sections?"),
        (&own_fp, "yep, text channels and voice channels as separate sections"),
        (&alice_fp, "the command palette feels snappy too"),
        (&carol_fp, "agreed, the fuzzy search is nice"),
        (&bob_fp, "what's next on the roadmap?"),
        (&own_fp, "voice UI — connecting the SFU relay to the frontend"),
        (&alice_fp, "can't wait to test that"),
    ];
    for (i, (sender, content)) in msgs.iter().enumerate() {
        let t = now - 3_600_000 + (i as u64 * 120_000);
        store.insert_message(&StoredMessage {
            message_id: id(), channel_id: g1_general, sender_fp: **sender,
            message_type: 0, timestamp: t, received_at: t, content: content.as_bytes().to_vec(),
            expires_at: None, references: vec![],
        }).map_err(|e| e.to_string())?;
    }

    // Messages in #bugs
    let bug_msgs: &[(&[u8; 32], &str)] = &[
        (&bob_fp, "scrollbar flickers on fast scroll in the message view"),
        (&alice_fp, "can confirm, happens on macOS 14.5"),
        (&own_fp, "looking into it — might be the custom scrollbar CSS"),
        (&carol_fp, "also seeing a layout shift when switching between groups"),
        (&own_fp, "that's the view transition — I'll check the timing"),
    ];
    for (i, (sender, content)) in bug_msgs.iter().enumerate() {
        let t = now - 7_200_000 + (i as u64 * 180_000);
        store.insert_message(&StoredMessage {
            message_id: id(), channel_id: g1_bugs, sender_fp: **sender,
            message_type: 0, timestamp: t, received_at: t, content: content.as_bytes().to_vec(),
            expires_at: None, references: vec![],
        }).map_err(|e| e.to_string())?;
    }

    // --- Group 2: design-club (2 text, 1 voice, 3 members) ---
    let g2 = id();
    store.insert_group(&Group { group_id: g2, name: "design-club".into(), creator_fp: alice_fp, created_at: now - 172_800_000 }).map_err(|e| e.to_string())?;
    let g2_inspo = id();
    let g2_feedback = id();
    let g2_voice = id();
    store.insert_channel(&Channel { channel_id: g2_inspo, group_id: g2, name: "inspiration".into(), kind: ChannelKind::Text, position: 0 }).map_err(|e| e.to_string())?;
    store.insert_channel(&Channel { channel_id: g2_feedback, group_id: g2, name: "feedback".into(), kind: ChannelKind::Text, position: 1 }).map_err(|e| e.to_string())?;
    store.insert_channel(&Channel { channel_id: g2_voice, group_id: g2, name: "voice-chat".into(), kind: ChannelKind::Voice, position: 2 }).map_err(|e| e.to_string())?;
    store.insert_member(&Member { group_id: g2, fingerprint: alice_fp, display_name: "alice".into(), role: MemberRole::Creator, joined_at: now - 172_800_000 }).map_err(|e| e.to_string())?;
    store.insert_member(&Member { group_id: g2, fingerprint: own_fp, display_name: client.identity().display_name.clone(), role: MemberRole::Member, joined_at: now - 170_000_000 }).map_err(|e| e.to_string())?;
    store.insert_member(&Member { group_id: g2, fingerprint: dave_fp, display_name: "dave".into(), role: MemberRole::Member, joined_at: now - 168_000_000 }).map_err(|e| e.to_string())?;

    let inspo_msgs: &[(&[u8; 32], &str)] = &[
        (&alice_fp, "found this amazing dark UI kit — pure black with accent colors"),
        (&dave_fp, "link?"),
        (&alice_fp, "it's that linear-style approach, everything is var-based"),
        (&own_fp, "that's exactly what we're going for with ghost"),
        (&dave_fp, "the monospace font choice is a nice touch"),
        (&alice_fp, "iosevka is perfect for this"),
    ];
    for (i, (sender, content)) in inspo_msgs.iter().enumerate() {
        let t = now - 14_400_000 + (i as u64 * 240_000);
        store.insert_message(&StoredMessage {
            message_id: id(), channel_id: g2_inspo, sender_fp: **sender,
            message_type: 0, timestamp: t, received_at: t, content: content.as_bytes().to_vec(),
            expires_at: None, references: vec![],
        }).map_err(|e| e.to_string())?;
    }

    // --- Group 3: music (1 text, 1 voice, 5 members) ---
    let g3 = id();
    store.insert_group(&Group { group_id: g3, name: "music".into(), creator_fp: carol_fp, created_at: now - 259_200_000 }).map_err(|e| e.to_string())?;
    let g3_recs = id();
    let g3_listen = id();
    store.insert_channel(&Channel { channel_id: g3_recs, group_id: g3, name: "recommendations".into(), kind: ChannelKind::Text, position: 0 }).map_err(|e| e.to_string())?;
    store.insert_channel(&Channel { channel_id: g3_listen, group_id: g3, name: "listening-party".into(), kind: ChannelKind::Voice, position: 1 }).map_err(|e| e.to_string())?;
    store.insert_member(&Member { group_id: g3, fingerprint: carol_fp, display_name: "carol".into(), role: MemberRole::Creator, joined_at: now - 259_200_000 }).map_err(|e| e.to_string())?;
    store.insert_member(&Member { group_id: g3, fingerprint: own_fp, display_name: client.identity().display_name.clone(), role: MemberRole::Member, joined_at: now - 250_000_000 }).map_err(|e| e.to_string())?;
    store.insert_member(&Member { group_id: g3, fingerprint: alice_fp, display_name: "alice".into(), role: MemberRole::Member, joined_at: now - 248_000_000 }).map_err(|e| e.to_string())?;
    store.insert_member(&Member { group_id: g3, fingerprint: bob_fp, display_name: "bob".into(), role: MemberRole::Member, joined_at: now - 246_000_000 }).map_err(|e| e.to_string())?;
    store.insert_member(&Member { group_id: g3, fingerprint: eve_fp, display_name: "eve".into(), role: MemberRole::Member, joined_at: now - 244_000_000 }).map_err(|e| e.to_string())?;

    let rec_msgs: &[(&[u8; 32], &str)] = &[
        (&carol_fp, "new burial album dropped"),
        (&eve_fp, "oh nice, listening now"),
        (&bob_fp, "anyone heard the new four tet set?"),
        (&alice_fp, "yes! the transition at 42 min is insane"),
        (&own_fp, "adding both to the queue"),
        (&carol_fp, "we should do a listening party this weekend"),
        (&eve_fp, "I'm in"),
        (&bob_fp, "same"),
    ];
    for (i, (sender, content)) in rec_msgs.iter().enumerate() {
        let t = now - 28_800_000 + (i as u64 * 300_000);
        store.insert_message(&StoredMessage {
            message_id: id(), channel_id: g3_recs, sender_fp: **sender,
            message_type: 0, timestamp: t, received_at: t, content: content.as_bytes().to_vec(),
            expires_at: None, references: vec![],
        }).map_err(|e| e.to_string())?;
    }

    // Pin the first group
    store.pin_group(&g1, now).map_err(|e| e.to_string())?;

    Ok(())
}

// Dev session file for multi-instance testing — instance 1 writes this, others read and auto-join
const DEV_SESSION_PATH: &str = "/tmp/ghost-dev-session.json";

#[derive(serde::Serialize, serde::Deserialize)]
pub struct DevSession {
    relay_url: String,
    token: String,
}

#[tauri::command]
pub async fn create_dev_session(state: State<'_, AppState>) -> Result<GroupDto, String> {
    // Create group
    let (group_id, mailbox_id) = {
        let mut client = state.client.lock().await;
        let gid = client
            .create_group("dev", now_millis())
            .map_err(|e| e.to_string())?;
        let mid = client.mailbox_id_for_group(&gid);

        // Create default channels
        let mut general_id = [0u8; 32];
        let mut voice_id = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut general_id);
        rand::rngs::OsRng.fill_bytes(&mut voice_id);
        let position = client
            .store()
            .list_channels(&gid)
            .map_err(|e| e.to_string())?
            .len() as i32;
        client
            .store()
            .insert_channel(&Channel {
                channel_id: general_id,
                group_id: gid,
                name: "general".into(),
                kind: ChannelKind::Text,
                position,
            })
            .map_err(|e| e.to_string())?;
        client
            .store()
            .insert_channel(&Channel {
                channel_id: voice_id,
                group_id: gid,
                name: "voice".into(),
                kind: ChannelKind::Voice,
                position: position + 1,
            })
            .map_err(|e| e.to_string())?;

        (gid, mid)
    };

    // Subscribe to mailbox
    if let Some(mid) = mailbox_id {
        let mut relay = state.relay.lock().await;
        relay.subscribe(mid, 0);
    }

    // Create invite and upload to relay
    let (token, payload_bytes) = {
        let client = state.client.lock().await;
        client.create_invite(&group_id).map_err(|e| e.to_string())?
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

    // Write session file so other instances can auto-join
    let session = DevSession {
        relay_url: state.relay_url.clone(),
        token,
    };
    std::fs::write(
        DEV_SESSION_PATH,
        serde_json::to_string(&session).unwrap(),
    )
    .map_err(|e| format!("write dev session: {e}"))?;

    let client = state.client.lock().await;
    let group = client
        .store()
        .get_group(&group_id)
        .map_err(|e| e.to_string())?;
    Ok(GroupDto::from_group(&group, false))
}

#[tauri::command]
pub async fn read_dev_session() -> Result<Option<DevSession>, String> {
    match std::fs::read_to_string(DEV_SESSION_PATH) {
        Ok(content) => {
            let session: DevSession =
                serde_json::from_str(&content).map_err(|e| e.to_string())?;
            Ok(Some(session))
        }
        Err(_) => Ok(None),
    }
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
    let ns = match mode.as_str() {
        "off" => crate::audio::NoiseSuppressionMode::Off,
        _ => crate::audio::NoiseSuppressionMode::Nnnoiseless,
    };
    let mut cfg = state.config.lock().await;
    cfg.noise_suppression = Some(mode);
    cfg.save(&state.config_path)?;
    state
        .voice
        .cmd_tx
        .send(VoiceCommand::SetNoiseSuppression(ns as u8))
        .await
        .map_err(|_| "voice task not running".to_string())
}

#[tauri::command]
pub async fn set_agc(
    mode: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let agc = match mode.as_str() {
        "off" => crate::audio::AgcMode::Off,
        _ => crate::audio::AgcMode::Auto,
    };
    let mut cfg = state.config.lock().await;
    cfg.agc = Some(mode);
    cfg.save(&state.config_path)?;
    state
        .voice
        .cmd_tx
        .send(VoiceCommand::SetAgc(agc as u8))
        .await
        .map_err(|_| "voice task not running".to_string())
}

#[tauri::command]
pub async fn set_input_mode(
    mode: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    match mode.as_str() {
        "voice_activity" | "push_to_talk" => {}
        _ => return Err(format!("unknown input mode: {mode}")),
    }
    let mut cfg = state.config.lock().await;
    cfg.input_mode = Some(mode);
    cfg.save(&state.config_path)
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
