//! Who is in each voice channel and who is online in each server, rebuilt from the
//! sealed presence blobs relays fan out over mailbox connections.

use std::collections::{HashMap, HashSet};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::Deserialize;

use crate::client::GhostClient;
use crate::mls::presence::OnlinePresence;
use crate::mls::voice::PresenceState;

use super::events::{ClientEvent, OnlineMember, VoiceMember};

/// Most presence blobs kept per server while they cannot be opened yet (they were
/// sealed at an epoch this device has not reached).
const MAX_PENDING_PRESENCE: usize = 64;

fn json_str<'a>(obj: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    obj.get(key)?.as_str()
}

fn decode_b64(b64: &str) -> Option<Vec<u8>> {
    B64.decode(b64).ok()
}

fn decode_id(b64: &str) -> Option<[u8; 32]> {
    decode_b64(b64)?.try_into().ok()
}

#[derive(Deserialize)]
struct VoiceStateMsg {
    ch: String,
    p: Option<String>,
    leave: Option<bool>,
}

/// Voice channel membership across this device's servers.
#[derive(Default)]
pub(super) struct VoiceRoster {
    members: HashMap<[u8; 32], Vec<PresenceState>>,
    /// Channels each mailbox reported, so one server's snapshot leaves others alone.
    mailbox_channels: HashMap<[u8; 32], HashSet<[u8; 32]>>,
}

fn voice_event(channel_id: &[u8; 32], members: &[PresenceState]) -> ClientEvent {
    ClientEvent::VoiceChannelMembers {
        channel_id: *channel_id,
        members: members
            .iter()
            .map(|m| VoiceMember { fingerprint: m.fingerprint, muted: m.muted, deafened: m.deafened })
            .collect(),
    }
}

impl VoiceRoster {
    /// Apply a voice-state message (a snapshot or one update) from a mailbox.
    pub(super) fn apply(&mut self, client: &GhostClient, mailbox_id: &[u8; 32], json: &str) -> Vec<ClientEvent> {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(json) else { return Vec::new() };
        if client.server_id_for_mailbox(mailbox_id).is_none() {
            return Vec::new();
        }
        let mut events = Vec::new();

        if let Some(entries) = value.get("vs_snap").and_then(|v| v.as_array()) {
            // A snapshot replaces only the channels belonging to this mailbox.
            if let Some(old_channels) = self.mailbox_channels.remove(mailbox_id) {
                for channel_id in &old_channels {
                    if self.members.remove(channel_id).is_some_and(|m| !m.is_empty()) {
                        events.push(voice_event(channel_id, &[]));
                    }
                }
            }
            for entry in entries {
                let Some(channel_id) = json_str(entry, "ch").and_then(decode_id) else { continue };
                let Some(blob) = json_str(entry, "p").and_then(decode_b64) else { continue };
                if let Ok(ps) = client.open_presence_blob(&channel_id, &blob) {
                    self.members.entry(channel_id).or_default().push(ps);
                    self.mailbox_channels.entry(*mailbox_id).or_default().insert(channel_id);
                }
            }
            if let Some(channels) = self.mailbox_channels.get(mailbox_id) {
                for channel_id in channels {
                    if let Some(members) = self.members.get(channel_id) {
                        events.push(voice_event(channel_id, members));
                    }
                }
            }
            return events;
        }

        let Some(msg) = value.get("vs").and_then(|v| serde_json::from_value::<VoiceStateMsg>(v.clone()).ok()) else {
            return events;
        };
        let Some(channel_id) = decode_id(&msg.ch) else { return events };
        let Some(blob) = msg.p.as_deref().and_then(decode_b64) else { return events };
        let Ok(ps) = client.open_presence_blob(&channel_id, &blob) else { return events };
        if msg.leave == Some(true) {
            self.leave(&channel_id, &ps, mailbox_id, &mut events);
        } else {
            self.join(&channel_id, ps, mailbox_id, &mut events);
        }
        events
    }

    fn leave(&mut self, channel_id: &[u8; 32], ps: &PresenceState, mailbox_id: &[u8; 32], events: &mut Vec<ClientEvent>) {
        let Some(members) = self.members.get_mut(channel_id) else { return };
        members.retain(|m| !(m.fingerprint == ps.fingerprint && m.device_vk == ps.device_vk));
        if members.is_empty() {
            events.push(voice_event(channel_id, &[]));
            self.members.remove(channel_id);
            if let Some(channels) = self.mailbox_channels.get_mut(mailbox_id) {
                channels.remove(channel_id);
            }
        } else {
            events.push(voice_event(channel_id, members));
        }
    }

    fn join(&mut self, channel_id: &[u8; 32], ps: PresenceState, mailbox_id: &[u8; 32], events: &mut Vec<ClientEvent>) {
        self.mailbox_channels.entry(*mailbox_id).or_default().insert(*channel_id);
        let members = self.members.entry(*channel_id).or_default();
        match members.iter_mut().find(|m| m.fingerprint == ps.fingerprint && m.device_vk == ps.device_vk) {
            Some(existing) => {
                existing.muted = ps.muted;
                existing.deafened = ps.deafened;
            }
            None => members.push(ps),
        }
        events.push(voice_event(channel_id, members));
    }
}

/// Online presence across this device's servers.
#[derive(Default)]
pub(super) struct OnlineRoster {
    members: HashMap<[u8; 32], Vec<OnlineMember>>,
    /// Blobs that did not open yet (sealed at a later epoch), retried after commits.
    pending: HashMap<[u8; 32], Vec<Vec<u8>>>,
}

/// What applying online presence produced: events, and avatars to fetch.
#[derive(Default)]
pub(super) struct OnlineUpdate {
    pub events: Vec<ClientEvent>,
    /// (server, member, avatar hash) for avatars the cache may be missing.
    pub avatars: Vec<([u8; 32], [u8; 32], [u8; 32])>,
}

fn online_event(server_id: &[u8; 32], members: &[OnlineMember]) -> ClientEvent {
    ClientEvent::OnlinePresence { server_id: *server_id, members: members.to_vec() }
}

/// Drop a status message whose expiry passed (its sender may have crashed before clearing it).
fn drop_expired_status(ps: &mut OnlinePresence, now: u64) {
    if ps.status_expiry.is_some_and(|expiry| now >= expiry) {
        ps.status_message = None;
        ps.status_expiry = None;
    }
}

/// Open a presence blob and upsert the member. Returns the member and its avatar hash.
fn upsert(
    client: &GhostClient,
    server_id: &[u8; 32],
    blob: &[u8],
    members: &mut Vec<OnlineMember>,
    now: u64,
) -> Option<([u8; 32], Option<[u8; 32]>)> {
    let mut ps = client.open_online_presence_blob(server_id, blob).ok()?;
    drop_expired_status(&mut ps, now);
    let member = OnlineMember {
        fingerprint: ps.fingerprint,
        status: ps.status,
        status_message: ps.status_message,
        avatar_hash: ps.avatar_hash,
    };
    match members.iter_mut().find(|m| m.fingerprint == member.fingerprint) {
        Some(existing) => *existing = member,
        None => members.push(member),
    }
    Some((ps.fingerprint, ps.avatar_hash))
}

impl OnlineRoster {
    /// Apply an online-presence message (a snapshot, an update or a leave) from a mailbox.
    pub(super) fn apply(&mut self, client: &GhostClient, mailbox_id: &[u8; 32], json: &str, now: u64) -> OnlineUpdate {
        let mut update = OnlineUpdate::default();
        let Ok(value) = serde_json::from_str::<serde_json::Value>(json) else { return update };
        let Some(server_id) = client.server_id_for_mailbox(mailbox_id) else { return update };

        if let Some(entries) = value.get("ps_snap").and_then(|v| v.as_array()) {
            let mut members = Vec::new();
            let mut failed = Vec::new();
            for entry in entries {
                let Some(blob) = json_str(entry, "p").and_then(decode_b64) else { continue };
                match upsert(client, &server_id, &blob, &mut members, now) {
                    Some((fp, Some(hash))) => update.avatars.push((server_id, fp, hash)),
                    Some(_) => {}
                    None => failed.push(blob),
                }
            }
            update.events.push(online_event(&server_id, &members));
            self.members.insert(server_id, members);
            if failed.is_empty() {
                self.pending.remove(&server_id);
            } else {
                failed.truncate(MAX_PENDING_PRESENCE);
                self.pending.insert(server_id, failed);
            }
            return update;
        }

        let Some(ps_value) = value.get("ps") else { return update };
        let leave = ps_value.get("leave").and_then(|v| v.as_bool()).unwrap_or(false);
        let Some(blob) = json_str(ps_value, "p").and_then(decode_b64) else { return update };
        let members = self.members.entry(server_id).or_default();
        if leave {
            // Opened only to learn who left.
            if let Ok(ps) = client.open_online_presence_blob(&server_id, &blob) {
                members.retain(|m| m.fingerprint != ps.fingerprint);
                update.events.push(online_event(&server_id, members));
            }
        } else if let Some((fp, hash)) = upsert(client, &server_id, &blob, members, now) {
            update.events.push(online_event(&server_id, members));
            if let Some(hash) = hash {
                update.avatars.push((server_id, fp, hash));
            }
        } else {
            let pending = self.pending.entry(server_id).or_default();
            if pending.len() < MAX_PENDING_PRESENCE {
                pending.push(blob);
            }
        }
        update
    }

    /// Retry blobs that did not open, after a commit moved this device's epoch.
    pub(super) fn retry_pending(&mut self, client: &GhostClient, server_id: &[u8; 32], now: u64) -> Vec<ClientEvent> {
        let Some(blobs) = self.pending.remove(server_id).filter(|b| !b.is_empty()) else { return Vec::new() };
        let members = self.members.entry(*server_id).or_default();
        let still_pending: Vec<Vec<u8>> = blobs
            .into_iter()
            .filter(|blob| upsert(client, server_id, blob, members, now).is_none())
            .collect();
        let event = online_event(server_id, members);
        if !still_pending.is_empty() {
            self.pending.insert(*server_id, still_pending);
        }
        vec![event]
    }
}
