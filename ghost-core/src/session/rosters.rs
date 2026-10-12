//! Who is in each voice channel and who is online in each server, rebuilt from the
//! sealed presence blobs relays fan out over mailbox connections. Each announcement
//! carries the relay's stamp of the device that sent it; a blob opens only as that
//! device's, so the rosters trust the stamp exactly as far as the seal confirms it.

use std::collections::{HashMap, HashSet};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ghost_wire::presence::{OnlineStateMsg, PresenceSender, VoiceStateMsg};

use crate::client::GhostClient;
use crate::mls::presence::{AvatarRef, OnlinePresence};
use crate::mls::voice::PresenceState;

use super::events::{ClientEvent, OnlineMember, VoiceMember};

/// Most senders whose presence is kept per server while it cannot be opened yet (it was
/// sealed at an epoch this device has not reached).
const MAX_PENDING_PRESENCE: usize = 64;

fn decode_b64(b64: &str) -> Option<Vec<u8>> {
    B64.decode(b64).ok()
}

fn decode_id(b64: &str) -> Option<[u8; 32]> {
    decode_b64(b64)?.try_into().ok()
}

/// The entries of a snapshot, each parsed as an announcement; malformed ones are skipped.
fn snapshot_entries<T: serde::de::DeserializeOwned>(value: &serde_json::Value, key: &str) -> Option<Vec<T>> {
    let entries = value.get(key)?.as_array()?;
    Some(entries.iter().filter_map(|entry| serde_json::from_value(entry.clone()).ok()).collect())
}

/// A voice presence that did not open yet: its channel, its sender and the blob.
type PendingVoice = ([u8; 32], PresenceSender, Vec<u8>);

/// Voice channel membership across this device's servers.
#[derive(Default)]
pub(super) struct VoiceRoster {
    members: HashMap<[u8; 32], Vec<PresenceState>>,
    /// Channels each mailbox reported, so one server's snapshot leaves others alone.
    mailbox_channels: HashMap<[u8; 32], HashSet<[u8; 32]>>,
    /// Per mailbox, each sender's latest presence that did not open (sealed at an epoch
    /// this device has not reached), retried after commits. Whatever the sender says
    /// next replaces it.
    pending: HashMap<[u8; 32], Vec<PendingVoice>>,
}

/// One member per account: what its most recently joined device says. The relay holds
/// one device per account in a call, so two show only while one replaces the other.
fn voice_event(channel_id: &[u8; 32], members: &[PresenceState]) -> ClientEvent {
    let mut shown: Vec<VoiceMember> = Vec::new();
    for m in members {
        let member = VoiceMember { fingerprint: m.fingerprint, muted: m.muted, deafened: m.deafened };
        match shown.iter_mut().find(|s| s.fingerprint == m.fingerprint) {
            Some(existing) => *existing = member,
            None => shown.push(member),
        }
    }
    ClientEvent::VoiceChannelMembers { channel_id: *channel_id, members: shown }
}

impl VoiceRoster {
    /// Apply a voice-state message (a snapshot or one update) from a mailbox.
    pub(super) fn apply(&mut self, client: &GhostClient, mailbox_id: &[u8; 32], json: &str) -> Vec<ClientEvent> {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(json) else { return Vec::new() };
        if client.server_id_for_mailbox(mailbox_id).is_none() {
            return Vec::new();
        }
        let mut events = Vec::new();

        if let Some(entries) = snapshot_entries::<VoiceStateMsg>(&value, "vs_snap") {
            // A snapshot replaces only the channels belonging to this mailbox, and reports
            // each once, as it ends up: a channel still in the snapshot never shows empty.
            let old_channels = self.mailbox_channels.remove(mailbox_id).unwrap_or_default();
            for channel_id in &old_channels {
                self.members.remove(channel_id);
            }
            let mut failed = Vec::new();
            for entry in entries {
                let Some(channel_id) = decode_id(&entry.ch) else { continue };
                let Some(blob) = entry.p.as_deref().and_then(decode_b64) else { continue };
                match client.open_presence_blob(&channel_id, &entry.from, &blob) {
                    Ok(ps) => {
                        self.members.entry(channel_id).or_default().push(ps);
                        self.mailbox_channels.entry(*mailbox_id).or_default().insert(channel_id);
                    }
                    Err(_) => failed.push((channel_id, entry.from, blob)),
                }
            }
            failed.truncate(MAX_PENDING_PRESENCE);
            self.pending.insert(*mailbox_id, failed);
            let channels = self.mailbox_channels.get(mailbox_id).cloned().unwrap_or_default();
            for channel_id in old_channels.difference(&channels) {
                events.push(voice_event(channel_id, &[]));
            }
            for channel_id in &channels {
                if let Some(members) = self.members.get(channel_id) {
                    events.push(voice_event(channel_id, members));
                }
            }
            return events;
        }

        let Some(msg) = value.get("vs").and_then(|v| serde_json::from_value::<VoiceStateMsg>(v.clone()).ok()) else {
            return events;
        };
        let Some(channel_id) = decode_id(&msg.ch) else { return events };
        // What the sender says now outdates a presence of theirs still waiting to open.
        let pending = self.pending.entry(*mailbox_id).or_default();
        pending.retain(|(_, sender, _)| *sender != msg.from);
        if msg.leave == Some(true) {
            self.leave(&channel_id, &msg.from, mailbox_id, &mut events);
            return events;
        }
        let Some(blob) = msg.p.as_deref().and_then(decode_b64) else { return events };
        match client.open_presence_blob(&channel_id, &msg.from, &blob) {
            Ok(ps) => self.join(&channel_id, ps, mailbox_id, &mut events),
            Err(_) if pending.len() < MAX_PENDING_PRESENCE => pending.push((channel_id, msg.from, blob)),
            Err(_) => {}
        }
        events
    }

    /// Retry the presences on `mailbox_id` that did not open, after a commit moved this
    /// device's epoch in one of its server's groups.
    pub(super) fn retry_pending(&mut self, client: &GhostClient, mailbox_id: &[u8; 32]) -> Vec<ClientEvent> {
        let Some(waiting) = self.pending.remove(mailbox_id).filter(|w| !w.is_empty()) else { return Vec::new() };
        let mut events = Vec::new();
        let mut still = Vec::new();
        for (channel_id, sender, blob) in waiting {
            match client.open_presence_blob(&channel_id, &sender, &blob) {
                Ok(ps) => self.join(&channel_id, ps, mailbox_id, &mut events),
                Err(_) => still.push((channel_id, sender, blob)),
            }
        }
        self.pending.insert(*mailbox_id, still);
        events
    }

    fn leave(&mut self, channel_id: &[u8; 32], from: &PresenceSender, mailbox_id: &[u8; 32], events: &mut Vec<ClientEvent>) {
        let Some(members) = self.members.get_mut(channel_id) else { return };
        members.retain(|m| m.sender() != *from);
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
        match members.iter_mut().find(|m| m.sender() == ps.sender()) {
            Some(existing) => {
                existing.muted = ps.muted;
                existing.deafened = ps.deafened;
            }
            None => members.push(ps),
        }
        events.push(voice_event(channel_id, members));
    }
}

/// One device's announced online presence.
struct OnlineEntry {
    sender: PresenceSender,
    member: OnlineMember,
}

/// Online presence across this device's servers, per announcing device, as each server's
/// own mailbox reports it.
#[derive(Default)]
pub(super) struct OnlineRoster {
    /// Each server's entries, oldest announcement first.
    entries: HashMap<[u8; 32], Vec<OnlineEntry>>,
    /// Each sender's latest blob that did not open yet (sealed at a later epoch), retried
    /// after commits. Whatever the sender says next replaces it.
    pending: HashMap<[u8; 32], Vec<(PresenceSender, Vec<u8>)>>,
}

/// What applying online presence produced: events, and avatars to fetch.
#[derive(Default)]
pub(super) struct OnlineUpdate {
    pub events: Vec<ClientEvent>,
    /// (server, member, avatar) as announced, for avatars the cache may be missing.
    pub avatars: Vec<([u8; 32], [u8; 32], AvatarRef)>,
}

/// One member per account: what its most recently announcing device said.
fn online_event(server_id: &[u8; 32], entries: &[OnlineEntry]) -> ClientEvent {
    let mut members: Vec<OnlineMember> = Vec::new();
    for entry in entries {
        match members.iter_mut().find(|m| m.fingerprint == entry.member.fingerprint) {
            Some(existing) => *existing = entry.member.clone(),
            None => members.push(entry.member.clone()),
        }
    }
    ClientEvent::OnlinePresence { server_id: *server_id, members }
}

/// Drop a status message whose expiry passed (its sender may have crashed before clearing it).
fn drop_expired_status(ps: &mut OnlinePresence, now: u64) {
    if ps.status_expiry.is_some_and(|expiry| now >= expiry) {
        ps.status_message = None;
        ps.status_expiry = None;
    }
}

/// Open a presence blob and record it as the sender's latest. Returns the sender's
/// account and the avatar it announced.
fn upsert(
    client: &GhostClient,
    server_id: &[u8; 32],
    sender: &PresenceSender,
    blob: &[u8],
    entries: &mut Vec<OnlineEntry>,
    now: u64,
) -> Option<([u8; 32], Option<AvatarRef>)> {
    let mut ps = client.open_online_presence_blob(server_id, sender, blob).ok()?;
    drop_expired_status(&mut ps, now);
    let member = OnlineMember {
        fingerprint: sender.account_fp,
        status: ps.status,
        status_message: ps.status_message,
        avatar_hash: ps.avatar.map(|a| a.hash),
    };
    entries.retain(|e| e.sender != *sender);
    entries.push(OnlineEntry { sender: *sender, member });
    Some((sender.account_fp, ps.avatar))
}

impl OnlineRoster {
    /// Apply an online-presence message (a snapshot, an update or a leave) from a mailbox.
    /// Only a server's own mailbox speaks for its roster: a private channel's would
    /// report just the members connected to it.
    pub(super) fn apply(&mut self, client: &GhostClient, mailbox_id: &[u8; 32], json: &str, now: u64) -> OnlineUpdate {
        let mut update = OnlineUpdate::default();
        let Ok(value) = serde_json::from_str::<serde_json::Value>(json) else { return update };
        let Some(server_id) = client.server_id_for_server_mailbox(mailbox_id) else { return update };

        if let Some(announced) = snapshot_entries::<OnlineStateMsg>(&value, "ps_snap") {
            let mut entries = Vec::new();
            let mut failed = Vec::new();
            for msg in announced {
                let Some(blob) = msg.p.as_deref().and_then(decode_b64) else { continue };
                match upsert(client, &server_id, &msg.from, &blob, &mut entries, now) {
                    Some((fp, Some(avatar))) => update.avatars.push((server_id, fp, avatar)),
                    Some(_) => {}
                    None => failed.push((msg.from, blob)),
                }
            }
            update.events.push(online_event(&server_id, &entries));
            self.entries.insert(server_id, entries);
            if failed.is_empty() {
                self.pending.remove(&server_id);
            } else {
                failed.truncate(MAX_PENDING_PRESENCE);
                self.pending.insert(server_id, failed);
            }
            return update;
        }

        let Some(msg) = value.get("ps").and_then(|v| serde_json::from_value::<OnlineStateMsg>(v.clone()).ok()) else {
            return update;
        };
        // What the sender says now outdates a blob of theirs still waiting to open.
        if let Some(pending) = self.pending.get_mut(&server_id) {
            pending.retain(|(sender, _)| *sender != msg.from);
        }
        let entries = self.entries.entry(server_id).or_default();
        if msg.leave == Some(true) {
            let before = entries.len();
            entries.retain(|e| e.sender != msg.from);
            if entries.len() != before {
                update.events.push(online_event(&server_id, entries));
            }
            return update;
        }
        let Some(blob) = msg.p.as_deref().and_then(decode_b64) else { return update };
        if let Some((fp, avatar)) = upsert(client, &server_id, &msg.from, &blob, entries, now) {
            update.events.push(online_event(&server_id, entries));
            if let Some(avatar) = avatar {
                update.avatars.push((server_id, fp, avatar));
            }
        } else {
            let pending = self.pending.entry(server_id).or_default();
            if pending.len() < MAX_PENDING_PRESENCE {
                pending.push((msg.from, blob));
            }
        }
        update
    }

    /// Retry blobs that did not open, after a commit moved this device's epoch.
    pub(super) fn retry_pending(&mut self, client: &GhostClient, server_id: &[u8; 32], now: u64) -> Vec<ClientEvent> {
        let Some(blobs) = self.pending.remove(server_id).filter(|b| !b.is_empty()) else { return Vec::new() };
        let entries = self.entries.entry(*server_id).or_default();
        let still_pending: Vec<(PresenceSender, Vec<u8>)> = blobs
            .into_iter()
            .filter(|(sender, blob)| upsert(client, server_id, sender, blob, entries, now).is_none())
            .collect();
        let event = online_event(server_id, entries);
        if !still_pending.is_empty() {
            self.pending.insert(*server_id, still_pending);
        }
        vec![event]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::testing::setup_two_clients;
    use crate::mls::presence::OnlineStatus;
    use crate::storage::ChannelKind;

    const NOW: u64 = 10_000;

    fn announced(client: &GhostClient, server_id: &[u8; 32], status: OnlineStatus) -> String {
        let blob = client.seal_online_presence_blob(server_id, status, None, None, None).unwrap();
        serde_json::json!({ "ps": OnlineStateMsg { p: Some(B64.encode(blob)), leave: None, from: client.presence_sender() } }).to_string()
    }

    fn left(client: &GhostClient) -> String {
        serde_json::json!({ "ps": OnlineStateMsg { p: None, leave: Some(true), from: client.presence_sender() } }).to_string()
    }

    /// The accounts the last roster event shows online.
    fn shown(events: &[ClientEvent]) -> Vec<[u8; 32]> {
        events
            .iter()
            .rev()
            .find_map(|e| match e {
                ClientEvent::OnlinePresence { members, .. } => Some(members.iter().map(|m| m.fingerprint).collect()),
                _ => None,
            })
            .unwrap_or_default()
    }

    #[test]
    fn only_a_servers_own_mailbox_speaks_for_its_roster() {
        let (mut owner, member, server_id) = setup_two_clients();
        let server_mailbox = owner.mailbox_id_for_server(&server_id).unwrap();
        let private = owner.create_private_channel(&server_id, "staff", ChannelKind::Text, 1, Vec::new(), Vec::new()).unwrap();
        let mut roster = OnlineRoster::default();

        let update = roster.apply(&owner, &server_mailbox, &announced(&member, &server_id, OnlineStatus::Online), NOW);
        assert_eq!(shown(&update.events), vec![*member.fingerprint()]);

        // The private channel's mailbox reports only who connected to it: here, nobody.
        assert!(roster.apply(&owner, &private.mailbox_id, r#"{"ps_snap":[]}"#, NOW).events.is_empty());
        assert!(roster.apply(&owner, &private.mailbox_id, &left(&member), NOW).events.is_empty());
        let update = roster.apply(&owner, &server_mailbox, &announced(&member, &server_id, OnlineStatus::Idle), NOW);
        assert_eq!(shown(&update.events), vec![*member.fingerprint()], "the member's entry did not survive the private mailbox");
    }

    #[test]
    fn a_voice_presence_from_a_later_epoch_shows_once_the_commit_is_in() {
        let (mut owner, mut member, server_id) = setup_two_clients();
        let server_mailbox = member.mailbox_id_for_server(&server_id).unwrap();
        let channel_id = crate::wire::derive_default_channel_id(&server_id);
        let mut roster = VoiceRoster::default();

        let mut policy = owner.server_policy(&server_id).unwrap();
        policy.everyone = 0;
        let commit = owner.stage_server_policy(&server_id, &policy).unwrap();
        owner.merge_pending_commit_for_channel(&commit.channel_id).unwrap();
        let blob = owner.seal_presence_blob(&channel_id, true, false, [9; 32]).unwrap();
        let announced = serde_json::json!({ "vs": VoiceStateMsg { ch: B64.encode(channel_id), p: Some(B64.encode(blob)), leave: None, from: owner.presence_sender() } });
        assert!(roster.apply(&member, &server_mailbox, &announced.to_string()).is_empty(), "a presence from a later epoch opened");

        member.receive_any(&commit.channel_id, &commit.blob, Some(1500)).unwrap();
        let events = roster.retry_pending(&member, &server_mailbox);
        let shown = events.iter().find_map(|e| match e {
            ClientEvent::VoiceChannelMembers { channel_id: c, members } if *c == channel_id => Some(members.clone()),
            _ => None,
        });
        assert_eq!(shown, Some(vec![VoiceMember { fingerprint: *owner.fingerprint(), muted: true, deafened: false }]));
    }

    #[test]
    fn a_voice_snapshot_reports_a_channel_still_in_it_once_and_never_empty() {
        let (owner, member, server_id) = setup_two_clients();
        let server_mailbox = member.mailbox_id_for_server(&server_id).unwrap();
        let channel_id = crate::wire::derive_default_channel_id(&server_id);
        let blob = owner.seal_presence_blob(&channel_id, false, false, [9; 32]).unwrap();
        let entry = VoiceStateMsg { ch: B64.encode(channel_id), p: Some(B64.encode(blob)), leave: None, from: owner.presence_sender() };
        let mut roster = VoiceRoster::default();
        roster.apply(&member, &server_mailbox, &serde_json::json!({ "vs": entry.clone() }).to_string());

        let events = roster.apply(&member, &server_mailbox, &serde_json::json!({ "vs_snap": [entry] }).to_string());
        let reported: Vec<usize> = events
            .iter()
            .filter_map(|e| match e {
                ClientEvent::VoiceChannelMembers { channel_id: c, members } if *c == channel_id => Some(members.len()),
                _ => None,
            })
            .collect();
        assert_eq!(reported, vec![1], "the channel was reported as {reported:?}");
        let emptied = roster.apply(&member, &server_mailbox, r#"{"vs_snap":[]}"#);
        assert!(matches!(&emptied[..], [ClientEvent::VoiceChannelMembers { members, .. }] if members.is_empty()), "a channel gone from the snapshot is reported empty");
    }

    #[test]
    fn two_devices_of_one_account_in_a_call_show_as_one_member() {
        let account = [7; 32];
        let phone = PresenceState::new(&PresenceSender { account_fp: account, device_vk: [1; 32] }, true, false, [0; 32]);
        let laptop = PresenceState::new(&PresenceSender { account_fp: account, device_vk: [2; 32] }, false, false, [0; 32]);
        let ClientEvent::VoiceChannelMembers { members, .. } = voice_event(&[3; 32], &[phone, laptop]) else { panic!("not a voice event") };
        assert_eq!(members, vec![VoiceMember { fingerprint: account, muted: false, deafened: false }], "the device that joined last speaks for the account");
    }

    #[test]
    fn a_blob_waiting_to_open_gives_way_to_what_its_sender_says_next() {
        let (mut owner, mut member, server_id) = setup_two_clients();
        let server_mailbox = member.mailbox_id_for_server(&server_id).unwrap();
        let mut roster = OnlineRoster::default();

        // The owner moves to an epoch the member has not reached and announces there.
        let mut policy = owner.server_policy(&server_id).unwrap();
        policy.everyone = 0;
        let commit = owner.stage_server_policy(&server_id, &policy).unwrap();
        owner.merge_pending_commit_for_channel(&commit.channel_id).unwrap();
        let ahead = announced(&owner, &server_id, OnlineStatus::Online);
        assert!(roster.apply(&member, &server_mailbox, &ahead, NOW).events.is_empty(), "a blob from a later epoch opened");

        // The owner goes offline before the member takes in the commit: the blob that
        // waited must not bring the owner back.
        roster.apply(&member, &server_mailbox, &left(&owner), NOW);
        member.receive_any(&commit.channel_id, &commit.blob, Some(1500)).unwrap();
        let events = roster.retry_pending(&member, &server_id, NOW);
        assert!(shown(&events).is_empty(), "an owner who left came back online");
    }
}
