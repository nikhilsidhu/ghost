//! The client's event loop: everything a running device does with what its relays
//! deliver. The desktop app and headless clients run this same loop and differ only
//! in what they do with the events it reports.

mod avatars;
mod events;
mod rosters;

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::{mpsc, Mutex};

use crate::client::{ChannelOpOutcome, ReceiveResult};
use crate::crypto::MessageType;
use crate::deferred::DeferredBlobs;
use crate::error::GhostError;
use crate::flows::presence::PresenceInfo;
use crate::flows::{self, SharedClient, SharedRelay};
use crate::relay::{IncomingBlob, RelayEvent};
use crate::storage::{Member, MemberRole};
use crate::wire::{decode_metadata, derive_default_channel_id, MetadataPayload, ProvisionPayload, SyncMessageType, SyncReceiveResult};

pub use avatars::AVATARS_DIR;
pub use events::{ClientEvent, EventSink, OnlineMember, ServerScope, VoiceMember};

use rosters::{OnlineRoster, VoiceRoster};

/// Receive errors in a row on one mailbox after which this device rejoins its group.
const EPOCH_RECOVERY_ERROR_THRESHOLD: u32 = 3;

/// How often a commit of queued proposals the relay refused (the group or the server
/// moved meanwhile) is tried again.
const PROPOSAL_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// Retries before giving up on committing a mailbox's queued proposals.
const PROPOSAL_RETRY_LIMIT: u32 = 30;

/// File in the data directory holding the account's genesis entry, kept so it can be
/// pushed again to a relay that lost it.
pub const GENESIS_PENDING_FILE: &str = "genesis.pending";

/// A running device: its client state, relay connections, announced presence and
/// where its events go.
#[derive(Clone)]
pub struct Session {
    pub client: Arc<SharedClient>,
    pub relay: Arc<SharedRelay>,
    pub presence: Arc<Mutex<PresenceInfo>>,
    pub sink: Arc<dyn EventSink>,
    /// Holds the pending genesis entry and the avatar cache.
    pub data_dir: PathBuf,
    /// One discovery run per server at a time: two at once would both join a new
    /// channel and the second join would replace the first's group state.
    pub discovery: Arc<DiscoveryLocks>,
}

/// Per-server locks serializing private channel discovery.
#[derive(Default)]
pub struct DiscoveryLocks(std::sync::Mutex<HashMap<[u8; 32], Arc<Mutex<()>>>>);

impl DiscoveryLocks {
    fn for_server(&self, server_id: &[u8; 32]) -> Arc<Mutex<()>> {
        self.0.lock().unwrap().entry(*server_id).or_default().clone()
    }
}

/// State the loop keeps between events.
#[derive(Default)]
struct LoopState {
    voice: VoiceRoster,
    online: OnlineRoster,
    connected: HashSet<[u8; 32]>,
    consecutive_errors: HashMap<[u8; 32], u32>,
    /// Private channel blobs waiting for the server group to reach the epoch they name.
    deferred: DeferredBlobs,
    /// Blobs released from `deferred`, processed before new events.
    requeued: VecDeque<IncomingBlob>,
    /// Groups whose queued proposals still need committing, by mailbox.
    proposal_retries: HashMap<[u8; 32], ProposalRetry>,
}

/// A group whose queued proposals this device has not managed to commit yet.
struct ProposalRetry {
    server_id: [u8; 32],
    channel_id: [u8; 32],
    attempts: u32,
}

/// What became of an attempt to commit a group's queued proposals.
enum ProposalCommit {
    /// Committed, or nothing left for this device to commit.
    Done,
    /// Not committed yet: the relay refused it (the group or its server moved
    /// meanwhile), or this device's view has not caught up with why it is allowed.
    Retry,
}

impl Session {
    fn emit(&self, event: ClientEvent) {
        self.sink.emit(event);
    }

    /// Run the loop over `events` (the receiver the relay client was created with)
    /// until it closes, after subscribing and the start-up work.
    pub async fn run(self, mut events: mpsc::Receiver<RelayEvent>) {
        let sync_mailbox = self.start().await;
        let mut state = LoopState::default();
        let mut retry_tick = tokio::time::interval(PROPOSAL_RETRY_INTERVAL);
        retry_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            if let Some(blob) = state.requeued.pop_front() {
                self.handle_event(RelayEvent::Blob(blob), sync_mailbox, &mut state).await;
                continue;
            }
            tokio::select! {
                event = events.recv() => match event {
                    Some(event) => self.handle_event(event, sync_mailbox, &mut state).await,
                    None => break,
                },
                _ = retry_tick.tick(), if !state.proposal_retries.is_empty() => self.retry_proposal_commits(&mut state).await,
            }
        }
    }

    /// Try again to commit queued proposals the relay refused earlier.
    async fn retry_proposal_commits(&self, state: &mut LoopState) {
        let pending: Vec<([u8; 32], ProposalRetry)> = state.proposal_retries.drain().collect();
        for (mailbox_id, retry) in pending {
            match self.commit_pending_proposals(retry.server_id, retry.channel_id, mailbox_id).await {
                ProposalCommit::Done => {}
                ProposalCommit::Retry if retry.attempts + 1 >= PROPOSAL_RETRY_LIMIT => {
                    eprintln!("relay: giving up committing queued proposals on {}", hex::encode(&mailbox_id[..8]));
                }
                ProposalCommit::Retry => {
                    state.proposal_retries.insert(mailbox_id, ProposalRetry { attempts: retry.attempts + 1, ..retry });
                }
            }
        }
    }

    /// Subscribe to every mailbox and do the start-up work. Returns the sync mailbox.
    async fn start(&self) -> Option<[u8; 32]> {
        // The relay's key is needed to verify its checkpoints.
        match self.relay.lock().await.get_relay_info().await {
            Ok(info) => self.client.lock().await.set_relay_vk(info.relay_vk),
            Err(e) => eprintln!("failed to fetch relay info: {e}"),
        }

        // Each server mailbox on the relay hosting it, the sync mailbox on the home
        // relay, resuming from the persisted last_seen_seq.
        let sync_mailbox = {
            let c = self.client.lock().await;
            let mut r = self.relay.lock().await;
            flows::subscribe_known_mailboxes(&c, &mut r);
            c.sync_mailbox_id()
        };

        self.repush_genesis_if_lost().await;

        // Other relays only register accounts whose log names a home; this also
        // refreshes the cached copy of our own log. Retried on every start.
        if let Err(e) = flows::account::ensure_home_relay(&self.client, &self.relay).await {
            eprintln!("failed to record home relay in identity log: {e}");
        }

        // Servers whose relay went away before announcing a move can be found through
        // their owners' home relays.
        let session = self.clone();
        tokio::spawn(async move {
            let moved = flows::server::check_all_locations(&session.client, &session.relay).await;
            if moved > 0 {
                eprintln!("{moved} servers moved while this device was away");
            }
        });

        // Identity logs serve gossip (kt_head_hash) and remove-proposal validation.
        let member_fps = self.client.lock().await.all_member_fingerprints();
        for fp in &member_fps {
            flows::idlog::cache_member(&self.client, &self.relay, fp).await;
        }

        // Bring groups made before policies under one, then join the private channels
        // each server's relay lists for this account (granted while this device was away).
        let session = self.clone();
        tokio::spawn(async move {
            flows::roles::migrate(&session.client, &session.relay).await;
            let servers: Vec<[u8; 32]> = {
                let c = session.client.lock().await;
                c.store().list_servers().map(|list| list.into_iter().map(|s| s.server_id).collect()).unwrap_or_default()
            };
            for server_id in servers {
                session.spawn_join_private_channels(server_id);
            }
        });

        sync_mailbox
    }

    /// Push the genesis entry again if the home relay lost it (database reset).
    async fn repush_genesis_if_lost(&self) {
        let Ok(payload) = std::fs::read(self.data_dir.join(GENESIS_PENDING_FILE)) else { return };
        let account_fp = *self.client.lock().await.fingerprint();
        let r = self.relay.lock().await;
        let lost = r.get_idlog(&account_fp, 0).await.map(|resp| resp.entries.is_empty()).unwrap_or(true);
        if lost {
            if let Err(e) = r.put_idlog_entry(&account_fp, payload).await {
                eprintln!("failed to push genesis entry: {e}");
            }
        }
    }

    /// Join the private channels of a server that the relay lists for this account, in
    /// the background so the loop keeps running.
    fn spawn_join_private_channels(&self, server_id: [u8; 32]) {
        let session = self.clone();
        tokio::spawn(async move {
            let lock = session.discovery.for_server(&server_id);
            let _running = lock.lock().await;
            match flows::channels::join_admitted(&session.client, &session.relay, &server_id).await {
                Ok(joined) if !joined.is_empty() => session.emit(ClientEvent::ServerChanged(ServerScope::One(server_id))),
                Ok(_) => {}
                Err(e) => eprintln!("private channels of {}: {e}", hex::encode(&server_id[..8])),
            }
        });
    }

    async fn rebroadcast_presence(&self, mailbox_id: &[u8; 32]) {
        let info = self.presence.lock().await.clone();
        flows::presence::broadcast_to_mailbox(&self.client, &self.relay, mailbox_id, &info).await;
    }

    async fn set_last_seen(&self, mailbox_id: &[u8; 32], seq: u64) {
        let _ = self.client.lock().await.store().set_last_seen_seq(mailbox_id, seq);
    }

    async fn handle_event(&self, event: RelayEvent, sync_mailbox: Option<[u8; 32]>, state: &mut LoopState) {
        match event {
            RelayEvent::Blob(blob) if Some(blob.mailbox_id) == sync_mailbox => self.handle_sync_blob(blob).await,
            RelayEvent::Blob(blob) => {
                self.handle_blob(blob, state).await;
                // A server commit may have released held-back private channel blobs.
                let ready = state.deferred.take_ready(&*self.client.lock().await);
                state.requeued.extend(ready);
            }
            RelayEvent::Ack(ack) => {
                if ack.epoch_mismatch {
                    eprintln!("relay: epoch mismatch ack on {}, triggering recovery", hex::encode(&ack.mailbox_id[..8]));
                    self.recover_group(&ack.mailbox_id).await;
                }
            }
            RelayEvent::Error { mailbox_id, message } => {
                eprintln!("relay: ws error on {}: {}", hex::encode(&mailbox_id[..8]), message);
            }
            RelayEvent::Gap { mailbox_id } => self.recover_group(&mailbox_id).await,
            RelayEvent::ChannelsChanged { mailbox_id } => {
                let server_id = self.client.lock().await.server_id_for_mailbox(&mailbox_id);
                if let Some(server_id) = server_id {
                    self.spawn_join_private_channels(server_id);
                }
            }
            RelayEvent::VoiceState { mailbox_id, json } => {
                let events = state.voice.apply(&*self.client.lock().await, &mailbox_id, &json);
                events.into_iter().for_each(|e| self.emit(e));
            }
            RelayEvent::Presence { mailbox_id, json } => {
                let update = state.online.apply(&*self.client.lock().await, &mailbox_id, &json, flows::now_millis());
                update.events.into_iter().for_each(|e| self.emit(e));
                for (server_id, fingerprint, hash) in update.avatars {
                    self.fetch_avatar(&server_id, &fingerprint, &hash).await;
                }
            }
            RelayEvent::ConnectionState { mailbox_id, connected } => {
                if connected {
                    state.connected.insert(mailbox_id);
                    self.rebroadcast_presence(&mailbox_id).await;
                    // On (re)connecting the sync mailbox, catch up from the durable snapshot.
                    if sync_mailbox == Some(mailbox_id) {
                        let session = self.clone();
                        tokio::spawn(async move { session.merge_sync_snapshot().await });
                    }
                } else {
                    state.connected.remove(&mailbox_id);
                }
                self.emit(ClientEvent::RelayConnectivity(!state.connected.is_empty()));
            }
        }
    }

    async fn fetch_avatar(&self, server_id: &[u8; 32], fingerprint: &[u8; 32], hash: &[u8; 32]) {
        if avatars::fetch_if_missing(&self.client, &self.relay, &self.data_dir, server_id, fingerprint, hash).await {
            self.emit(ClientEvent::AvatarUpdated(*fingerprint));
        }
    }

    async fn handle_blob(&self, blob: IncomingBlob, state: &mut LoopState) {
        let (mailbox_id, seq, received_at) = (blob.mailbox_id, blob.seq, blob.received_at);

        // Later blobs of a mailbox wait behind one already held back.
        if state.deferred.is_waiting(&mailbox_id) {
            state.deferred.queue(blob);
            return;
        }

        let result = {
            let mut c = self.client.lock().await;
            match (c.channel_id_for_mailbox(&mailbox_id), c.server_id_for_mailbox(&mailbox_id)) {
                (Some(cid), Some(sid)) => (sid, cid, c.receive_any(&cid, &blob.payload, Some(received_at))),
                _ => return,
            }
        };
        let (server_id, group_channel, result) = result;

        // A private channel commit authorized at a server epoch this device has not
        // reached: hold it (and what follows it) until the server group catches up.
        if let Err(GhostError::PolicyBehind { server_mailbox, epoch }) = &result {
            let (server_mailbox, epoch) = (*server_mailbox, *epoch);
            state.deferred.hold(blob, server_mailbox, epoch);
            return;
        }
        if result.is_ok() {
            state.consecutive_errors.remove(&mailbox_id);
        }

        match result {
            Ok(ReceiveResult::Message(msg) | ReceiveResult::MessageWithKtWarning(msg)) if msg.message_type == MessageType::Metadata => {
                self.apply_metadata(server_id, group_channel, mailbox_id, seq, msg).await;
            }
            Ok(ReceiveResult::Message(message) | ReceiveResult::MessageWithKtWarning(message)) => {
                self.emit(ClientEvent::Message { message, received_at });
                self.set_last_seen(&mailbox_id, seq).await;
            }
            Ok(ReceiveResult::CommitProcessed) => {
                self.set_last_seen(&mailbox_id, seq).await;
                let server_group = group_channel == derive_default_channel_id(&server_id);
                let joined = if server_group { self.record_new_members(&server_id, received_at).await } else { Vec::new() };
                flows::publish_server_info(&self.client, &self.relay, &mailbox_id).await;
                // A server commit may have granted access to private channels.
                if server_group {
                    self.spawn_join_private_channels(server_id);
                }
                for fp in &joined {
                    flows::idlog::cache_member(&self.client, &self.relay, fp).await;
                }
                self.after_epoch_change(&server_id, &mailbox_id, state).await;
            }
            Ok(ReceiveResult::Kicked) => {
                use crate::wire::SYNC_KEY_SERVER_PREFIX;
                {
                    let c = self.client.lock().await;
                    let _ = c.store().set_last_seen_seq(&mailbox_id, seq);
                    let key = format!("{}{}", SYNC_KEY_SERVER_PREFIX, hex::encode(server_id));
                    let _ = c.sync_remove(&key, flows::now_millis());
                }
                flows::sync::post_message(&self.client, &self.relay, SyncMessageType::ServerLeft, &server_id).await;
                flows::sync::push_snapshot(&self.client, &self.relay).await;
                self.emit(ClientEvent::Kicked(server_id));
            }
            Ok(ReceiveResult::DeviceRemoved) => {
                // This device was revoked; the account's other devices are still members,
                // so nothing goes to the sync group.
                self.set_last_seen(&mailbox_id, seq).await;
                self.emit(ClientEvent::Kicked(server_id));
            }
            Ok(ReceiveResult::MembersRemoved(removed)) => {
                {
                    let c = self.client.lock().await;
                    let _ = c.store().set_last_seen_seq(&mailbox_id, seq);
                    // Leaving a private channel does not end server membership.
                    if group_channel == derive_default_channel_id(&server_id) {
                        for fp in &removed {
                            let _ = c.store().remove_member(&server_id, fp);
                        }
                    }
                }
                flows::publish_server_info(&self.client, &self.relay, &mailbox_id).await;
                self.after_epoch_change(&server_id, &mailbox_id, state).await;
            }
            Ok(ReceiveResult::ProposalProcessed) => {
                self.set_last_seen(&mailbox_id, seq).await;
                if let ProposalCommit::Retry = self.commit_pending_proposals(server_id, group_channel, mailbox_id).await {
                    state.proposal_retries.entry(mailbox_id).or_insert(ProposalRetry { server_id, channel_id: group_channel, attempts: 0 });
                }
            }
            Ok(ReceiveResult::ChannelAccessLost(_)) => {
                // Removed from a private channel; the server membership stands.
                self.set_last_seen(&mailbox_id, seq).await;
                self.relay.lock().await.unsubscribe(&mailbox_id);
                self.emit(ClientEvent::ServerChanged(ServerScope::One(server_id)));
            }
            Ok(ReceiveResult::Skipped) => self.set_last_seen(&mailbox_id, seq).await,
            Err(e) => {
                eprintln!("relay: receive error on {} seq={seq}: {e}", hex::encode(&mailbox_id[..8]));
                self.set_last_seen(&mailbox_id, seq).await;
                let count = state.consecutive_errors.entry(mailbox_id).or_insert(0);
                *count += 1;
                if *count >= EPOCH_RECOVERY_ERROR_THRESHOLD {
                    eprintln!("relay: {} consecutive errors on {}, triggering epoch recovery", *count, hex::encode(&mailbox_id[..8]));
                    *count = 0;
                    self.recover_group(&mailbox_id).await;
                }
            }
        }
    }

    /// After this device's epoch moved in a server's group: re-announce presence there,
    /// retry presence blobs sealed at the new epoch, and report the change.
    async fn after_epoch_change(&self, server_id: &[u8; 32], mailbox_id: &[u8; 32], state: &mut LoopState) {
        self.rebroadcast_presence(mailbox_id).await;
        let events = state.online.retry_pending(&*self.client.lock().await, server_id, flows::now_millis());
        events.into_iter().for_each(|e| self.emit(e));
        self.emit(ClientEvent::ServerChanged(ServerScope::One(*server_id)));
    }

    /// Record members a commit added to the server group (an external join). Returns them.
    async fn record_new_members(&self, server_id: &[u8; 32], joined_at: u64) -> Vec<[u8; 32]> {
        let c = self.client.lock().await;
        let Ok(in_group) = c.mls_member_fingerprints(server_id) else { return Vec::new() };
        let stored: HashSet<[u8; 32]> = c.store().list_members(server_id).unwrap_or_default().iter().map(|m| m.fingerprint).collect();
        let mut joined = Vec::new();
        for fp in in_group.into_iter().filter(|fp| !stored.contains(fp)) {
            let _ = c.store().insert_member(&Member {
                server_id: *server_id,
                fingerprint: fp,
                display_name: hex::encode(&fp[..8]),
                role: MemberRole::Member,
                joined_at,
                avatar_hash: None,
                avatar_key: None,
            });
            joined.push(fp);
        }
        joined
    }

    /// Commit queued proposals (relay removals of revoked or excluded devices). Every
    /// member's device tries; the relay takes the first and refuses the rest, whose
    /// devices then see the winner's commit.
    async fn commit_pending_proposals(&self, server_id: [u8; 32], channel_id: [u8; 32], mailbox_id: [u8; 32]) -> ProposalCommit {
        let outbound = {
            let mut c = self.client.lock().await;
            c.commit_pending_proposals(&channel_id).map(|out| (out, c.awaiting_proposals(&channel_id)))
        };
        let out = match outbound {
            Ok((Some(out), _)) => out,
            // A removal this device's view cannot justify yet (e.g. its own policy commit
            // is not merged) may be committable once it catches up.
            Ok((None, true)) => return ProposalCommit::Retry,
            Ok((None, false)) => return ProposalCommit::Done,
            Err(e) => {
                eprintln!("relay: failed to build pending commit: {e}");
                return ProposalCommit::Done;
            }
        };
        let posted = self.relay.lock().await.post_blob(&out.mailbox_id, out.blob).await;
        match posted {
            Ok(_) => {
                let _ = self.client.lock().await.merge_pending_commit_for_channel(&channel_id);
                flows::publish_server_info(&self.client, &self.relay, &mailbox_id).await;
                self.rebroadcast_presence(&mailbox_id).await;
                self.emit(ClientEvent::ServerChanged(ServerScope::One(server_id)));
                ProposalCommit::Done
            }
            Err(e) => {
                let _ = self.client.lock().await.clear_pending_commit_for_channel(&channel_id);
                if matches!(e, GhostError::RelayStatus { status: 409, .. }) {
                    ProposalCommit::Retry
                } else {
                    eprintln!("relay: failed to post pending commit: {e}");
                    ProposalCommit::Done
                }
            }
        }
    }

    async fn apply_metadata(
        &self,
        server_id: [u8; 32],
        group_channel: [u8; 32],
        mailbox_id: [u8; 32],
        seq: u64,
        msg: crate::wire::ApplicationMessage,
    ) {
        let mut fetch_avatar = None;
        let mut own_name_changed = false;
        let mut server_move = None;
        let mut info_reply = None;
        match decode_metadata(&msg.content) {
            Ok(payload) => {
                let mut c = self.client.lock().await;
                match payload {
                    // Who may change channels comes from the server policy, checked in the client.
                    MetadataPayload::ChannelOp(op) => match c.apply_channel_op(&group_channel, &msg.sender_fp, op) {
                        Ok(ChannelOpOutcome::Reply(out)) => info_reply = Some(out),
                        Ok(_) => {}
                        Err(e) => eprintln!("channel op: {e}"),
                    },
                    MetadataPayload::RoleName { role_id, name } => {
                        if let Err(e) = c.apply_role_name(&server_id, &msg.sender_fp, role_id, &name) {
                            eprintln!("role name: {e}");
                        }
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
                        fetch_avatar = Some(avatar_hash);
                    }
                    MetadataPayload::AvatarClear => {
                        let _ = c.store().clear_member_avatar(&server_id, &msg.sender_fp);
                        avatars::clear(&self.data_dir, &msg.sender_fp);
                        self.emit(ClientEvent::AvatarCleared(msg.sender_fp));
                    }
                    MetadataPayload::ServerMoved(location) => {
                        // Only the owner may move a server; the record is verified when followed.
                        if c.server_owner(&server_id).is_ok_and(|owner| owner == msg.sender_fp) {
                            server_move = Some(location);
                        }
                    }
                }
                let _ = c.store().set_last_seen_seq(&mailbox_id, seq);
            }
            Err(e) => eprintln!("decode metadata: {e}"),
        }
        if let Some(out) = info_reply {
            if let Err(e) = self.relay.lock().await.send(&out.mailbox_id, out.blob).await {
                eprintln!("channel info reply: {e}");
            }
        }
        if let Some(hash) = fetch_avatar {
            self.fetch_avatar(&server_id, &msg.sender_fp, &hash).await;
        }
        if let Some(location) = server_move {
            match flows::server::follow_move(&self.client, &self.relay, &server_id, &location).await {
                Ok(true) => eprintln!("server {} moved to another relay", hex::encode(&server_id[..8])),
                Ok(false) => {}
                Err(e) => eprintln!("server move not followed: {e}"),
            }
        }
        if own_name_changed {
            self.emit(ClientEvent::DisplayNameSynced);
        }
        self.emit(ClientEvent::ServerChanged(ServerScope::One(server_id)));
    }

    /// Rejoin the group of a mailbox this device fell out of step with (a gap past the
    /// relay's retention, or repeated errors).
    async fn recover_group(&self, mailbox_id: &[u8; 32]) {
        let Some(channel_id) = self.client.lock().await.channel_id_for_mailbox(mailbox_id) else { return };
        match flows::epoch::recover(&self.client, &self.relay, &channel_id, mailbox_id, "gap recovery").await {
            Ok(true) => {}
            Ok(false) => eprintln!("gap recovery: failed after attempts"),
            Err(GhostError::RelayStatus { status: 404, .. }) => {
                eprintln!("gap recovery: relay has no server_info, resetting last_seen");
                self.set_last_seen(mailbox_id, 0).await;
                self.relay.lock().await.subscribe(*mailbox_id, 0);
            }
            Err(e) => eprintln!("gap recovery: {e}"),
        }
    }

    async fn handle_sync_blob(&self, blob: IncomingBlob) {
        let result = self.client.lock().await.receive_sync(&blob.payload);
        match result {
            Ok(SyncReceiveResult::Application(plaintext)) => self.handle_sync_message(&plaintext).await,
            Ok(SyncReceiveResult::CommitProcessed) | Ok(SyncReceiveResult::SelfMessage) => {}
            Err(e) => eprintln!("sync: process failed: {e}"),
        }
        self.set_last_seen(&blob.mailbox_id, blob.seq).await;
    }

    /// A message from another device of this account, through the sync group.
    async fn handle_sync_message(&self, plaintext: &[u8]) {
        let Some((&msg_type, body)) = plaintext.split_first() else { return };
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
                if flows::provision::join_payload_if_unknown(&self.client, &self.relay, &payload, flows::now_millis()).await {
                    self.emit(ClientEvent::ServerChanged(ServerScope::All));
                } else {
                    // A known server: the other device may have made or entered a private channel.
                    self.spawn_join_private_channels(payload.server_id);
                }
            }
            x if x == SyncMessageType::ServerLeft as u8 => {
                let Some(server_id) = body.get(..32).and_then(|b| <[u8; 32]>::try_from(b).ok()) else {
                    eprintln!("sync: ServerLeft body too short");
                    return;
                };
                let mailbox_id = {
                    use crate::wire::SYNC_KEY_SERVER_PREFIX;
                    let c = self.client.lock().await;
                    let mailbox_id = c.mailbox_id_for_server(&server_id);
                    let _ = c.store().delete_server(&server_id);
                    let key = format!("{}{}", SYNC_KEY_SERVER_PREFIX, hex::encode(server_id));
                    let _ = c.sync_remove(&key, flows::now_millis());
                    mailbox_id
                };
                if let Some(mailbox_id) = mailbox_id {
                    self.relay.lock().await.unsubscribe(&mailbox_id);
                }
                // No sync broadcast: this is the broadcast from the other device.
                flows::sync::push_snapshot(&self.client, &self.relay).await;
                self.emit(ClientEvent::Kicked(server_id));
            }
            x if x == SyncMessageType::VoiceTakeover as u8 => {
                match body.get(..32).and_then(|b| <[u8; 32]>::try_from(b).ok()) {
                    Some(channel_id) => self.emit(ClientEvent::VoiceTakeover(channel_id)),
                    None => eprintln!("sync: VoiceTakeover body too short"),
                }
            }
            x if x == SyncMessageType::MutationSync as u8 => {
                use crate::wire::{decode_mutation, MUTATION_REMOVE, MUTATION_SET};
                let (op, ts, key, value) = match decode_mutation(body) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("sync: bad mutation: {e}");
                        return;
                    }
                };
                let applied = {
                    let c = self.client.lock().await;
                    match op {
                        MUTATION_SET => c.sync_set(&key, &value, ts).unwrap_or(false),
                        MUTATION_REMOVE => c.sync_remove(&key, ts).unwrap_or(false),
                        _ => false,
                    }
                };
                if !applied {
                    return;
                }
                let entry = if op == MUTATION_SET { vec![(key, Some(value), ts)] } else { vec![(key, None, ts)] };
                self.apply_synced_settings(flows::sync::parse_entries(&entry)).await;
            }
            x if x == SyncMessageType::SyncKeyRotate as u8 => {
                let Ok(new_key) = <[u8; 32]>::try_from(body) else {
                    eprintln!("sync: bad SyncKeyRotate payload (expected 32 bytes, got {})", body.len());
                    return;
                };
                if let Err(e) = self.client.lock().await.set_sync_key(new_key) {
                    eprintln!("sync: failed to store rotated sync key: {e}");
                }
            }
            _ => eprintln!("sync: unknown message type {msg_type:#04x}"),
        }
    }

    /// Apply settings synced from another device: read marks, display name and presence
    /// status here; servers this device is missing are joined; the rest is reported.
    async fn apply_synced_settings(&self, settings: flows::sync::SyncSettings) {
        {
            let mut c = self.client.lock().await;
            for (channel_id, read_ts) in &settings.read_marks {
                let _ = c.store().mark_channel_read(channel_id, *read_ts);
            }
            if let Some(name) = &settings.display_name {
                c.set_display_name(name.clone());
            }
        }
        if settings.status.is_some() || settings.status_message.is_some() {
            let info = {
                let mut p = self.presence.lock().await;
                if let Some(status) = &settings.status {
                    p.status = crate::mls::presence::OnlineStatus::from_config(status);
                }
                if let Some(message) = &settings.status_message {
                    p.status_message = message.clone();
                }
                p.clone()
            };
            flows::presence::broadcast(&self.client, &self.relay, &info).await;
        }
        // Servers listed in synced state that this device is missing (a provision it missed).
        for (server_id, meta) in &settings.server_entries {
            if flows::provision::join_if_unknown(&self.client, &self.relay, *server_id, meta, flows::now_millis()).await {
                self.emit(ClientEvent::ServerChanged(ServerScope::One(*server_id)));
            }
        }
        self.emit(ClientEvent::SettingsSynced(settings));
    }

    /// Catch up from the account's durable sync snapshot, then write the merged state back.
    async fn merge_sync_snapshot(&self) {
        use crate::wire::{decode_sync_state_dump, sync_open};
        let (sync_key, account_fp) = {
            let c = self.client.lock().await;
            let Some(key) = c.sync_key() else { return };
            (key, *c.fingerprint())
        };
        let fetched = self.relay.lock().await.get_sync_state(&account_fp).await;
        let sealed = match fetched {
            Ok(Some((_generation, data))) => data,
            Ok(None) => {
                // No snapshot yet: ours becomes the first.
                flows::sync::push_snapshot(&self.client, &self.relay).await;
                return;
            }
            Err(e) => {
                eprintln!("sync: failed to GET sync_state: {e}");
                return;
            }
        };
        let entries = match sync_open(&sync_key, &sealed).and_then(|dump| decode_sync_state_dump(&dump)) {
            Ok(entries) => entries,
            Err(e) => {
                eprintln!("sync: unreadable sync_state snapshot: {e}");
                return;
            }
        };
        let _ = self.client.lock().await.sync_import(&entries);
        self.apply_synced_settings(flows::sync::parse_entries(&entries)).await;
        flows::sync::push_snapshot(&self.client, &self.relay).await;
    }
}
