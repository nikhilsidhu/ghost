use std::collections::{HashMap, HashSet};
use std::path::Path;

use openmls::prelude::LeafNodeIndex;
use rusqlite::Connection;

use openmls_traits::OpenMlsProvider;
use crate::account_keys::AccountSeed;
use crate::crypto::constants::{HISTORY_GAP_ID_TAG, SYNC_SIGN_PREFIX, UNDECRYPTABLE_ID_TAG};
use crate::crypto::{GhostProvider, MessageType};
use crate::error::{GhostError, Result};
use crate::identity::Identity;
use crate::idlog_cache::{CredentialClaim, DeviceStatus, HeadClaim, IdLogCache};
use crate::mls::group::{GhostExtension, GhostGroup};
use crate::storage::{Delivery, 
    Channel, ChannelKind, GhostStore, Server, ServerKind, Member, OnConflict, StoredMessage,
};
use crate::wire::{
    derive_default_channel_id, mls_group_mailbox_id, open, open_any, seal,
    ApplicationMessage, CommitChecks, InboundMessage, InviteChannel, InviteMember, InvitePayload, Outbound,
    ProvisionPayload, ServerStatePayload, SyncDump, SyncEntry, SyncReceiveResult, SyncServerMeta,
};
use ghost_wire::policy::{CommitAad, PolicyError, RemovedAccount, ServerPolicy, ServerView};
use ghost_wire::policy_mls;
use ghost_wire::{now_millis, short_id};

/// Sender key, its sequence number, generation and signature ahead of a sync message's
/// sealed body. A relay sees the key and sequence number; the rest is for the devices.
const SYNC_HEADER_LEN: usize = 32 + 8 + 4 + 64;

/// What a device signs for a sync message: the account (not a mailbox, so the same bytes
/// go to every relay), its sequence number, the generation and the sealed body.
fn sync_message(account_fp: &[u8; 32], seq: u64, generation: u32, sealed: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(SYNC_SIGN_PREFIX.len() + 32 + 8 + 4 + sealed.len());
    msg.extend_from_slice(SYNC_SIGN_PREFIX);
    msg.extend_from_slice(account_fp);
    msg.extend_from_slice(&seq.to_be_bytes());
    msg.extend_from_slice(&generation.to_be_bytes());
    msg.extend_from_slice(sealed);
    msg
}

/// Open an encrypted SQLite connection for MLS state, separate from the app DB.
fn open_mls_connection(mls_db_key: &[u8; 32], app_db_path: &Path) -> Result<Connection> {
    let mls_path = app_db_path.with_extension("mls.db");

    let conn = Connection::open(&mls_path)
        .map_err(|e| GhostError::Database(format!("open mls db: {e}")))?;

    conn.pragma_update(None, "key", format!("x'{}'", hex::encode(mls_db_key)))
        .map_err(|e| GhostError::Database(format!("set mls key: {e}")))?;

    conn.pragma_update(None, "journal_mode", "WAL")
        .map_err(|e| GhostError::Database(format!("set mls WAL: {e}")))?;

    Ok(conn)
}

pub enum ReceiveResult {
    /// A message from a checked device, already stored. Its `kt_head_hash` is the
    /// sender's view of its own log head, for the caller to judge with
    /// [`GhostClient::judge_head`].
    Message(ApplicationMessage),
    /// A message from a device this client's identity log does not list yet, already
    /// decrypted and not stored. The caller refreshes the sender's log and passes it to
    /// [`GhostClient::accept_unverified`], which stores it only if the device is active.
    Unverified { message: ApplicationMessage, claim: CredentialClaim, received_at: u64 },
    CommitProcessed,
    /// The account was removed from the group by a commit `by` an account: no device
    /// of it remains.
    Kicked { by: [u8; 32] },
    /// This device's leaf was removed while other devices of the account remain,
    /// which is what revoking this device does. Other devices are unaffected, so
    /// this must not be propagated to the account's sync state.
    DeviceRemoved,
    /// A commit removed these members (fingerprints) from the group.
    MembersRemoved(Vec<[u8; 32]>),
    /// A proposal was queued (e.g. relay Remove). Creator should commit pending proposals.
    ProposalProcessed,
    /// This device was removed from a private channel (its access ended); the channel
    /// is forgotten locally. The server membership is unaffected.
    ChannelAccessLost([u8; 32]),
    /// A message sealed in an epoch this device never held, so its content is lost to
    /// it: sent before this device rejoined the group after falling out of step.
    Unreadable,
    /// Nothing to do: this device's own message echoed back, or a commit already applied.
    Skipped,
}

/// A freshly created invite. The relay stores `sealed_payload` under `token`; `key`
/// opens it and must reach joiners only inside the invite link.
pub struct NewInvite {
    pub key: [u8; 32],
    pub sealed_payload: Vec<u8>,
}

/// A private channel just created on this device. Its group's GroupInfo goes to the
/// relay first, which admits the group only from someone who may manage channels;
/// `announcement` then names the channel inside its group.
pub struct NewPrivateChannel {
    pub channel_id: [u8; 32],
    pub mailbox_id: [u8; 32],
    pub group_info: Vec<u8>,
    pub announcement: Outbound,
}

/// Where a blob sits in its mailbox's log. A message stored from it marks it seen in the
/// same write, so a restart never replays a blob whose key decrypting it spent.
#[derive(Debug, Clone, Copy)]
pub struct BlobOrigin {
    pub mailbox_id: [u8; 32],
    pub seq: u64,
}

/// What became of a server's state sent to this device.
#[derive(Debug, PartialEq, Eq)]
pub enum ServerStateOutcome {
    /// The channels, role names and members' names now match the sender's.
    Applied,
    /// Not waited for, not from a member who may manage channels, or answering a request
    /// made before this device's.
    Ignored,
    /// As of before a change this device saw: ask again.
    Stale,
}

/// What became of a channel operation received in a metadata message.
pub enum ChannelOpOutcome {
    /// Local channel state changed.
    Applied,
    /// A newly joined device asked for a private channel's name: send this reply.
    Reply(Outbound),
    /// The sender may not do this, or it does not fit where it arrived.
    Ignored,
}

/// Session-level orchestration: holds identity, MLS state, and local storage.
pub struct GhostClient {
    identity: Identity,
    provider: GhostProvider,
    store: GhostStore,
    /// Per-channel MLS groups: channel_id → GhostGroup
    channel_groups: HashMap<[u8; 32], GhostGroup>,
    /// mailbox_id → channel_id for O(1) reverse lookup
    mailbox_map: HashMap<[u8; 32], [u8; 32]>,
    /// channel_id → server_id for reverse lookup
    channel_server: HashMap<[u8; 32], [u8; 32]>,
    /// Relay's Ed25519 verifying key for ExternalSendersExtension
    relay_vk: Option<[u8; 32]>,
    /// Cached identity log states for credential validation
    idlog_cache: IdLogCache,
    /// When sync state first changed since the last snapshot push, if it did; the
    /// session pushes once the changes have settled.
    snapshot_push_requested: Option<std::time::Instant>,
    /// Rejoins whose commit the relay has not answered: the group each channel had, to
    /// go back to if the relay refuses.
    pending_rejoins: HashMap<[u8; 32], PendingRejoin>,
    /// Private channels whose name this device asked for in this run: one still unnamed
    /// is asked again in the next run, and one whose request failed at the next discovery.
    names_asked: HashSet<[u8; 32]>,
}

/// A channel's group as it was before a rejoin, in memory and as rows in the MLS storage.
struct PendingRejoin {
    old: GhostGroup,
    rows: crate::crypto::provider::GroupRows,
}

impl GhostClient {
    pub fn open(identity: Identity, db_key: [u8; 32], mls_db_key: [u8; 32], db_path: &Path) -> Result<Self> {
        let store = GhostStore::open(&db_key, db_path)?;
        // Nothing answers for a message handed to a connection of an earlier run: it is
        // sent again. Failing here fails the open rather than leaving it "sending".
        store.reset_in_flight()?;

        let mls_conn = open_mls_connection(&mls_db_key, db_path)?;
        let provider = GhostProvider::new(mls_conn)?;

        // Reload per-channel MLS groups from previous sessions. A server none of whose
        // groups was ever stored is the leftover of an interrupted join, and goes so the
        // account's other devices can provision it again. One whose group fails to load
        // stays, with its history, until it loads: its rows are the only copy.
        let mut channel_groups = HashMap::new();
        let mut mailbox_map = HashMap::new();
        let mut channel_server = HashMap::new();
        if let Ok(stored_servers) = store.list_servers() {
            for s in &stored_servers {
                let channels = store.list_channels(&s.server_id).unwrap_or_default();
                let mut loaded_any = false;
                let mut load_failed = false;
                for ch in &channels {
                    match GhostGroup::load(&provider, &identity, &s.server_id, &ch.channel_id) {
                        Ok(Some(group)) => {
                            let mb = mls_group_mailbox_id(group.group_id());
                            mailbox_map.insert(mb, ch.channel_id);
                            channel_server.insert(ch.channel_id, s.server_id);
                            channel_groups.insert(ch.channel_id, group);
                            loaded_any = true;
                        }
                        Ok(None) => {}
                        Err(e) => {
                            load_failed = true;
                            tracing::error!("group of channel {} not loaded: {e}", short_id(&ch.channel_id));
                        }
                    }
                }
                if !loaded_any && !load_failed {
                    let _ = store.delete_server(&s.server_id);
                }
            }
        }

        let client = Self {
            identity,
            provider,
            store,
            channel_groups,
            mailbox_map,
            channel_server,
            relay_vk: None,
            idlog_cache: IdLogCache::new(),
            snapshot_push_requested: None,
            pending_rejoins: HashMap::new(),
            names_asked: HashSet::new(),
        };
        // Servers joined before views were recorded start their history here.
        for server_id in client.channel_server.values().collect::<std::collections::HashSet<_>>() {
            if let Err(e) = client.record_server_view(server_id) {
                tracing::error!("server view for {}: {e}", short_id(server_id));
            }
        }
        Ok(client)
    }

    pub fn open_in_memory(identity: Identity, db_key: [u8; 32]) -> Result<Self> {
        let provider = GhostProvider::new_in_memory()?;
        let store = GhostStore::open_in_memory(&db_key)?;
        Ok(Self {
            identity,
            provider,
            store,
            channel_groups: HashMap::new(),
            mailbox_map: HashMap::new(),
            channel_server: HashMap::new(),
            relay_vk: None,
            idlog_cache: IdLogCache::new(),
            snapshot_push_requested: None,
            pending_rejoins: HashMap::new(),
            names_asked: HashSet::new(),
        })
    }

    /// Get the default channel's MLS group for a server (for server-wide operations).
    fn default_group(&self, server_id: &[u8; 32]) -> Result<&GhostGroup> {
        let ch = derive_default_channel_id(server_id);
        self.channel_groups.get(&ch).ok_or_else(|| {
            GhostError::ServerNotLoaded(short_id(server_id))
        })
    }

    /// The channel whose MLS group carries traffic for `channel_id`: the channel itself
    /// when it has its own group (a private channel), otherwise its server's default
    /// channel, whose group all public channels share. Messages and voice keys keep the
    /// real channel id, so channels stay distinct inside the shared group.
    fn group_channel(&self, channel_id: &[u8; 32]) -> [u8; 32] {
        if self.channel_groups.contains_key(channel_id) {
            return *channel_id;
        }
        match self.store.get_channel(channel_id) {
            Ok(channel) => derive_default_channel_id(&channel.server_id),
            Err(_) => *channel_id,
        }
    }

    /// A private channel is one with an MLS group of its own besides the server's.
    pub fn is_private_channel(&self, channel_id: &[u8; 32]) -> bool {
        self.channel_groups.contains_key(channel_id)
            && self.channel_server.get(channel_id).is_some_and(|sid| derive_default_channel_id(sid) != *channel_id)
    }

    /// Authenticated data for a commit to a channel's group. A private channel's
    /// commits name the server group epoch they were authorized against: the relay
    /// requires it to be current, and members judge the commit by that epoch's policy.
    fn commit_aad(&self, channel_id: &[u8; 32]) -> CommitAad {
        if !self.is_private_channel(channel_id) {
            return CommitAad::default();
        }
        let server_epoch = self
            .channel_server
            .get(channel_id)
            .and_then(|server_id| self.default_group(server_id).ok())
            .map(GhostGroup::epoch);
        CommitAad { invite: None, server_epoch }
    }

    /// The policy governing a server, from its group state.
    pub fn server_policy(&self, server_id: &[u8; 32]) -> Result<ServerPolicy> {
        let group = self.default_group(server_id)?;
        let members: Vec<openmls::prelude::Member> = group.members().collect();
        policy_mls::server_policy(group.context_extensions(), &members)
            .map_err(|e| GhostError::Format(format!("server policy: {e}")))
    }

    /// Mailbox of a server's own group, which its private channels name.
    pub fn server_mailbox(&self, server_id: &[u8; 32]) -> Result<[u8; 32]> {
        Ok(mls_group_mailbox_id(self.default_group(server_id)?.group_id()))
    }

    /// The account that owns a server under its policy.
    pub fn server_owner(&self, server_id: &[u8; 32]) -> Result<[u8; 32]> {
        Ok(self.server_policy(server_id)?.owner)
    }

    /// The server group's view at an epoch of it, against which a private channel
    /// commit naming that epoch is judged.
    fn server_view_at(&self, server_mailbox: &[u8; 32], epoch: u64) -> std::result::Result<ServerView, PolicyError> {
        let denied = |msg: &str| PolicyError::Denied(msg.into());
        let server_id = self
            .server_id_for_mailbox(server_mailbox)
            .ok_or_else(|| denied("the channel names a server this device is not in"))?;
        let group = self.default_group(&server_id).map_err(|e| PolicyError::Denied(e.to_string()))?;
        if mls_group_mailbox_id(group.group_id()) != *server_mailbox {
            return Err(denied("the channel names a mailbox that is not its server's group"));
        }
        let current = group.epoch();
        if epoch > current {
            return Err(PolicyError::ContextBehind { server_mailbox: *server_mailbox, epoch });
        }
        if epoch == current {
            let members: Vec<openmls::prelude::Member> = group.members().collect();
            return policy_mls::server_view(group.context_extensions(), &members);
        }
        self.store
            .server_view_at(&server_id, epoch)
            .map_err(|e| PolicyError::Denied(e.to_string()))?
            .ok_or_else(|| denied("no record of the server group at that epoch"))
    }

    /// Record the server group's current view for judging later private channel
    /// commits. Called after anything that changes the server group's epoch.
    fn record_server_view(&self, server_id: &[u8; 32]) -> Result<()> {
        let group = self.default_group(server_id)?;
        let members: Vec<openmls::prelude::Member> = group.members().collect();
        let view = policy_mls::server_view(group.context_extensions(), &members)
            .map_err(|e| GhostError::Format(format!("server policy: {e}")))?;
        self.store.record_server_view(server_id, group.epoch(), &view)
    }

    /// Record the server view if `channel_id` is a server's default channel.
    fn record_if_server_group(&self, channel_id: &[u8; 32]) -> Result<()> {
        match self.channel_server.get(channel_id) {
            Some(server_id) if derive_default_channel_id(server_id) == *channel_id => self.record_server_view(server_id),
            _ => Ok(()),
        }
    }

    /// Whether this device holds the server group at or past `epoch`, so private
    /// channel commits held back for it can be retried.
    pub fn server_epoch_reached(&self, server_mailbox: &[u8; 32], epoch: u64) -> bool {
        self.server_id_for_mailbox(server_mailbox)
            .and_then(|server_id| self.default_group(&server_id).ok())
            .is_some_and(|group| group.epoch() >= epoch)
    }

    /// Get all channel_ids belonging to a server.
    fn server_channel_ids(&self, server_id: &[u8; 32]) -> Vec<[u8; 32]> {
        self.channel_server.iter()
            .filter(|(_, sid)| *sid == server_id)
            .map(|(cid, _)| *cid)
            .collect()
    }

    /// Set the relay's verifying key for ExternalSendersExtension in new groups.
    pub fn set_relay_vk(&mut self, vk: [u8; 32]) {
        self.relay_vk = Some(vk);
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub fn fingerprint(&self) -> &[u8; 32] {
        &self.identity.fingerprint
    }

    /// What to call `server` here: its name, or for a DM the other member's name once this
    /// device knows it. A DM's own name is whatever its creator typed, the same for both.
    pub fn server_display_name(&self, server: &Server) -> String {
        if server.kind != ServerKind::Dm {
            return server.name.clone();
        }
        self.store
            .list_members(&server.server_id)
            .ok()
            .and_then(|members| members.into_iter().find(|m| m.fingerprint != self.identity.fingerprint && m.has_name()))
            .map_or_else(|| server.name.clone(), |other| other.display_name)
    }

    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.identity.verifying_key.to_bytes()
    }

    pub fn signing_key_clone(&self) -> ed25519_dalek::SigningKey {
        self.identity.signing_key.clone()
    }

    pub fn store(&self) -> &GhostStore {
        &self.store
    }

    /// Note that sync state changed and the relays' snapshots should follow.
    pub fn request_snapshot_push(&mut self) {
        self.snapshot_push_requested.get_or_insert_with(std::time::Instant::now);
    }

    /// Take a pending snapshot push once the first change behind it is `settle` old,
    /// so a burst of changes costs one push.
    pub fn take_snapshot_push(&mut self, settle: std::time::Duration) -> bool {
        match self.snapshot_push_requested {
            Some(since) if since.elapsed() >= settle => {
                self.snapshot_push_requested = None;
                true
            }
            _ => false,
        }
    }

    /// The head of an account's identity log as cached: its sequence and hash.
    pub fn cached_head(&self, account_fp: &[u8; 32]) -> Option<(u64, [u8; 32])> {
        self.idlog_cache.get(account_fp).map(|state| (state.head_seq, state.head_hash))
    }

    /// The home relay an account's cached log names, if the log is cached and names one.
    pub fn cached_home_relay(&self, account_fp: &[u8; 32]) -> Option<[u8; 32]> {
        self.idlog_cache.get(account_fp).and_then(|state| state.home_relay_vk)
    }

    /// Accounts whose leaves queued proposals in a channel's group would remove, so
    /// their identity logs can be fetched before the removals are judged.
    pub fn pending_removal_accounts(&self, channel_id: &[u8; 32]) -> Vec<[u8; 32]> {
        let Some(group) = self.channel_groups.get(channel_id) else { return Vec::new() };
        group.pending_removal_accounts()
    }

    /// Access the identity log cache (e.g. to check device status).
    pub fn idlog_cache(&self) -> &IdLogCache {
        &self.idlog_cache
    }

    /// Verifying key of the relay this client is connected to, once fetched.
    pub fn relay_vk(&self) -> Option<[u8; 32]> {
        self.relay_vk
    }

    /// Validate an anchored identity log (chain plus every home anchor), merge it
    /// into the local cache, and return the account's state.
    pub fn cache_anchored_log(
        &mut self,
        account_fp: &[u8; 32],
        log: &crate::relay::AnchoredLog,
    ) -> Result<ghost_wire::idlog::LogState> {
        let (state, replaced) = self.idlog_cache.cache_and_validate(&self.store, account_fp, log)?;
        if let Some(replaced) = replaced {
            if *account_fp == self.identity.fingerprint {
                // Told by the next account check, whichever fetch found it.
                self.store.record_replaced_history(&replaced, now_millis())?;
            } else {
                tracing::warn!("identity log of {}: cached history from entry {} replaced by a root-signed branch", short_id(account_fp), replaced.from_seq);
            }
        }
        Ok(state)
    }

    /// Last KT head accepted from this relay, if any.
    pub fn kt_head(&self, relay_vk: &[u8; 32]) -> Result<Option<ghost_wire::merkle::Checkpoint>> {
        match self.store.get_kt_state(relay_vk)? {
            Some(state) => ghost_wire::merkle::Checkpoint::from_bytes(&state.checkpoint)
                .map(Some)
                .map_err(|e| GhostError::IdentityLog(format!("stored kt head: {e}"))),
            None => Ok(None),
        }
    }

    /// Accept a new KT head from `relay_vk`: it must be signed by that relay and
    /// extend the last head accepted from it (`proof` covers the growth). A relay
    /// that shows two clients different trees fails this check on one of them.
    pub fn accept_kt_head(
        &mut self,
        relay_vk: &[u8; 32],
        head: &ghost_wire::merkle::Checkpoint,
        proof: Option<&ghost_wire::merkle::ConsistencyProof>,
    ) -> Result<()> {
        let vk = ed25519_dalek::VerifyingKey::from_bytes(relay_vk)
            .map_err(|e| GhostError::IdentityLog(format!("bad relay vk: {e}")))?;
        head.verify(&vk)
            .map_err(|_| GhostError::IdentityLog("kt head signature invalid".into()))?;
        if let Some(prior) = self.kt_head(relay_vk)? {
            ghost_wire::merkle::verify_extension(&prior, head, proof).map_err(|e| {
                GhostError::IdentityLog(format!("kt head does not extend the last one seen ({e}); possible split view"))
            })?;
        }
        self.store.set_kt_state(relay_vk, head.tree_size, &head.root_hash, &head.to_bytes())
    }

    /// The cached identity log state for an account, loading it from the local
    /// database when it is not in memory yet. `None` if this device never cached it.
    pub fn cached_identity_log(&mut self, account_fp: &[u8; 32]) -> Result<Option<ghost_wire::idlog::LogState>> {
        if let Some(state) = self.idlog_cache.get(account_fp) {
            return Ok(Some(state.clone()));
        }
        Ok(self.idlog_cache.load_from_store(&self.store, account_fp)?.cloned())
    }

    /// Validate a chain held locally and cache it, as when a device has just written
    /// entries itself.
    pub fn cache_identity_chain(&mut self, entries: &[ghost_wire::idlog::LogEntry]) -> Result<()> {
        self.idlog_cache.insert_chain(entries)
    }

    /// What this client's identity log says about the device a credential claims.
    pub fn device_status(&self, claim: &CredentialClaim) -> DeviceStatus {
        self.idlog_cache.status(claim)
    }

    /// This device's own account, as its cached log has it.
    pub fn own_log(&self) -> Option<&ghost_wire::idlog::LogState> {
        self.idlog_cache.get(&self.identity.fingerprint)
    }

    /// Update own display name in identity and all server member records.
    pub fn set_display_name(&mut self, name: String) {
        let fp = self.identity.fingerprint;
        let server_ids: Vec<[u8; 32]> = self.channel_server.values().copied().collect::<std::collections::HashSet<_>>().into_iter().collect();
        for server_id in &server_ids {
            let _ = self.store.update_member_name(server_id, &fp, &name);
        }
        self.identity.display_name = name;
    }

    pub fn store_account_seed(&self, seed: &AccountSeed) -> Result<()> {
        self.store.store_account_seed(seed)
    }

    /// A generation's seed, if held and it is the one the account's log published.
    pub fn account_seed(&self, generation: u32) -> Result<Option<AccountSeed>> {
        let Some(key) = self.own_log().and_then(|log| log.account_keys.iter().find(|k| k.generation == generation)) else {
            return Ok(None);
        };
        match self.store.account_seed(generation)? {
            Some(seed) if seed.matches(key)? => Ok(Some(seed)),
            _ => Ok(None),
        }
    }

    /// The seed new data is sealed under: the account's current generation, and only
    /// while it covers exactly the account's devices, so nothing new is ever sealed to
    /// a key a revoked device holds.
    pub fn sealing_seed(&self) -> Result<AccountSeed> {
        let log = self.own_log().ok_or_else(|| GhostError::IdentityLog("own identity log is not cached".into()))?;
        let key = log
            .account_key()
            .ok_or_else(|| GhostError::AccountKeyUnavailable("the account has no account key yet".into()))?;
        if log.rekey_needed() {
            return Err(GhostError::AccountKeyUnavailable(format!("generation {} no longer covers the account", key.generation)));
        }
        let generation = key.generation;
        self.account_seed(generation)?
            .ok_or_else(|| GhostError::AccountKeyUnavailable(format!("generation {generation} is not held yet")))
    }

    pub fn sync_get(&self, key: &str) -> Result<Option<(Option<Vec<u8>>, u64)>> {
        self.store.sync_get(key)
    }

    pub fn sync_set(&self, key: &str, value: &[u8], ts: u64) -> Result<bool> {
        self.store.sync_set(key, value, ts)
    }

    pub fn sync_remove(&self, key: &str, ts: u64) -> Result<bool> {
        self.store.sync_remove(key, ts)
    }

    /// This device's state with what it covers, for a snapshot or a provision.
    pub fn sync_dump(&self) -> Result<SyncDump> {
        Ok(SyncDump { covered: self.store.sync_cursors()?, entries: self.store.sync_dump()? })
    }

    /// Merge entries other devices wrote by each key's rule, their clocks clamped to what
    /// this device accepts; returns those that changed this device's state.
    pub fn sync_import(&self, entries: &[SyncEntry]) -> Result<Vec<SyncEntry>> {
        let now = now_millis();
        let clamped: Vec<SyncEntry> =
            entries.iter().map(|(key, value, ts)| (key.clone(), value.clone(), crate::sync::clock::clamp(*ts, now))).collect();
        self.store.sync_import(&clamped)
    }

    /// A snapshot included every message of these devices up to these sequence numbers:
    /// a copy of one arriving later is nothing new, and a gap below is closed.
    pub fn cover_sync(&self, covered: &[([u8; 32], u64)]) -> Result<()> {
        let own = self.identity.verifying_key.to_bytes();
        for (device_vk, high) in covered {
            if *device_vk == own {
                continue;
            }
            let mut window = self.store.sync_cursor(device_vk)?;
            window.cover_up_to(*high);
            self.store.set_sync_cursor(device_vk, &window)?;
        }
        Ok(())
    }

    /// A clock for a write this device makes now, past everything it has seen.
    pub fn sync_tick(&self) -> Result<u64> {
        let mut clock = crate::sync::clock::HybridClock::new(self.store.sync_clock()?);
        let value = clock.tick(now_millis());
        self.store.set_sync_clock(clock.last())?;
        Ok(value)
    }

    /// Take in a clock another device wrote; returns it clamped as it is stored.
    pub fn sync_observe(&self, clock: u64) -> Result<u64> {
        let mut hybrid = crate::sync::clock::HybridClock::new(self.store.sync_clock()?);
        let stored = hybrid.observe(clock, now_millis());
        self.store.set_sync_clock(hybrid.last())?;
        Ok(stored)
    }

    // --- Sync mailbox ---

    /// The mailbox the account's devices sync through, the same on every relay.
    pub fn account_sync_mailbox(&self) -> [u8; 32] {
        ghost_wire::sync_mailbox_id(&self.identity.fingerprint)
    }

    /// Seal a sync plaintext under the current account key generation, numbered and
    /// signed by this device. The sequence number is reserved before the message leaves.
    /// Format: `[envelope_header][device_vk:32][seq:8][generation:4][signature:64][sealed]`
    pub fn send_sync(&self, plaintext: &[u8]) -> Result<Outbound> {
        use ed25519_dalek::Signer;
        let seed = self.sealing_seed()?;
        let sealed = crate::wire::sync_seal(&*seed.sync_key()?, plaintext)?;
        let seq = self.store.next_sync_seq()?;
        let signature = self.identity.signing_key.sign(&sync_message(&self.identity.fingerprint, seq, seed.generation(), &sealed));
        let header = ghost_wire::encode_envelope(ghost_wire::EnvelopeType::Application, 0);
        let mut blob = Vec::with_capacity(ghost_wire::ENVELOPE_HEADER_SIZE + SYNC_HEADER_LEN + sealed.len());
        blob.extend_from_slice(&header);
        blob.extend_from_slice(self.identity.verifying_key.as_bytes());
        blob.extend_from_slice(&seq.to_be_bytes());
        blob.extend_from_slice(&seed.generation().to_be_bytes());
        blob.extend_from_slice(&signature.to_bytes());
        blob.extend_from_slice(&sealed);
        Ok(Outbound { channel_id: [0u8; 32], mailbox_id: self.account_sync_mailbox(), blob })
    }

    /// Take in a sync blob from any relay. A copy of a message seen already, or this
    /// device's own message back, is `Seen` without being opened. Otherwise the sender
    /// must be an active device of this account by this device's log, which is fetched
    /// again on `UnknownDevice`; a generation not held yet fails with
    /// `AccountKeyUnavailable`, and the message opens once its key set is fetched. The
    /// message counts as seen only once it opened, so a retry after either is not dropped.
    pub fn receive_sync(&mut self, blob: &[u8]) -> Result<SyncReceiveResult> {
        let (envelope_type, _epoch) = ghost_wire::decode_envelope(blob)
            .map_err(|e| GhostError::Format(format!("envelope: {e}")))?;
        if envelope_type != ghost_wire::EnvelopeType::Application {
            return Err(GhostError::Format("the sync mailbox carries no MLS messages".into()));
        }
        let payload = ghost_wire::envelope_payload(blob);
        if payload.len() < SYNC_HEADER_LEN {
            return Err(GhostError::Format("sync payload too short".into()));
        }
        let sender_vk: [u8; 32] = payload[..32].try_into().unwrap();
        let seq = u64::from_be_bytes(payload[32..40].try_into().unwrap());
        let generation = u32::from_be_bytes(payload[40..44].try_into().unwrap());
        let signature = ed25519_dalek::Signature::from_bytes(payload[44..108].try_into().unwrap());
        let sealed = &payload[SYNC_HEADER_LEN..];
        if sender_vk == *self.identity.verifying_key.as_bytes() {
            return Ok(SyncReceiveResult::Seen);
        }
        let mut window = self.store.sync_cursor(&sender_vk)?;
        let gap = match window.accept(seq) {
            crate::sync::window::Arrival::Seen => return Ok(SyncReceiveResult::Seen),
            crate::sync::window::Arrival::New { gap } => gap,
        };

        let log = self.own_log().ok_or_else(|| GhostError::IdentityLog("own identity log is not cached".into()))?;
        match log.devices.get(&sender_vk) {
            None => return Err(GhostError::UnknownDevice { account_fp: self.identity.fingerprint }),
            Some(device) if !device.is_active() => {
                return Err(GhostError::IdentityLog("sync message from a revoked device".into()));
            }
            Some(_) => {}
        }
        ed25519_dalek::VerifyingKey::from_bytes(&sender_vk)
            .map_err(|e| GhostError::InvalidKey(format!("sync sender key: {e}")))?
            .verify_strict(&sync_message(&self.identity.fingerprint, seq, generation, sealed), &signature)
            .map_err(|_| GhostError::AuthenticationFailed)?;
        let seed = self
            .account_seed(generation)?
            .ok_or_else(|| GhostError::AccountKeyUnavailable(format!("generation {generation} is not held yet")))?;
        let plaintext = crate::wire::sync_open(&*seed.sync_key()?, sealed)?;
        self.store.set_sync_cursor(&sender_vk, &window)?;
        Ok(SyncReceiveResult::Application { plaintext, sender: sender_vk, gap })
    }

    /// Export server metadata for provisioning a sibling device (no role check).
    pub fn export_provision_payload(&self, server_id: &[u8; 32]) -> Result<ProvisionPayload> {
        let default_group = self.default_group(server_id)?;
        let meta = self.store.get_server(server_id)?;
        let members = self.store.list_members(server_id)?;
        let channels = self.store.list_channels(server_id)?;
        let mailbox_id = mls_group_mailbox_id(default_group.group_id());

        // Private channels are found through the relay's discovery and joined with the
        // server epoch they are authorized against, not provisioned.
        let invite_channels: Vec<InviteChannel> = channels
            .iter()
            .filter(|c| !self.is_private_channel(&c.channel_id))
            .map(|c| {
                let gi = self.channel_groups.get(&c.channel_id)
                    .and_then(|g| g.export_group_info(&self.provider).ok())
                    .unwrap_or_default();
                InviteChannel {
                    channel_id: c.channel_id,
                    name: c.name.clone(),
                    kind: c.kind,
                    position: c.position,
                    group_info_bytes: gi,
                }
            })
            .collect();

        Ok(ProvisionPayload {
            server_id: *server_id,
            server_name: meta.name,
            kind: meta.kind,
            members: members
                .iter()
                .map(|m| InviteMember {
                    fingerprint: m.fingerprint,
                    display_name: m.display_name.clone(),
                })
                .collect(),
            channels: invite_channels,
            mailbox_id,
            relay_ref: self.server_relay_ref(server_id)?,
            role_names: self.store.list_role_names(server_id)?,
        })
    }

    /// Relay hosting a server, as recorded at join time; `None` means the home relay.
    fn server_relay_ref(&self, server_id: &[u8; 32]) -> Result<Option<ghost_wire::relay_ref::RelayRef>> {
        match self.store.server_relay(server_id)? {
            Some(relay_vk) => Ok(self.store.get_relay(&relay_vk)?),
            None => Ok(None),
        }
    }

    /// Export lightweight server metadata for sync_state (no members).
    pub fn export_server_meta(&self, server_id: &[u8; 32]) -> Result<SyncServerMeta> {
        let default_group = self.default_group(server_id)?;
        let meta = self.store.get_server(server_id)?;
        let channels = self.store.list_channels(server_id)?;
        let mailbox_id = mls_group_mailbox_id(default_group.group_id());

        Ok(SyncServerMeta {
            server_name: meta.name,
            kind: meta.kind,
            mailbox_id,
            channels: channels
                .iter()
                .filter(|c| !self.is_private_channel(&c.channel_id))
                .map(|c| InviteChannel {
                    channel_id: c.channel_id,
                    name: c.name.clone(),
                    kind: c.kind,
                    position: c.position,
                    group_info_bytes: Vec::new(),
                })
                .collect(),
            relay_ref: self.server_relay_ref(server_id)?,
            role_names: self.store.list_role_names(server_id)?,
            removal: self.store.server_removal(server_id)?.map(|r| crate::wire::SyncRemoval { by: r.by }),
        })
    }

    /// Core join logic: external commit → persist metadata → register.
    /// `idempotent`: true uses `_if_not_exists` inserts (provision/sync), false uses strict inserts (invite).
    /// Join a server by joining each channel's MLS group.
    /// Returns Vec of (channel_id, commit_bytes, mailbox_id) — one per channel.
    /// `grant` admits an account that is not yet a member to the server group.
    #[allow(clippy::too_many_arguments)]
    fn join_server_common(
        &mut self,
        server_id: [u8; 32],
        server_name: String,
        kind: ServerKind,
        members: &[InviteMember],
        channels: &[InviteChannel],
        role_names: &[(u8, String)],
        grant: Option<&ghost_wire::policy::InviteGrant>,
        timestamp: u64,
        idempotent: bool,
    ) -> Result<Vec<([u8; 32], Vec<u8>, [u8; 32])>> {
        // A server this account was removed from is still here, read-only: rejoining it
        // after being let back in keeps its rows and history.
        let idempotent = idempotent || self.store.server_removal(&server_id)?.is_some();
        let on_conflict = if idempotent { OnConflict::Keep } else { OnConflict::Fail };
        let server = Server { server_id, name: server_name, kind, created_at: timestamp };
        self.store.insert_server(&server, on_conflict)?;

        for ch in channels {
            let channel = Channel {
                channel_id: ch.channel_id, server_id, name: ch.name.clone(),
                kind: ch.kind, position: ch.position,
            };
            self.store.insert_channel(&channel, on_conflict)?;
        }

        for m in members {
            let member = Member {
                server_id, fingerprint: m.fingerprint, display_name: m.display_name.clone(),
                joined_at: timestamp, avatar_hash: None, avatar_key: None,
            };
            self.store.insert_member(&member, on_conflict)?;
        }

        let self_member = Member {
            server_id, fingerprint: self.identity.fingerprint,
            display_name: self.identity.display_name.clone(),
            joined_at: timestamp, avatar_hash: None, avatar_key: None,
        };
        self.store.insert_member(&self_member, on_conflict)?;

        for (role_id, name) in role_names {
            self.store.set_role_name(&server_id, *role_id, name)?;
        }

        let mut results = Vec::with_capacity(channels.len());
        let aad = CommitAad { invite: grant.cloned(), server_epoch: None };
        // Channels without GroupInfo have no MLS group: metadata only.
        for ch in channels.iter().filter(|ch| !ch.group_info_bytes.is_empty()) {
            let (ghost_group, commit_bytes) = GhostGroup::join_by_external_commit(
                &self.provider,
                &self.identity,
                &ch.group_info_bytes,
                &aad,
            )?;
            let mailbox_id = mls_group_mailbox_id(ghost_group.group_id());
            self.store.record_group_join(&ch.channel_id, ghost_group.epoch())?;
            self.channel_groups.insert(ch.channel_id, ghost_group);
            self.mailbox_map.insert(mailbox_id, ch.channel_id);
            self.channel_server.insert(ch.channel_id, server_id);
            results.push((ch.channel_id, commit_bytes, mailbox_id));
        }
        self.record_server_view(&server_id)?;
        // Members who joined after the payload was made are in the tree; their names come
        // when they announce, or with the server's state.
        for fingerprint in self.mls_member_fingerprints(&server_id)? {
            let member = Member {
                server_id, fingerprint, display_name: crate::storage::placeholder_name(&fingerprint),
                joined_at: timestamp, avatar_hash: None, avatar_key: None,
            };
            self.store.insert_member(&member, OnConflict::Keep)?;
        }
        Ok(results)
    }

    /// Join a server from a provision payload (handles duplicates).
    /// Returns Vec of (channel_id, commit_bytes, mailbox_id) for each channel.
    pub fn join_from_provision(
        &mut self,
        payload: &ProvisionPayload,
        group_infos: &HashMap<[u8; 32], Vec<u8>>,
        timestamp: u64,
    ) -> Result<Vec<([u8; 32], Vec<u8>, [u8; 32])>> {
        // Provision payloads carry channel metadata only; each channel's GroupInfo comes
        // from that channel's mailbox on the relay. Channels without one have no MLS group
        // and are stored as metadata; the default channel must have one.
        let default_ch = derive_default_channel_id(&payload.server_id);
        if !group_infos.contains_key(&default_ch) {
            return Err(GhostError::Mls("no GroupInfo for the server's default channel".into()));
        }
        let mut channels = payload.channels.clone();
        for ch in &mut channels {
            ch.group_info_bytes = group_infos.get(&ch.channel_id).cloned().unwrap_or_default();
        }
        self.join_server_common(
            payload.server_id, payload.server_name.clone(), payload.kind,
            &payload.members, &channels, &payload.role_names, None, timestamp, true,
        )
    }

    pub fn create_server(&mut self, name: &str, kind: ServerKind, timestamp: u64) -> Result<[u8; 32]> {
        let mut server_id = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut server_id);

        let channel_name = match kind {
            ServerKind::Dm | ServerKind::Group => "messages",
            ServerKind::Server => "general",
        };
        let channel_id = derive_default_channel_id(&server_id);

        // The relay is every group's external sender, so it can propose removals in it.
        let relay_vk = self.relay_vk.ok_or_else(|| GhostError::Network("the home relay's key is not known yet; connect to it first".into()))?;
        let ghost_group =
            GhostGroup::create(
                &self.provider,
                &self.identity,
                &server_id,
                &channel_id,
                Some(&relay_vk),
                Some(crate::mls::group::GhostExtension::Server(ghost_wire::policy::ServerPolicy::new(self.identity.fingerprint))),
            )?;

        let server = Server { server_id, name: name.to_string(), kind, created_at: timestamp };
        let channel = Channel { channel_id, server_id, name: channel_name.to_string(), kind: ChannelKind::Text, position: 0 };
        let creator = Member {
            server_id,
            fingerprint: self.identity.fingerprint,
            display_name: self.identity.display_name.clone(),
            joined_at: timestamp,
            avatar_hash: None,
            avatar_key: None,
        };
        if let Err(e) = self.store.insert_created_server(&server, &channel, &creator) {
            let _ = ghost_group.delete(&self.provider);
            return Err(e);
        }

        let mailbox_id = mls_group_mailbox_id(ghost_group.group_id());
        self.channel_groups.insert(channel_id, ghost_group);
        self.mailbox_map.insert(mailbox_id, channel_id);
        self.channel_server.insert(channel_id, server_id);
        if let Err(e) = self.record_server_view(&server_id) {
            let _ = self.drop_server(&server_id);
            return Err(e);
        }
        Ok(server_id)
    }

    /// Undo a server this device made whose group state the relay would not take: a
    /// server cannot exist without it.
    pub fn abandon_created_server(&mut self, server_id: &[u8; 32]) -> Result<()> {
        self.drop_server(server_id)
    }

    /// Stage, in one channel's group, a commit naming `relay_vk` as the group's
    /// external sender. Returns the commit; the caller posts it to the new relay and
    /// merges or clears it. A private channel's commit names the server group's
    /// current epoch, so the server group's own commit must be merged first.
    pub fn stage_external_sender(&mut self, channel_id: &[u8; 32], relay_vk: &[u8; 32]) -> Result<Vec<u8>> {
        let aad = self.commit_aad(channel_id);
        let group = self.channel_groups.get_mut(channel_id).ok_or_else(|| {
            GhostError::ServerNotLoaded(format!("channel {}", short_id(channel_id)))
        })?;
        group.set_external_sender(&self.provider, relay_vk, &aad)
    }

    /// Ids of the server's channels that have an MLS group, with their mailboxes; the
    /// server's own group comes first, since its private channels are judged by it.
    pub fn server_channel_mailboxes(&self, server_id: &[u8; 32]) -> Vec<([u8; 32], [u8; 32])> {
        let default_channel = derive_default_channel_id(server_id);
        let mut mailboxes: Vec<([u8; 32], [u8; 32])> = self
            .server_channel_ids(server_id)
            .into_iter()
            .filter_map(|cid| self.channel_groups.get(&cid).map(|g| (cid, mls_group_mailbox_id(g.group_id()))))
            .collect();
        mailboxes.sort_by_key(|(cid, _)| *cid != default_channel);
        mailboxes
    }

    pub fn send_message(
        &mut self,
        server_id: &[u8; 32],
        channel_id: &[u8; 32],
        content: Vec<u8>,
        references: Vec<[u8; 32]>,
        timestamp: u64,
    ) -> Result<(Outbound, [u8; 32])> {
        self.ready_to_seal(server_id, channel_id)?;
        let group_channel = self.group_channel(channel_id);
        let group = self.channel_groups.get_mut(&group_channel).ok_or_else(|| {
            GhostError::ServerNotLoaded(format!("channel {}", short_id(channel_id)))
        })?;

        let kt_head_hash = self
            .idlog_cache
            .get(&self.identity.fingerprint)
            .map(|s| s.head_hash)
            .unwrap_or([0u8; 32]);
        let msg = ApplicationMessage::new(
            MessageType::Text,
            *channel_id,
            self.identity.fingerprint,
            timestamp,
            kt_head_hash,
            references,
            content,
        )?;

        let blob = seal(group, &self.provider, &msg)?;
        let mailbox_id = mls_group_mailbox_id(group.group_id());
        let message_id = msg.message_id;

        let now = now_millis();

        self.store.insert_message(&StoredMessage {
            message_id: msg.message_id,
            channel_id: msg.channel_id,
            sender_fp: msg.sender_fp,
            message_type: msg.message_type as u8,
            timestamp: msg.timestamp,
            received_at: now,
            content: msg.content,
            expires_at: None,
            references: msg.references,
            delivery: Delivery::Pending,
        })?;

        Ok((Outbound { channel_id: *channel_id, mailbox_id, blob }, message_id))
    }

    /// Whether a message may be sealed in the channel now: the account is still in the
    /// server, the device still follows it, and no one the channel's policy excludes is
    /// left in its group. The same gate for a first send and a resend.
    fn ready_to_seal(&self, server_id: &[u8; 32], channel_id: &[u8; 32]) -> Result<()> {
        self.ensure_member(server_id)?;
        self.ensure_following(server_id)?;
        // Never encrypt to someone a private channel no longer admits.
        if !self.excluded_leaves(&self.group_channel(channel_id))?.is_empty() {
            return Err(GhostError::PermissionDenied(
                "the channel still holds members who lost access; remove them first".into(),
            ));
        }
        Ok(())
    }

    /// Seal one of this device's pending messages again, at its group's current epoch,
    /// to send it anew, under the same checks as a first send. The message keeps its id,
    /// so a receiver that saw an earlier copy drops this one.
    pub fn reseal_message(&mut self, message_id: &[u8; 32]) -> Result<Outbound> {
        let stored = self.store.get_message(message_id)?;
        if stored.sender_fp != self.identity.fingerprint {
            return Err(GhostError::PermissionDenied("not a message of this account".into()));
        }
        let server_id = *self
            .channel_server
            .get(&stored.channel_id)
            .ok_or_else(|| GhostError::ServerNotLoaded(format!("channel {}", short_id(&stored.channel_id))))?;
        self.ready_to_seal(&server_id, &stored.channel_id)?;
        let message_type = MessageType::try_from(stored.message_type)
            .map_err(|v| GhostError::Format(format!("unknown message type: {v:#04x}")))?;
        let kt_head_hash = self.idlog_cache.get(&self.identity.fingerprint).map(|s| s.head_hash).unwrap_or([0u8; 32]);
        let msg = ApplicationMessage::new(
            message_type,
            stored.channel_id,
            stored.sender_fp,
            stored.timestamp,
            kt_head_hash,
            stored.references,
            stored.content,
        )?;
        let group_channel = self.group_channel(&stored.channel_id);
        let group = self.channel_groups.get_mut(&group_channel).ok_or_else(|| {
            GhostError::ServerNotLoaded(format!("channel {}", short_id(&stored.channel_id)))
        })?;
        let blob = seal(group, &self.provider, &msg)?;
        Ok(Outbound { channel_id: stored.channel_id, mailbox_id: mls_group_mailbox_id(group.group_id()), blob })
    }

    /// This device's messages the relay has not acknowledged, in the channels carried by
    /// `mailbox_id`'s group, oldest first.
    pub fn pending_messages_for_mailbox(&self, mailbox_id: &[u8; 32]) -> Result<Vec<StoredMessage>> {
        let Some(server_id) = self.server_id_for_mailbox(mailbox_id) else { return Ok(Vec::new()) };
        let channel_ids: Vec<[u8; 32]> = self
            .store
            .list_channels(&server_id)?
            .iter()
            .map(|c| c.channel_id)
            .filter(|cid| self.mailbox_id_for_channel(cid) == Some(*mailbox_id))
            .collect();
        self.store.pending_messages(&channel_ids)
    }

    /// Send a control message (e.g. channel ops). MLS-encrypted but not stored locally.
    /// Sent via the default channel's MLS group.
    pub fn send_control(
        &mut self,
        server_id: &[u8; 32],
        content: Vec<u8>,
    ) -> Result<Outbound> {
        self.send_control_in(&derive_default_channel_id(server_id), content)
    }

    /// Send a control message inside one channel's own group: for a private channel,
    /// whatever must stay among the members it admits, such as its name.
    pub fn send_control_in(&mut self, channel_id: &[u8; 32], content: Vec<u8>) -> Result<Outbound> {
        self.ensure_following_channel(channel_id)?;
        let fingerprint = self.identity.fingerprint;
        let channel_id = *channel_id;
        let group = self.channel_groups.get_mut(&channel_id).ok_or_else(|| {
            GhostError::ServerNotLoaded(format!("channel {}", short_id(&channel_id)))
        })?;

        let now = now_millis();

        let msg = ApplicationMessage::new(
            MessageType::Metadata,
            [0u8; 32],
            fingerprint,
            now,
            [0u8; 32],
            vec![],
            content,
        )?;

        let blob = seal(group, &self.provider, &msg)?;
        let mailbox_id = mls_group_mailbox_id(group.group_id());
        Ok(Outbound { channel_id, mailbox_id, blob })
    }

    /// Decrypt a blob and store the message. Uses relay-stamped arrival time if
    /// provided, otherwise falls back to local clock.
    pub fn receive_blob(
        &mut self,
        channel_id: &[u8; 32],
        blob: &[u8],
        received_at: Option<u64>,
    ) -> Result<ApplicationMessage> {
        let cache = &self.idlog_cache;
        let devices = |claim: &CredentialClaim| cache.status(claim);
        let group = self.channel_groups.get_mut(channel_id).ok_or_else(|| {
            GhostError::ServerNotLoaded(format!("channel {}", short_id(channel_id)))
        })?;

        let msg = open(group, &self.provider, blob, &devices)?;

        let recv_ts = received_at.unwrap_or_else(now_millis);

        self.store.insert_message(&StoredMessage {
            message_id: msg.message_id,
            channel_id: msg.channel_id,
            sender_fp: msg.sender_fp,
            message_type: msg.message_type as u8,
            timestamp: msg.timestamp,
            received_at: recv_ts,
            content: msg.content.clone(),
            expires_at: None,
            references: msg.references.clone(),
            delivery: Delivery::Delivered,
        })?;

        Ok(msg)
    }

    fn build_invite_payload(
        &self,
        server_id: &[u8; 32],
        server_name: &str,
        kind: ServerKind,
        members: &[Member],
        channels: &[Channel],
        grant: &ghost_wire::policy::InviteGrant,
    ) -> Result<InvitePayload> {
        // Public channels travel as metadata; the server group's GroupInfo is read from
        // the relay at join time, since every commit makes an embedded one stale. Private
        // channels never appear in an invite: joiners find the ones they may enter through
        // the relay's discovery, and others never learn of them.
        let invite_channels: Vec<InviteChannel> = channels
            .iter()
            .filter(|c| !self.is_private_channel(&c.channel_id))
            .map(|c| InviteChannel {
                channel_id: c.channel_id,
                name: c.name.clone(),
                kind: c.kind,
                position: c.position,
                group_info_bytes: Vec::new(),
            })
            .collect();

        Ok(InvitePayload {
            server_id: *server_id,
            server_name: server_name.to_string(),
            kind,
            members: members
                .iter()
                .map(|m| InviteMember {
                    fingerprint: m.fingerprint,
                    display_name: m.display_name.clone(),
                })
                .collect(),
            channels: invite_channels,
            role_names: self.store.list_role_names(server_id)?,
            grant: grant.clone(),
        })
    }

    /// Create an invite to a server: a grant signed by this device admitting whoever
    /// holds it until `expires_at`, inside a payload sealed under a fresh key that
    /// travels only in the invite link, so the relay storing it learns nothing. Needs
    /// the invite permission; the relay and members check the grant again at the join.
    pub fn create_invite(&self, server_id: &[u8; 32], expires_at: u64) -> Result<NewInvite> {
        let server_mailbox = self.check_may_invite(server_id)?;
        let mut nonce = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
        let grant = ghost_wire::policy::InviteGrant::sign(server_mailbox, self.identity.fingerprint, expires_at, nonce, &self.identity.signing_key);

        let mut key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
        let sealed_payload = self.sealed_invite_payload(server_id, &grant, &key)?;
        Ok(NewInvite { key, sealed_payload })
    }

    /// Whether this account may invite to the server: a member following it, holding the
    /// invite permission. Returns the server group's mailbox, which invites name.
    pub fn check_may_invite(&self, server_id: &[u8; 32]) -> Result<[u8; 32]> {
        self.ensure_member(server_id)?;
        self.ensure_following(server_id)?;
        if !self.server_policy(server_id)?.has(&self.identity.fingerprint, ghost_wire::policy::INVITE) {
            return Err(GhostError::PermissionDenied("creating invites needs the invite permission".into()));
        }
        Ok(mls_group_mailbox_id(self.default_group(server_id)?.group_id()))
    }

    /// Open a sealed invite payload with the key from its link.
    pub fn open_invite(&self, sealed_payload: &[u8], key: &[u8; 32]) -> Result<InvitePayload> {
        let opened = crate::crypto::aead::open(key, sealed_payload, crate::wire::INVITE_PAYLOAD_CONTEXT)?;
        InvitePayload::from_bytes(&opened)
    }

    /// Join the server an invite is into, by an external commit built on
    /// `server_group_info`: the server group's state as its relay holds it now. Returns
    /// the server id, one (channel, commit, mailbox) per group joined, and the grant.
    #[allow(clippy::type_complexity)]
    pub fn join_by_invite(
        &mut self,
        mut payload: InvitePayload,
        server_group_info: Vec<u8>,
        timestamp: u64,
    ) -> Result<([u8; 32], Vec<([u8; 32], Vec<u8>, [u8; 32])>, ghost_wire::policy::InviteGrant)> {
        let default_channel = derive_default_channel_id(&payload.server_id);
        let server_channel = payload
            .channels
            .iter_mut()
            .find(|ch| ch.channel_id == default_channel)
            .ok_or_else(|| GhostError::Format("invite names no default channel".into()))?;
        server_channel.group_info_bytes = server_group_info;
        let channel_results = self.join_server_common(
            payload.server_id, payload.server_name, payload.kind,
            &payload.members, &payload.channels, &payload.role_names, Some(&payload.grant), timestamp, false,
        )?;
        // The payload is from when the invite was made: the server's managers tell the rest.
        self.store.begin_server_state_wait(&payload.server_id)?;
        Ok((payload.server_id, channel_results, payload.grant))
    }

    /// Ask the server's members for its current state, as a device that just joined it.
    pub fn ask_server_state(&mut self, server_id: &[u8; 32]) -> Result<Outbound> {
        self.send_control(server_id, crate::wire::encode_server_state_request())
    }

    /// Answer a request for the server's state made at `request_seq`, when this account
    /// may manage the server's channels; `None` otherwise.
    pub fn server_state_reply(&mut self, server_id: &[u8; 32], request_seq: u64) -> Result<Option<Outbound>> {
        if !self.server_policy(server_id)?.has(&self.identity.fingerprint, ghost_wire::policy::MANAGE_CHANNELS) {
            return Ok(None);
        }
        let channels = self
            .store
            .list_channels(server_id)?
            .into_iter()
            .filter(|c| !self.is_private_channel(&c.channel_id))
            .map(|c| InviteChannel { channel_id: c.channel_id, name: c.name, kind: c.kind, position: c.position, group_info_bytes: Vec::new() })
            .collect();
        let members = self
            .store
            .list_members(server_id)?
            .into_iter()
            .filter(Member::has_name)
            .map(|m| InviteMember { fingerprint: m.fingerprint, display_name: m.display_name })
            .collect();
        let state = ServerStatePayload { request_seq, channels, role_names: self.store.list_role_names(server_id)?, members };
        self.send_control(server_id, crate::wire::encode_server_state(&state)).map(Some)
    }

    /// Take in a server's state sent by `sender`, while this device waits for it: the
    /// public channels become those listed, role names come when the sender may manage
    /// roles, and members still unnamed here take the names listed. An answer as of before
    /// a change this device saw would undo it, so it is refused as stale.
    pub fn apply_server_state(&mut self, server_id: &[u8; 32], sender: &[u8; 32], state: ServerStatePayload) -> Result<ServerStateOutcome> {
        let Some(wait) = self.store.server_state_wait(server_id)? else { return Ok(ServerStateOutcome::Ignored) };
        let Some(asked_at) = wait.request_seq else { return Ok(ServerStateOutcome::Ignored) };
        if state.request_seq < asked_at || !self.server_policy(server_id)?.has(sender, ghost_wire::policy::MANAGE_CHANNELS) {
            return Ok(ServerStateOutcome::Ignored);
        }
        if wait.last_change_seq > state.request_seq {
            return Ok(ServerStateOutcome::Stale);
        }
        let default_channel = derive_default_channel_id(server_id);
        let listed: HashSet<[u8; 32]> = state.channels.iter().map(|c| c.channel_id).collect();
        for c in state.channels.into_iter().filter(|c| !self.is_private_channel(&c.channel_id)) {
            self.store.upsert_channel(&Channel { channel_id: c.channel_id, server_id: *server_id, name: c.name, kind: c.kind, position: c.position })?;
        }
        for c in self.store.list_channels(server_id)? {
            let gone = !listed.contains(&c.channel_id) && c.channel_id != default_channel && !self.is_private_channel(&c.channel_id);
            if gone {
                self.store.delete_channel(&c.channel_id)?;
            }
        }
        self.apply_role_names(server_id, sender, &state.role_names)?;
        let unnamed: HashSet<[u8; 32]> = self.store.list_members(server_id)?.into_iter().filter(|m| !m.has_name()).map(|m| m.fingerprint).collect();
        for m in state.members.into_iter().filter(|m| unnamed.contains(&m.fingerprint)) {
            self.store.update_member_name(server_id, &m.fingerprint, &m.display_name)?;
        }
        self.store.end_server_state_wait(server_id)?;
        Ok(ServerStateOutcome::Applied)
    }

    fn sealed_invite_payload(
        &self,
        server_id: &[u8; 32],
        grant: &ghost_wire::policy::InviteGrant,
        key: &[u8; 32],
    ) -> Result<Vec<u8>> {
        let meta = self.store.get_server(server_id)?;
        let members = self.store.list_members(server_id)?;
        let channels = self.store.list_channels(server_id)?;
        let payload = self.build_invite_payload(server_id, &meta.name, meta.kind, &members, &channels, grant)?;
        crate::crypto::aead::seal(key, &payload.to_bytes(), crate::wire::INVITE_PAYLOAD_CONTEXT)
    }

    /// Export GroupInfo for a server's default channel so other clients can recover via external commit.
    pub fn export_server_info(&self, server_id: &[u8; 32]) -> Result<Vec<u8>> {
        let group = self.default_group(server_id)?;
        group.export_group_info(&self.provider)
    }

    /// Export GroupInfo for one channel's MLS group, which is what that channel's
    /// mailbox must hold for external-commit joins of that channel.
    pub fn export_channel_group_info(&self, channel_id: &[u8; 32]) -> Result<Vec<u8>> {
        let group = self.channel_groups.get(channel_id).ok_or_else(|| {
            GhostError::ServerNotLoaded(format!("channel {}", short_id(channel_id)))
        })?;
        group.export_group_info(&self.provider)
    }

    /// Build an external commit rejoining a channel's group at the epoch
    /// `group_info_bytes` describes, and use the new group from here on. The old group
    /// is kept, in memory and as its rows in the MLS storage, until `confirm_rejoin` or
    /// `abandon_rejoin` says whether the relay took the commit: a refused rejoin must
    /// leave the group exactly as it was.
    pub fn stage_rejoin(&mut self, channel_id: &[u8; 32], group_info_bytes: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
        if self.pending_rejoins.contains_key(channel_id) {
            return Err(GhostError::Mls("a rejoin of this group is still waiting for the relay".into()));
        }
        let aad = self.commit_aad(channel_id);
        let old = self
            .channel_groups
            .remove(channel_id)
            .ok_or_else(|| GhostError::ServerNotLoaded(format!("channel {}", short_id(channel_id))))?;
        let rows = self.provider.storage().group_rows(old.group_id())?;
        // The new group shares the old one's id, so writing it overwrites the old rows.
        let (new, commit_bytes) = match GhostGroup::join_by_external_commit(&self.provider, &self.identity, group_info_bytes, &aad) {
            Ok(built) => built,
            Err(e) => {
                if let Err(restore) = self.provider.storage().restore_group_rows(old.group_id(), &rows) {
                    tracing::error!("rejoin of {}: group rows not restored after a failed build: {restore}", short_id(channel_id));
                }
                self.channel_groups.insert(*channel_id, old);
                return Err(e);
            }
        };
        let mailbox_id = mls_group_mailbox_id(new.group_id());
        self.channel_groups.insert(*channel_id, new);
        self.mailbox_map.insert(mailbox_id, *channel_id);
        self.pending_rejoins.insert(*channel_id, PendingRejoin { old, rows });
        self.record_if_server_group(channel_id)?;
        Ok((commit_bytes, mailbox_id))
    }

    /// The relay took the rejoin: the rows the old group left behind go.
    pub fn confirm_rejoin(&mut self, channel_id: &[u8; 32]) -> Result<()> {
        let Some(pending) = self.pending_rejoins.remove(channel_id) else { return Ok(()) };
        self.provider.storage().delete_rows_still_held(&pending.rows)
    }

    /// The relay refused the rejoin: the old group is back, in memory and in storage.
    pub fn abandon_rejoin(&mut self, channel_id: &[u8; 32]) -> Result<()> {
        let Some(pending) = self.pending_rejoins.remove(channel_id) else { return Ok(()) };
        self.provider.storage().restore_group_rows(pending.old.group_id(), &pending.rows)?;
        self.channel_groups.insert(*channel_id, pending.old);
        self.record_if_server_group(channel_id)
    }

    /// Load a channel's group from the MLS storage again, as a restart would.
    #[cfg(test)]
    pub(crate) fn reload_group(&mut self, channel_id: &[u8; 32]) {
        let server_id = self.channel_server[channel_id];
        let group = GhostGroup::load(&self.provider, &self.identity, &server_id, channel_id).unwrap().expect("the group is in storage");
        self.channel_groups.insert(*channel_id, group);
    }

    /// Stage a commit replacing the server's policy: its roles, their assignments, what
    /// everyone may do, or its owner. Checked here against the current policy so a
    /// refusal comes early; the relay and every member check it again. Returns the
    /// commit to post; merge or clear the server group's pending commit afterwards.
    pub fn stage_server_policy(&mut self, server_id: &[u8; 32], policy: &ServerPolicy) -> Result<Outbound> {
        self.ensure_following(server_id)?;
        use ghost_wire::policy::{authorize_server_commit, CommitSummary, Committer, GrantContext};
        let current = self.server_policy(server_id)?;
        let channel_id = derive_default_channel_id(server_id);
        let group = self.channel_groups.get_mut(&channel_id).ok_or_else(|| {
            GhostError::ServerNotLoaded(short_id(server_id))
        })?;
        let mailbox_id = mls_group_mailbox_id(group.group_id());
        let summary = CommitSummary {
            committer: Committer::Member(self.identity.fingerprint),
            adds: Vec::new(),
            removes: Vec::new(),
            departed: Vec::new(),
            new_server_policy: Some(policy.clone()),
            new_channel_policy: None,
            new_removed: None,
        };
        let removed = group.removed_accounts()?.unwrap_or_default();
        let no_devices = |_: &[u8; 32], _: &[u8; 32]| false;
        let ctx = GrantContext { server_mailbox: mailbox_id, now_millis: now_millis(), is_member_device: &no_devices, removed: &removed };
        authorize_server_commit(&current, &summary, &ctx).map_err(|e| GhostError::PermissionDenied(e.to_string()))?;

        let policy = crate::mls::group::GhostExtension::Server(policy.clone());
        let blob = group.stage_policy(&self.provider, policy, &CommitAad::default())?;
        Ok(Outbound { channel_id, mailbox_id, blob })
    }

    /// Create a private channel: an MLS group of its own whose ChannelPolicy admits
    /// `roles` and `accounts` (and always the server's channel managers). Nothing goes
    /// to the server group, so members it does not admit never learn it exists. Needs
    /// the manage channels permission, which the relay checks again.
    #[allow(clippy::too_many_arguments)]
    pub fn create_private_channel(
        &mut self,
        server_id: &[u8; 32],
        name: &str,
        kind: ChannelKind,
        position: i32,
        roles: Vec<u8>,
        accounts: Vec<[u8; 32]>,
    ) -> Result<NewPrivateChannel> {
        self.ensure_following(server_id)?;
        use crate::mls::group::GhostExtension;
        use ghost_wire::policy::{ChannelPolicy, MANAGE_CHANNELS};
        let own = self.identity.fingerprint;
        if !self.server_policy(server_id)?.has(&own, MANAGE_CHANNELS) {
            return Err(GhostError::PermissionDenied("creating channels needs the manage channels permission".into()));
        }
        let server_mailbox = mls_group_mailbox_id(self.default_group(server_id)?.group_id());
        // The relay hosting the server proposes removals in its channels too.
        // The hosting relay is the group's external sender, so it can propose removals.
        let relay_vk = self
            .store
            .server_relay(server_id)?
            .or(self.relay_vk)
            .ok_or_else(|| GhostError::Network("the server's relay key is not known yet; connect to it first".into()))?;

        let mut channel_id = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut channel_id);
        let policy = ChannelPolicy { server_mailbox, channel_id, roles, accounts };
        let group = GhostGroup::create(
            &self.provider,
            &self.identity,
            server_id,
            &channel_id,
            Some(&relay_vk),
            Some(GhostExtension::Channel(policy)),
        )?;
        let group_info = group.export_group_info(&self.provider)?;
        let mailbox_id = mls_group_mailbox_id(group.group_id());

        self.store.insert_channel(&Channel { channel_id, server_id: *server_id, name: name.to_string(), kind, position }, OnConflict::Fail)?;
        self.channel_groups.insert(channel_id, group);
        self.mailbox_map.insert(mailbox_id, channel_id);
        self.channel_server.insert(channel_id, *server_id);

        let op = crate::wire::ChannelOpPayload::Create { channel_id, name: name.to_string(), kind, position };
        let announcement = self.send_control_in(&channel_id, crate::wire::encode_channel_op(&op))?;
        Ok(NewPrivateChannel { channel_id, mailbox_id, group_info, announcement })
    }

    /// Join a private channel the relay listed: stage an external commit, then check
    /// that the group belongs to this server (its id derives from the server id, which
    /// the relay never learns) and admits this account before letting the commit go.
    /// Returns (channel_id, mailbox_id, commit). The channel is unnamed until a member
    /// answers the info request this device sends once the relay accepts the commit;
    /// if the relay refuses it, call `drop_private_channel`.
    pub fn join_private_channel(&mut self, server_id: &[u8; 32], group_info: &[u8]) -> Result<([u8; 32], [u8; 32], Vec<u8>)> {
        let server_epoch = self.default_group(server_id)?.epoch();
        let aad = CommitAad { invite: None, server_epoch: Some(server_epoch) };
        let (group, commit) = GhostGroup::join_by_external_commit(&self.provider, &self.identity, group_info, &aad)?;

        let refuse = |group: GhostGroup, provider: &GhostProvider, why: &str| {
            let _ = group.delete(provider);
            Err(GhostError::PermissionDenied(format!("not joining listed channel: {why}")))
        };
        let Some(policy) = group.channel_policy()? else {
            return refuse(group, &self.provider, "it is not a private channel");
        };
        if group.group_id() != crate::wire::derive_mls_group_id(server_id, &policy.channel_id) {
            return refuse(group, &self.provider, "its group does not belong to this server");
        }
        let server_group = self.default_group(server_id)?;
        if mls_group_mailbox_id(server_group.group_id()) != policy.server_mailbox {
            return refuse(group, &self.provider, "it names another server");
        }
        let members: Vec<openmls::prelude::Member> = server_group.members().collect();
        let view = policy_mls::server_view(server_group.context_extensions(), &members)
            .map_err(|e| GhostError::Format(format!("server policy: {e}")))?;
        if !policy.admits(&self.identity.fingerprint, &view) {
            return refuse(group, &self.provider, "its policy does not admit this account");
        }

        let channel_id = policy.channel_id;
        let mailbox_id = mls_group_mailbox_id(group.group_id());
        self.store.insert_channel(&Channel {
            channel_id,
            server_id: *server_id,
            name: crate::wire::UNNAMED_PRIVATE_CHANNEL.to_string(),
            kind: ChannelKind::Text,
            position: 0,
        }, OnConflict::Keep)?;
        self.store.record_group_join(&channel_id, group.epoch())?;
        self.channel_groups.insert(channel_id, group);
        self.mailbox_map.insert(mailbox_id, channel_id);
        self.channel_server.insert(channel_id, *server_id);
        Ok((channel_id, mailbox_id, commit))
    }

    /// The server's private channels this device holds without a name and has not asked
    /// about in this run.
    pub fn unasked_unnamed_channels(&self, server_id: &[u8; 32]) -> Result<Vec<[u8; 32]>> {
        Ok(self
            .store
            .list_channels(server_id)?
            .into_iter()
            .filter(|ch| ch.name == crate::wire::UNNAMED_PRIVATE_CHANNEL && self.is_private_channel(&ch.channel_id))
            .map(|ch| ch.channel_id)
            .filter(|channel_id| !self.names_asked.contains(channel_id))
            .collect())
    }

    /// Ask a private channel's members for its name and kind, which a device that joined
    /// cannot read from before its join. Counted as asked once the relay takes it.
    pub fn ask_channel_name(&mut self, channel_id: &[u8; 32]) -> Result<Outbound> {
        let op = crate::wire::ChannelOpPayload::InfoRequest { channel_id: *channel_id };
        self.send_control_in(channel_id, crate::wire::encode_channel_op(&op))
    }

    /// The relay took this device's request for a private channel's name.
    pub fn channel_name_asked(&mut self, channel_id: &[u8; 32]) {
        self.names_asked.insert(*channel_id);
    }

    /// Answer a newly joined device's request for a private channel's name and kind,
    /// inside the channel's group. `None` when this device does not know them either.
    pub fn channel_info_reply(&mut self, channel_id: &[u8; 32]) -> Result<Option<Outbound>> {
        let channel = self.store.get_channel(channel_id)?;
        if !self.is_private_channel(channel_id) || channel.name == crate::wire::UNNAMED_PRIVATE_CHANNEL {
            return Ok(None);
        }
        let op = crate::wire::ChannelOpPayload::Create {
            channel_id: *channel_id,
            name: channel.name,
            kind: channel.kind,
            position: channel.position,
        };
        self.send_control_in(channel_id, crate::wire::encode_channel_op(&op)).map(Some)
    }

    /// Apply a channel operation that `sender` sent in the group of `group_channel`.
    /// Senders are authenticated by MLS; what they may do comes from the server policy,
    /// so every member's device reaches the same channel list. Operations inside a
    /// private channel's group concern only that channel.
    pub fn apply_channel_op(
        &mut self,
        group_channel: &[u8; 32],
        sender: &[u8; 32],
        op: crate::wire::ChannelOpPayload,
    ) -> Result<ChannelOpOutcome> {
        use crate::wire::ChannelOpPayload;
        let server_id = *self
            .channel_server
            .get(group_channel)
            .ok_or_else(|| GhostError::ServerNotLoaded(format!("channel {}", short_id(group_channel))))?;
        let may_manage = self.server_policy(&server_id)?.has(sender, ghost_wire::policy::MANAGE_CHANNELS);

        if self.is_private_channel(group_channel) {
            let target = match &op {
                ChannelOpPayload::Create { channel_id, .. }
                | ChannelOpPayload::Rename { channel_id, .. }
                | ChannelOpPayload::Delete { channel_id }
                | ChannelOpPayload::InfoRequest { channel_id } => *channel_id,
                // A private channel takes its place through `Create` in its own group.
                ChannelOpPayload::Reorder { .. } => return Ok(ChannelOpOutcome::Ignored),
            };
            if target != *group_channel {
                return Ok(ChannelOpOutcome::Ignored);
            }
            return match op {
                ChannelOpPayload::Create { channel_id, name, kind, position } => {
                    // Any member may tell a device that has no name yet; renaming needs the permission.
                    let unnamed = self.store.get_channel(&channel_id)?.name == crate::wire::UNNAMED_PRIVATE_CHANNEL;
                    if !unnamed && !may_manage {
                        return Ok(ChannelOpOutcome::Ignored);
                    }
                    self.store.upsert_channel(&Channel { channel_id, server_id, name, kind, position })?;
                    Ok(ChannelOpOutcome::Applied)
                }
                ChannelOpPayload::Rename { channel_id, name } if may_manage => {
                    self.store.rename_channel(&channel_id, &name)?;
                    Ok(ChannelOpOutcome::Applied)
                }
                ChannelOpPayload::Delete { channel_id } if may_manage => {
                    self.forget_deleted_private_channel(&channel_id, false)?;
                    Ok(ChannelOpOutcome::Applied)
                }
                ChannelOpPayload::InfoRequest { channel_id } => Ok(match self.channel_info_reply(&channel_id)? {
                    Some(reply) => ChannelOpOutcome::Reply(reply),
                    None => ChannelOpOutcome::Ignored,
                }),
                _ => Ok(ChannelOpOutcome::Ignored),
            };
        }

        if !may_manage {
            return Ok(ChannelOpOutcome::Ignored);
        }
        match op {
            ChannelOpPayload::Create { channel_id, name, kind, position } => {
                self.store.insert_channel(&Channel { channel_id, server_id, name, kind, position }, OnConflict::Keep)?;
            }
            ChannelOpPayload::Reorder { positions } => {
                // Private channels take their place through their own groups.
                let public: Vec<([u8; 32], i32)> = positions.into_iter().filter(|(channel_id, _)| !self.is_private_channel(channel_id)).collect();
                self.store.set_channel_positions(&server_id, &public)?;
            }
            // Private channels are renamed and deleted only inside their own group.
            ChannelOpPayload::Rename { channel_id, name } if !self.is_private_channel(&channel_id) => {
                self.store.rename_channel(&channel_id, &name)?;
            }
            ChannelOpPayload::Delete { channel_id } if !self.is_private_channel(&channel_id) => {
                self.store.delete_channel(&channel_id)?;
            }
            _ => return Ok(ChannelOpOutcome::Ignored),
        }
        Ok(ChannelOpOutcome::Applied)
    }

    /// Record roles' display names sent by `sender`, who must be able to manage roles.
    /// Returns whether they were recorded.
    pub fn apply_role_names(&mut self, server_id: &[u8; 32], sender: &[u8; 32], names: &[(u8, String)]) -> Result<bool> {
        if !self.server_policy(server_id)?.has(sender, ghost_wire::policy::MANAGE_ROLES) {
            return Ok(false);
        }
        for (role_id, name) in names {
            self.store.set_role_name(server_id, *role_id, name)?;
        }
        Ok(true)
    }

    /// Name roles: stored here and sent to the server's members in one encrypted
    /// metadata message. Needs the manage roles permission.
    pub fn name_roles(&mut self, server_id: &[u8; 32], names: &[(u8, String)]) -> Result<Outbound> {
        if !self.server_policy(server_id)?.has(&self.identity.fingerprint, ghost_wire::policy::MANAGE_ROLES) {
            return Err(GhostError::PermissionDenied("naming roles needs the manage roles permission".into()));
        }
        self.send_control(server_id, crate::wire::encode_role_names(names))
    }

    /// Forget a private channel this device is no longer in (or failed to join).
    /// Forget a deleted private channel and remember its mailbox, so discovery does not
    /// join it again while the relay still lists it; `owed` when this device deleted it
    /// and must still delete the mailbox at the relay. Returns the mailbox.
    pub fn forget_deleted_private_channel(&mut self, channel_id: &[u8; 32], owed: bool) -> Result<[u8; 32]> {
        let server_id = *self.channel_server.get(channel_id).ok_or_else(|| GhostError::ServerNotLoaded(format!("channel {}", short_id(channel_id))))?;
        let group = self.channel_groups.get(channel_id).ok_or_else(|| GhostError::ServerNotLoaded(format!("channel {}", short_id(channel_id))))?;
        let mailbox_id = mls_group_mailbox_id(group.group_id());
        self.store.record_deleted_channel(&mailbox_id, &server_id, owed)?;
        self.drop_private_channel(channel_id)?;
        Ok(mailbox_id)
    }

    pub fn drop_private_channel(&mut self, channel_id: &[u8; 32]) -> Result<()> {
        if let Some(group) = self.channel_groups.remove(channel_id) {
            self.mailbox_map.remove(&mls_group_mailbox_id(group.group_id()));
            let _ = group.delete(&self.provider);
        }
        self.channel_server.remove(channel_id);
        let _ = self.store.delete_channel(channel_id);
        Ok(())
    }

    /// The policy of a private channel, or `None` for a public one.
    pub fn channel_policy(&self, channel_id: &[u8; 32]) -> Result<Option<ghost_wire::policy::ChannelPolicy>> {
        match self.channel_groups.get(channel_id) {
            Some(group) if self.is_private_channel(channel_id) => group.channel_policy(),
            _ => Ok(None),
        }
    }

    /// Stage a commit changing who a private channel admits. Needs the manage channels
    /// permission; the relay and members check it again and the relay then proposes
    /// removing whoever it no longer admits.
    pub fn stage_channel_policy(&mut self, channel_id: &[u8; 32], policy: &ghost_wire::policy::ChannelPolicy) -> Result<Outbound> {
        self.ensure_following_channel(channel_id)?;
        let current = self
            .channel_policy(channel_id)?
            .ok_or_else(|| GhostError::Format("not a private channel".into()))?;
        if policy.server_mailbox != current.server_mailbox || policy.channel_id != current.channel_id {
            return Err(GhostError::PermissionDenied("a channel's server and id are fixed".into()));
        }
        let server_id = *self.channel_server.get(channel_id).ok_or_else(|| GhostError::ServerNotLoaded("channel's server".into()))?;
        if !self.server_policy(&server_id)?.has(&self.identity.fingerprint, ghost_wire::policy::MANAGE_CHANNELS) {
            return Err(GhostError::PermissionDenied("changing a channel's access needs the manage channels permission".into()));
        }
        let aad = self.commit_aad(channel_id);
        let group = self.channel_groups.get_mut(channel_id).expect("policy read above");
        let blob = group.stage_policy(&self.provider, crate::mls::group::GhostExtension::Channel(policy.clone()), &aad)?;
        let mailbox_id = mls_group_mailbox_id(group.group_id());
        Ok(Outbound { channel_id: *channel_id, mailbox_id, blob })
    }

    /// Leaves of a private channel's group whose accounts its policy no longer admits
    /// under the server's current state; empty for a public channel.
    pub fn excluded_leaves(&self, channel_id: &[u8; 32]) -> Result<Vec<LeafNodeIndex>> {
        let Some(policy) = self.channel_policy(channel_id)? else { return Ok(Vec::new()) };
        let server_id = self.channel_server.get(channel_id).ok_or_else(|| GhostError::ServerNotLoaded("channel's server".into()))?;
        let server_group = self.default_group(server_id)?;
        let server_members: Vec<openmls::prelude::Member> = server_group.members().collect();
        let view = policy_mls::server_view(server_group.context_extensions(), &server_members)
            .map_err(|e| GhostError::Format(format!("server policy: {e}")))?;
        let group = self.channel_groups.get(channel_id).expect("policy read above");
        let members: Vec<openmls::prelude::Member> = group.members().collect();
        Ok(policy_mls::excluded_leaves(&policy, &view, &members))
    }

    /// Stage a commit removing everyone a private channel no longer admits, which must
    /// happen before anything more is sent there. `None` when nobody is excluded.
    pub fn remove_excluded(&mut self, channel_id: &[u8; 32]) -> Result<Option<Outbound>> {
        let excluded = self.excluded_leaves(channel_id)?;
        if excluded.is_empty() {
            return Ok(None);
        }
        let blob = self.remove_channel_members(channel_id, &excluded)?;
        let mailbox_id = self.channel_groups.get(channel_id).map(|g| mls_group_mailbox_id(g.group_id())).expect("checked above");
        Ok(Some(Outbound { channel_id: *channel_id, mailbox_id, blob }))
    }

    /// The name `account` goes by in the server: a member's, else a former member's.
    pub fn member_name(&self, server_id: &[u8; 32], account: &[u8; 32]) -> Option<String> {
        let members = self.store.list_members(server_id).ok()?;
        match members.into_iter().find(|m| m.fingerprint == *account) {
            Some(member) => Some(member.display_name),
            None => self.store.former_member_name(server_id, account).ok().flatten(),
        }
    }

    /// When, and by whom when known, this account was removed from a server it still
    /// shows read-only.
    pub fn removed_from(&self, server_id: &[u8; 32]) -> Result<Option<crate::storage::ServerRemoval>> {
        self.store.server_removal(server_id)
    }

    /// Fail with `RemovedFromServer` once this account was removed from the server, so
    /// nothing is sent to a server it is no longer in.
    pub fn ensure_member(&self, server_id: &[u8; 32]) -> Result<()> {
        match self.removed_from(server_id)? {
            Some(_) => Err(GhostError::RemovedFromServer),
            None => Ok(()),
        }
    }

    /// Why this device stopped following the server, if it did.
    pub fn halt(&self, server_id: &[u8; 32]) -> Result<Option<crate::storage::ServerHalt>> {
        self.store.server_halt(server_id)
    }

    /// Fail while the server is halted: its relay accepted a change the rules forbid, and
    /// nothing goes there until the person accepts the relay's state or leaves.
    pub fn ensure_following(&self, server_id: &[u8; 32]) -> Result<()> {
        match self.store.server_halt(server_id)? {
            Some(halt) => Err(GhostError::PolicyRefused(format!("{}; the server is read-only until you accept the relay's state or leave", halt.reason))),
            None => Ok(()),
        }
    }

    /// `ensure_following` for the server a channel belongs to.
    fn ensure_following_channel(&self, channel_id: &[u8; 32]) -> Result<()> {
        match self.channel_server.get(channel_id) {
            Some(server_id) => self.ensure_following(&server_id.clone()),
            None => Ok(()),
        }
    }

    /// Forget a server this account was removed from, or stopped following, with its
    /// history. A server this device is still in is left through its group, not here.
    pub fn forget_server(&mut self, server_id: &[u8; 32]) -> Result<()> {
        if self.removed_from(server_id)?.is_none() && self.store.server_halt(server_id)?.is_none() {
            return Err(GhostError::PermissionDenied("only a server you were removed from or stopped following can be forgotten".into()));
        }
        self.drop_server(server_id)
    }

    /// Undo a first join the relay refused: nothing of the server stays.
    pub fn abandon_join(&mut self, server_id: &[u8; 32]) -> Result<()> {
        self.drop_server(server_id)
    }

    /// Drop a server and its groups from this device: the groups' state, and every row
    /// of the server, which go with it.
    fn drop_server(&mut self, server_id: &[u8; 32]) -> Result<()> {
        let channels: Vec<[u8; 32]> = self.channel_server.iter().filter(|(_, s)| *s == server_id).map(|(c, _)| *c).collect();
        for channel_id in channels {
            if let Some(group) = self.channel_groups.remove(&channel_id) {
                if let Err(e) = group.delete(&self.provider) {
                    tracing::warn!("group of channel {} not deleted: {e}", short_id(&channel_id));
                }
            }
            self.channel_server.remove(&channel_id);
        }
        self.mailbox_map.retain(|_, channel_id| self.channel_groups.contains_key(channel_id));
        self.store.delete_server(server_id)
    }

    /// Accounts the server keeps from rejoining, with the name each had here when known.
    pub fn kept_out(&self, server_id: &[u8; 32]) -> Result<Vec<(RemovedAccount, Option<String>)>> {
        let removed = self.default_group(server_id)?.removed_accounts()?.unwrap_or_default();
        removed
            .entries
            .into_iter()
            .map(|entry| Ok((entry, self.store.former_member_name(server_id, &entry.account)?)))
            .collect()
    }

    /// Let a removed account back in, so it may rejoin with an invite. Needs the kick
    /// permission; any roles the account still held go with the same commit.
    pub fn let_back_in(&mut self, server_id: &[u8; 32], account: &[u8; 32]) -> Result<Outbound> {
        let policy = self.server_policy(server_id)?;
        if !policy.has(&self.identity.fingerprint, ghost_wire::policy::KICK) {
            return Err(GhostError::PermissionDenied("letting someone back in needs the kick permission".into()));
        }
        let channel_id = derive_default_channel_id(server_id);
        let group = self.channel_groups.get_mut(&channel_id).ok_or_else(|| GhostError::ServerNotLoaded(short_id(server_id)))?;
        let removed = group.removed_accounts()?.unwrap_or_default();
        if !removed.contains(account) {
            return Err(GhostError::PermissionDenied("that account is not kept out of this server".into()));
        }
        let mut updates = vec![GhostExtension::Removals(removed.without(account))];
        let pruned = policy.without_assignments(&[*account]);
        if pruned != policy {
            updates.push(GhostExtension::Server(pruned));
        }
        let blob = group.stage_change(&self.provider, &[], &updates, &CommitAad::default())?;
        let mailbox_id = mls_group_mailbox_id(group.group_id());
        Ok(Outbound { channel_id, mailbox_id, blob })
    }

    /// Remove a member from the server group: needs the kick permission and a rank above
    /// the member's. The same commit keeps the account from rejoining until someone who
    /// may kick lets it back, and drops its roles, as Signal's removal does. The relay then
    /// proposes removing the member from every private channel, whose policies admit only
    /// server members.
    pub fn kick_member(&mut self, server_id: &[u8; 32], target_fp: &[u8; 32], now: u64) -> Result<Outbound> {
        self.ensure_following(server_id)?;
        if target_fp == &self.identity.fingerprint {
            return Err(GhostError::PermissionDenied("cannot kick yourself".into()));
        }
        let policy = self.server_policy(server_id)?;
        let own = self.identity.fingerprint;
        if !policy.has(&own, ghost_wire::policy::KICK) || !policy.rank(&own).outranks(policy.rank(target_fp)) {
            return Err(GhostError::PermissionDenied(
                "kicking this member needs the kick permission and a higher rank".into(),
            ));
        }

        let channel_id = derive_default_channel_id(server_id);
        let group = self.channel_groups.get_mut(&channel_id).ok_or_else(|| {
            GhostError::ServerNotLoaded(short_id(server_id))
        })?;
        let leaf_indices: Vec<_> = group
            .members()
            .filter(|m| {
                crate::mls::credential::parse_credential(&m.credential)
                    .is_ok_and(|pc| pc.account_fp == *target_fp)
            })
            .map(|m| m.index)
            .collect();
        if leaf_indices.is_empty() {
            return Err(GhostError::Mls("member not found in the server group".into()));
        }
        let mut updates = vec![GhostExtension::Removals(group.removed_accounts()?.unwrap_or_default().with_removed(*target_fp, now))];
        let pruned = policy.without_assignments(&[*target_fp]);
        if pruned != policy {
            updates.push(GhostExtension::Server(pruned));
        }
        let blob = group.stage_change(&self.provider, &leaf_indices, &updates, &CommitAad::default())?;
        let mailbox_id = mls_group_mailbox_id(group.group_id());
        Ok(Outbound { channel_id, mailbox_id, blob })
    }

    /// Remove a specific device's leaf from all channel MLS groups by its verifying key.
    /// Returns a list of (mailbox_id, commit_blob) to broadcast.
    /// One commit per channel group removing every leaf of the given devices.
    pub fn revoke_devices_leaves(&mut self, device_vks: &[[u8; 32]]) -> Vec<Outbound> {
        let channel_ids: Vec<[u8; 32]> = self.channel_groups.keys().copied().collect();
        let mut outbound = Vec::new();
        for cid in channel_ids {
            let leaf_indices = self.find_devices_leaves(&cid, device_vks);
            if leaf_indices.is_empty() {
                continue;
            }
            let aad = self.commit_aad(&cid);
            let Some(group) = self.channel_groups.get_mut(&cid) else { continue };
            if let Ok(commit_blob) = group.remove_members(&self.provider, &leaf_indices, &aad) {
                let mailbox_id = mls_group_mailbox_id(group.group_id());
                outbound.push(Outbound { channel_id: cid, mailbox_id, blob: commit_blob });
            }
        }
        outbound
    }

    /// The leaves of one device in a channel's MLS group.
    pub fn find_device_leaves(&self, channel_id: &[u8; 32], device_vk: &[u8; 32]) -> Vec<LeafNodeIndex> {
        self.find_devices_leaves(channel_id, std::slice::from_ref(device_vk))
    }

    /// The leaves of the given devices in a channel's MLS group.
    pub fn find_devices_leaves(&self, channel_id: &[u8; 32], device_vks: &[[u8; 32]]) -> Vec<LeafNodeIndex> {
        let Some(group) = self.channel_groups.get(channel_id) else { return vec![] };
        group
            .members()
            .filter(|m| device_vks.iter().any(|vk| m.signature_key.as_slice() == vk.as_slice()))
            .map(|m| m.index)
            .collect()
    }

    /// Create a remove-members commit for a specific channel's MLS group.
    pub fn remove_channel_members(
        &mut self,
        channel_id: &[u8; 32],
        members: &[LeafNodeIndex],
    ) -> Result<Vec<u8>> {
        let aad = self.commit_aad(channel_id);
        let group = self.channel_groups.get_mut(channel_id).ok_or_else(|| {
            GhostError::ServerNotLoaded(format!("channel {}", short_id(channel_id)))
        })?;
        group.remove_members(&self.provider, members, &aad)
    }

    /// Merge a pending commit for a channel's MLS group after the relay accepted it.
    pub fn merge_pending_commit_for_channel(&mut self, channel_id: &[u8; 32]) -> Result<()> {
        let group = self.channel_groups.get_mut(channel_id).ok_or_else(|| {
            GhostError::ServerNotLoaded(format!("channel {}", short_id(channel_id)))
        })?;
        group.merge_pending_commit(&self.provider)?;
        self.record_if_server_group(channel_id)
    }

    /// Discard a pending commit for a channel's MLS group after the relay rejected it.
    pub fn clear_pending_commit_for_channel(&mut self, channel_id: &[u8; 32]) -> Result<()> {
        let group = self.channel_groups.get_mut(channel_id).ok_or_else(|| {
            GhostError::ServerNotLoaded(format!("channel {}", short_id(channel_id)))
        })?;
        group.clear_pending_commit(&self.provider)
    }

    /// Convenience: clear pending commit using server_id (operates on default channel).
    pub fn clear_pending_commit_for_server(&mut self, server_id: &[u8; 32]) -> Result<()> {
        let channel_id = derive_default_channel_id(server_id);
        self.clear_pending_commit_for_channel(&channel_id)
    }

    /// Get the current MLS epoch for a channel's group.
    /// The epoch of the group carrying `channel_id`.
    pub fn channel_epoch(&self, channel_id: &[u8; 32]) -> Result<u64> {
        let group = self.channel_groups.get(&self.group_channel(channel_id)).ok_or_else(|| {
            GhostError::ServerNotLoaded(format!("channel {}", short_id(channel_id)))
        })?;
        Ok(group.epoch())
    }

    /// The group carrying `channel_id`.
    fn group_of_channel(&self, channel_id: &[u8; 32]) -> Result<&GhostGroup> {
        self.channel_groups.get(&self.group_channel(channel_id)).ok_or_else(|| {
            GhostError::ServerNotLoaded(format!("channel {}", short_id(channel_id)))
        })
    }

    /// This device, as the relay stamps it on the presence it sends.
    pub fn presence_sender(&self) -> ghost_wire::presence::PresenceSender {
        ghost_wire::presence::PresenceSender {
            account_fp: self.identity.fingerprint,
            device_vk: *self.identity.verifying_key.as_bytes(),
        }
    }

    /// The group must hold a leaf for the stamped sender: that account, signing with
    /// that device key. Otherwise the relay attributed the blob to someone outside it.
    fn require_member_device(group: &GhostGroup, sender: &ghost_wire::presence::PresenceSender) -> Result<()> {
        let present = group.members().any(|m| {
            m.signature_key.as_slice() == sender.device_vk
                && crate::mls::credential::parse_credential(&m.credential).is_ok_and(|c| c.account_fp == sender.account_fp)
        });
        if present {
            Ok(())
        } else {
            Err(GhostError::Crypto("presence from a device that is not in the group".into()))
        }
    }

    /// Derive a per-sender encryption key for voice in this channel.
    /// `voice_salt` is a random value from the sender's presence blob, ensuring
    /// unique keys per voice session even within the same MLS epoch.
    pub fn derive_voice_key(
        &self,
        channel_id: &[u8; 32],
        sender_fp: &[u8; 32],
        device_vk: &[u8; 32],
        voice_salt: &[u8; 32],
    ) -> Result<[u8; 32]> {
        let group = self.group_of_channel(channel_id)?;
        crate::mls::voice::derive_voice_key(group, &self.provider, channel_id, sender_fp, device_vk, voice_salt)
    }

    /// Seal this device's presence in a voice channel. `voice_salt` is a random value
    /// generated once per voice session and reused for all presence updates within it.
    pub fn seal_presence_blob(&self, channel_id: &[u8; 32], muted: bool, deafened: bool, voice_salt: [u8; 32]) -> Result<Vec<u8>> {
        let group = self.group_of_channel(channel_id)?;
        let sender = self.presence_sender();
        let key = crate::mls::voice::derive_presence_key(group, &self.provider, channel_id, &sender)?;
        let state = crate::mls::voice::PresenceState::new(&sender, muted, deafened, voice_salt);
        crate::mls::voice::seal_presence(&key, channel_id, &state)
    }

    /// Open a voice presence blob the relay attributed to `sender`, who must be in the
    /// channel's group.
    pub fn open_presence_blob(
        &self,
        channel_id: &[u8; 32],
        sender: &ghost_wire::presence::PresenceSender,
        blob: &[u8],
    ) -> Result<crate::mls::voice::PresenceState> {
        let group = self.group_of_channel(channel_id)?;
        Self::require_member_device(group, sender)?;
        let key = crate::mls::voice::derive_presence_key(group, &self.provider, channel_id, sender)?;
        crate::mls::voice::open_presence(&key, channel_id, sender, blob)
    }

    /// Seal this device's online presence for a server.
    pub fn seal_online_presence_blob(
        &self,
        server_id: &[u8; 32],
        status: crate::mls::presence::OnlineStatus,
        status_message: Option<String>,
        status_expiry: Option<u64>,
        avatar: Option<crate::mls::presence::AvatarRef>,
    ) -> Result<Vec<u8>> {
        let group = self.default_group(server_id)?;
        let sender = self.presence_sender();
        let key = crate::mls::presence::derive_online_presence_key(group, &self.provider, &sender)?;
        let state = crate::mls::presence::OnlinePresence { status, status_message, status_expiry, avatar };
        crate::mls::presence::seal_online_presence(&key, &sender, &state)
    }

    /// Open an online presence blob the relay attributed to `sender`, who must be in
    /// the server's group.
    pub fn open_online_presence_blob(
        &self,
        server_id: &[u8; 32],
        sender: &ghost_wire::presence::PresenceSender,
        blob: &[u8],
    ) -> Result<crate::mls::presence::OnlinePresence> {
        let group = self.default_group(server_id)?;
        Self::require_member_device(group, sender)?;
        let key = crate::mls::presence::derive_online_presence_key(group, &self.provider, sender)?;
        crate::mls::presence::open_online_presence(&key, sender, blob)
    }

    /// Returns (channel_id, mailbox_id) for every loaded channel group.
    pub fn channel_mailboxes(&self) -> Vec<([u8; 32], [u8; 32])> {
        self.channel_groups
            .iter()
            .map(|(cid, g)| (*cid, mls_group_mailbox_id(g.group_id())))
            .collect()
    }

    /// Returns (server_id, mailbox_id) for each server's default channel.
    /// Deduplicated by server_id — one entry per server.
    pub fn server_mailboxes(&self) -> Vec<([u8; 32], [u8; 32])> {
        let mut seen = std::collections::HashSet::new();
        let mut result = Vec::new();
        for (cid, g) in &self.channel_groups {
            if let Some(&sid) = self.channel_server.get(cid) {
                let default_ch = derive_default_channel_id(&sid);
                if *cid == default_ch && seen.insert(sid) {
                    result.push((sid, mls_group_mailbox_id(g.group_id())));
                }
            }
        }
        result
    }

    /// Direct lookup: get mailbox_id for the default channel of a server.
    pub fn mailbox_id_for_server(&self, server_id: &[u8; 32]) -> Option<[u8; 32]> {
        let ch = derive_default_channel_id(server_id);
        self.channel_groups
            .get(&ch)
            .map(|g| mls_group_mailbox_id(g.group_id()))
    }

    /// Mailbox of the group carrying a channel's traffic: its own for a private
    /// channel, its server's otherwise.
    pub fn mailbox_id_for_channel(&self, channel_id: &[u8; 32]) -> Option<[u8; 32]> {
        self.channel_groups
            .get(&self.group_channel(channel_id))
            .map(|g| mls_group_mailbox_id(g.group_id()))
    }

    /// Reverse lookup: find channel_id for a given mailbox_id.
    pub fn channel_id_for_mailbox(&self, mailbox_id: &[u8; 32]) -> Option<[u8; 32]> {
        self.mailbox_map.get(mailbox_id).copied()
    }

    /// Reverse lookup: find server_id for a given mailbox_id.
    pub fn server_id_for_mailbox(&self, mailbox_id: &[u8; 32]) -> Option<[u8; 32]> {
        self.mailbox_map.get(mailbox_id)
            .and_then(|cid| self.channel_server.get(cid))
            .copied()
    }

    /// The server whose own group's mailbox this is, the one its online presence goes
    /// over; `None` for a private channel's mailbox, which only some members connect to.
    pub fn server_id_for_server_mailbox(&self, mailbox_id: &[u8; 32]) -> Option<[u8; 32]> {
        let channel_id = self.mailbox_map.get(mailbox_id)?;
        let server_id = self.channel_server.get(channel_id)?;
        (*channel_id == derive_default_channel_id(server_id)).then_some(*server_id)
    }

    /// Extract fingerprints of all MLS group members from a channel's group.
    pub fn mls_member_fingerprints_for_channel(&self, channel_id: &[u8; 32]) -> Result<Vec<[u8; 32]>> {
        let group = self.channel_groups.get(&self.group_channel(channel_id)).ok_or_else(|| {
            GhostError::ServerNotLoaded(format!("channel {}", short_id(channel_id)))
        })?;
        let mut fps = Vec::new();
        for member in group.members() {
            if let Ok(pc) = crate::mls::credential::parse_credential(&member.credential) {
                fps.push(pc.account_fp);
            }
        }
        Ok(fps)
    }

    /// Convenience: extract member fingerprints from a server's default channel group.
    pub fn mls_member_fingerprints(&self, server_id: &[u8; 32]) -> Result<Vec<[u8; 32]>> {
        let ch = derive_default_channel_id(server_id);
        self.mls_member_fingerprints_for_channel(&ch)
    }

    /// Unique member fingerprints across all loaded channel groups (excluding own).
    pub fn all_member_fingerprints(&self) -> Vec<[u8; 32]> {
        let own = *self.fingerprint();
        let mut seen = std::collections::HashSet::new();
        for group in self.channel_groups.values() {
            for member in group.members() {
                if let Ok(pc) = crate::mls::credential::parse_credential(&member.credential) {
                    if pc.account_fp != own {
                        seen.insert(pc.account_fp);
                    }
                }
            }
        }
        seen.into_iter().collect()
    }

    /// Process an inbound blob — could be an app message, a commit, or a self-message.
    /// Takes channel_id to identify which MLS group to decrypt with.
    pub fn receive_any(
        &mut self,
        channel_id: &[u8; 32],
        blob: &[u8],
        received_at: Option<u64>,
    ) -> Result<ReceiveResult> {
        self.receive_from(channel_id, blob, received_at, None)
    }

    /// `receive_any` for a blob read from a mailbox at `origin`: a message stored from it
    /// marks the blob seen in the same write.
    pub fn receive_at(&mut self, channel_id: &[u8; 32], blob: &[u8], received_at: u64, origin: BlobOrigin) -> Result<ReceiveResult> {
        self.receive_from(channel_id, blob, Some(received_at), Some(origin))
    }

    fn receive_from(
        &mut self,
        channel_id: &[u8; 32],
        blob: &[u8],
        received_at: Option<u64>,
        origin: Option<BlobOrigin>,
    ) -> Result<ReceiveResult> {
        // A commit from before the group's epoch is already applied: this device's own
        // commit echoed back, or one seen before.
        let (envelope_type, envelope_epoch) = ghost_wire::decode_envelope(blob)
            .map_err(|e| GhostError::Format(format!("envelope: {e}")))?;
        let current_epoch = self.channel_groups.get(channel_id).map(GhostGroup::epoch);
        if envelope_type == ghost_wire::EnvelopeType::Commit && current_epoch.is_some_and(|e| envelope_epoch < e) {
            return Ok(ReceiveResult::Skipped);
        }

        // Out of the map while it is processed, so a private channel's commit can be
        // judged against its server group's state.
        let mut group = self.channel_groups.remove(channel_id).ok_or_else(|| {
            GhostError::ServerNotLoaded(format!("channel {}", short_id(channel_id)))
        })?;
        let opened = {
            let cache = &self.idlog_cache;
            let devices = |claim: &CredentialClaim| cache.status(claim);
            let server_at = |server_mailbox: &[u8; 32], epoch: u64| self.server_view_at(server_mailbox, epoch);
            let checks = CommitChecks {
                devices: &devices,
                mailbox: mls_group_mailbox_id(group.group_id()),
                received_at: received_at.unwrap_or_else(now_millis),
                server_at: &server_at,
            };
            open_any(&mut group, &self.provider, blob, &checks)
        };
        self.channel_groups.insert(*channel_id, group);

        let inbound = match opened {
            Err(GhostError::SelfMessage) => return Ok(ReceiveResult::Skipped),
            // Sent at an epoch before this device's: never readable here, and no sign the
            // group is out of step now. One from before this device joined was not for it.
            Err(GhostError::Mls(_))
                if envelope_type == ghost_wire::EnvelopeType::Application && current_epoch.is_some_and(|e| envelope_epoch < e) =>
            {
                let joined = self.store.joined_epoch(channel_id)?;
                if envelope_epoch < joined {
                    tracing::debug!("message sealed at epoch {envelope_epoch}, before this device joined at {joined}; not for it");
                    return Ok(ReceiveResult::Skipped);
                }
                return Ok(ReceiveResult::Unreadable);
            }
            other => other?,
        };

        let received_at = received_at.unwrap_or_else(now_millis);
        match inbound {
            InboundMessage::Application(msg) => self.store_received(msg, received_at, origin),
            InboundMessage::Unverified { msg, claim } => Ok(ReceiveResult::Unverified { message: msg, claim, received_at }),
            InboundMessage::Commit { removed, committer } => {
                self.record_if_server_group(channel_id)?;
                let group = self.channel_groups.get(channel_id).ok_or_else(|| {
                    GhostError::ServerNotLoaded(format!("channel {}", short_id(channel_id)))
                })?;

                // This device is out once its own leaf is gone. If other devices of the
                // account remain, only this device was removed (it was revoked).
                if removed.contains(&self.identity.fingerprint) {
                    let own_vk = self.identity.verifying_key.as_bytes();
                    let device_still_in = group.members().any(|m| m.signature_key.as_slice() == own_vk);
                    // Out of a private channel only: the server membership is unaffected.
                    if !device_still_in && self.is_private_channel(channel_id) {
                        self.drop_private_channel(channel_id)?;
                        return Ok(ReceiveResult::ChannelAccessLost(*channel_id));
                    }
                    if !device_still_in {
                        let account_still_in = group.members().any(|m| {
                            crate::mls::credential::parse_credential(&m.credential)
                                .is_ok_and(|pc| pc.account_fp == self.identity.fingerprint)
                        });
                        return Ok(if account_still_in {
                            ReceiveResult::DeviceRemoved
                        } else {
                            ReceiveResult::Kicked { by: committer }
                        });
                    }
                }

                // Only report members as truly removed if they have no leaves remaining.
                let truly_removed: Vec<[u8; 32]> = removed.into_iter().filter(|rm_fp| {
                    !group.members().any(|m| {
                        crate::mls::credential::parse_credential(&m.credential)
                            .ok()
                            .map(|pc| pc.account_fp == *rm_fp)
                            .unwrap_or(false)
                    })
                }).collect();

                if truly_removed.is_empty() {
                    Ok(ReceiveResult::CommitProcessed)
                } else {
                    Ok(ReceiveResult::MembersRemoved(truly_removed))
                }
            }
            InboundMessage::ProposalProcessed => {
                Ok(ReceiveResult::ProposalProcessed)
            }
        }
    }

    /// Store a message from a device this client checked against its identity log.
    /// Control messages (Metadata) aren't chat and are not stored.
    fn store_received(&mut self, msg: ApplicationMessage, received_at: u64, origin: Option<BlobOrigin>) -> Result<ReceiveResult> {
        if msg.message_type != MessageType::Metadata {
            let seen = origin.as_ref().map(|o| (&o.mailbox_id, o.seq));
            self.store.insert_message_seen(&StoredMessage {
                message_id: msg.message_id,
                channel_id: msg.channel_id,
                sender_fp: msg.sender_fp,
                message_type: msg.message_type as u8,
                timestamp: msg.timestamp,
                received_at,
                content: msg.content.clone(),
                expires_at: None,
                references: msg.references.clone(),
                delivery: Delivery::Delivered,
            }, seen)?;
        }
        Ok(ReceiveResult::Message(msg))
    }

    /// Judge the head a message's sender claims for its own identity log against the
    /// cached copy of that log.
    pub fn judge_head(&self, account_fp: &[u8; 32], claimed: &[u8; 32]) -> HeadClaim {
        self.idlog_cache.judge_head(account_fp, claimed)
    }

    /// Stand in for a message at `seq` of `mailbox_id` that this device could not
    /// decrypt, in the history of the channel whose group carried it. The same blob
    /// delivered again stands in once. Returns the message as the stored row says it.
    pub fn store_undecryptable(&self, group_channel: &[u8; 32], mailbox_id: &[u8; 32], seq: u64, received_at: u64) -> Result<ApplicationMessage> {
        self.store_local_marker(MessageType::Undecryptable, UNDECRYPTABLE_ID_TAG, group_channel, mailbox_id, seq, received_at)
    }

    /// Mark where the history of the channel whose group uses `mailbox_id` skips what
    /// its relay no longer kept, resuming after `head`. The same gap reported again is
    /// marked once. Returns the message as the stored row says it.
    pub fn store_history_gap(&self, group_channel: &[u8; 32], mailbox_id: &[u8; 32], head: u64, received_at: u64) -> Result<ApplicationMessage> {
        self.store_local_marker(MessageType::HistoryGap, HISTORY_GAP_ID_TAG, group_channel, mailbox_id, head, received_at)
    }

    /// A message this device makes for its own history, with no sender, its id derived
    /// from `tag`, the mailbox and `seq`.
    fn store_local_marker(&self, kind: MessageType, tag: &[u8], group_channel: &[u8; 32], mailbox_id: &[u8; 32], seq: u64, received_at: u64) -> Result<ApplicationMessage> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(tag);
        hasher.update(mailbox_id);
        hasher.update(&seq.to_be_bytes());
        let message_id: [u8; 32] = hasher.finalize().into();
        let message = ApplicationMessage {
            message_type: kind,
            channel_id: *group_channel,
            sender_fp: [0u8; 32],
            timestamp: received_at,
            message_id,
            kt_head_hash: [0u8; 32],
            references: Vec::new(),
            content: Vec::new(),
        };
        self.store.insert_message(&StoredMessage {
            message_id,
            channel_id: *group_channel,
            sender_fp: message.sender_fp,
            message_type: kind as u8,
            timestamp: received_at,
            received_at,
            content: Vec::new(),
            expires_at: None,
            delivery: Delivery::Delivered,
            references: Vec::new(),
        })?;
        Ok(message)
    }

    /// Settle a message held as [`ReceiveResult::Unverified`] once the sender's log has
    /// been refreshed: stored if the device is now listed active, refused otherwise.
    pub fn accept_unverified(&mut self, message: ApplicationMessage, claim: &CredentialClaim, received_at: u64, origin: Option<BlobOrigin>) -> Result<ReceiveResult> {
        match self.idlog_cache.status(claim) {
            DeviceStatus::Active => self.store_received(message, received_at, origin),
            DeviceStatus::Unknown => Err(GhostError::IdentityLog("the sender's device is not in its account's identity log".into())),
            DeviceStatus::Revoked => Err(GhostError::SenderRefused("sender device has been revoked".into())),
            DeviceStatus::Contradicted => Err(GhostError::SenderRefused(
                "sender's credential names a different identity log entry than its account's log holds; possible fork".into(),
            )),
        }
    }

    /// Commit the pending proposals of a channel's group that this device may commit
    /// (relay removals of revoked or excluded devices). `None` when there are none.
    pub fn commit_pending_proposals(
        &mut self,
        channel_id: &[u8; 32],
    ) -> Result<Option<Outbound>> {
        let aad = self.commit_aad(channel_id);
        let excluded = self.excluded_leaves(channel_id)?;
        let group = self.channel_groups.get_mut(channel_id).ok_or_else(|| {
            GhostError::ServerNotLoaded(format!("channel {}", short_id(channel_id)))
        })?;
        let Some(commit) = group.commit_pending_proposals(&self.provider, &self.idlog_cache, &excluded, &aad)? else {
            return Ok(None);
        };
        let mailbox_id = mls_group_mailbox_id(group.group_id());
        Ok(Some(Outbound { channel_id: *channel_id, mailbox_id, blob: commit }))
    }

    /// Whether a channel's group holds queued proposals this device may yet commit, once
    /// its view of the group and server catches up.
    pub fn awaiting_proposals(&self, channel_id: &[u8; 32]) -> bool {
        self.channel_groups.get(channel_id).is_some_and(GhostGroup::has_pending_proposals_for_others)
    }

    /// The server's groups, server and private channels, holding proposals another
    /// member's leaf is the subject of, with each group's mailbox.
    pub fn groups_awaiting_proposals(&self, server_id: &[u8; 32]) -> Vec<([u8; 32], [u8; 32])> {
        self.server_channel_ids(server_id)
            .into_iter()
            .filter(|channel_id| self.awaiting_proposals(channel_id))
            .filter_map(|channel_id| self.channel_groups.get(&channel_id).map(|group| (channel_id, mls_group_mailbox_id(group.group_id()))))
            .collect()
    }

}

/// Clients for tests across the crate: in memory, talking to no relay.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;

    /// A relay key for groups made in these tests, which talk to no relay.
    pub(crate) const TEST_RELAY_VK: [u8; 32] = [0x7E; 32];

    pub(crate) fn test_client(seed: [u8; 32]) -> GhostClient {
        let identity = Identity::from_seed(seed).unwrap();
        let mut client = GhostClient::open_in_memory(identity, seed).unwrap();
        client.set_relay_vk(TEST_RELAY_VK);
        // Register own identity so self-validation passes
        register_identity_in_cache(&mut client, &Identity::from_seed(seed).unwrap());
        client
    }

    /// Put an identity's one-entry account in a client's identity log cache.
    pub(crate) fn register_identity_in_cache(client: &mut GhostClient, identity: &Identity) {
        client.idlog_cache.insert_chain(&[identity.own_genesis()]).unwrap();
    }

    /// `joiner` joins `creator`'s server through an invite, with the join applied on both.
    pub(crate) fn join_through_invite(creator: &mut GhostClient, joiner: &mut GhostClient, server_id: &[u8; 32]) {
        let invite = creator.create_invite(server_id, u64::MAX).unwrap();
        let payload = joiner.open_invite(&invite.sealed_payload, &invite.key).unwrap();
        let group_info = creator.export_server_info(server_id).unwrap();
        let (_, channel_results, _) = joiner.join_by_invite(payload, group_info, 1000).unwrap();
        let (channel_id, commit, _) = &channel_results[0];
        creator.receive_any(channel_id, commit, Some(1000)).unwrap();
    }

    /// Returns (creator, joiner, server_id) with both clients in a shared MLS group.
    pub(crate) fn setup_two_clients() -> (GhostClient, GhostClient, [u8; 32]) {
        let mut c1 = test_client([0x01; 32]);
        let mut c2 = test_client([0x02; 32]);

        // Each client needs the other's identity in its cache for validation
        let id1 = Identity::from_seed([0x01; 32]).unwrap();
        let id2 = Identity::from_seed([0x02; 32]).unwrap();
        register_identity_in_cache(&mut c1, &id2);
        register_identity_in_cache(&mut c2, &id1);

        let server_id = c1.create_server("test", ServerKind::Server, 1000).unwrap();
        join_through_invite(&mut c1, &mut c2, &server_id);
        (c1, c2, server_id)
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;

    #[test]
    fn imported_clocks_from_the_future_are_clamped_and_own_writes_still_get_ahead() {
        use crate::sync::clock::{from_millis, millis_of, MAX_CLOCK_SKEW_MS};
        let client = test_client([0x42; 32]);
        let far = from_millis(now_millis() + 3_600_000);
        client.sync_import(&[("pref:a".into(), Some(b"1".to_vec()), far)]).unwrap();
        let (_, stored) = client.sync_get("pref:a").unwrap().unwrap();
        assert!(stored < far && millis_of(stored) <= now_millis() + MAX_CLOCK_SKEW_MS);
        client.sync_observe(stored).unwrap();
        let own = client.sync_tick().unwrap();
        assert!(own > stored, "a write made here orders after the clamped clock");
        assert!(client.sync_set("pref:a", b"2", own).unwrap());
    }

    #[test]
    fn open_deterministic_and_stores_accessible() {
        let a = test_client([0x01; 32]);
        let b = test_client([0x01; 32]);
        assert_eq!(a.fingerprint(), b.fingerprint());

        let c = test_client([0x02; 32]);
        assert_ne!(a.fingerprint(), c.fingerprint());

        // Store is functional
        assert!(a.store().list_servers().unwrap().is_empty());
    }

    #[test]
    fn create_server_stores_records() {
        let mut client = test_client([0x01; 32]);
        let server_id = client.create_server("test-server", ServerKind::Server, 1000).unwrap();

        let server = client.store().get_server(&server_id).unwrap();
        assert_eq!(server.name, "test-server");
        assert_eq!(server.created_at, 1000);

        let channels = client.store().list_channels(&server_id).unwrap();
        assert_eq!(channels.len(), 1);
        assert_eq!(channels[0].name, "general");
        assert_eq!(channels[0].kind, ChannelKind::Text);
        assert_eq!(channels[0].channel_id, derive_default_channel_id(&server_id));

        let members = client.store().list_members(&server_id).unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].fingerprint, *client.fingerprint());
    }

    /// A server made here is unpublished until the relay holds it; undone, nothing of it
    /// stays: no rows, no group in memory or in storage, no mailbox routed to it.
    #[test]
    fn a_server_made_here_is_unpublished_until_published_and_undone_whole() {
        let mut client = test_client([0x01; 32]);
        let server_id = client.create_server("club", ServerKind::Server, 1000).unwrap();
        let mailbox_id = client.mailbox_id_for_server(&server_id).unwrap();
        assert_eq!(client.store().unpublished_servers().unwrap(), vec![server_id]);

        client.abandon_created_server(&server_id).unwrap();
        assert!(client.store().get_server(&server_id).is_err());
        assert!(client.store().list_channels(&server_id).unwrap().is_empty());
        assert!(client.store().list_members(&server_id).unwrap().is_empty());
        assert!(client.store().unpublished_servers().unwrap().is_empty());
        assert!(client.mailbox_id_for_server(&server_id).is_none());
        assert!(client.channel_id_for_mailbox(&mailbox_id).is_none());
        let stored = GhostGroup::load(&client.provider, &client.identity, &server_id, &derive_default_channel_id(&server_id)).unwrap();
        assert!(stored.is_none(), "the group's state stayed in storage");

        let kept = client.create_server("club", ServerKind::Server, 2000).unwrap();
        client.store().server_published(&kept).unwrap();
        assert!(client.store().unpublished_servers().unwrap().is_empty());
    }

    #[test]
    fn send_to_unknown_server_fails() {
        let mut client = test_client([0x01; 32]);
        let result = client.send_message(&[0xFF; 32], &[0xAA; 32], b"hi".to_vec(), vec![], 1000);
        assert!(matches!(result, Err(GhostError::ServerNotLoaded(_))));
    }

    #[test]
    fn receive_from_unknown_server_fails() {
        let mut client = test_client([0x01; 32]);
        let result = client.receive_blob(&[0xFF; 32], &[0x00; 64], None);
        assert!(matches!(result, Err(GhostError::ServerNotLoaded(_))));
    }

    #[test]
    fn no_group_is_made_without_the_relay_as_its_external_sender() {
        let identity = Identity::from_seed([0x05; 32]).unwrap();
        let mut client = GhostClient::open_in_memory(identity, [0x05; 32]).unwrap();
        assert!(matches!(client.create_server("early", ServerKind::Server, 1000), Err(GhostError::Network(_))));
        assert!(client.store().list_servers().unwrap().is_empty(), "a refused server left rows behind");
        client.set_relay_vk(TEST_RELAY_VK);
        client.create_server("later", ServerKind::Server, 1000).unwrap();
    }

    #[test]
    fn a_message_sent_in_an_earlier_run_is_pending_again_at_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ghost.db");
        let identity = || Identity::from_seed([0x06; 32]).unwrap();
        let message_id = {
            let mut client = GhostClient::open(identity(), [0x06; 32], [0x16; 32], &path).unwrap();
            register_identity_in_cache(&mut client, &identity());
            client.set_relay_vk(TEST_RELAY_VK);
            let server_id = client.create_server("club", ServerKind::Server, 1000).unwrap();
            let (_, message_id) = client.send_message(&server_id, &derive_default_channel_id(&server_id), b"hi".to_vec(), vec![], 2000).unwrap();
            client.store().set_delivery(&message_id, Delivery::Sent).unwrap();
            message_id
        };
        let client = GhostClient::open(identity(), [0x06; 32], [0x16; 32], &path).unwrap();
        assert_eq!(client.store().get_message(&message_id).unwrap().delivery, Delivery::Pending);
    }

    #[test]
    fn send_message_stores_in_db() {
        let (mut c1, _c2, server_id) = setup_two_clients();
        let channel_id = derive_default_channel_id(&server_id);

        let (_outbound, msg_id) = c1
            .send_message(&server_id, &channel_id, b"hello".to_vec(), vec![], 2000)
            .unwrap();

        let stored = c1.store().get_message(&msg_id).unwrap();
        assert_eq!(stored.content, b"hello");
        assert_eq!(stored.sender_fp, *c1.fingerprint());
        assert_eq!(stored.timestamp, 2000);
    }

    #[test]
    fn send_receive_roundtrip() {
        let (mut c1, mut c2, server_id) = setup_two_clients();
        let channel_id = derive_default_channel_id(&server_id);

        let (outbound, msg_id) = c1
            .send_message(&server_id, &channel_id, b"hello".to_vec(), vec![], 2000)
            .unwrap();

        let received = c2.receive_blob(&channel_id, &outbound.blob, None).unwrap();
        assert_eq!(received.content, b"hello");
        assert_eq!(received.sender_fp, *c1.fingerprint());
        assert_eq!(received.message_id, msg_id);

        let stored = c2.store().get_message(&msg_id).unwrap();
        assert_eq!(stored.content, b"hello");
    }

    /// A rejoin the relay refuses leaves the group exactly as it was, in memory and in
    /// storage; one the relay takes moves it on and leaves nothing of the old copy behind.
    #[test]
    fn a_refused_rejoin_leaves_the_group_as_it_was_and_an_accepted_one_moves_it_on() {
        let (mut c1, mut c2, server_id) = setup_two_clients();
        let channel_id = derive_default_channel_id(&server_id);
        let before = c2.channel_epoch(&channel_id).unwrap();

        // Refused: the test plays a relay that does not take the commit.
        let info = c1.export_channel_group_info(&channel_id).unwrap();
        c2.stage_rejoin(&channel_id, &info).unwrap();
        assert!(c2.channel_epoch(&channel_id).unwrap() > before);
        c2.abandon_rejoin(&channel_id).unwrap();
        assert_eq!(c2.channel_epoch(&channel_id).unwrap(), before);
        c2.reload_group(&channel_id);
        assert_eq!(c2.channel_epoch(&channel_id).unwrap(), before, "the storage holds a different group than memory");
        let (out, _) = c1.send_message(&server_id, &channel_id, b"still here".to_vec(), vec![], 2000).unwrap();
        assert_eq!(c2.receive_blob(&channel_id, &out.blob, None).unwrap().content, b"still here");
        let (out, _) = c2.send_message(&server_id, &channel_id, b"and you".to_vec(), vec![], 2001).unwrap();
        assert_eq!(c1.receive_blob(&channel_id, &out.blob, None).unwrap().content, b"and you");

        // Accepted: the other member merges the external commit, and both go on.
        let info = c1.export_channel_group_info(&channel_id).unwrap();
        let (commit, _) = c2.stage_rejoin(&channel_id, &info).unwrap();
        assert!(matches!(c1.receive_any(&channel_id, &commit, Some(3000)).unwrap(), ReceiveResult::CommitProcessed));
        c2.confirm_rejoin(&channel_id).unwrap();
        let after = c2.channel_epoch(&channel_id).unwrap();
        assert!(after > before);
        c2.reload_group(&channel_id);
        assert_eq!(c2.channel_epoch(&channel_id).unwrap(), after, "the storage holds a different group than memory");
        let (out, _) = c1.send_message(&server_id, &channel_id, b"moved on".to_vec(), vec![], 2002).unwrap();
        assert_eq!(c2.receive_blob(&channel_id, &out.blob, None).unwrap().content, b"moved on");
        let (out, _) = c2.send_message(&server_id, &channel_id, b"with you".to_vec(), vec![], 2003).unwrap();
        assert_eq!(c1.receive_blob(&channel_id, &out.blob, None).unwrap().content, b"with you");
    }

    #[test]
    fn two_client_full_flow() {
        let mut c1 = test_client([0x01; 32]);
        let mut c2 = test_client([0x02; 32]);

        // Register identities for credential validation
        let id1 = Identity::from_seed([0x01; 32]).unwrap();
        let id2 = Identity::from_seed([0x02; 32]).unwrap();
        register_identity_in_cache(&mut c1, &id2);
        register_identity_in_cache(&mut c2, &id1);

        let server_id = c1.create_server("full-flow", ServerKind::Server, 1000).unwrap();
        let channel_id = derive_default_channel_id(&server_id);
        join_through_invite(&mut c1, &mut c2, &server_id);

        // c1 sends, c2 receives
        let (out1, id1) = c1
            .send_message(&server_id, &channel_id, b"from c1".to_vec(), vec![], 2000)
            .unwrap();
        let recv1 = c2.receive_blob(&channel_id, &out1.blob, None).unwrap();
        assert_eq!(recv1.content, b"from c1");
        assert_eq!(recv1.sender_fp, *c1.fingerprint());

        // c2 sends, c1 receives
        let (out2, id2) = c2
            .send_message(&server_id, &channel_id, b"from c2".to_vec(), vec![], 3000)
            .unwrap();
        let recv2 = c1.receive_blob(&channel_id, &out2.blob, None).unwrap();
        assert_eq!(recv2.content, b"from c2");
        assert_eq!(recv2.sender_fp, *c2.fingerprint());

        // Both stores have both messages
        assert_eq!(c1.store().get_message(&id1).unwrap().content, b"from c1");
        assert_eq!(c1.store().get_message(&id2).unwrap().content, b"from c2");
        assert_eq!(c2.store().get_message(&id1).unwrap().content, b"from c1");
        assert_eq!(c2.store().get_message(&id2).unwrap().content, b"from c2");
    }

    /// A joiner takes the first server state a manager sends for its request or a later
    /// one, unless a change it saw since would be undone; the public channels become those
    /// listed, the role names arrive, and only members still unnamed take the names listed.
    #[test]
    fn a_joiner_takes_in_a_managers_server_state_unless_a_later_change_would_be_undone() {
        let (creator, mut joiner, server_id) = setup_two_clients();
        let owner = *creator.fingerprint();
        let default_channel = derive_default_channel_id(&server_id);
        let channel = |channel_id: [u8; 32], name: &str, position: i32| InviteChannel { channel_id, name: name.into(), kind: ChannelKind::Text, position, group_info_bytes: Vec::new() };
        let stale_channel = [0x51; 32];
        joiner.store().insert_channel(&Channel { channel_id: stale_channel, server_id, name: "old".into(), kind: ChannelKind::Text, position: 1 }, OnConflict::Fail).unwrap();
        let newcomer = [0x77; 32];
        joiner.store().insert_member(&Member { server_id, fingerprint: newcomer, display_name: crate::storage::placeholder_name(&newcomer), joined_at: 0, avatar_hash: None, avatar_key: None }, OnConflict::Fail).unwrap();
        let state = |request_seq: u64| ServerStatePayload {
            request_seq,
            channels: vec![channel(default_channel, "lobby", 0), channel([0x52; 32], "news", 1)],
            role_names: vec![(1, "staff".into())],
            members: vec![InviteMember { fingerprint: newcomer, display_name: "dana".into() }, InviteMember { fingerprint: owner, display_name: "renamed".into() }],
        };

        assert_eq!(joiner.apply_server_state(&server_id, &owner, state(12)).unwrap(), ServerStateOutcome::Ignored, "taken before the request was");
        joiner.store().server_state_requested(&server_id, 10).unwrap();
        assert_eq!(joiner.apply_server_state(&server_id, &owner, state(9)).unwrap(), ServerStateOutcome::Ignored, "answers an earlier request");
        assert_eq!(joiner.apply_server_state(&server_id, &[0x99; 32], state(12)).unwrap(), ServerStateOutcome::Ignored, "from someone who may not manage channels");
        joiner.store().note_server_change(&server_id, 12).unwrap();
        assert_eq!(joiner.apply_server_state(&server_id, &owner, state(11)).unwrap(), ServerStateOutcome::Stale);

        assert_eq!(joiner.apply_server_state(&server_id, &owner, state(12)).unwrap(), ServerStateOutcome::Applied);
        let channels: Vec<(String, i32)> = joiner.store().list_channels(&server_id).unwrap().into_iter().map(|c| (c.name, c.position)).collect();
        assert_eq!(channels, vec![("lobby".to_string(), 0), ("news".to_string(), 1)]);
        assert_eq!(joiner.store().list_role_names(&server_id).unwrap(), vec![(1, "staff".to_string())]);
        let name_of = |fp: &[u8; 32]| joiner.store().list_members(&server_id).unwrap().into_iter().find(|m| m.fingerprint == *fp).unwrap().display_name;
        assert_eq!(name_of(&newcomer), "dana");
        assert_ne!(name_of(&owner), "renamed", "a name this device knew was replaced");
        assert_eq!(joiner.apply_server_state(&server_id, &owner, state(13)).unwrap(), ServerStateOutcome::Ignored, "taken after the wait ended");
    }

    #[test]
    fn create_invite_needs_the_invite_permission() {
        let (mut c1, mut c2, server_id) = setup_two_clients();

        // Everyone may invite under a new server's policy.
        assert!(c1.create_invite(&server_id, u64::MAX).is_ok());
        assert!(c2.create_invite(&server_id, u64::MAX).is_ok());

        // Once the owner takes the permission away, the member cannot.
        let mut policy = c1.server_policy(&server_id).unwrap();
        policy.everyone = 0;
        let out = c1.stage_server_policy(&server_id, &policy).unwrap();
        c1.merge_pending_commit_for_channel(&derive_default_channel_id(&server_id)).unwrap();
        c2.receive_any(&out.channel_id, &out.blob, Some(1500)).unwrap();
        assert!(matches!(c2.create_invite(&server_id, u64::MAX), Err(GhostError::PermissionDenied(_))));
        assert!(c1.create_invite(&server_id, u64::MAX).is_ok(), "the owner holds every permission");
    }

    #[test]
    fn member_cannot_stage_a_policy_change_it_may_not_make() {
        let (_c1, mut c2, server_id) = setup_two_clients();
        let mut policy = c2.server_policy(&server_id).unwrap();
        policy.owner = *c2.fingerprint();
        assert!(matches!(c2.stage_server_policy(&server_id, &policy), Err(GhostError::PermissionDenied(_))));
    }

    #[test]
    fn invite_full_roundtrip() {
        let mut c1 = test_client([0x01; 32]);
        let mut c2 = test_client([0x02; 32]);

        // Register each other's identities for credential validation
        let id1 = Identity::from_seed([0x01; 32]).unwrap();
        let id2 = Identity::from_seed([0x02; 32]).unwrap();
        register_identity_in_cache(&mut c1, &id2);
        register_identity_in_cache(&mut c2, &id1);

        let server_id = c1.create_server("test", ServerKind::Server, 1000).unwrap();

        let invite = c1.create_invite(&server_id, u64::MAX).unwrap();

        let payload = c2.open_invite(&invite.sealed_payload, &invite.key).unwrap();
        let group_info = c1.export_server_info(&server_id).unwrap();
        let (joined_server_id, channel_results, _grant) = c2.join_by_invite(payload, group_info, 2000).unwrap();
        assert_eq!(joined_server_id, server_id);

        // c2 should have the server, channel, and members in their store
        let server = c2.store().get_server(&server_id).unwrap();
        assert_eq!(server.name, "test");
        let channels = c2.store().list_channels(&server_id).unwrap();
        assert_eq!(channels.len(), 1);
        assert_eq!(channels[0].name, "general");
        let members = c2.store().list_members(&server_id).unwrap();
        assert_eq!(members.len(), 2); // c1 + c2

        // c1 processes the external commit for the default channel
        let (channel_id, commit, _mailbox_id) = &channel_results[0];
        let result = c1.receive_any(channel_id, commit, Some(2000)).unwrap();
        assert!(matches!(result, ReceiveResult::CommitProcessed));

        // After merging, c1's MLS group should include c2
        let mls_fps = c1.mls_member_fingerprints(&server_id).unwrap();
        assert_eq!(mls_fps.len(), 2, "MLS group should have both members after external commit");
        assert!(mls_fps.contains(c1.fingerprint()));
        assert!(mls_fps.contains(c2.fingerprint()));
    }
}
