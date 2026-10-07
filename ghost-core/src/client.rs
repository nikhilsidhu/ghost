use std::collections::HashMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use openmls::prelude::{KeyPackage, LeafNodeIndex};
use rusqlite::Connection;

use crate::crypto::{GhostProvider, MessageType};
use crate::error::{GhostError, Result};
use crate::identity::Identity;
use crate::idlog_cache::IdLogCache;
use crate::mls::credential::generate_key_package;
use crate::mls::group::GhostGroup;
use crate::storage::{
    Channel, ChannelKind, GhostStore, Server, ServerKind, Member, MemberRole, StoredMessage,
};
use crate::wire::{
    derive_default_channel_id, mls_group_mailbox_id, open, open_any, seal, sync_server_id,
    ApplicationMessage, CommitChecks, InboundMessage, InviteChannel, InviteMember, InvitePayload, Outbound,
    ProvisionPayload, SyncReceiveResult, SyncServerMeta,
};
use ghost_wire::policy::{CommitAad, PolicyError, ServerPolicy, ServerView};
use ghost_wire::policy_mls;

fn now_millis() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
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
    Message(ApplicationMessage),
    /// Message received, but sender's kt_head_hash doesn't match our cached copy. Likely stale cache; could indicate a split-view attack.
    MessageWithKtWarning(ApplicationMessage),
    CommitProcessed,
    /// The account was removed from the group by a commit: no device of it remains.
    Kicked,
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
    Skipped,
}

/// A freshly created invite. The relay stores `sealed_payload` under `token`; `key`
/// opens it and must reach joiners only inside the invite link.
pub struct NewInvite {
    pub token: String,
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
    /// MLS self-group for cross-device sync (separate from server groups)
    sync_group: Option<GhostGroup>,
    /// Relay's Ed25519 verifying key for ExternalSendersExtension
    relay_vk: Option<[u8; 32]>,
    /// Cached identity log states for credential validation
    idlog_cache: IdLogCache,
}

impl GhostClient {
    pub fn open(identity: Identity, db_key: [u8; 32], mls_db_key: [u8; 32], db_path: &Path) -> Result<Self> {
        let store = GhostStore::open(&db_key, db_path)?;

        let mls_conn = open_mls_connection(&mls_db_key, db_path)?;
        let provider = GhostProvider::new(mls_conn)?;

        // Reload per-channel MLS groups from previous sessions.
        // Clean up orphan server records whose channels have no loadable MLS groups.
        let mut channel_groups = HashMap::new();
        let mut mailbox_map = HashMap::new();
        let mut channel_server = HashMap::new();
        if let Ok(stored_servers) = store.list_servers() {
            for s in &stored_servers {
                let channels = store.list_channels(&s.server_id).unwrap_or_default();
                let mut has_any_group = false;
                for ch in &channels {
                    if let Ok(Some(group)) =
                        GhostGroup::load(&provider, &identity, &s.server_id, &ch.channel_id)
                    {
                        let mb = mls_group_mailbox_id(group.group_id());
                        mailbox_map.insert(mb, ch.channel_id);
                        channel_server.insert(ch.channel_id, s.server_id);
                        channel_groups.insert(ch.channel_id, group);
                        has_any_group = true;
                    }
                }
                if !has_any_group {
                    let _ = store.delete_server(&s.server_id);
                }
            }
        }

        let sync_sid = sync_server_id(&identity.fingerprint);
        let sync_group = GhostGroup::load_by_group_id(&provider, &identity, &sync_sid)
            .ok()
            .flatten();

        let client = Self {
            identity,
            provider,
            store,
            channel_groups,
            mailbox_map,
            channel_server,
            sync_group,
            relay_vk: None,
            idlog_cache: IdLogCache::new(),
        };
        // Servers joined before views were recorded start their history here.
        for server_id in client.channel_server.values().collect::<std::collections::HashSet<_>>() {
            if let Err(e) = client.record_server_view(server_id) {
                eprintln!("server view for {}: {e}", hex::encode(&server_id[..8]));
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
            sync_group: None,
            relay_vk: None,
            idlog_cache: IdLogCache::new(),
        })
    }

    /// Get the default channel's MLS group for a server (for server-wide operations).
    fn default_group(&self, server_id: &[u8; 32]) -> Result<&GhostGroup> {
        let ch = derive_default_channel_id(server_id);
        self.channel_groups.get(&ch).ok_or_else(|| {
            GhostError::ServerNotLoaded(hex::encode(&server_id[..8]))
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

    /// Whether the server's group carries an explicit policy, rather than the implicit
    /// one of a group made before roles existed.
    pub fn server_policy_is_explicit(&self, server_id: &[u8; 32]) -> Result<bool> {
        Ok(self.default_group(server_id)?.server_policy()?.is_some())
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

    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.identity.verifying_key.to_bytes()
    }

    pub fn signing_key_clone(&self) -> ed25519_dalek::SigningKey {
        self.identity.signing_key.clone()
    }

    pub fn store(&self) -> &GhostStore {
        &self.store
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
        self.idlog_cache.cache_and_validate(&self.store, account_fp, log)
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

    /// Insert a pre-validated LogState directly (e.g. for our own account).
    pub fn cache_own_identity_log(&mut self, state: ghost_wire::idlog::LogState) {
        self.idlog_cache.insert(state);
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

    pub fn sync_key(&self) -> Option<[u8; 32]> {
        self.store
            .get_config_blob("sync_key")
            .ok()
            .flatten()
            .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
    }

    pub fn set_sync_key(&self, key: [u8; 32]) -> Result<()> {
        self.store.set_config_blob("sync_key", &key)
    }

    /// Generate a new random sync key and store it. Returns the new key.
    pub fn rotate_sync_key(&self) -> Result<[u8; 32]> {
        use rand::RngCore;
        let mut new_key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut new_key);
        self.set_sync_key(new_key)?;
        Ok(new_key)
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

    pub fn sync_dump(&self) -> Result<Vec<(String, Option<Vec<u8>>, u64)>> {
        self.store.sync_dump()
    }

    pub fn sync_import(&self, entries: &[(String, Option<Vec<u8>>, u64)]) -> Result<()> {
        self.store.sync_import(entries)
    }

    // --- Sync MLS group ---

    pub fn create_sync_group(&mut self) -> Result<()> {
        let sid = sync_server_id(&self.identity.fingerprint);
        let group = GhostGroup::create_with_raw_id(&self.provider, &self.identity, &sid, self.relay_vk.as_ref())?;
        self.sync_group = Some(group);
        Ok(())
    }

    pub fn has_sync_group(&self) -> bool {
        self.sync_group.is_some()
    }

    pub fn sync_mailbox_id(&self) -> Option<[u8; 32]> {
        self.sync_group.as_ref().map(|g| mls_group_mailbox_id(g.group_id()))
    }

    /// Encrypt a sync plaintext with the shared sync key (epoch-independent).
    /// Format: [envelope_header][device_vk:32][sync_sealed_blob]
    pub fn send_sync(&self, plaintext: &[u8]) -> Result<Outbound> {
        let group = self.sync_group.as_ref()
            .ok_or_else(|| GhostError::Format("no sync group".into()))?;
        let sync_key = self.sync_key()
            .ok_or_else(|| GhostError::Format("no sync key".into()))?;
        let sealed = crate::wire::sync_seal(&sync_key, plaintext)?;
        let header = ghost_wire::encode_envelope(ghost_wire::EnvelopeType::Application, 0);
        let device_vk = self.identity.verifying_key.as_bytes();
        let mut blob = Vec::with_capacity(ghost_wire::ENVELOPE_HEADER_SIZE + 32 + sealed.len());
        blob.extend_from_slice(&header);
        blob.extend_from_slice(device_vk);
        blob.extend_from_slice(&sealed);
        let mailbox_id = mls_group_mailbox_id(group.group_id());
        Ok(Outbound { channel_id: [0u8; 32], mailbox_id, blob })
    }

    /// Decrypt an inbound sync blob.
    /// Application messages use sync_seal (epoch-independent).
    /// Commits/proposals use MLS (membership management).
    pub fn receive_sync(&mut self, blob: &[u8]) -> Result<SyncReceiveResult> {
        let cache = &self.idlog_cache;
        let revoked = |fp: &[u8; 32], vk: &[u8; 32]| cache.is_revoked(fp, vk);
        let no_server = |_: &[u8; 32], _: u64| Err(PolicyError::Denied("the sync group has no server".into()));
        let group = self.sync_group.as_mut()
            .ok_or_else(|| GhostError::Format("no sync group".into()))?;
        let (envelope_type, _epoch) = ghost_wire::decode_envelope(blob)
            .map_err(|e| GhostError::Format(format!("envelope: {e}")))?;
        let payload = ghost_wire::envelope_payload(blob);

        match envelope_type {
            ghost_wire::EnvelopeType::Application => {
                // sync_seal message: [device_vk:32][sealed_blob]
                if payload.len() < 32 {
                    return Err(GhostError::Format("sync payload too short".into()));
                }
                let sender_vk: [u8; 32] = payload[..32].try_into().unwrap();
                if sender_vk == *self.identity.verifying_key.as_bytes() {
                    return Ok(SyncReceiveResult::SelfMessage);
                }
                let sync_key = self.sync_key()
                    .ok_or_else(|| GhostError::Format("no sync key".into()))?;
                let plaintext = crate::wire::sync_open(&sync_key, &payload[32..])?;
                Ok(SyncReceiveResult::Application(plaintext))
            }
            _ => {
                // MLS handshake (Commit, Proposal)
                match group.process_message_bytes(&self.provider, payload) {
                    Err(GhostError::SelfMessage) => Ok(SyncReceiveResult::SelfMessage),
                    Err(e) => Err(e),
                    Ok(processed) => {
                        let credential = processed.credential().clone();
                        let sender = processed.sender().clone();
                        let aad = processed.aad().to_vec();
                        match processed.into_content() {
                            openmls::prelude::ProcessedMessageContent::StagedCommitMessage(staged) => {
                                crate::wire::validate_sender(group, &credential, &sender, Some(&staged), &revoked)?;
                                let checks = CommitChecks {
                                    revoked: &revoked,
                                    mailbox: mls_group_mailbox_id(group.group_id()),
                                    received_at: now_millis(),
                                    server_at: &no_server,
                                };
                                crate::wire::check_policy(group, &sender, &staged, &aad, &checks)?;
                                group.merge_staged_commit(&self.provider, *staged)?;
                                Ok(SyncReceiveResult::CommitProcessed)
                            }
                            openmls::prelude::ProcessedMessageContent::ProposalMessage(proposal) => {
                                group.store_pending_proposal(&self.provider, *proposal)?;
                                Ok(SyncReceiveResult::CommitProcessed)
                            }
                            _ => Ok(SyncReceiveResult::CommitProcessed),
                        }
                    }
                }
            }
        }
    }

    /// Export GroupInfo for pairing (so the new device can join via external commit).
    pub fn sync_group_info(&self) -> Result<Vec<u8>> {
        let group = self.sync_group.as_ref()
            .ok_or_else(|| GhostError::Format("no sync group".into()))?;
        group.export_group_info(&self.provider)
    }

    /// Join the sync group via external commit.
    /// Returns (commit blob to post, sync mailbox ID).
    pub fn join_sync_group(&mut self, group_info_bytes: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
        let (group, commit_bytes) = GhostGroup::join_by_external_commit(
            &self.provider,
            &self.identity,
            group_info_bytes,
            &CommitAad::default(),
        )?;
        let mailbox_id = mls_group_mailbox_id(group.group_id());
        self.sync_group = Some(group);
        Ok((commit_bytes, mailbox_id))
    }

    /// Remove a device from the sync group by its verifying key.
    pub fn remove_device_from_sync_group(&mut self, device_vk: &[u8; 32]) -> Result<Vec<u8>> {
        let group = self.sync_group.as_mut()
            .ok_or_else(|| GhostError::Format("no sync group".into()))?;
        let leaf_indices: Vec<openmls::prelude::LeafNodeIndex> = group
            .members()
            .filter(|m| m.signature_key.as_slice() == device_vk.as_slice())
            .map(|m| m.index)
            .collect();
        if leaf_indices.is_empty() {
            return Err(GhostError::Mls("device not in sync group".into()));
        }
        group.remove_members(&self.provider, &leaf_indices, &CommitAad::default())
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
                    role: m.role,
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
        let creator_fp = members
            .iter()
            .find(|m| m.role == MemberRole::Creator)
            .map(|m| m.fingerprint)
            .unwrap_or([0u8; 32]);

        let server = Server { server_id, name: server_name, kind, creator_fp, created_at: timestamp };
        if idempotent { self.store.insert_server_if_not_exists(&server)?; }
        else { self.store.insert_server(&server)?; }

        for ch in channels {
            let channel = Channel {
                channel_id: ch.channel_id, server_id, name: ch.name.clone(),
                kind: ch.kind, position: ch.position,
            };
            if idempotent { self.store.insert_channel_if_not_exists(&channel)?; }
            else { self.store.insert_channel(&channel)?; }
        }

        for m in members {
            let member = Member {
                server_id, fingerprint: m.fingerprint, display_name: m.display_name.clone(),
                role: m.role, joined_at: timestamp, avatar_hash: None, avatar_key: None,
            };
            if idempotent { self.store.insert_member_if_not_exists(&member)?; }
            else { self.store.insert_member(&member)?; }
        }

        let self_member = Member {
            server_id, fingerprint: self.identity.fingerprint,
            display_name: self.identity.display_name.clone(),
            role: MemberRole::Member, joined_at: timestamp, avatar_hash: None, avatar_key: None,
        };
        if idempotent { self.store.insert_member_if_not_exists(&self_member)?; }
        else { self.store.insert_member(&self_member)?; }

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
            self.channel_groups.insert(ch.channel_id, ghost_group);
            self.mailbox_map.insert(mailbox_id, ch.channel_id);
            self.channel_server.insert(ch.channel_id, server_id);
            results.push((ch.channel_id, commit_bytes, mailbox_id));
        }
        self.record_server_view(&server_id)?;
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

    pub fn generate_key_package(&self) -> Result<KeyPackage> {
        generate_key_package(&self.provider, &self.identity)
    }

    pub fn create_server(&mut self, name: &str, kind: ServerKind, timestamp: u64) -> Result<[u8; 32]> {
        let mut server_id = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut server_id);

        let channel_name = match kind {
            ServerKind::Dm | ServerKind::Group => "messages",
            ServerKind::Server => "general",
        };
        let channel_id = derive_default_channel_id(&server_id);

        let ghost_group =
            GhostGroup::create_with_id(
                &self.provider,
                &self.identity,
                &server_id,
                &channel_id,
                self.relay_vk.as_ref(),
                Some(&crate::mls::group::GroupPolicy::Server(ghost_wire::policy::ServerPolicy::new(self.identity.fingerprint))),
            )?;

        self.store.insert_server(&Server {
            server_id,
            name: name.to_string(),
            kind,
            creator_fp: self.identity.fingerprint,
            created_at: timestamp,
        })?;

        self.store.insert_channel(&Channel {
            channel_id,
            server_id,
            name: channel_name.to_string(),
            kind: ChannelKind::Text,
            position: 0,
        })?;

        self.store.insert_member(&Member {
            server_id,
            fingerprint: self.identity.fingerprint,
            display_name: self.identity.display_name.clone(),
            role: MemberRole::Creator,
            joined_at: timestamp,
            avatar_hash: None,
            avatar_key: None,
        })?;

        let mailbox_id = mls_group_mailbox_id(ghost_group.group_id());
        self.channel_groups.insert(channel_id, ghost_group);
        self.mailbox_map.insert(mailbox_id, channel_id);
        self.channel_server.insert(channel_id, server_id);
        self.record_server_view(&server_id)?;
        Ok(server_id)
    }

    /// Stage, in one channel's group, a commit naming `relay_vk` as the group's
    /// external sender. Returns the commit; the caller posts it to the new relay and
    /// merges or clears it. A private channel's commit names the server group's
    /// current epoch, so the server group's own commit must be merged first.
    pub fn stage_external_sender(&mut self, channel_id: &[u8; 32], relay_vk: &[u8; 32]) -> Result<Vec<u8>> {
        let aad = self.commit_aad(channel_id);
        let group = self.channel_groups.get_mut(channel_id).ok_or_else(|| {
            GhostError::ServerNotLoaded(format!("channel {}", hex::encode(&channel_id[..8])))
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

    /// Migrate pre-upgrade groups to include ExternalSendersExtension.
    /// Returns (server_id, commit_bytes) for each migrated group.
    pub fn migrate_group_extensions(&mut self) -> Vec<([u8; 32], Vec<u8>)> {
        let relay_vk = match self.relay_vk {
            Some(vk) => vk,
            None => return Vec::new(),
        };

        let servers = match self.store.list_servers() {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let mut results = Vec::new();
        for server in &servers {
            if server.creator_fp != self.identity.fingerprint {
                continue;
            }
            let channel_ids: Vec<[u8; 32]> = self.channel_server.iter()
                .filter(|(_, sid)| **sid == server.server_id)
                .map(|(cid, _)| *cid)
                .collect();
            for cid in channel_ids {
                let aad = self.commit_aad(&cid);
                let group = match self.channel_groups.get_mut(&cid) {
                    Some(g) => g,
                    None => continue,
                };
                if group.has_external_senders() {
                    continue;
                }
                if let Ok(commit) = group.add_external_sender_extension(&self.provider, &relay_vk, &aad) {
                    let mailbox_id = mls_group_mailbox_id(group.group_id());
                    results.push((mailbox_id, commit));
                }
            }
        }

        // Also migrate sync group
        if let Some(ref mut sync_group) = self.sync_group {
            if !sync_group.has_external_senders() {
                if let Ok(commit) = sync_group.add_external_sender_extension(&self.provider, &relay_vk, &CommitAad::default()) {
                    let mailbox_id = mls_group_mailbox_id(sync_group.group_id());
                    results.push((mailbox_id, commit));
                }
            }
        }

        results
    }

    pub fn send_message(
        &mut self,
        _server_id: &[u8; 32],
        channel_id: &[u8; 32],
        content: Vec<u8>,
        references: Vec<[u8; 32]>,
        timestamp: u64,
    ) -> Result<(Outbound, [u8; 32])> {
        let group_channel = self.group_channel(channel_id);
        // Never encrypt to someone a private channel no longer admits.
        if !self.excluded_leaves(&group_channel)?.is_empty() {
            return Err(GhostError::PermissionDenied(
                "the channel still holds members who lost access; remove them first".into(),
            ));
        }
        let group = self.channel_groups.get_mut(&group_channel).ok_or_else(|| {
            GhostError::ServerNotLoaded(format!("channel {}", hex::encode(&channel_id[..8])))
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

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

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
        })?;

        Ok((Outbound { channel_id: *channel_id, mailbox_id, blob }, message_id))
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
        let fingerprint = self.identity.fingerprint;
        let channel_id = *channel_id;
        let group = self.channel_groups.get_mut(&channel_id).ok_or_else(|| {
            GhostError::ServerNotLoaded(format!("channel {}", hex::encode(&channel_id[..8])))
        })?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

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
        let revoked = |fp: &[u8; 32], vk: &[u8; 32]| cache.is_revoked(fp, vk);
        let group = self.channel_groups.get_mut(channel_id).ok_or_else(|| {
            GhostError::ServerNotLoaded(format!("channel {}", hex::encode(&channel_id[..8])))
        })?;

        let msg = open(group, &self.provider, blob, &revoked)?;

        let recv_ts = received_at.unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64
        });

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
        })?;

        Ok(msg)
    }

    pub fn invite_member(
        &mut self,
        server_id: &[u8; 32],
        key_package: KeyPackage,
        invitee_fp: [u8; 32],
        invitee_name: &str,
        timestamp: u64,
    ) -> Result<(Outbound, Vec<u8>)> {
        let channel_id = derive_default_channel_id(server_id);
        let group = self.channel_groups.get_mut(&channel_id).ok_or_else(|| {
            GhostError::ServerNotLoaded(hex::encode(&server_id[..8]))
        })?;

        let (commit_blob, welcome) = group.add_member(&self.provider, key_package, &CommitAad::default())?;
        let welcome_bytes = welcome
            .to_bytes()
            .map_err(|e| GhostError::Mls(format!("serialize welcome: {e}")))?;

        let mailbox_id = mls_group_mailbox_id(group.group_id());

        self.store.insert_member(&Member {
            server_id: *server_id,
            fingerprint: invitee_fp,
            display_name: invitee_name.to_string(),
            role: MemberRole::Member,
            joined_at: timestamp,
            avatar_hash: None,
            avatar_key: None,
        })?;

        Ok((Outbound { channel_id, mailbox_id, blob: commit_blob }, welcome_bytes))
    }

    pub fn join_server(
        &mut self,
        server_id: &[u8; 32],
        welcome_bytes: &[u8],
        server_name: &str,
        kind: ServerKind,
        timestamp: u64,
    ) -> Result<()> {
        let ghost_group =
            GhostGroup::join(&self.provider, &self.identity, welcome_bytes)?;

        self.store.insert_server(&Server {
            server_id: *server_id,
            name: server_name.to_string(),
            kind,
            creator_fp: [0u8; 32],
            created_at: timestamp,
        })?;

        let channel_name = match kind {
            ServerKind::Dm | ServerKind::Group => "messages",
            ServerKind::Server => "general",
        };
        let channel_id = derive_default_channel_id(server_id);
        self.store.insert_channel(&Channel {
            channel_id,
            server_id: *server_id,
            name: channel_name.to_string(),
            kind: ChannelKind::Text,
            position: 0,
        })?;

        self.store.insert_member(&Member {
            server_id: *server_id,
            fingerprint: self.identity.fingerprint,
            display_name: self.identity.display_name.clone(),
            role: MemberRole::Member,
            joined_at: timestamp,
            avatar_hash: None,
            avatar_key: None,
        })?;

        let mailbox_id = mls_group_mailbox_id(ghost_group.group_id());
        self.channel_groups.insert(channel_id, ghost_group);
        self.mailbox_map.insert(mailbox_id, channel_id);
        self.channel_server.insert(channel_id, *server_id);
        self.record_server_view(server_id)
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
        // Public channels travel as metadata and the default channel carries the server
        // group's GroupInfo. Private channels never appear in an invite: joiners find the
        // ones they may enter through the relay's discovery, and others never learn of them.
        let invite_channels: Vec<InviteChannel> = channels
            .iter()
            .filter(|c| !self.is_private_channel(&c.channel_id))
            .map(|c| {
                let gi = match self.channel_groups.get(&c.channel_id) {
                    Some(group) => group.export_group_info(&self.provider)?,
                    None => Vec::new(),
                };
                Ok(InviteChannel {
                    channel_id: c.channel_id,
                    name: c.name.clone(),
                    kind: c.kind,
                    position: c.position,
                    group_info_bytes: gi,
                })
            })
            .collect::<Result<_>>()?;

        Ok(InvitePayload {
            server_id: *server_id,
            server_name: server_name.to_string(),
            kind,
            members: members
                .iter()
                .map(|m| InviteMember {
                    fingerprint: m.fingerprint,
                    display_name: m.display_name.clone(),
                    role: m.role,
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
        let own = self.identity.fingerprint;
        if !self.server_policy(server_id)?.has(&own, ghost_wire::policy::INVITE) {
            return Err(GhostError::PermissionDenied("creating invites needs the invite permission".into()));
        }
        let server_mailbox = mls_group_mailbox_id(self.default_group(server_id)?.group_id());
        let mut nonce = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
        let grant = ghost_wire::policy::InviteGrant::sign(server_mailbox, own, expires_at, nonce, &self.identity.signing_key);

        let mut key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
        let sealed_payload = self.sealed_invite_payload(server_id, &grant, &key)?;

        let mut token_bytes = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut token_bytes);
        Ok(NewInvite { token: hex::encode(token_bytes), key, sealed_payload })
    }

    /// Join a server via a sealed invite payload (external commit carrying its grant).
    /// Returns (server_id, Vec<(channel_id, commit_bytes, mailbox_id)>, grant); the
    /// grant goes into the payload refreshed for the next joiner.
    #[allow(clippy::type_complexity)]
    pub fn join_by_invite(
        &mut self,
        sealed_payload: &[u8],
        key: &[u8; 32],
        timestamp: u64,
    ) -> Result<([u8; 32], Vec<([u8; 32], Vec<u8>, [u8; 32])>, ghost_wire::policy::InviteGrant)> {
        let opened = crate::crypto::aead::open(key, sealed_payload, crate::wire::INVITE_PAYLOAD_CONTEXT)?;
        let payload = InvitePayload::from_bytes(&opened)?;
        let channel_results = self.join_server_common(
            payload.server_id, payload.server_name, payload.kind,
            &payload.members, &payload.channels, &payload.role_names, Some(&payload.grant), timestamp, false,
        )?;
        Ok((payload.server_id, channel_results, payload.grant))
    }

    /// Re-seal an invite payload with fresh GroupInfo and the same grant, for the next
    /// joiner (after joining via external commit).
    pub fn refresh_invite_payload(
        &self,
        server_id: &[u8; 32],
        grant: &ghost_wire::policy::InviteGrant,
        key: &[u8; 32],
    ) -> Result<Vec<u8>> {
        self.sealed_invite_payload(server_id, grant, key)
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
            GhostError::ServerNotLoaded(format!("channel {}", hex::encode(&channel_id[..8])))
        })?;
        group.export_group_info(&self.provider)
    }

    /// Build an external commit to rejoin a channel's MLS group.
    /// Does NOT delete the old group — caller must call `finalize_recovery`
    /// after successfully posting the commit to the relay.
    pub fn recover_via_external_commit(
        &mut self,
        channel_id: &[u8; 32],
        group_info_bytes: &[u8],
    ) -> Result<(Vec<u8>, [u8; 32])> {
        let aad = self.commit_aad(channel_id);
        let (ghost_group, commit_bytes) = GhostGroup::join_by_external_commit(
            &self.provider,
            &self.identity,
            group_info_bytes,
            &aad,
        )?;

        let mailbox_id = mls_group_mailbox_id(ghost_group.group_id());

        // Swap: remove old group, insert new one
        if let Some(old_group) = self.channel_groups.remove(channel_id) {
            let old_mb = mls_group_mailbox_id(old_group.group_id());
            self.mailbox_map.remove(&old_mb);
            let _ = old_group.delete(&self.provider);
        }
        self.channel_groups.insert(*channel_id, ghost_group);
        self.mailbox_map.insert(mailbox_id, *channel_id);
        self.record_if_server_group(channel_id)?;

        Ok((commit_bytes, mailbox_id))
    }

    /// Stage a commit replacing the server's policy: its roles, their assignments, what
    /// everyone may do, or its owner. Checked here against the current policy so a
    /// refusal comes early; the relay and every member check it again. Returns the
    /// commit to post; merge or clear the server group's pending commit afterwards.
    pub fn stage_server_policy(&mut self, server_id: &[u8; 32], policy: &ServerPolicy) -> Result<Outbound> {
        use ghost_wire::policy::{authorize_server_commit, CommitSummary, Committer, GrantContext};
        let current = self.server_policy(server_id)?;
        let channel_id = derive_default_channel_id(server_id);
        let group = self.channel_groups.get_mut(&channel_id).ok_or_else(|| {
            GhostError::ServerNotLoaded(hex::encode(&server_id[..8]))
        })?;
        let mailbox_id = mls_group_mailbox_id(group.group_id());
        let summary = CommitSummary {
            committer: Committer::Member(self.identity.fingerprint),
            adds: Vec::new(),
            removes: Vec::new(),
            new_server_policy: Some(policy.clone()),
            new_channel_policy: None,
        };
        let no_devices = |_: &[u8; 32], _: &[u8; 32]| false;
        let ctx = GrantContext { server_mailbox: mailbox_id, now_millis: now_millis(), is_member_device: &no_devices };
        authorize_server_commit(&current, &summary, &ctx).map_err(|e| GhostError::PermissionDenied(e.to_string()))?;

        let policy = crate::mls::group::GroupPolicy::Server(policy.clone());
        let blob = group.stage_policy(&self.provider, &policy, &CommitAad::default())?;
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
        use crate::mls::group::GroupPolicy;
        use ghost_wire::policy::{ChannelPolicy, MANAGE_CHANNELS};
        let own = self.identity.fingerprint;
        if !self.server_policy(server_id)?.has(&own, MANAGE_CHANNELS) {
            return Err(GhostError::PermissionDenied("creating channels needs the manage channels permission".into()));
        }
        let server_mailbox = mls_group_mailbox_id(self.default_group(server_id)?.group_id());
        // The relay hosting the server proposes removals in its channels too.
        let relay_vk = self.store.server_relay(server_id)?.or(self.relay_vk);

        let mut channel_id = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut channel_id);
        let policy = ChannelPolicy { server_mailbox, channel_id, roles, accounts };
        let group = GhostGroup::create_with_id(
            &self.provider,
            &self.identity,
            server_id,
            &channel_id,
            relay_vk.as_ref(),
            Some(&GroupPolicy::Channel(policy)),
        )?;
        let group_info = group.export_group_info(&self.provider)?;
        let mailbox_id = mls_group_mailbox_id(group.group_id());

        self.store.insert_channel(&Channel { channel_id, server_id: *server_id, name: name.to_string(), kind, position })?;
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
        self.store.insert_channel_if_not_exists(&Channel {
            channel_id,
            server_id: *server_id,
            name: crate::wire::UNNAMED_PRIVATE_CHANNEL.to_string(),
            kind: ChannelKind::Text,
            position: 0,
        })?;
        self.channel_groups.insert(channel_id, group);
        self.mailbox_map.insert(mailbox_id, channel_id);
        self.channel_server.insert(channel_id, *server_id);
        Ok((channel_id, mailbox_id, commit))
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
            .ok_or_else(|| GhostError::ServerNotLoaded(format!("channel {}", hex::encode(&group_channel[..8]))))?;
        let may_manage = self.server_policy(&server_id)?.has(sender, ghost_wire::policy::MANAGE_CHANNELS);

        if self.is_private_channel(group_channel) {
            let target = match &op {
                ChannelOpPayload::Create { channel_id, .. }
                | ChannelOpPayload::Rename { channel_id, .. }
                | ChannelOpPayload::Delete { channel_id }
                | ChannelOpPayload::InfoRequest { channel_id } => *channel_id,
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
                    self.drop_private_channel(&channel_id)?;
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
                self.store.insert_channel_if_not_exists(&Channel { channel_id, server_id, name, kind, position })?;
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

    /// Record a role's display name sent by `sender`, who must be able to manage roles.
    /// Returns whether it was recorded.
    pub fn apply_role_name(&mut self, server_id: &[u8; 32], sender: &[u8; 32], role_id: u8, name: &str) -> Result<bool> {
        if !self.server_policy(server_id)?.has(sender, ghost_wire::policy::MANAGE_ROLES) {
            return Ok(false);
        }
        self.store.set_role_name(server_id, role_id, name)?;
        Ok(true)
    }

    /// Name a role: stored here and sent to the server's members in an encrypted
    /// metadata message. Needs the manage roles permission.
    pub fn name_role(&mut self, server_id: &[u8; 32], role_id: u8, name: &str) -> Result<Outbound> {
        if !self.server_policy(server_id)?.has(&self.identity.fingerprint, ghost_wire::policy::MANAGE_ROLES) {
            return Err(GhostError::PermissionDenied("naming roles needs the manage roles permission".into()));
        }
        self.store.set_role_name(server_id, role_id, name)?;
        self.send_control(server_id, crate::wire::encode_role_name(role_id, name))
    }

    /// Forget a private channel this device is no longer in (or failed to join).
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
        let blob = group.stage_policy(&self.provider, &crate::mls::group::GroupPolicy::Channel(policy.clone()), &aad)?;
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

    /// Channels whose group still holds this device's leaf without Ghost's policy
    /// capabilities: groups made before policies existed, which cannot carry one until
    /// every leaf advertises support.
    pub fn channels_needing_capability_update(&self) -> Vec<[u8; 32]> {
        self.channel_groups
            .iter()
            .filter(|(_, group)| !group.own_leaf_supports_policy())
            .map(|(channel_id, _)| *channel_id)
            .collect()
    }

    /// Stage a commit updating this device's leaf in a channel's group to advertise
    /// Ghost's policy capabilities.
    pub fn stage_capabilities_update(&mut self, channel_id: &[u8; 32]) -> Result<Outbound> {
        let aad = self.commit_aad(channel_id);
        let group = self.channel_groups.get_mut(channel_id).ok_or_else(|| {
            GhostError::ServerNotLoaded(format!("channel {}", hex::encode(&channel_id[..8])))
        })?;
        let blob = group.stage_capabilities_update(&self.provider, &aad)?;
        let mailbox_id = mls_group_mailbox_id(group.group_id());
        Ok(Outbound { channel_id: *channel_id, mailbox_id, blob })
    }

    /// Accounts in a server whose leaves cannot carry a policy yet, holding back the
    /// server's move from the implicit policy to an explicit one.
    pub fn members_missing_policy_support(&self, server_id: &[u8; 32]) -> Result<Vec<[u8; 32]>> {
        self.default_group(server_id)?.members_missing_policy_support(&self.provider)
    }

    /// Servers still under the implicit policy that this account owns and whose every
    /// leaf now supports policies, so this device may commit the explicit policy.
    pub fn servers_ready_for_policy(&self) -> Vec<[u8; 32]> {
        let own = self.identity.fingerprint;
        let mut ready = Vec::new();
        for (channel_id, server_id) in &self.channel_server {
            if derive_default_channel_id(server_id) != *channel_id {
                continue;
            }
            let Some(group) = self.channel_groups.get(channel_id) else { continue };
            let implicit = group.server_policy().is_ok_and(|p| p.is_none());
            let owned = self.server_owner(server_id).is_ok_and(|owner| owner == own);
            let supported = group.members_missing_policy_support(&self.provider).is_ok_and(|m| m.is_empty());
            if implicit && owned && supported {
                ready.push(*server_id);
            }
        }
        ready
    }

    /// Remove a member from the server group: needs the kick permission and a rank above
    /// the member's. The relay then proposes removing the member from every private
    /// channel, whose policies admit only server members.
    pub fn kick_member(
        &mut self,
        server_id: &[u8; 32],
        target_fp: &[u8; 32],
    ) -> Result<Outbound> {
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
            GhostError::ServerNotLoaded(hex::encode(&server_id[..8]))
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
        let blob = group.remove_members(&self.provider, &leaf_indices, &CommitAad::default())?;
        let mailbox_id = mls_group_mailbox_id(group.group_id());
        Ok(Outbound { channel_id, mailbox_id, blob })
    }

    /// Remove a specific device's leaf from all channel MLS groups by its verifying key.
    /// Returns a list of (mailbox_id, commit_blob) to broadcast.
    pub fn revoke_device_leaves(&mut self, device_vk: &[u8; 32]) -> Vec<Outbound> {
        let channel_ids: Vec<[u8; 32]> = self.channel_groups.keys().copied().collect();
        let mut outbound = Vec::new();
        for cid in channel_ids {
            let aad = self.commit_aad(&cid);
            let group = match self.channel_groups.get_mut(&cid) {
                Some(g) => g,
                None => continue,
            };
            let leaf_indices: Vec<_> = group
                .members()
                .filter(|m| m.signature_key.as_slice() == device_vk.as_slice())
                .map(|m| m.index)
                .collect();
            if leaf_indices.is_empty() {
                continue;
            }
            if let Ok(commit_blob) = group.remove_members(&self.provider, &leaf_indices, &aad) {
                let mailbox_id = mls_group_mailbox_id(group.group_id());
                outbound.push(Outbound { channel_id: cid, mailbox_id, blob: commit_blob });
            }
        }
        outbound
    }

    /// Find leaf indices for a device in a channel's MLS group.
    pub fn find_device_leaves(&self, channel_id: &[u8; 32], device_vk: &[u8; 32]) -> Vec<LeafNodeIndex> {
        let Some(group) = self.channel_groups.get(channel_id) else { return vec![] };
        group.members()
            .filter(|m| m.signature_key.as_slice() == device_vk.as_slice())
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
            GhostError::ServerNotLoaded(format!("channel {}", hex::encode(&channel_id[..8])))
        })?;
        group.remove_members(&self.provider, members, &aad)
    }

    /// Merge a pending commit for a channel's MLS group after the relay accepted it.
    pub fn merge_pending_commit_for_channel(&mut self, channel_id: &[u8; 32]) -> Result<()> {
        let group = self.channel_groups.get_mut(channel_id).ok_or_else(|| {
            GhostError::ServerNotLoaded(format!("channel {}", hex::encode(&channel_id[..8])))
        })?;
        group.merge_pending_commit(&self.provider)?;
        self.record_if_server_group(channel_id)
    }

    /// Convenience: merge pending commit using server_id (operates on default channel).
    pub fn merge_pending_commit_for_server(&mut self, server_id: &[u8; 32]) -> Result<()> {
        let channel_id = derive_default_channel_id(server_id);
        self.merge_pending_commit_for_channel(&channel_id)
    }

    /// Discard a pending commit for a channel's MLS group after the relay rejected it.
    pub fn clear_pending_commit_for_channel(&mut self, channel_id: &[u8; 32]) -> Result<()> {
        let group = self.channel_groups.get_mut(channel_id).ok_or_else(|| {
            GhostError::ServerNotLoaded(format!("channel {}", hex::encode(&channel_id[..8])))
        })?;
        group.clear_pending_commit(&self.provider)
    }

    /// Convenience: clear pending commit using server_id (operates on default channel).
    pub fn clear_pending_commit_for_server(&mut self, server_id: &[u8; 32]) -> Result<()> {
        let channel_id = derive_default_channel_id(server_id);
        self.clear_pending_commit_for_channel(&channel_id)
    }

    /// Merge a pending commit for the sync group after the relay accepted it.
    pub fn merge_pending_commit_for_sync(&mut self) -> Result<()> {
        let group = self.sync_group.as_mut()
            .ok_or_else(|| GhostError::Format("no sync group".into()))?;
        group.merge_pending_commit(&self.provider)
    }

    /// Discard a pending commit for the sync group after the relay rejected it.
    pub fn clear_pending_commit_for_sync(&mut self) -> Result<()> {
        let group = self.sync_group.as_mut()
            .ok_or_else(|| GhostError::Format("no sync group".into()))?;
        group.clear_pending_commit(&self.provider)
    }

    /// Get the current MLS epoch for a channel's group.
    pub fn voice_epoch(&self, channel_id: &[u8; 32]) -> Result<u64> {
        let group = self.channel_groups.get(&self.group_channel(channel_id)).ok_or_else(|| {
            GhostError::ServerNotLoaded(format!("channel {}", hex::encode(&channel_id[..8])))
        })?;
        Ok(group.epoch())
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
        let group = self.channel_groups.get(&self.group_channel(channel_id)).ok_or_else(|| {
            GhostError::ServerNotLoaded(format!("channel {}", hex::encode(&channel_id[..8])))
        })?;
        crate::mls::voice::derive_voice_key(group, &self.provider, channel_id, sender_fp, device_vk, voice_salt)
    }

    /// Derive a per-sender presence encryption key for a voice channel.
    pub fn derive_presence_key(
        &self,
        channel_id: &[u8; 32],
        sender_fp: &[u8; 32],
    ) -> Result<[u8; 32]> {
        let group = self.channel_groups.get(&self.group_channel(channel_id)).ok_or_else(|| {
            GhostError::ServerNotLoaded(format!("channel {}", hex::encode(&channel_id[..8])))
        })?;
        crate::mls::voice::derive_presence_key(group, &self.provider, channel_id, sender_fp)
    }

    /// Seal an encrypted presence blob for the current identity.
    /// `voice_salt` is a random value generated once per voice session and reused
    /// for all presence updates within that session.
    pub fn seal_presence_blob(
        &self,
        channel_id: &[u8; 32],
        muted: bool,
        deafened: bool,
        voice_salt: [u8; 32],
    ) -> Result<Vec<u8>> {
        let key = self.derive_presence_key(channel_id, &self.identity.fingerprint)?;
        let state = crate::mls::voice::PresenceState {
            fingerprint: self.identity.fingerprint,
            muted,
            deafened,
            device_vk: *self.identity.verifying_key.as_bytes(),
            voice_salt,
        };
        crate::mls::voice::seal_presence(&key, &state)
    }

    /// Decrypt a presence blob by trial-decrypting with all channel members' keys.
    pub fn open_presence_blob(
        &self,
        channel_id: &[u8; 32],
        blob: &[u8],
    ) -> Result<crate::mls::voice::PresenceState> {
        let group = self.channel_groups.get(&self.group_channel(channel_id)).ok_or_else(|| {
            GhostError::ServerNotLoaded(format!("channel {}", hex::encode(&channel_id[..8])))
        })?;
        let member_fps = self.mls_member_fingerprints_for_channel(channel_id)?;
        crate::mls::voice::try_open_presence(&member_fps, group, &self.provider, channel_id, blob)
    }

    /// Seal an encrypted online presence blob for the current identity.
    pub fn seal_online_presence_blob(
        &self,
        server_id: &[u8; 32],
        status: crate::mls::presence::OnlineStatus,
        status_message: Option<String>,
        status_expiry: Option<u64>,
        avatar_hash: Option<[u8; 32]>,
    ) -> Result<Vec<u8>> {
        let group = self.default_group(server_id)?;
        let key = crate::mls::presence::derive_online_presence_key(
            group, &self.provider, &self.identity.fingerprint,
        )?;
        let state = crate::mls::presence::OnlinePresence {
            fingerprint: self.identity.fingerprint,
            status,
            status_message,
            status_expiry,
            avatar_hash,
        };
        crate::mls::presence::seal_online_presence(&key, &state)
    }

    /// Decrypt an online presence blob by trial-decrypting with all server members' keys.
    /// Uses the default channel's MLS group for server-wide presence.
    pub fn open_online_presence_blob(
        &self,
        server_id: &[u8; 32],
        blob: &[u8],
    ) -> Result<crate::mls::presence::OnlinePresence> {
        let default_ch = derive_default_channel_id(server_id);
        let group = self.channel_groups.get(&default_ch).ok_or_else(|| {
            GhostError::ServerNotLoaded(hex::encode(&server_id[..8]))
        })?;
        let member_fps = self.mls_member_fingerprints_for_channel(&default_ch)?;
        crate::mls::presence::try_open_online_presence(&member_fps, group, &self.provider, blob)
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

    /// Extract fingerprints of all MLS group members from a channel's group.
    pub fn mls_member_fingerprints_for_channel(&self, channel_id: &[u8; 32]) -> Result<Vec<[u8; 32]>> {
        let group = self.channel_groups.get(&self.group_channel(channel_id)).ok_or_else(|| {
            GhostError::ServerNotLoaded(format!("channel {}", hex::encode(&channel_id[..8])))
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
            GhostError::ServerNotLoaded(format!("channel {}", hex::encode(&channel_id[..8])))
        })?;
        let opened = {
            let cache = &self.idlog_cache;
            let revoked = |fp: &[u8; 32], vk: &[u8; 32]| cache.is_revoked(fp, vk);
            let server_at = |server_mailbox: &[u8; 32], epoch: u64| self.server_view_at(server_mailbox, epoch);
            let checks = CommitChecks {
                revoked: &revoked,
                mailbox: mls_group_mailbox_id(group.group_id()),
                received_at: received_at.unwrap_or_else(now_millis),
                server_at: &server_at,
            };
            open_any(&mut group, &self.provider, blob, &checks)
        };
        self.channel_groups.insert(*channel_id, group);

        let inbound = match opened {
            Err(GhostError::SelfMessage) => return Ok(ReceiveResult::Skipped),
            // Sent at an epoch before this device's (e.g. before it joined): never
            // readable here, and no sign the group is out of step.
            Err(GhostError::Mls(_))
                if envelope_type == ghost_wire::EnvelopeType::Application && current_epoch.is_some_and(|e| envelope_epoch < e) =>
            {
                return Ok(ReceiveResult::Skipped);
            }
            other => other?,
        };

        match inbound {
            InboundMessage::Application(msg) => {
                // Control messages (Metadata) aren't chat — don't persist them
                if msg.message_type != MessageType::Metadata {
                    let recv_ts = received_at.unwrap_or_else(|| {
                        SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_millis() as u64
                    });

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
                    })?;
                }

                // Gossip: compare sender's kt_head_hash against our cache
                let kt_warning = self
                    .idlog_cache
                    .get(&msg.sender_fp)
                    .map(|cached| cached.head_hash != msg.kt_head_hash)
                    .unwrap_or(false);

                if kt_warning {
                    Ok(ReceiveResult::MessageWithKtWarning(msg))
                } else {
                    Ok(ReceiveResult::Message(msg))
                }
            }
            InboundMessage::Commit { removed } => {
                self.record_if_server_group(channel_id)?;
                let group = self.channel_groups.get(channel_id).ok_or_else(|| {
                    GhostError::ServerNotLoaded(format!("channel {}", hex::encode(&channel_id[..8])))
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
                            ReceiveResult::Kicked
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

    /// Commit the pending proposals of a channel's group that this device may commit
    /// (relay removals of revoked or excluded devices). `None` when there are none.
    pub fn commit_pending_proposals(
        &mut self,
        channel_id: &[u8; 32],
    ) -> Result<Option<Outbound>> {
        let aad = self.commit_aad(channel_id);
        let excluded = self.excluded_leaves(channel_id)?;
        let group = self.channel_groups.get_mut(channel_id).ok_or_else(|| {
            GhostError::ServerNotLoaded(format!("channel {}", hex::encode(&channel_id[..8])))
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

    /// Check if this client is the creator of a server.
    pub fn is_server_creator(&self, server_id: &[u8; 32]) -> bool {
        self.store.get_server(server_id)
            .map(|s| s.creator_fp == self.identity.fingerprint)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_client(seed: [u8; 32]) -> GhostClient {
        let identity = Identity::from_seed(seed).unwrap();
        let mut client = GhostClient::open_in_memory(identity, seed).unwrap();
        // Register own identity so self-validation passes
        register_identity_in_cache(&mut client, &Identity::from_seed(seed).unwrap());
        client
    }

    /// Register an identity's device key as active in a client's idlog cache.
    fn register_identity_in_cache(client: &mut GhostClient, identity: &Identity) {
        use ghost_wire::idlog::{DeviceInfo, LogState};
        let mut devices = HashMap::new();
        devices.insert(
            identity.verifying_key.to_bytes(),
            DeviceInfo {
                verifying_key: identity.verifying_key.to_bytes(),
                label: "test".to_string(),
                added_at_seq: 1,
                revoked_at_seq: None,
            },
        );
        let mut state = LogState::empty(identity.fingerprint);
        state.devices = devices;
        state.head_seq = 1;
        client.idlog_cache.insert(state);
    }

    /// Returns (creator, joiner, server_id) with both clients in a shared MLS group.
    fn setup_two_clients() -> (GhostClient, GhostClient, [u8; 32]) {
        let mut c1 = test_client([0x01; 32]);
        let mut c2 = test_client([0x02; 32]);

        // Each client needs the other's identity in its cache for validation
        let id1 = Identity::from_seed([0x01; 32]).unwrap();
        let id2 = Identity::from_seed([0x02; 32]).unwrap();
        register_identity_in_cache(&mut c1, &id2);
        register_identity_in_cache(&mut c2, &id1);

        let server_id = c1.create_server("test", ServerKind::Server, 1000).unwrap();

        let kp = c2.generate_key_package().unwrap();
        let fp = *c2.fingerprint();
        let name = c2.identity().display_name.clone();
        let (_outbound, welcome_bytes) =
            c1.invite_member(&server_id, kp, fp, &name, 1000).unwrap();
        c1.merge_pending_commit_for_server(&server_id).unwrap();

        c2.join_server(&server_id, &welcome_bytes, "test", ServerKind::Server, 1000).unwrap();

        (c1, c2, server_id)
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
        assert_eq!(server.creator_fp, *client.fingerprint());
        assert_eq!(server.created_at, 1000);

        let channels = client.store().list_channels(&server_id).unwrap();
        assert_eq!(channels.len(), 1);
        assert_eq!(channels[0].name, "general");
        assert_eq!(channels[0].kind, ChannelKind::Text);
        assert_eq!(channels[0].channel_id, derive_default_channel_id(&server_id));

        let members = client.store().list_members(&server_id).unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].fingerprint, *client.fingerprint());
        assert_eq!(members[0].role, MemberRole::Creator);
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

        // c1 invites c2
        let kp = c2.generate_key_package().unwrap();
        let fp = *c2.fingerprint();
        let name = c2.identity().display_name.clone();
        let (_outbound, welcome) =
            c1.invite_member(&server_id, kp, fp, &name, 1000).unwrap();
        c1.merge_pending_commit_for_server(&server_id).unwrap();

        // c2 joins
        c2.join_server(&server_id, &welcome, "full-flow", ServerKind::Server, 1000).unwrap();

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
        c1.merge_pending_commit_for_server(&server_id).unwrap();
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

        let (joined_server_id, channel_results, _grant) =
            c2.join_by_invite(&invite.sealed_payload, &invite.key, 2000).unwrap();
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

    #[test]
    fn refresh_invite_payload_has_new_member() {
        let mut c1 = test_client([0x01; 32]);
        let mut c2 = test_client([0x02; 32]);

        let server_id = c1.create_server("test", ServerKind::Server, 1000).unwrap();
        let invite = c1.create_invite(&server_id, u64::MAX).unwrap();

        let (_, _, grant) = c2.join_by_invite(&invite.sealed_payload, &invite.key, 2000).unwrap();

        let refreshed = c2.refresh_invite_payload(&server_id, &grant, &invite.key).unwrap();
        let opened = crate::crypto::aead::open(&invite.key, &refreshed, crate::wire::INVITE_PAYLOAD_CONTEXT).unwrap();
        let payload = InvitePayload::from_bytes(&opened).unwrap();

        // Should include c1 + c2, and the inviter's grant for the next joiner
        assert_eq!(payload.members.len(), 2);
        assert_eq!(payload.server_name, "test");
        assert!(!payload.channels[0].group_info_bytes.is_empty());
        assert_eq!(payload.grant, grant);
    }
}
