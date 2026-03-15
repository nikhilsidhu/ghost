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
    ApplicationMessage, InboundMessage, InviteChannel, InviteMember, InvitePayload, Outbound,
    ProvisionPayload, SyncReceiveResult, SyncServerMeta,
};

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
    /// This client was removed from the group by a commit.
    Kicked,
    /// A commit removed these members (fingerprints) from the group.
    MembersRemoved(Vec<[u8; 32]>),
    /// A proposal was queued (e.g. relay Remove). Creator should commit pending proposals.
    ProposalProcessed,
    Skipped,
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

        Ok(Self {
            identity,
            provider,
            store,
            channel_groups,
            mailbox_map,
            channel_server,
            sync_group,
            relay_vk: None,
            idlog_cache: IdLogCache::new(),
        })
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

    /// Cache identity log entries from the relay and validate the chain.
    pub fn cache_identity_log(
        &mut self,
        account_fp: &[u8; 32],
        entries: &[(u64, Vec<u8>)],
    ) -> Result<ghost_wire::idlog::LogState> {
        self.idlog_cache
            .cache_and_validate(&self.store, account_fp, entries)
    }

    /// Return the previously-seen KT tree size for this relay, or 0 if none.
    /// The app layer uses this to decide whether to fetch a consistency proof.
    pub fn kt_last_tree_size(&self, relay_url: &str) -> Result<u64> {
        Ok(self
            .store
            .get_kt_state(relay_url)?
            .map(|s| s.tree_size)
            .unwrap_or(0))
    }

    /// Verify KT proofs and cache identity log entries.
    ///
    /// 1. Verify checkpoint signature (relay's Ed25519 key)
    /// 2. Verify each entry's inclusion proof against the checkpoint root
    /// 3. If we have a previous checkpoint, verify the consistency proof
    ///    proving the old tree is a prefix of the new tree
    /// 4. Persist the new checkpoint and cache the identity log chain
    ///
    /// `consistency_proof_bytes`: required when we already have a checkpoint
    /// for this relay (i.e. `kt_last_tree_size() > 0`). Pass `None` on first
    /// fetch.
    pub fn cache_identity_log_with_proofs(
        &mut self,
        relay_url: &str,
        account_fp: &[u8; 32],
        response: &crate::relay::IdLogWithProofs,
        consistency_proof_bytes: Option<&[u8]>,
    ) -> Result<ghost_wire::idlog::LogState> {
        use ghost_wire::merkle::{leaf_hash, Checkpoint, ConsistencyProof, InclusionProof};

        let relay_vk = self.relay_vk.ok_or_else(|| {
            GhostError::IdentityLog("no relay verifying key configured".into())
        })?;
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&relay_vk)
            .map_err(|e| GhostError::IdentityLog(format!("bad relay vk: {e}")))?;

        // 1. Verify checkpoint signature
        let checkpoint = Checkpoint::from_bytes(&response.checkpoint)
            .map_err(|e| GhostError::IdentityLog(format!("bad checkpoint: {e}")))?;
        checkpoint
            .verify(&vk)
            .map_err(|_| GhostError::IdentityLog("checkpoint signature invalid".into()))?;

        // 2. Verify each entry's inclusion proof
        for entry in &response.entries {
            if entry.inclusion_proof.is_empty() {
                continue; // entry predates KT tree
            }
            let proof = InclusionProof::from_bytes(&entry.inclusion_proof)
                .map_err(|e| GhostError::IdentityLog(format!("bad inclusion proof: {e}")))?;
            let lh = leaf_hash(&entry.payload);
            if !proof.verify(&lh, &checkpoint.root_hash) {
                return Err(GhostError::IdentityLog(
                    "inclusion proof verification failed".into(),
                ));
            }
        }

        // 3. Verify consistency with previously-seen checkpoint
        if let Some(prev) = self.store.get_kt_state(relay_url)? {
            if checkpoint.tree_size < prev.tree_size {
                return Err(GhostError::IdentityLog(
                    "relay checkpoint went backwards".into(),
                ));
            }
            if checkpoint.tree_size > prev.tree_size {
                let proof_bytes = consistency_proof_bytes.ok_or_else(|| {
                    GhostError::IdentityLog(
                        "consistency proof required but not provided".into(),
                    )
                })?;
                let proof = ConsistencyProof::from_bytes(proof_bytes)
                    .map_err(|e| GhostError::IdentityLog(format!("bad consistency proof: {e}")))?;
                if !proof.verify(&prev.root_hash, &checkpoint.root_hash) {
                    return Err(GhostError::IdentityLog(
                        "consistency proof verification failed — possible split-view attack".into(),
                    ));
                }
            }
            // tree_size == prev.tree_size: same checkpoint, no consistency proof needed
        }

        // 4. Persist new checkpoint and cache the identity log
        self.store.set_kt_state(
            relay_url,
            checkpoint.tree_size,
            &checkpoint.root_hash,
            &response.checkpoint,
        )?;

        let entries: Vec<(u64, Vec<u8>)> = response
            .entries
            .iter()
            .map(|e| (e.seq, e.payload.clone()))
            .collect();
        self.idlog_cache
            .cache_and_validate(&self.store, account_fp, &entries)
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

    /// Encrypt a sync plaintext and wrap in relay envelope.
    pub fn send_sync(&mut self, plaintext: &[u8]) -> Result<Outbound> {
        let group = self.sync_group.as_mut()
            .ok_or_else(|| GhostError::Format("no sync group".into()))?;
        let mls_out = group.encrypt(&self.provider, plaintext)?;
        let mls_bytes = mls_out
            .to_bytes()
            .map_err(|e| GhostError::Mls(format!("serialize: {e}")))?;
        let header = ghost_wire::encode_envelope(ghost_wire::EnvelopeType::Application, group.epoch());
        let mut blob = Vec::with_capacity(ghost_wire::ENVELOPE_HEADER_SIZE + mls_bytes.len());
        blob.extend_from_slice(&header);
        blob.extend_from_slice(&mls_bytes);
        let mailbox_id = mls_group_mailbox_id(group.group_id());
        Ok(Outbound { channel_id: [0u8; 32], mailbox_id, blob })
    }

    /// Decrypt an inbound sync blob (envelope-wrapped MLS ciphertext).
    pub fn receive_sync(&mut self, blob: &[u8]) -> Result<SyncReceiveResult> {
        let group = self.sync_group.as_mut()
            .ok_or_else(|| GhostError::Format("no sync group".into()))?;
        ghost_wire::decode_envelope(blob)
            .map_err(|e| GhostError::Format(format!("envelope: {e}")))?;
        let mls_bytes = ghost_wire::envelope_payload(blob);
        match group.process_message_bytes(&self.provider, mls_bytes) {
            Err(GhostError::SelfMessage) => Ok(SyncReceiveResult::SelfMessage),
            Err(e) => Err(e),
            Ok(processed) => {
                let credential = processed.credential().clone();
                let sender = processed.sender().clone();
                match processed.into_content() {
                    openmls::prelude::ProcessedMessageContent::ApplicationMessage(app) => {
                        crate::wire::validate_sender(group, &credential, &sender, &self.idlog_cache, None)?;
                        Ok(SyncReceiveResult::Application(app.into_bytes()))
                    }
                    openmls::prelude::ProcessedMessageContent::StagedCommitMessage(staged) => {
                        crate::wire::validate_sender(group, &credential, &sender, &self.idlog_cache, Some(&staged))?;
                        group.merge_staged_commit(&self.provider, *staged)?;
                        Ok(SyncReceiveResult::CommitProcessed)
                    }
                    _ => Ok(SyncReceiveResult::CommitProcessed),
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
        group.remove_members(&self.provider, &leaf_indices)
    }

    /// Export server metadata for provisioning a sibling device (no role check).
    pub fn export_provision_payload(&self, server_id: &[u8; 32]) -> Result<ProvisionPayload> {
        let default_group = self.default_group(server_id)?;
        let meta = self.store.get_server(server_id)?;
        let members = self.store.list_members(server_id)?;
        let channels = self.store.list_channels(server_id)?;
        let mailbox_id = mls_group_mailbox_id(default_group.group_id());

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
            channels: channels
                .iter()
                .map(|c| InviteChannel {
                    channel_id: c.channel_id,
                    name: c.name.clone(),
                    kind: c.kind,
                    position: c.position,
                    group_info_bytes: Vec::new(),
                })
                .collect(),
            mailbox_id,
        })
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
                .map(|c| InviteChannel {
                    channel_id: c.channel_id,
                    name: c.name.clone(),
                    kind: c.kind,
                    position: c.position,
                    group_info_bytes: Vec::new(),
                })
                .collect(),
        })
    }

    /// Core join logic: external commit → persist metadata → register.
    /// `idempotent`: true uses `_if_not_exists` inserts (provision/sync), false uses strict inserts (invite).
    /// Join a server by joining each channel's MLS group.
    /// Returns Vec of (channel_id, commit_bytes, mailbox_id) — one per channel.
    fn join_server_common(
        &mut self,
        server_id: [u8; 32],
        server_name: String,
        kind: ServerKind,
        members: &[InviteMember],
        channels: &[InviteChannel],
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

        let mut results = Vec::with_capacity(channels.len());
        for ch in channels {
            let (ghost_group, commit_bytes) = GhostGroup::join_by_external_commit(
                &self.provider,
                &self.identity,
                &ch.group_info_bytes,
            )?;
            let mailbox_id = mls_group_mailbox_id(ghost_group.group_id());
            self.channel_groups.insert(ch.channel_id, ghost_group);
            self.mailbox_map.insert(mailbox_id, ch.channel_id);
            self.channel_server.insert(ch.channel_id, server_id);
            results.push((ch.channel_id, commit_bytes, mailbox_id));
        }
        Ok(results)
    }

    /// Join a server from a provision payload (handles duplicates).
    /// Returns Vec of (channel_id, commit_bytes, mailbox_id) for each channel.
    pub fn join_from_provision(
        &mut self,
        payload: &ProvisionPayload,
        group_info_bytes: &[u8],
        timestamp: u64,
    ) -> Result<Vec<([u8; 32], Vec<u8>, [u8; 32])>> {
        // Provision payloads carry channel metadata but the GroupInfo comes
        // separately (fetched from the relay's server_info endpoint).
        // Inject it into the default channel's group_info_bytes.
        let mut channels = payload.channels.clone();
        let default_ch = derive_default_channel_id(&payload.server_id);
        for ch in &mut channels {
            if ch.channel_id == default_ch {
                ch.group_info_bytes = group_info_bytes.to_vec();
            }
        }
        self.join_server_common(
            payload.server_id, payload.server_name.clone(), payload.kind,
            &payload.members, &channels, timestamp, true,
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
            GhostGroup::create_with_id(&self.provider, &self.identity, &server_id, &channel_id, self.relay_vk.as_ref())?;

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
        Ok(server_id)
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
                let group = match self.channel_groups.get_mut(&cid) {
                    Some(g) => g,
                    None => continue,
                };
                if group.has_external_senders() {
                    continue;
                }
                if let Ok(commit) = group.add_external_sender_extension(&self.provider, &relay_vk) {
                    let mailbox_id = mls_group_mailbox_id(group.group_id());
                    results.push((mailbox_id, commit));
                }
            }
        }

        // Also migrate sync group
        if let Some(ref mut sync_group) = self.sync_group {
            if !sync_group.has_external_senders() {
                if let Ok(commit) = sync_group.add_external_sender_extension(&self.provider, &relay_vk) {
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
        let group = self.channel_groups.get_mut(channel_id).ok_or_else(|| {
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
        let fingerprint = self.identity.fingerprint;
        let channel_id = derive_default_channel_id(server_id);
        let group = self.channel_groups.get_mut(&channel_id).ok_or_else(|| {
            GhostError::ServerNotLoaded(hex::encode(&server_id[..8]))
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
        let group = self.channel_groups.get_mut(channel_id).ok_or_else(|| {
            GhostError::ServerNotLoaded(format!("channel {}", hex::encode(&channel_id[..8])))
        })?;

        let msg = open(group, &self.provider, blob)?;

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

        let (commit_blob, welcome) = group.add_member(&self.provider, key_package)?;
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
        Ok(())
    }

    fn build_invite_payload(
        &self,
        server_id: &[u8; 32],
        server_name: &str,
        kind: ServerKind,
        members: &[Member],
        channels: &[Channel],
    ) -> Result<InvitePayload> {
        let invite_channels: Vec<InviteChannel> = channels
            .iter()
            .map(|c| {
                let group = self.channel_groups.get(&c.channel_id).ok_or_else(|| {
                    GhostError::ServerNotLoaded(format!("channel {}", hex::encode(&c.channel_id[..8])))
                })?;
                let gi = group.export_group_info(&self.provider)?;
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
        })
    }

    /// Creator exports an invite payload with per-channel GroupInfo.
    /// Returns (random_token, serialized_payload).
    pub fn create_invite(&self, server_id: &[u8; 32]) -> Result<(String, Vec<u8>)> {
        let member = self.store.get_member(server_id, &self.identity.fingerprint)?;
        if member.role != MemberRole::Creator {
            return Err(GhostError::PermissionDenied(
                "only the creator can create invites".into(),
            ));
        }

        let meta = self.store.get_server(server_id)?;
        let members = self.store.list_members(server_id)?;
        let channels = self.store.list_channels(server_id)?;

        let payload = self.build_invite_payload(server_id, &meta.name, meta.kind, &members, &channels)?;

        let mut token_bytes = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut token_bytes);
        let token = hex::encode(token_bytes);

        Ok((token, payload.to_bytes()))
    }

    /// Join a server via an invite payload (external commit).
    /// Join a server via an invite payload (external commit).
    /// Returns (server_id, Vec<(channel_id, commit_bytes, mailbox_id)>).
    pub fn join_by_invite(
        &mut self,
        payload_bytes: &[u8],
        timestamp: u64,
    ) -> Result<([u8; 32], Vec<([u8; 32], Vec<u8>, [u8; 32])>)> {
        let payload = InvitePayload::from_bytes(payload_bytes)?;
        let channel_results = self.join_server_common(
            payload.server_id, payload.server_name, payload.kind,
            &payload.members, &payload.channels, timestamp, false,
        )?;
        Ok((payload.server_id, channel_results))
    }

    /// Re-export an invite payload with fresh GroupInfo (after joining via external commit).
    pub fn refresh_invite_payload(&self, server_id: &[u8; 32]) -> Result<Vec<u8>> {
        let meta = self.store.get_server(server_id)?;
        let members = self.store.list_members(server_id)?;
        let channels = self.store.list_channels(server_id)?;

        let payload = self.build_invite_payload(server_id, &meta.name, meta.kind, &members, &channels)?;
        Ok(payload.to_bytes())
    }

    /// Export GroupInfo for a server's default channel so other clients can recover via external commit.
    pub fn export_server_info(&self, server_id: &[u8; 32]) -> Result<Vec<u8>> {
        let group = self.default_group(server_id)?;
        group.export_group_info(&self.provider)
    }

    /// Rejoin a channel's MLS group via external commit after falling too far behind.
    /// Deletes old MLS state and creates a fresh session from GroupInfo.
    pub fn recover_via_external_commit(
        &mut self,
        channel_id: &[u8; 32],
        group_info_bytes: &[u8],
    ) -> Result<(Vec<u8>, [u8; 32])> {
        if let Some(old_group) = self.channel_groups.remove(channel_id) {
            // Remove old mailbox mapping
            let old_mb = mls_group_mailbox_id(old_group.group_id());
            self.mailbox_map.remove(&old_mb);
            let _ = old_group.delete(&self.provider);
        }

        let (ghost_group, commit_bytes) = GhostGroup::join_by_external_commit(
            &self.provider,
            &self.identity,
            group_info_bytes,
        )?;

        let mailbox_id = mls_group_mailbox_id(ghost_group.group_id());
        self.channel_groups.insert(*channel_id, ghost_group);
        self.mailbox_map.insert(mailbox_id, *channel_id);

        Ok((commit_bytes, mailbox_id))
    }

    /// Creator-only: remove a member from ALL channel MLS groups in the server.
    /// Returns one Outbound per channel group where the member was found.
    pub fn kick_member(
        &mut self,
        server_id: &[u8; 32],
        target_fp: &[u8; 32],
    ) -> Result<Vec<Outbound>> {
        if target_fp == &self.identity.fingerprint {
            return Err(GhostError::PermissionDenied("cannot kick yourself".into()));
        }

        let member = self.store.get_member(server_id, &self.identity.fingerprint)?;
        if member.role != MemberRole::Creator {
            return Err(GhostError::PermissionDenied(
                "only the creator can kick members".into(),
            ));
        }

        let channel_ids = self.server_channel_ids(server_id);
        let mut outbound = Vec::new();
        let mut found_any = false;

        for cid in channel_ids {
            let group = match self.channel_groups.get_mut(&cid) {
                Some(g) => g,
                None => continue,
            };

            let leaf_indices: Vec<_> = group
                .members()
                .filter(|m| {
                    openmls::prelude::BasicCredential::try_from(m.credential.clone())
                        .ok()
                        .map(|bc: openmls::prelude::BasicCredential| bc.identity() == target_fp.as_slice())
                        .unwrap_or(false)
                })
                .map(|m| m.index)
                .collect();

            if leaf_indices.is_empty() {
                continue;
            }

            found_any = true;
            let commit_blob = group.remove_members(&self.provider, &leaf_indices)?;
            let mailbox_id = mls_group_mailbox_id(group.group_id());
            outbound.push(Outbound { channel_id: cid, mailbox_id, blob: commit_blob });
        }

        if !found_any {
            return Err(GhostError::Mls("member not found in any channel group".into()));
        }

        Ok(outbound)
    }

    /// Remove a specific device's leaf from all channel MLS groups by its verifying key.
    /// Returns a list of (mailbox_id, commit_blob) to broadcast.
    pub fn revoke_device_leaves(&mut self, device_vk: &[u8; 32]) -> Vec<Outbound> {
        let channel_ids: Vec<[u8; 32]> = self.channel_groups.keys().copied().collect();
        let mut outbound = Vec::new();
        for cid in channel_ids {
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
            if let Ok(commit_blob) = group.remove_members(&self.provider, &leaf_indices) {
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
        let group = self.channel_groups.get_mut(channel_id).ok_or_else(|| {
            GhostError::ServerNotLoaded(format!("channel {}", hex::encode(&channel_id[..8])))
        })?;
        group.remove_members(&self.provider, members)
    }

    /// Merge a pending commit for a channel's MLS group after the relay accepted it.
    pub fn merge_pending_commit_for_channel(&mut self, channel_id: &[u8; 32]) -> Result<()> {
        let group = self.channel_groups.get_mut(channel_id).ok_or_else(|| {
            GhostError::ServerNotLoaded(format!("channel {}", hex::encode(&channel_id[..8])))
        })?;
        group.merge_pending_commit(&self.provider)
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
        let group = self.channel_groups.get(channel_id).ok_or_else(|| {
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
        let group = self.channel_groups.get(channel_id).ok_or_else(|| {
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
        let group = self.channel_groups.get(channel_id).ok_or_else(|| {
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
        let group = self.channel_groups.get(channel_id).ok_or_else(|| {
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
        let group = self.channel_groups.get(channel_id).ok_or_else(|| {
            GhostError::ServerNotLoaded(format!("channel {}", hex::encode(&channel_id[..8])))
        })?;
        let mut fps = Vec::new();
        for member in group.members() {
            if let Ok(bc) = openmls::prelude::BasicCredential::try_from(member.credential) {
                if let Ok(fp) = <[u8; 32]>::try_from(bc.identity().as_ref()) {
                    fps.push(fp);
                }
            }
        }
        Ok(fps)
    }

    /// Convenience: extract member fingerprints from a server's default channel group.
    pub fn mls_member_fingerprints(&self, server_id: &[u8; 32]) -> Result<Vec<[u8; 32]>> {
        let ch = derive_default_channel_id(server_id);
        self.mls_member_fingerprints_for_channel(&ch)
    }

    /// Process an inbound blob — could be an app message, a commit, or a self-message.
    /// Takes channel_id to identify which MLS group to decrypt with.
    pub fn receive_any(
        &mut self,
        channel_id: &[u8; 32],
        blob: &[u8],
        received_at: Option<u64>,
    ) -> Result<ReceiveResult> {
        let group = self.channel_groups.get_mut(channel_id).ok_or_else(|| {
            GhostError::ServerNotLoaded(format!("channel {}", hex::encode(&channel_id[..8])))
        })?;

        let inbound = match open_any(group, &self.provider, blob, &self.idlog_cache) {
            Err(GhostError::SelfMessage) => return Ok(ReceiveResult::Skipped),
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
                let group = self.channel_groups.get(channel_id).ok_or_else(|| {
                    GhostError::ServerNotLoaded(format!("channel {}", hex::encode(&channel_id[..8])))
                })?;

                // Check if we were fully kicked (all our leaves removed from this channel)
                if removed.contains(&self.identity.fingerprint) {
                    let still_in = group.members().any(|m| {
                        openmls::prelude::BasicCredential::try_from(m.credential)
                            .ok()
                            .map(|bc: openmls::prelude::BasicCredential| bc.identity() == self.identity.fingerprint.as_slice())
                            .unwrap_or(false)
                    });
                    if !still_in {
                        return Ok(ReceiveResult::Kicked);
                    }
                }

                // Only report members as truly removed if they have no leaves remaining.
                // A device revocation removes one leaf but the account stays if other devices remain.
                let truly_removed: Vec<[u8; 32]> = removed.into_iter().filter(|fp| {
                    !group.members().any(|m| {
                        openmls::prelude::BasicCredential::try_from(m.credential)
                            .ok()
                            .map(|bc: openmls::prelude::BasicCredential| bc.identity() == fp.as_slice())
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

    /// Commit any pending proposals for a channel's MLS group.
    /// Used by the group creator to immediately commit relay-generated Remove proposals.
    pub fn commit_pending_proposals(
        &mut self,
        channel_id: &[u8; 32],
    ) -> Result<Outbound> {
        let group = self.channel_groups.get_mut(channel_id).ok_or_else(|| {
            GhostError::ServerNotLoaded(format!("channel {}", hex::encode(&channel_id[..8])))
        })?;
        let commit = group.commit_pending_proposals(&self.provider, &self.idlog_cache)?;
        let mailbox_id = mls_group_mailbox_id(group.group_id());
        Ok(Outbound { channel_id: *channel_id, mailbox_id, blob: commit })
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
        let state = LogState {
            account_fp: identity.fingerprint,
            master_verifying_key: None,
            devices,
            head_seq: 1,
            head_hash: [0u8; 32],
        };
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
    fn create_invite_requires_creator() {
        let (c1, c2, server_id) = setup_two_clients();

        // c1 (creator) can create invite
        let result = c1.create_invite(&server_id);
        assert!(result.is_ok());

        // c2 (member) cannot
        let result = c2.create_invite(&server_id);
        assert!(matches!(result, Err(GhostError::PermissionDenied(_))));
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

        let (_token, payload_bytes) = c1.create_invite(&server_id).unwrap();

        let (joined_server_id, channel_results) =
            c2.join_by_invite(&payload_bytes, 2000).unwrap();
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
        let (_, payload_bytes) = c1.create_invite(&server_id).unwrap();

        c2.join_by_invite(&payload_bytes, 2000).unwrap();

        let refreshed = c2.refresh_invite_payload(&server_id).unwrap();
        let payload = InvitePayload::from_bytes(&refreshed).unwrap();

        // Should include c1 + c2
        assert_eq!(payload.members.len(), 2);
        assert_eq!(payload.server_name, "test");
        assert!(!payload.channels[0].group_info_bytes.is_empty());
    }
}
