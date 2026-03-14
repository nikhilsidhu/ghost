use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Instant;

use openmls::messages::external_proposals::ExternalProposal;
use openmls::prelude::*;
use openmls::prelude::tls_codec::Deserialize as _;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::{OpenMlsRustCrypto, RustCrypto};
use tokio::sync::{broadcast, watch, RwLock};

use crate::config::Config;
use crate::error::RelayError;
use crate::mailbox::Mailbox;
use crate::mls_storage::MlsPublicStorage;
use crate::rate_limit::RateLimiter;
use crate::storage::Storage;
use crate::util::now_millis;
use crate::voice::{RoutingTable, VoiceChannel};

pub struct Invite {
    pub expires_at: u64,
    pub join: Option<Vec<u8>>,
    pub accept: Option<Vec<u8>>,
    pub seq: u64,
    pub join_notify: broadcast::Sender<()>,
    pub accept_notify: broadcast::Sender<()>,
}

/// Cached voice presence entry for mailbox WS broadcast
pub struct VpEntry {
    pub mailbox_id: [u8; 32],
    pub channel_id: [u8; 32],
    pub conn_id: u64,
    pub blob: Vec<u8>,
}

/// Cached online presence entry for mailbox WS broadcast
pub struct OpEntry {
    pub mailbox_id: [u8; 32],
    pub conn_id: u64,
    pub blob: Vec<u8>,
}

/// Ephemeral pairing session for device linking (5-minute TTL, in-memory only)
pub struct PairingSession {
    pub offer: Vec<u8>,
    pub response: Option<Vec<u8>>,
    pub expires_at: Instant,
}

/// One-shot provision blob posted by device A after pairing, fetched by device B
pub struct ProvisionEntry {
    pub data: Vec<u8>,
    pub expires_at: Instant,
}

pub struct Inner {
    pub mailboxes: RwLock<HashMap<[u8; 32], Mailbox>>,
    pub invites: RwLock<HashMap<String, Invite>>,
    pub voice_channels: RwLock<HashMap<[u8; 32], VoiceChannel>>,
    pub routing: RoutingTable,
    pub voice_udp_port: watch::Sender<u16>,
    pub voice_udp_port_rx: watch::Receiver<u16>,
    pub config: Config,
    pub start_time: Instant,
    pub storage: Storage,
    pub voice_presence: RwLock<Vec<VpEntry>>,
    pub online_presence: RwLock<Vec<OpEntry>>,
    pub pairing: RwLock<HashMap<[u8; 32], PairingSession>>,
    pub provision: RwLock<HashMap<[u8; 32], ProvisionEntry>>,
    pub next_conn_id: AtomicU64,
    /// Broadcast (account_fp, device_vk) when a device is revoked, so WS
    /// connections belonging to that device can close immediately.
    pub revocation_tx: broadcast::Sender<([u8; 32], [u8; 32])>,
    /// (PublicGroup, creator_fp) — creator_fp is captured at group init time.
    pub groups: RwLock<HashMap<[u8; 32], (PublicGroup, [u8; 32])>>,
    pub relay_crypto: RustCrypto,
    pub relay_vk: [u8; 32],
    /// Raw ed25519 keypair bytes (64) for constructing OpenMLS signer
    pub relay_sk_bytes: [u8; 64],
    /// In-memory Merkle tree for key transparency (frontier-based, O(log N) storage)
    pub kt_tree: RwLock<ghost_wire::merkle::MerkleTree>,
    /// Per-account rate limiter for unauthenticated recovery blob downloads
    pub recovery_limiter: RateLimiter,
}

impl Inner {
    pub async fn store_blob(&self, mailbox_id: &[u8; 32], data: &[u8]) -> crate::error::Result<(u64, bool)> {
        if data.len() > self.config.max_blob_size {
            return Err(crate::error::RelayError::PayloadTooLarge);
        }
        let (envelope_type, epoch) = ghost_wire::decode_envelope(data)
            .map_err(|e| crate::error::RelayError::BadRequest(format!("envelope: {e}")))?;

        let et = envelope_type as u8;
        let is_commit = et == ghost_wire::EnvelopeType::Commit as u8;
        let is_proposal = et == ghost_wire::EnvelopeType::Proposal as u8;

        // MLS validation for commits and proposals
        if is_commit || is_proposal {
            self.validate_mls(mailbox_id, data, is_commit).await?;
        }

        let (seq, _, epoch_mismatch) =
            self.storage
                .append(mailbox_id, et, epoch, data)?;
        let map = self.mailboxes.read().await;
        if let Some(mailbox) = map.get(mailbox_id) {
            let _ = mailbox.seq_tx.send(seq);
        }
        Ok((seq, epoch_mismatch))
    }

    /// Hash an identity log entry, append it to the KT Merkle tree,
    /// sign a new checkpoint, and persist everything.
    pub async fn kt_append_and_sign(
        &self,
        entry_payload: &[u8],
        account_fp: &[u8; 32],
        seq: u64,
    ) {
        let lh = ghost_wire::merkle::leaf_hash(entry_payload);

        // Hold the tree lock for the entire operation to prevent concurrent
        // appends from racing on leaf_index or seeing partial DB state.
        let mut tree = self.kt_tree.write().await;

        if let Err(e) = self.storage.kt_append_leaf(&lh, account_fp, seq) {
            tracing::warn!("kt_append_leaf failed: {e}");
            return;
        }

        tree.append(lh);

        let root = tree.root();
        let size = tree.size();

        // Update the O(log N) internal nodes along the right edge
        let storage = &self.storage;
        let mut pending_nodes = Vec::new();
        ghost_wire::merkle::update_stored_nodes(
            size,
            &|start, count| storage.kt_load_hash(start, count).ok().flatten(),
            &mut |start, count, hash| pending_nodes.push((start, count, hash)),
        );
        if let Err(e) = self.storage.kt_store_nodes(&pending_nodes) {
            tracing::warn!("kt_store_nodes failed: {e}");
            return;
        }

        let sk = match ed25519_dalek::SigningKey::from_keypair_bytes(&self.relay_sk_bytes) {
            Ok(sk) => sk,
            Err(e) => {
                tracing::warn!("kt checkpoint sign: bad relay key: {e}");
                return;
            }
        };
        let cp = ghost_wire::merkle::Checkpoint::sign(size, root, now_millis(), &sk);
        let cp_bytes = cp.to_bytes();

        if let Err(e) = self.storage.kt_persist_state(tree.frontier(), size, &root, &cp_bytes) {
            tracing::warn!("kt_persist_state failed: {e}");
        }
    }

    /// Validate a commit or proposal via PublicGroup.
    /// For commits: process, check authorization, merge, update members.
    /// For proposals: process and queue.
    async fn validate_mls(
        &self,
        mailbox_id: &[u8; 32],
        data: &[u8],
        is_commit: bool,
    ) -> Result<(), RelayError> {
        let mut groups = self.groups.write().await;
        let (pg, creator_fp) = match groups.get_mut(mailbox_id) {
            Some(entry) => entry,
            // No PublicGroup for this mailbox — skip validation (pre-upgrade group)
            None => return Ok(()),
        };

        let mls_bytes = ghost_wire::envelope_payload(data);
        let msg_in = MlsMessageIn::tls_deserialize_exact(mls_bytes)
            .map_err(|e| RelayError::Forbidden(format!("MLS parse: {e}")))?;

        let protocol_msg = msg_in
            .try_into_protocol_message()
            .map_err(|e| RelayError::Forbidden(format!("not a protocol message: {e}")))?;

        let processed = pg
            .process_message(&self.relay_crypto, protocol_msg)
            .map_err(|e| RelayError::Forbidden(format!("MLS validation failed: {e}")))?;

        let sender = processed.sender().clone();

        match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                if !is_commit {
                    return Err(RelayError::Forbidden("commit in non-commit envelope".into()));
                }
                self.check_commit_authorization(pg, creator_fp, &sender, &staged_commit)?;

                let mls_storage = MlsPublicStorage::new(self.storage.conn());
                pg.merge_commit(&mls_storage, *staged_commit)
                    .map_err(|e| RelayError::Forbidden(format!("merge commit: {e}")))?;

                let members = extract_member_fps(pg);
                self.storage.update_mailbox_members(mailbox_id, &members)?;
            }
            ProcessedMessageContent::ProposalMessage(proposal) => {
                let mls_storage = MlsPublicStorage::new(self.storage.conn());
                pg.add_proposal(&mls_storage, *proposal)
                    .map_err(|e| RelayError::Storage(format!("queue proposal: {e}")))?;
            }
            ProcessedMessageContent::ExternalJoinProposalMessage(proposal) => {
                let mls_storage = MlsPublicStorage::new(self.storage.conn());
                pg.add_proposal(&mls_storage, *proposal)
                    .map_err(|e| RelayError::Storage(format!("queue proposal: {e}")))?;
            }
            _ => {
                return Err(RelayError::Forbidden("unexpected MLS content type".into()));
            }
        }

        Ok(())
    }

    /// Check if account is a member of this mailbox. Skips if no ACL data exists.
    pub fn check_membership(
        &self,
        mailbox_id: &[u8; 32],
        account_fp: &[u8; 32],
    ) -> Result<(), RelayError> {
        if self.storage.has_mailbox_members(mailbox_id)?
            && !self.storage.is_mailbox_member(mailbox_id, account_fp)?
        {
            return Err(RelayError::Forbidden("not a member of this mailbox".into()));
        }
        Ok(())
    }

    /// Check if account_fp matches the group creator. Returns true if no PublicGroup exists.
    pub async fn is_creator(&self, mailbox_id: &[u8; 32], account_fp: &[u8; 32]) -> bool {
        let groups = self.groups.read().await;
        match groups.get(mailbox_id) {
            Some((_pg, creator_fp)) => *creator_fp == *account_fp,
            None => true,
        }
    }

    /// Check commit authorization rules.
    /// Add/remove require the sender to be the group creator (stored at init time).
    fn check_commit_authorization(
        &self,
        pg: &PublicGroup,
        creator_fp: &[u8; 32],
        sender: &Sender,
        staged_commit: &StagedCommit,
    ) -> Result<(), RelayError> {
        let has_adds = staged_commit.add_proposals().next().is_some();
        let has_removes = staged_commit.remove_proposals().next().is_some();

        match sender {
            Sender::Member(leaf_index) => {
                if has_adds || has_removes {
                    let sender_fp = credential_fp(pg, *leaf_index);
                    match sender_fp {
                        Some(s) if s == *creator_fp => {}
                        _ => {
                            return Err(RelayError::Forbidden(
                                "only group creator can add/remove members".into(),
                            ));
                        }
                    }
                }
            }
            Sender::NewMemberCommit => {
                // External commit (new device joining) — validated by PublicGroup
            }
            Sender::External(_) => {
                // External sender (relay) — allowed for remove proposals
            }
            _ => {
                return Err(RelayError::Forbidden("unexpected sender type".into()));
            }
        }

        Ok(())
    }

    /// Generate external remove proposals for a revoked device across all groups
    /// the account belongs to. Non-fatal: logs warnings on failure.
    pub async fn generate_removal_proposals(
        &self,
        account_fp: &[u8; 32],
        revoked_device_vk: &[u8; 32],
    ) {
        let mailbox_ids = match self.storage.mailboxes_for_account(account_fp) {
            Ok(ids) => ids,
            Err(e) => {
                tracing::warn!("removal proposals: failed to get mailboxes: {e}");
                return;
            }
        };

        let relay_signer = SignatureKeyPair::from_raw(
            SignatureScheme::ED25519,
            self.relay_sk_bytes[..32].to_vec(),
            self.relay_vk.to_vec(),
        );

        let mut groups = self.groups.write().await;
        let mut evict = Vec::new();

        for mailbox_id in mailbox_ids {
            let (pg, _creator_fp) = match groups.get_mut(&mailbox_id) {
                Some(entry) => entry,
                None => continue,
            };

            // Skip groups without ExternalSendersExtension
            if pg.group_context().extensions().external_senders().is_none() {
                continue;
            }

            // Find leaf indices matching the revoked device's signature key
            let leaves: Vec<LeafNodeIndex> = pg
                .members()
                .filter(|m| m.signature_key.as_slice() == revoked_device_vk.as_slice())
                .map(|m| m.index)
                .collect();

            let group_id = pg.group_id().clone();
            let epoch = pg.group_context().epoch();

            for leaf in leaves {
                match ExternalProposal::new_remove::<OpenMlsRustCrypto>(
                    leaf,
                    group_id.clone(),
                    epoch,
                    &relay_signer,
                    SenderExtensionIndex::new(0),
                ) {
                    Ok(proposal_out) => {
                        let mls_bytes = match proposal_out.to_bytes() {
                            Ok(b) => b,
                            Err(e) => {
                                tracing::warn!("removal proposal serialize: {e}");
                                continue;
                            }
                        };
                        let envelope = ghost_wire::encode_envelope(
                            ghost_wire::EnvelopeType::Proposal,
                            epoch.as_u64(),
                        );
                        let mut data = Vec::with_capacity(
                            ghost_wire::ENVELOPE_HEADER_SIZE + mls_bytes.len(),
                        );
                        data.extend_from_slice(&envelope);
                        data.extend_from_slice(&mls_bytes);

                        // Queue proposal in PublicGroup — only store in mailbox if successful
                        let queued = (|| -> Result<(), String> {
                            let msg_in = MlsMessageIn::tls_deserialize_exact(&mls_bytes)
                                .map_err(|e| format!("deserialize: {e}"))?;
                            let protocol_msg = msg_in.try_into_protocol_message()
                                .map_err(|e| format!("protocol: {e}"))?;
                            let processed = pg.process_message(&self.relay_crypto, protocol_msg)
                                .map_err(|e| format!("process: {e}"))?;
                            match processed.into_content() {
                                ProcessedMessageContent::ProposalMessage(proposal) => {
                                    let mls_storage = MlsPublicStorage::new(self.storage.conn());
                                    pg.add_proposal(&mls_storage, *proposal)
                                        .map_err(|e| format!("add_proposal: {e}"))?;
                                    Ok(())
                                }
                                _ => Err("unexpected content type".into()),
                            }
                        })();
                        if let Err(e) = queued {
                            tracing::warn!("removal proposal queue for {}: {e}", hex::encode(mailbox_id));
                            continue;
                        }

                        // Store in mailbox log — must stay in sync with PublicGroup
                        let et = ghost_wire::EnvelopeType::Proposal as u8;
                        match self.storage.append(
                            &mailbox_id,
                            et,
                            epoch.as_u64(),
                            &data,
                        ) {
                            Ok((seq, _, _)) => {
                                let map = self.mailboxes.read().await;
                                if let Some(mb) = map.get(&mailbox_id) {
                                    let _ = mb.seq_tx.send(seq);
                                }
                            }
                            Err(e) => {
                                // PublicGroup has the proposal queued but mailbox log
                                // doesn't — mark for eviction so it re-inits from
                                // the next GroupInfo upload.
                                tracing::warn!("removal proposal store failed, will evict PublicGroup: {e}");
                                evict.push(mailbox_id);
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("removal proposal create: {e:?}");
                    }
                }
            }
        }

        for mid in evict {
            groups.remove(&mid);
        }
    }

    /// Parse GroupInfo bytes, create/update PublicGroup, and update mailbox members.
    pub async fn init_public_group(
        &self,
        mailbox_id: &[u8; 32],
        group_info_bytes: &[u8],
    ) -> Result<(), RelayError> {
        let mls_storage = MlsPublicStorage::new(self.storage.conn());

        let msg_in = MlsMessageIn::tls_deserialize_exact(group_info_bytes)
            .map_err(|e| RelayError::BadRequest(format!("GroupInfo parse: {e}")))?;

        let vgi = match msg_in.extract() {
            MlsMessageBodyIn::GroupInfo(vgi) => vgi,
            _ => return Err(RelayError::BadRequest("expected GroupInfo message".into())),
        };

        let ratchet_tree = vgi
            .extensions()
            .ratchet_tree()
            .ok_or_else(|| RelayError::BadRequest("no ratchet tree extension in GroupInfo".into()))?
            .ratchet_tree()
            .clone();

        let (pg, _gi) = PublicGroup::from_external(
            &self.relay_crypto,
            &mls_storage,
            ratchet_tree,
            vgi,
            ProposalStore::new(),
        )
        .map_err(|e| RelayError::BadRequest(format!("PublicGroup init: {e}")))?;

        // Don't regress to a stale epoch
        let new_epoch = pg.group_context().epoch().as_u64();
        let mut groups = self.groups.write().await;
        if let Some((existing, _)) = groups.get(mailbox_id) {
            if existing.group_context().epoch().as_u64() > new_epoch {
                return Ok(());
            }
        }

        // Capture creator_fp from leaf 0 at init time (creator always starts at leaf 0).
        // Once stored, this persists even if the ratchet tree changes shape.
        let creator_fp = credential_fp(&pg, LeafNodeIndex::new(0))
            .unwrap_or(*mailbox_id); // fallback: shouldn't happen with valid groups

        let members = extract_member_fps(&pg);
        self.storage.update_mailbox_members(mailbox_id, &members)?;
        groups.insert(*mailbox_id, (pg, creator_fp));
        Ok(())
    }

}

/// Load persisted PublicGroups from storage on startup (before AppState is built).
fn load_mls_groups(storage: &Storage) -> HashMap<[u8; 32], (PublicGroup, [u8; 32])> {
    let mls_storage = MlsPublicStorage::new(storage.conn());
    let group_ids = match storage.stored_mls_group_ids() {
        Ok(ids) => ids,
        Err(e) => {
            tracing::warn!("failed to load MLS group IDs: {e}");
            return HashMap::new();
        }
    };

    let mut groups = HashMap::new();
    for serialized_gid in group_ids {
        let gid: GroupId = match serde_json::from_slice(&serialized_gid) {
            Ok(gid) => gid,
            Err(e) => {
                tracing::warn!("failed to deserialize group_id: {e}");
                continue;
            }
        };

        match PublicGroup::load(&mls_storage, &gid) {
            Ok(Some(pg)) => {
                let raw = gid.as_slice();
                if raw.len() == 32 {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(raw);
                    let creator_fp = credential_fp(&pg, LeafNodeIndex::new(0))
                        .unwrap_or(key);
                    let members = extract_member_fps(&pg);
                    if let Err(e) = storage.update_mailbox_members(&key, &members) {
                        tracing::warn!("failed to update members for loaded group: {e}");
                    }
                    groups.insert(key, (pg, creator_fp));
                }
            }
            Ok(None) => {
                tracing::warn!("no PublicGroup data for stored group_id");
            }
            Err(e) => {
                tracing::warn!("failed to load PublicGroup: {e:?}");
            }
        }
    }
    groups
}

/// Extract account fingerprints from a PublicGroup's member credentials.
/// Extract account fingerprint from a member's credential at the given leaf.
fn credential_fp(pg: &PublicGroup, leaf: LeafNodeIndex) -> Option<[u8; 32]> {
    for member in pg.members() {
        if member.index == leaf {
            if let Ok(basic) = BasicCredential::try_from(member.credential.clone()) {
                let id = basic.identity();
                if id.len() == 32 {
                    let mut fp = [0u8; 32];
                    fp.copy_from_slice(id);
                    return Some(fp);
                }
            }
        }
    }
    None
}

pub fn extract_member_fps(pg: &PublicGroup) -> Vec<[u8; 32]> {
    let mut fps = Vec::new();
    for member in pg.members() {
        if let Ok(basic) = openmls::prelude::BasicCredential::try_from(member.credential.clone()) {
            let id = basic.identity();
            if id.len() == 32 {
                let mut fp = [0u8; 32];
                fp.copy_from_slice(id);
                fps.push(fp);
            }
        }
    }
    fps
}

pub type AppState = Arc<Inner>;

pub fn new_state(config: Config, storage: Storage) -> AppState {
    let (voice_udp_port, voice_udp_port_rx) = watch::channel(0);
    let (revocation_tx, _) = broadcast::channel(16);
    let (relay_vk, relay_sk_bytes) = storage
        .get_or_create_relay_keypair()
        .expect("failed to initialize relay keypair");
    let groups = load_mls_groups(&storage);
    let (kt_frontier, kt_size) = storage
        .kt_load_frontier()
        .unwrap_or_else(|e| {
            tracing::warn!("failed to load KT frontier: {e}");
            (Vec::new(), 0)
        });
    let kt_tree = ghost_wire::merkle::MerkleTree::from_frontier(kt_frontier, kt_size);
    let recovery_limiter = RateLimiter::new(5, std::time::Duration::from_secs(15 * 60));
    Arc::new(Inner {
        mailboxes: RwLock::new(HashMap::new()),
        invites: RwLock::new(HashMap::new()),
        voice_channels: RwLock::new(HashMap::new()),
        routing: RoutingTable::new(),
        voice_udp_port,
        voice_udp_port_rx,
        config,
        start_time: Instant::now(),
        storage,
        voice_presence: RwLock::new(Vec::new()),
        online_presence: RwLock::new(Vec::new()),
        pairing: RwLock::new(HashMap::new()),
        provision: RwLock::new(HashMap::new()),
        next_conn_id: AtomicU64::new(1),
        revocation_tx,
        groups: RwLock::new(groups),
        relay_crypto: RustCrypto::default(),
        relay_vk,
        relay_sk_bytes,
        kt_tree: RwLock::new(kt_tree),
        recovery_limiter,
    })
}
