//! Public MLS group state the relay keeps per mailbox, and the storage-writer jobs that
//! change it: a commit or proposal entering a mailbox's log, a GroupInfo upload that
//! establishes a group, and the removals the relay proposes itself. Each job runs with
//! the group table locked on the writer, inside the transaction that changes the log,
//! so what the table says a group is never differs from what the log holds. A group
//! whose state could not be written is dropped from the table and comes back with the
//! next GroupInfo upload.

use ghost_wire::short_id;
use std::collections::HashMap;
use std::sync::Arc;

use openmls::messages::external_proposals::ExternalProposal;
use openmls::prelude::tls_codec::Deserialize as _;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use rusqlite::Connection;

use ghost_wire::policy::{ChannelPolicy, PolicyError, ServerView, MANAGE_CHANNELS};
use ghost_wire::policy_mls::{self, GroupFacts};
use ghost_wire::EnvelopeType;

use crate::error::RelayError;
use crate::mls_storage::MlsPublicStorage;
use crate::state::{Departure, Inner};
use crate::storage::sql;
use crate::util::now_millis;

/// Validated public state of each MLS group by mailbox, with each server group's
/// private channel groups indexed for policy enforcement and discovery.
#[derive(Default)]
pub struct GroupTable {
    groups: HashMap<[u8; 32], PublicGroup>,
    channels: HashMap<[u8; 32], Vec<[u8; 32]>>,
}

fn channel_policy_of(pg: &PublicGroup) -> Option<ChannelPolicy> {
    policy_mls::policies(pg.group_context().extensions()).ok().and_then(|(_, channel)| channel)
}

/// Accounts in the group, each once.
pub fn member_accounts(pg: &PublicGroup) -> Vec<[u8; 32]> {
    let members: Vec<Member> = pg.members().collect();
    policy_mls::member_accounts(&members)
}

impl GroupTable {
    pub fn get(&self, mailbox_id: &[u8; 32]) -> Option<&PublicGroup> {
        self.groups.get(mailbox_id)
    }

    /// Commits cannot retarget a channel to another server, so merging through this
    /// keeps the index valid.
    pub fn get_mut(&mut self, mailbox_id: &[u8; 32]) -> Option<&mut PublicGroup> {
        self.groups.get_mut(mailbox_id)
    }

    pub fn insert(&mut self, mailbox_id: [u8; 32], pg: PublicGroup) {
        self.remove(&mailbox_id);
        if let Some(channel) = channel_policy_of(&pg) {
            self.channels.entry(channel.server_mailbox).or_default().push(mailbox_id);
        }
        self.groups.insert(mailbox_id, pg);
    }

    pub fn remove(&mut self, mailbox_id: &[u8; 32]) -> Option<PublicGroup> {
        let pg = self.groups.remove(mailbox_id)?;
        if let Some(channel) = channel_policy_of(&pg) {
            if let Some(list) = self.channels.get_mut(&channel.server_mailbox) {
                list.retain(|m| m != mailbox_id);
            }
        }
        Some(pg)
    }

    /// Mailboxes of the private channel groups that belong to a server group.
    pub fn channels_of(&self, server_mailbox: &[u8; 32]) -> &[[u8; 32]] {
        self.channels.get(server_mailbox).map(Vec::as_slice).unwrap_or(&[])
    }

    /// The server group's policy and members, for judging a private channel of it.
    pub fn server_view(&self, server_mailbox: &[u8; 32]) -> Result<ServerView, PolicyError> {
        let server = self
            .groups
            .get(server_mailbox)
            .ok_or_else(|| PolicyError::Denied("the channel's server group is not on this relay".into()))?;
        let members: Vec<Member> = server.members().collect();
        policy_mls::server_view(server.group_context().extensions(), &members)
    }

    /// The account that owns a group: its server policy's owner, or for a private
    /// channel, its server's.
    pub fn owner_of(&self, mailbox_id: &[u8; 32]) -> Option<[u8; 32]> {
        let pg = self.groups.get(mailbox_id)?;
        if let Some(channel) = channel_policy_of(pg) {
            return self.server_view(&channel.server_mailbox).ok().map(|view| view.policy.owner);
        }
        let members: Vec<Member> = pg.members().collect();
        policy_mls::server_policy(pg.group_context().extensions(), &members).ok().map(|policy| policy.owner)
    }

    /// The server mailbox a private channel group belongs to, and the accounts its
    /// policy admits now.
    pub fn admitted_accounts(&self, channel_mailbox: &[u8; 32]) -> Option<([u8; 32], Vec<[u8; 32]>)> {
        let channel = channel_policy_of(self.groups.get(channel_mailbox)?)?;
        let view = self.server_view(&channel.server_mailbox).ok()?;
        let admitted = view.members.iter().filter(|account| channel.admits(account, &view)).copied().collect();
        Some((channel.server_mailbox, admitted))
    }

    /// Leaves to propose removing after a commit to `mailbox_id`: in that group if it
    /// is a private channel, or in each of its private channels if it is a server group.
    pub fn channel_exclusions(&self, mailbox_id: &[u8; 32]) -> Vec<([u8; 32], Vec<LeafNodeIndex>)> {
        let affected: Vec<[u8; 32]> = match self.groups.get(mailbox_id).and_then(channel_policy_of) {
            Some(_) => vec![*mailbox_id],
            None => self.channels_of(mailbox_id).to_vec(),
        };
        affected
            .into_iter()
            .filter_map(|channel_mailbox| {
                let pg = self.groups.get(&channel_mailbox)?;
                let channel = channel_policy_of(pg)?;
                let view = self.server_view(&channel.server_mailbox).ok()?;
                let members: Vec<Member> = pg.members().collect();
                let leaves = policy_mls::excluded_leaves(&channel, &view, &members);
                (!leaves.is_empty()).then_some((channel_mailbox, leaves))
            })
            .collect()
    }

    /// Whether the account may replace the group state from a GroupInfo: its owner, or
    /// anyone while no state exists yet (the creator's first upload, or a moved group).
    pub fn may_initialize(&self, mailbox_id: &[u8; 32], account_fp: &[u8; 32]) -> bool {
        match self.groups.get(mailbox_id) {
            Some(_) => self.owner_of(mailbox_id) == Some(*account_fp),
            None => true,
        }
    }

    /// Whether the account may delete the mailbox: the server's owner, or for a private
    /// channel, anyone who may manage the server's channels. A mailbox without group
    /// state is not found, so a deletion already done tells its retry so.
    pub fn may_delete(&self, mailbox_id: &[u8; 32], account_fp: &[u8; 32]) -> Result<(), RelayError> {
        let Some(pg) = self.groups.get(mailbox_id) else { return Err(RelayError::NotFound) };
        let allowed = match channel_policy_of(pg) {
            Some(channel) => self
                .server_view(&channel.server_mailbox)
                .is_ok_and(|view| view.members.contains(account_fp) && view.policy.has(account_fp, MANAGE_CHANNELS)),
            None => self.owner_of(mailbox_id) == Some(*account_fp),
        };
        if allowed {
            Ok(())
        } else {
            Err(RelayError::Forbidden("only the server's owner, or a channel manager for a private channel, can delete a mailbox".into()))
        }
    }

    /// Mailboxes of a server's private channel groups whose policy admits the account,
    /// which must be a member of the server group.
    pub fn admitted_channels(&self, server_mailbox: &[u8; 32], account_fp: &[u8; 32]) -> Result<Vec<[u8; 32]>, RelayError> {
        let view = self.server_view(server_mailbox).map_err(|_| RelayError::NotFound)?;
        if !view.members.contains(account_fp) {
            return Err(RelayError::Forbidden("not a member of this server".into()));
        }
        Ok(self
            .channels_of(server_mailbox)
            .iter()
            .filter(|mailbox| {
                self.groups
                    .get(*mailbox)
                    .and_then(channel_policy_of)
                    .is_some_and(|channel| channel.admits(account_fp, &view))
            })
            .copied()
            .collect())
    }
}

/// What storing a blob did, for the sender.
pub struct Stored {
    pub seq: u64,
}

/// An entry a writer job put in a mailbox's log, for its live subscribers.
pub struct NewEntry {
    pub mailbox_id: [u8; 32],
    pub seq: u64,
    pub received_at: u64,
    pub payload: Vec<u8>,
}

/// Everything a writer job changed that live connections must hear about.
#[derive(Default)]
pub struct Committed {
    /// In log order per mailbox: the blob itself and the proposals made because of it.
    pub appended: Vec<NewEntry>,
    pub departed: Vec<Departure>,
    /// Private channel groups whose admitted accounts should look for channels: just
    /// created, or admitting more accounts than before.
    pub channels_to_signal: Vec<[u8; 32]>,
}

/// What merging a commit changed beyond the group state itself.
#[derive(Default)]
struct CommitEffects {
    /// Private channel leaves the relay must now propose removing.
    exclusions: Vec<([u8; 32], Vec<LeafNodeIndex>)>,
    /// Accounts the commit removed from the group entirely.
    departed: Vec<[u8; 32]>,
    /// The commit changed a private channel group's policy, so whom it admits may
    /// have grown.
    channel_policy_changed: bool,
}

/// Parse an envelope's MLS payload into the message the public group processes.
fn protocol_message(data: &[u8]) -> Result<ProtocolMessage, RelayError> {
    let msg_in = MlsMessageIn::tls_deserialize_exact(ghost_wire::envelope_payload(data))
        .map_err(|e| RelayError::Forbidden(format!("MLS parse: {e}")))?;
    msg_in
        .try_into_protocol_message()
        .map_err(|e| RelayError::Forbidden(format!("not a protocol message: {e}")))
}

impl Inner {
    /// Store a blob in a mailbox's log and tell the mailbox's subscribers. A commit or
    /// proposal is validated against the group's public state first, and a commit that
    /// excludes accounts from private channels has the relay propose their removal.
    pub async fn store_blob(self: &Arc<Self>, mailbox_id: [u8; 32], data: Vec<u8>) -> Result<Stored, RelayError> {
        if data.len() > self.config.max_blob_size {
            return Err(RelayError::PayloadTooLarge);
        }
        let (envelope_type, epoch) =
            ghost_wire::decode_envelope(&data).map_err(|e| RelayError::BadRequest(format!("envelope: {e}")))?;
        let inner = self.clone();
        let (stored, committed) = self
            .storage
            .write(move |conn| inner.append_blob(conn, &mailbox_id, envelope_type, epoch, &data))
            .await?;
        self.announce(committed);
        Ok(stored)
    }

    /// The writer side of `store_blob`.
    fn append_blob(
        &self,
        conn: &Connection,
        mailbox_id: &[u8; 32],
        envelope_type: EnvelopeType,
        epoch: u64,
        data: &[u8],
    ) -> Result<(Stored, Committed), RelayError> {
        let is_commit = envelope_type == EnvelopeType::Commit;
        let is_proposal = envelope_type == EnvelopeType::Proposal;
        let entry_of = |appended: &crate::storage::Appended| NewEntry {
            mailbox_id: *mailbox_id,
            seq: appended.seq,
            received_at: appended.received_at,
            payload: data.to_vec(),
        };

        if !(is_commit || is_proposal) {
            let appended = sql::append(conn, mailbox_id, envelope_type as u8, epoch, data)?;
            return Ok((Stored { seq: appended.seq }, Committed { appended: vec![entry_of(&appended)], ..Committed::default() }));
        }

        if sql::sync_mailbox_owner(conn, mailbox_id)?.is_some() {
            return Err(RelayError::BadRequest("a sync mailbox carries no MLS messages".into()));
        }
        // A commit at any epoch but the mailbox's is refused before it touches the
        // group, so the sender catches up and tries again.
        let mailbox_epoch = sql::get_epoch(conn, mailbox_id)?;
        if !sql::epoch_accepted(envelope_type as u8, epoch, mailbox_epoch) {
            tracing::debug!("mailbox {}: {envelope_type:?} at epoch {epoch} refused; the mailbox is at epoch {mailbox_epoch}", short_id(mailbox_id));
            return Err(RelayError::Conflict);
        }

        let mut groups = self.groups.write().unwrap();
        // Applying the message moves the group in memory and in storage; the log entry
        // follows. If anything in between fails, storage goes back to before it, and the
        // group in memory is read back from storage to match.
        let group_id = groups.get(mailbox_id).map(|pg| pg.group_id().clone());
        conn.execute_batch("SAVEPOINT group_change").map_err(|e| RelayError::Storage(e.to_string()))?;
        let applied = self.validate_mls(conn, &mut groups, mailbox_id, data, is_commit).and_then(|effects| {
            let appended = sql::append(conn, mailbox_id, envelope_type as u8, epoch, data)?;
            sql::record_departures(conn, mailbox_id, &effects.departed, appended.seq)?;
            Ok((effects, appended))
        });
        let (effects, appended) = match applied {
            Ok(applied) => {
                conn.execute_batch("RELEASE group_change").map_err(|e| RelayError::Storage(e.to_string()))?;
                applied
            }
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK TO group_change; RELEASE group_change");
                if let Some(group_id) = group_id {
                    reload_group(conn, &mut groups, mailbox_id, &group_id);
                }
                return Err(e);
            }
        };

        let mut committed = Committed {
            appended: vec![entry_of(&appended)],
            departed: effects
                .departed
                .iter()
                .map(|account_fp| Departure { mailbox_id: *mailbox_id, account_fp: *account_fp, seq: appended.seq })
                .collect(),
            channels_to_signal: effects.channel_policy_changed.then_some(*mailbox_id).into_iter().collect(),
        };
        // Proposed after the commit is sequenced, so they target the epoch it created.
        for (channel_mailbox, leaves) in effects.exclusions {
            self.propose_removals(conn, &mut groups, &channel_mailbox, &leaves, &mut committed.appended);
        }
        Ok((Stored { seq: appended.seq }, committed))
    }

    /// Validate a commit or proposal against the group's public state and apply it:
    /// a commit is authorized under the group's policy, merged, and its membership
    /// recorded; a proposal is queued.
    fn validate_mls(
        &self,
        conn: &Connection,
        groups: &mut GroupTable,
        mailbox_id: &[u8; 32],
        data: &[u8],
        is_commit: bool,
    ) -> Result<CommitEffects, RelayError> {
        let pg = groups
            .get(mailbox_id)
            .ok_or_else(|| RelayError::Forbidden("no PublicGroup state for this mailbox".into()))?;
        let processed = pg
            .process_message(&self.relay_crypto, protocol_message(data)?)
            .map_err(|e| RelayError::Forbidden(format!("MLS validation failed: {e}")))?;
        let sender = processed.sender().clone();
        let aad = processed.aad().to_vec();

        let proposal = match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                if !is_commit {
                    return Err(RelayError::Forbidden("commit in non-commit envelope".into()));
                }
                if !self.config.skip_policy_checks_for_tests {
                    self.authorize_commit(groups, mailbox_id, &sender, &staged_commit, &aad)?;
                }
                return Self::merge_commit(conn, groups, mailbox_id, *staged_commit);
            }
            ProcessedMessageContent::ProposalMessage(proposal) => *proposal,
            ProcessedMessageContent::ExternalJoinProposalMessage(proposal) => *proposal,
            _ => return Err(RelayError::Forbidden("unexpected MLS content type".into())),
        };
        let pg = groups.get_mut(mailbox_id).expect("looked up above");
        if let Err(e) = pg.add_proposal(&MlsPublicStorage::new(conn), proposal) {
            groups.remove(mailbox_id);
            return Err(RelayError::Storage(format!("queue proposal: {e}")));
        }
        Ok(CommitEffects::default())
    }

    /// Merge an authorized commit into the group and record its membership. A write
    /// that fails drops the group from the table, since its state is no longer known.
    fn merge_commit(
        conn: &Connection,
        groups: &mut GroupTable,
        mailbox_id: &[u8; 32],
        staged_commit: StagedCommit,
    ) -> Result<CommitEffects, RelayError> {
        let policy_before = groups.get(mailbox_id).and_then(channel_policy_of);
        let pg = groups.get_mut(mailbox_id).expect("looked up above");
        let before = member_accounts(pg);
        let merged = pg
            .merge_commit(&MlsPublicStorage::new(conn), staged_commit)
            .map_err(|e| RelayError::Storage(format!("merge commit: {e}")))
            .and_then(|()| {
                let members = member_accounts(pg);
                sql::update_mailbox_members(conn, mailbox_id, &members).map(|()| members)
            });
        let members = match merged {
            Ok(members) => members,
            Err(e) => {
                groups.remove(mailbox_id);
                return Err(e);
            }
        };
        let departed = before.into_iter().filter(|fp| !members.contains(fp)).collect();
        let policy_after = groups.get(mailbox_id).and_then(channel_policy_of);
        Ok(CommitEffects {
            exclusions: groups.channel_exclusions(mailbox_id),
            departed,
            channel_policy_changed: policy_before.is_some() && policy_before != policy_after,
        })
    }

    /// Decide a commit under the group's policy, with the same rules every member's
    /// device applies. A private channel commit must be authorized against the server
    /// group's current epoch, so a role removed there cannot still be used.
    fn authorize_commit(
        &self,
        groups: &GroupTable,
        mailbox_id: &[u8; 32],
        sender: &Sender,
        staged_commit: &StagedCommit,
        aad: &[u8],
    ) -> Result<(), RelayError> {
        let pg = groups.get(mailbox_id).expect("caller looked it up");
        let members: Vec<Member> = pg.members().collect();
        let facts = GroupFacts {
            extensions: pg.group_context().extensions(),
            members: &members,
            mailbox: *mailbox_id,
            now_millis: now_millis(),
        };
        let server_at = |server_mailbox: &[u8; 32], epoch: u64| {
            let current = groups.get(server_mailbox).map(|server| server.group_context().epoch().as_u64());
            match current {
                Some(current) if current != epoch => {
                    Err(PolicyError::ContextBehind { server_mailbox: *server_mailbox, epoch: current })
                }
                _ => groups.server_view(server_mailbox),
            }
        };
        policy_mls::check_commit(sender, staged_commit, aad, &facts, &server_at).map_err(|e| match e {
            // The committer judged against a stale server policy: it must catch up and retry.
            PolicyError::ContextBehind { .. } => RelayError::Conflict,
            PolicyError::Removed => RelayError::Removed,
            other => RelayError::Forbidden(other.to_string()),
        })
    }

    /// Propose removing leaves from a group as its external sender, skipping leaves a
    /// queued proposal already removes. Each proposal is queued in the public group and
    /// appended to the mailbox's log as one change: one that fails is rolled back and the
    /// group read back from storage, and the rest are still proposed. Non-fatal: logs
    /// warnings on failure.
    fn propose_removals(
        &self,
        conn: &Connection,
        groups: &mut GroupTable,
        mailbox_id: &[u8; 32],
        leaves: &[LeafNodeIndex],
        appended: &mut Vec<NewEntry>,
    ) {
        let Some(pg) = groups.get_mut(mailbox_id) else { return };
        if pg.group_context().extensions().external_senders().is_none() {
            return;
        }
        let mls_storage = MlsPublicStorage::new(conn);
        let pending: Vec<LeafNodeIndex> = match pg.queued_proposals(&mls_storage) {
            Ok(queued) => queued
                .iter()
                .filter_map(|(_, qp)| match qp.proposal() {
                    Proposal::Remove(remove) => Some(remove.removed()),
                    _ => None,
                })
                .collect(),
            Err(e) => {
                tracing::warn!("removal proposals: read queue for {}: {e:?}", hex::encode(mailbox_id));
                Vec::new()
            }
        };

        let relay_signer = SignatureKeyPair::from_raw(
            SignatureScheme::ED25519,
            self.relay_sk_bytes[..32].to_vec(),
            self.relay_vk.to_vec(),
        );
        let group_id = pg.group_id().clone();
        let epoch = pg.group_context().epoch();

        for leaf in leaves.iter().copied().filter(|leaf| !pending.contains(leaf)) {
            let proposal_out = match ExternalProposal::new_remove::<OpenMlsRustCrypto>(
                leaf,
                group_id.clone(),
                epoch,
                &relay_signer,
                SenderExtensionIndex::new(0),
            ) {
                Ok(proposal_out) => proposal_out,
                Err(e) => {
                    tracing::warn!("removal proposal create: {e:?}");
                    continue;
                }
            };
            let mls_bytes = match proposal_out.to_bytes() {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!("removal proposal serialize: {e}");
                    continue;
                }
            };
            let mut data = ghost_wire::encode_envelope(EnvelopeType::Proposal, epoch.as_u64()).to_vec();
            data.extend_from_slice(&mls_bytes);

            // Queued in the group, then stored in the log, as one change.
            let Some(pg) = groups.get_mut(mailbox_id) else { return };
            if let Err(e) = conn.execute_batch("SAVEPOINT relay_proposal") {
                tracing::warn!("removal proposal for {}: {e}", hex::encode(mailbox_id));
                return;
            }
            let stored = protocol_message(&data)
                .and_then(|msg| pg.process_message(&self.relay_crypto, msg).map_err(|e| RelayError::Forbidden(format!("process: {e}"))))
                .and_then(|processed| match processed.into_content() {
                    ProcessedMessageContent::ProposalMessage(proposal) => pg
                        .add_proposal(&mls_storage, *proposal)
                        .map_err(|e| RelayError::Storage(format!("add_proposal: {e}"))),
                    _ => Err(RelayError::Forbidden("unexpected content type".into())),
                })
                .and_then(|()| sql::append(conn, mailbox_id, EnvelopeType::Proposal as u8, epoch.as_u64(), &data));
            match stored {
                Ok(entry) => {
                    let _ = conn.execute_batch("RELEASE relay_proposal");
                    appended.push(NewEntry { mailbox_id: *mailbox_id, seq: entry.seq, received_at: entry.received_at, payload: data });
                }
                Err(e) => {
                    tracing::warn!("removal proposal for {} not stored: {e}", hex::encode(mailbox_id));
                    let _ = conn.execute_batch("ROLLBACK TO relay_proposal; RELEASE relay_proposal");
                    reload_group(conn, groups, mailbox_id, &group_id);
                }
            }
        }
    }

    /// Verify a GroupInfo (signature by a leaf of its own tree, tree hash against its
    /// context) and build the public group it describes, persisting into `storage`.
    fn public_group_from_info<S>(&self, storage: &S, group_info_bytes: &[u8]) -> Result<PublicGroup, RelayError>
    where
        S: openmls_traits::public_storage::PublicStorageProvider<{ openmls_traits::storage::CURRENT_VERSION }>,
    {
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
        let (pg, _gi) = PublicGroup::from_external(&self.relay_crypto, storage, ratchet_tree, vgi, ProposalStore::new())
            .map_err(|e| RelayError::BadRequest(format!("PublicGroup init: {e}")))?;
        Ok(pg)
    }

    /// Whether a GroupInfo faithfully describes the group state this relay already
    /// validated: signed by a member and carrying exactly the current group context.
    /// Lets any member refresh the published GroupInfo after a commit without being
    /// able to change what the relay believes the group is.
    pub fn group_info_matches_state(&self, mailbox_id: &[u8; 32], group_info_bytes: &[u8]) -> Result<bool, RelayError> {
        let scratch = openmls_rust_crypto::MemoryStorage::default();
        let pg = self.public_group_from_info(&scratch, group_info_bytes)?;
        let groups = self.groups.read().unwrap();
        Ok(groups
            .get(mailbox_id)
            .is_some_and(|existing| existing.group_context() == pg.group_context()))
    }

    /// Build the group state from an uploaded GroupInfo. Refuses (`Forbidden`) a group
    /// with malformed policies, or a private channel group uploaded by someone who may
    /// not manage the server's channels: creating one is how a channel comes to exist.
    /// Returns false, leaving the state alone, when the relay holds a later epoch.
    pub async fn init_public_group(
        self: &Arc<Self>,
        mailbox_id: [u8; 32],
        group_info_bytes: Vec<u8>,
        uploader: [u8; 32],
    ) -> Result<bool, RelayError> {
        let inner = self.clone();
        let initialized = self
            .storage
            .write(move |conn| inner.init_public_group_on(conn, &mailbox_id, &group_info_bytes, &uploader))
            .await?;
        if let Some(committed) = initialized {
            self.announce(committed);
            return Ok(true);
        }
        Ok(false)
    }

    /// The writer side of `init_public_group`: `None` when a later epoch is held.
    fn init_public_group_on(
        &self,
        conn: &Connection,
        mailbox_id: &[u8; 32],
        group_info_bytes: &[u8],
        uploader: &[u8; 32],
    ) -> Result<Option<Committed>, RelayError> {
        let mut groups = self.groups.write().unwrap();
        // Built straight into the store, under a savepoint of its own: a refused or
        // stale upload must not leave its components in place of the held group's.
        conn.execute_batch("SAVEPOINT group_info").map_err(|e| RelayError::Storage(e.to_string()))?;
        let built = self.build_public_group(conn, &groups, mailbox_id, group_info_bytes, uploader);
        let keep = matches!(built, Ok(Some(_)));
        conn.execute_batch(if keep { "RELEASE group_info" } else { "ROLLBACK TO group_info; RELEASE group_info" })
            .map_err(|e| RelayError::Storage(e.to_string()))?;
        let Some(pg) = built? else { return Ok(None) };

        let is_channel = channel_policy_of(&pg).is_some();
        groups.insert(*mailbox_id, pg);
        Ok(Some(Committed {
            channels_to_signal: is_channel.then_some(*mailbox_id).into_iter().collect(),
            ..Committed::default()
        }))
    }

    /// Check an uploaded GroupInfo and write the group it describes, with its
    /// membership and the epoch its next commit must carry. `None` for a stale upload.
    fn build_public_group(
        &self,
        conn: &Connection,
        groups: &GroupTable,
        mailbox_id: &[u8; 32],
        group_info_bytes: &[u8],
        uploader: &[u8; 32],
    ) -> Result<Option<PublicGroup>, RelayError> {
        let pg = self.public_group_from_info(&MlsPublicStorage::new(conn), group_info_bytes)?;
        let policies = policy_mls::policies(pg.group_context().extensions())
            .map_err(|e| RelayError::Forbidden(format!("group policy: {e}")))?;
        match policies {
            (Some(_), Some(_)) => {
                return Err(RelayError::Forbidden("a group carries a server or a channel policy, not both".into()));
            }
            (None, Some(channel)) => {
                let view = groups.server_view(&channel.server_mailbox).map_err(|e| RelayError::Forbidden(e.to_string()))?;
                if !view.members.contains(uploader) || !view.policy.has(uploader, MANAGE_CHANNELS) {
                    return Err(RelayError::Forbidden("creating a private channel needs the manage channels permission".into()));
                }
            }
            _ => {}
        }

        let new_epoch = pg.group_context().epoch().as_u64();
        if groups.get(mailbox_id).is_some_and(|existing| existing.group_context().epoch().as_u64() > new_epoch) {
            return Ok(None);
        }

        let group_id_bytes =
            serde_json::to_vec(pg.group_id()).map_err(|e| RelayError::BadRequest(format!("serialize group_id: {e}")))?;
        sql::set_mailbox_group_id(conn, mailbox_id, &group_id_bytes)?;
        sql::update_mailbox_members(conn, mailbox_id, &member_accounts(&pg))?;
        // The next commit must be at the group's epoch, even if this relay never saw
        // the earlier ones (the group moved here).
        sql::raise_mailbox_epoch(conn, mailbox_id, new_epoch)?;
        Ok(Some(pg))
    }

    /// Delete all state for a mailbox: its log, group state, membership and avatars.
    pub async fn delete_mailbox(self: &Arc<Self>, mailbox_id: [u8; 32]) -> Result<(), RelayError> {
        let inner = self.clone();
        self.storage
            .write(move |conn| {
                let mut groups = inner.groups.write().unwrap();
                sql::delete_mailbox(conn, &mailbox_id)?;
                groups.remove(&mailbox_id);
                Ok(())
            })
            .await?;
        self.mailboxes.write().unwrap().remove(&mailbox_id);
        Ok(())
    }

    /// Act on what a log change did to the account's devices here: close the sessions
    /// and propose MLS removals of every device it revoked, and when the account's home
    /// moved away, admit its devices' live connections again.
    pub async fn apply_log_change(self: &Arc<Self>, account_fp: &[u8; 32], change: &crate::storage::IdlogChange) {
        for device_vk in &change.revoked {
            let _ = self.revocation_tx.send((*account_fp, *device_vk));
        }
        if change.left_home {
            let _ = self.readmission_tx.send(*account_fp);
        }
        for device_vk in &change.revoked {
            self.propose_device_removal(*account_fp, *device_vk).await;
        }
    }

    /// Propose removing a revoked device's leaves from every group its account belongs
    /// to. Non-fatal: logs warnings on failure.
    async fn propose_device_removal(self: &Arc<Self>, account_fp: [u8; 32], device_vk: [u8; 32]) {
        let inner = self.clone();
        let proposed = self
            .storage
            .write(move |conn| {
                let mut appended = Vec::new();
                let mut groups = inner.groups.write().unwrap();
                for mailbox_id in sql::mailboxes_for_account(conn, &account_fp)? {
                    let Some(pg) = groups.get(&mailbox_id) else { continue };
                    let leaves: Vec<LeafNodeIndex> = pg
                        .members()
                        .filter(|m| m.signature_key.as_slice() == device_vk.as_slice())
                        .map(|m| m.index)
                        .collect();
                    inner.propose_removals(conn, &mut groups, &mailbox_id, &leaves, &mut appended);
                }
                Ok(appended)
            })
            .await;
        match proposed {
            Ok(appended) => self.announce(Committed { appended, ..Committed::default() }),
            Err(e) => tracing::warn!("removal proposals for a revoked device: {e}"),
        }
    }
}

/// The public groups the store holds, with each one's membership refreshed, for the
/// table a relay starts with.
/// Read a group back from storage into memory, after a change to it was rolled back; one
/// that does not load is dropped, for the next GroupInfo upload to establish.
fn reload_group(conn: &Connection, groups: &mut GroupTable, mailbox_id: &[u8; 32], group_id: &GroupId) {
    match PublicGroup::load(&MlsPublicStorage::new(conn), group_id) {
        Ok(Some(pg)) => groups.insert(*mailbox_id, pg),
        loaded => {
            tracing::warn!("mailbox {}: group state not read back after a failed write ({loaded:?}); dropped", short_id(mailbox_id));
            groups.remove(mailbox_id);
        }
    }
}

pub fn load_groups(conn: &Connection) -> Result<GroupTable, RelayError> {
    let mls_storage = MlsPublicStorage::new(conn);
    let mut groups = GroupTable::default();
    for serialized_gid in sql::stored_mls_group_ids(conn)? {
        let gid: GroupId = match serde_json::from_slice(&serialized_gid) {
            Ok(gid) => gid,
            Err(e) => {
                tracing::warn!("stored group id does not parse: {e}");
                continue;
            }
        };
        let pg = match PublicGroup::load(&mls_storage, &gid) {
            Ok(Some(pg)) => pg,
            Ok(None) => {
                tracing::warn!("no PublicGroup data for stored group id");
                continue;
            }
            Err(e) => {
                tracing::warn!("stored PublicGroup does not load: {e:?}");
                continue;
            }
        };
        let raw = gid.as_slice();
        if raw.len() != 32 {
            continue;
        }
        let mailbox_id = ghost_wire::mls_group_mailbox_id(raw);
        sql::update_mailbox_members(conn, &mailbox_id, &member_accounts(&pg))?;
        groups.insert(mailbox_id, pg);
    }
    Ok(groups)
}
