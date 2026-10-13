//! Opening what arrives in a channel's group and keeping it: messages, commits, and the
//! metadata applied in the same write that spends the message's key.

use crate::crypto::constants::{HISTORY_GAP_ID_TAG, UNDECRYPTABLE_ID_TAG};
use crate::crypto::MessageType;
use crate::error::{GhostError, Result};
use crate::idlog_cache::CredentialClaim;
use crate::mls::group::GhostGroup;
use crate::mls::presence::AvatarRef;
use crate::storage::{Delivery, StoredMessage};
use crate::wire::{decode_metadata, derive_default_channel_id, mls_group_mailbox_id, open, open_any, ApplicationMessage, CommitChecks, InboundMessage, MetadataPayload, Outbound};
use ghost_wire::server_location::ServerLocation;
use ghost_wire::{now_millis, short_id};

use super::{ChannelOpOutcome, GhostClient, ServerStateOutcome};

pub enum ReceiveResult {
    /// A chat message from a checked device, already stored. Its `kt_head_hash` is the
    /// sender's view of its own log head, for the caller to judge with
    /// [`GhostClient::judge_head`].
    Message(ApplicationMessage),
    /// A metadata message from a checked device, already applied.
    Metadata(MetadataApplied),
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

/// What a metadata message leaves for the caller beyond the database, once applied and
/// its blob marked seen in the write that spent its key.
pub struct MetadataApplied {
    pub sender: [u8; 32],
    /// A channel op took effect here.
    pub channel_changed: bool,
    /// An answer to send: a private channel's name, or the server's state.
    pub reply: Option<Outbound>,
    /// The server's state came stale: ask for it again.
    pub ask_state_again: bool,
    /// The sender's new avatar, to fetch.
    pub fetch_avatar: Option<[u8; 32]>,
    /// The sender took its avatar down: its cached image goes.
    pub avatar_cleared: bool,
    /// Another device of this account renamed it.
    pub own_name: Option<String>,
    /// Another device of this account changed its avatar: `Some(None)` took it down.
    pub own_avatar: Option<Option<AvatarRef>>,
    /// The server's owner moved it: the record to follow.
    pub server_move: Option<ServerLocation>,
}

/// Where a blob sits in its mailbox's log. A message stored from it marks it seen in the
/// same write, so a restart never replays a blob whose key decrypting it spent.
#[derive(Debug, Clone, Copy)]
pub struct BlobOrigin {
    pub mailbox_id: [u8; 32],
    pub seq: u64,
}

impl GhostClient {
    /// Decrypt a blob and store the message. Uses relay-stamped arrival time if
    /// provided, otherwise falls back to local clock.
    #[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
    pub fn receive_blob(
        &mut self,
        channel_id: &[u8; 32],
        blob: &[u8],
        received_at: Option<u64>,
    ) -> Result<ApplicationMessage> {
        // The key the open spends and the stored message land together.
        self.mls_step(&[*channel_id], |c| {
            let cache = &c.idlog_cache;
            let devices = |claim: &CredentialClaim| cache.status(claim);
            let group = c.groups.get_mut(channel_id).ok_or_else(|| {
                GhostError::ServerNotLoaded(format!("channel {}", short_id(channel_id)))
            })?;
            let msg = open(group, &c.provider, blob, &devices)?;
            c.provider.store().insert_message(&StoredMessage {
                message_id: msg.message_id,
                channel_id: msg.channel_id,
                sender_fp: msg.sender_fp,
                message_type: msg.message_type as u8,
                timestamp: msg.timestamp,
                received_at: received_at.unwrap_or_else(now_millis),
                content: msg.content.clone(),
                expires_at: None,
                references: msg.references.clone(),
                delivery: Delivery::Delivered,
            })?;
            Ok(msg)
        })
    }

    /// Process an inbound blob — could be an app message, a commit, or a self-message.
    /// Takes channel_id to identify which MLS group to decrypt with.
    #[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
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
        let current_epoch = self.groups.get(channel_id).map(GhostGroup::epoch);
        if envelope_type == ghost_wire::EnvelopeType::Commit && current_epoch.is_some_and(|e| envelope_epoch < e) {
            return Ok(ReceiveResult::Skipped);
        }
        // Opening the blob spends its key or merges its commit, and what it carried is
        // kept: one write, or none if it fails or the process ends meanwhile.
        self.mls_step(&[*channel_id], |c| c.open_and_keep(channel_id, blob, (envelope_type, envelope_epoch), current_epoch, received_at, origin))
    }

    /// The step of `receive_from` that opens the blob and keeps what it carried.
    fn open_and_keep(
        &mut self,
        channel_id: &[u8; 32],
        blob: &[u8],
        (envelope_type, envelope_epoch): (ghost_wire::EnvelopeType, u64),
        current_epoch: Option<u64>,
        received_at: Option<u64>,
        origin: Option<BlobOrigin>,
    ) -> Result<ReceiveResult> {
        // Taken out while it is processed, so a private channel's commit can be judged
        // against its server group's state.
        let mut group = self.groups.take(channel_id).ok_or_else(|| {
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
        self.groups.replace(channel_id, group);

        let inbound = match opened {
            Err(GhostError::SelfMessage) => return Ok(ReceiveResult::Skipped),
            // Sent at an epoch before this device's: never readable here, and no sign the
            // group is out of step now. One from before this device joined was not for it.
            Err(GhostError::Mls(_))
                if envelope_type == ghost_wire::EnvelopeType::Application && current_epoch.is_some_and(|e| envelope_epoch < e) =>
            {
                let joined = self.provider.store().joined_epoch(channel_id)?;
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
            InboundMessage::Application(msg) if msg.message_type == MessageType::Metadata => {
                Ok(ReceiveResult::Metadata(self.apply_metadata(channel_id, &msg, origin.as_ref())?))
            }
            InboundMessage::Application(msg) => self.store_received(msg, received_at, origin),
            InboundMessage::Commit { removed, committer } => {
                self.record_if_server_group(channel_id)?;
                let group = self.groups.get(channel_id).ok_or_else(|| {
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

    /// Store a chat message from a device this client checked against its identity log.
    fn store_received(&mut self, msg: ApplicationMessage, received_at: u64, origin: Option<BlobOrigin>) -> Result<ReceiveResult> {
        let seen = origin.as_ref().map(|o| (&o.mailbox_id, o.seq));
        self.provider.store().insert_message_seen(&StoredMessage {
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
        Ok(ReceiveResult::Message(msg))
    }

    /// Apply a metadata message from a checked device, carried by `group_channel`'s
    /// group, and mark its blob seen. What a sender may not do, or does not fit where it
    /// arrived, is ignored; a kind from a newer app changes nothing here. A server change
    /// and a state answer need the blob's place in its mailbox, `origin`.
    fn apply_metadata(&mut self, group_channel: &[u8; 32], msg: &ApplicationMessage, origin: Option<&BlobOrigin>) -> Result<MetadataApplied> {
        let server_id = self.groups.server_of(group_channel).ok_or_else(|| GhostError::ServerNotLoaded(format!("channel {}", short_id(group_channel))))?;
        let in_server_group = *group_channel == derive_default_channel_id(&server_id);
        let seq = origin.map(|o| o.seq);
        let sender = msg.sender_fp;
        let own = sender == self.identity.fingerprint;
        let mut applied = MetadataApplied {
            sender,
            channel_changed: false,
            reply: None,
            ask_state_again: false,
            fetch_avatar: None,
            avatar_cleared: false,
            own_name: None,
            own_avatar: None,
            server_move: None,
        };
        match decode_metadata(&msg.content) {
            Ok(MetadataPayload::ChannelOp(op)) => match self.apply_channel_op(group_channel, &sender, op) {
                Ok(ChannelOpOutcome::Reply(out)) => applied.reply = Some(out),
                Ok(ChannelOpOutcome::Applied) => {
                    applied.channel_changed = true;
                    // A server state as of before this change would undo it.
                    if let (true, Some(seq)) = (in_server_group, seq) {
                        self.provider.store().note_server_change(&server_id, seq)?;
                    }
                }
                Ok(ChannelOpOutcome::Ignored) => {}
                Err(e) => tracing::warn!("channel op: {e}"),
            },
            Ok(MetadataPayload::RoleNames(names)) => match self.apply_role_names(&server_id, &sender, &names) {
                Ok(true) => {
                    if let Some(seq) = seq {
                        self.provider.store().note_server_change(&server_id, seq)?;
                    }
                }
                Ok(false) => {}
                Err(e) => tracing::warn!("role names: {e}"),
            },
            // A joiner asks; a member who may manage channels answers, as of the request.
            Ok(MetadataPayload::ServerStateRequest) => {
                if let (true, Some(seq)) = (in_server_group, seq) {
                    match self.server_state_reply(&server_id, seq) {
                        Ok(answer) => applied.reply = answer,
                        Err(e) => tracing::warn!("server state not answered: {e}"),
                    }
                }
            }
            Ok(MetadataPayload::ServerState(state)) if in_server_group => match self.apply_server_state(&server_id, &sender, state) {
                Ok(ServerStateOutcome::Stale) => applied.ask_state_again = true,
                Ok(_) => {}
                Err(e) => tracing::warn!("server state not taken in: {e}"),
            },
            Ok(MetadataPayload::ServerState(_)) => {}
            Ok(MetadataPayload::MemberAnnounce { display_name }) => {
                self.provider.store().update_member_name(&server_id, &sender, &display_name)?;
                if own {
                    applied.own_name = Some(display_name);
                }
            }
            Ok(MetadataPayload::AvatarUpdate { avatar_hash, avatar_key }) => {
                self.provider.store().update_member_avatar(&server_id, &sender, &avatar_hash, &avatar_key)?;
                applied.fetch_avatar = Some(avatar_hash);
                if own {
                    applied.own_avatar = Some(Some(AvatarRef { hash: avatar_hash, key: avatar_key }));
                }
            }
            Ok(MetadataPayload::AvatarClear) => {
                self.provider.store().clear_member_avatar(&server_id, &sender)?;
                applied.avatar_cleared = true;
                if own {
                    applied.own_avatar = Some(None);
                }
            }
            // Only the owner may move a server; the record is verified when followed.
            Ok(MetadataPayload::ServerMoved(location)) => {
                if self.server_owner(&server_id).is_ok_and(|owner| owner == sender) {
                    applied.server_move = Some(location);
                }
            }
            Err(e) => tracing::warn!("decode metadata: {e}"),
        }
        if let Some(origin) = origin {
            self.provider.store().set_last_seen_seq(&origin.mailbox_id, origin.seq)?;
        }
        Ok(applied)
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
        self.provider.store().insert_message(&StoredMessage {
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
}
