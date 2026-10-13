//! Sealing what this device sends: chat messages, control messages, and messages sealed
//! again after the relay refused them.

use crate::crypto::MessageType;
use crate::error::{GhostError, Result};
use crate::storage::{Delivery, StoredMessage};
use crate::wire::{derive_default_channel_id, mls_group_mailbox_id, seal, ApplicationMessage, Outbound};
use ghost_wire::{now_millis, short_id};

use super::GhostClient;

impl GhostClient {
    #[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
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

        // The sending key the seal spends and the pending row land together.
        self.mls_step(&[group_channel], |c| {
            let group = c.groups.get_mut(&group_channel).ok_or_else(|| {
                GhostError::ServerNotLoaded(format!("channel {}", short_id(channel_id)))
            })?;
            let blob = seal(group, &c.provider, &msg)?;
            let mailbox_id = mls_group_mailbox_id(group.group_id());
            c.provider.store().insert_message(&StoredMessage {
                message_id: msg.message_id,
                channel_id: msg.channel_id,
                sender_fp: msg.sender_fp,
                message_type: msg.message_type as u8,
                timestamp: msg.timestamp,
                received_at: now_millis(),
                content: msg.content.clone(),
                expires_at: None,
                references: msg.references.clone(),
                delivery: Delivery::Pending,
            })?;
            Ok((Outbound { channel_id: *channel_id, mailbox_id, blob }, msg.message_id))
        })
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
        let stored = self.provider.store().get_message(message_id)?;
        if stored.sender_fp != self.identity.fingerprint {
            return Err(GhostError::PermissionDenied("not a message of this account".into()));
        }
        let server_id = self.groups.server_of(&stored.channel_id).ok_or_else(|| GhostError::ServerNotLoaded(format!("channel {}", short_id(&stored.channel_id))))?;
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
        self.mls_step(&[group_channel], |c| {
            let group = c.groups.get_mut(&group_channel).ok_or_else(|| {
                GhostError::ServerNotLoaded(format!("channel {}", short_id(&stored.channel_id)))
            })?;
            let blob = seal(group, &c.provider, &msg)?;
            Ok(Outbound { channel_id: stored.channel_id, mailbox_id: mls_group_mailbox_id(group.group_id()), blob })
        })
    }

    /// This device's messages the relay has not acknowledged, in the channels carried by
    /// `mailbox_id`'s group, oldest first.
    pub fn pending_messages_for_mailbox(&self, mailbox_id: &[u8; 32]) -> Result<Vec<StoredMessage>> {
        let Some(server_id) = self.server_id_for_mailbox(mailbox_id) else { return Ok(Vec::new()) };
        let channel_ids: Vec<[u8; 32]> = self
            .provider
            .store()
            .list_channels(&server_id)?
            .iter()
            .map(|c| c.channel_id)
            .filter(|cid| self.mailbox_id_for_channel(cid) == Some(*mailbox_id))
            .collect();
        self.provider.store().pending_messages(&channel_ids)
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
        let channel_id = *channel_id;
        let msg = ApplicationMessage::new(
            MessageType::Metadata,
            [0u8; 32],
            self.identity.fingerprint,
            now_millis(),
            [0u8; 32],
            vec![],
            content,
        )?;
        self.mls_step(&[channel_id], |c| {
            let group = c.groups.get_mut(&channel_id).ok_or_else(|| {
                GhostError::ServerNotLoaded(format!("channel {}", short_id(&channel_id)))
            })?;
            let blob = seal(group, &c.provider, &msg)?;
            Ok(Outbound { channel_id, mailbox_id: mls_group_mailbox_id(group.group_id()), blob })
        })
    }
}
