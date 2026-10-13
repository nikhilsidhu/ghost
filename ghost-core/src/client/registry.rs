//! Which groups this device holds and what they are: lookups between channels, their
//! servers, their groups' mailboxes and their members. Reads only.

use openmls::prelude::LeafNodeIndex;

use crate::error::{GhostError, Result};
use crate::mls::group::GhostGroup;
use crate::wire::{derive_default_channel_id, mls_group_mailbox_id};
use ghost_wire::short_id;

use super::GhostClient;

impl GhostClient {
    /// Get the default channel's MLS group for a server (for server-wide operations).
    pub(super) fn default_group(&self, server_id: &[u8; 32]) -> Result<&GhostGroup> {
        let ch = derive_default_channel_id(server_id);
        self.groups.get(&ch).ok_or_else(|| {
            GhostError::ServerNotLoaded(short_id(server_id))
        })
    }

    /// The channel whose MLS group carries traffic for `channel_id`: the channel itself
    /// when it has its own group (a private channel), otherwise its server's default
    /// channel, whose group all public channels share. Messages and voice keys keep the
    /// real channel id, so channels stay distinct inside the shared group.
    pub(super) fn group_channel(&self, channel_id: &[u8; 32]) -> [u8; 32] {
        if self.groups.contains(channel_id) {
            return *channel_id;
        }
        match self.provider.store().get_channel(channel_id) {
            Ok(channel) => derive_default_channel_id(&channel.server_id),
            Err(_) => *channel_id,
        }
    }

    /// A private channel is one with an MLS group of its own besides the server's.
    pub fn is_private_channel(&self, channel_id: &[u8; 32]) -> bool {
        self.groups.contains(channel_id) && self.groups.server_of(channel_id).is_some_and(|sid| derive_default_channel_id(&sid) != *channel_id)
    }

    /// Get all channel_ids belonging to a server.
    pub(super) fn server_channel_ids(&self, server_id: &[u8; 32]) -> Vec<[u8; 32]> {
        self.groups.channels_of(server_id).collect()
    }

    /// Ids of the server's channels that have an MLS group, with their mailboxes; the
    /// server's own group comes first, since its private channels are judged by it.
    pub fn server_channel_mailboxes(&self, server_id: &[u8; 32]) -> Vec<([u8; 32], [u8; 32])> {
        let default_channel = derive_default_channel_id(server_id);
        let mut mailboxes: Vec<([u8; 32], [u8; 32])> = self
            .server_channel_ids(server_id)
            .into_iter()
            .filter_map(|cid| self.groups.get(&cid).map(|g| (cid, mls_group_mailbox_id(g.group_id()))))
            .collect();
        mailboxes.sort_by_key(|(cid, _)| *cid != default_channel);
        mailboxes
    }

    /// Export GroupInfo for a server's default channel so other clients can recover via external commit.
    pub fn export_server_info(&self, server_id: &[u8; 32]) -> Result<Vec<u8>> {
        let group = self.default_group(server_id)?;
        group.export_group_info(&self.provider)
    }

    /// Export GroupInfo for one channel's MLS group, which is what that channel's
    /// mailbox must hold for external-commit joins of that channel.
    pub fn export_channel_group_info(&self, channel_id: &[u8; 32]) -> Result<Vec<u8>> {
        let group = self.groups.get(channel_id).ok_or_else(|| {
            GhostError::ServerNotLoaded(format!("channel {}", short_id(channel_id)))
        })?;
        group.export_group_info(&self.provider)
    }

    /// The leaves of one device in a channel's MLS group.
    pub fn find_device_leaves(&self, channel_id: &[u8; 32], device_vk: &[u8; 32]) -> Vec<LeafNodeIndex> {
        self.find_devices_leaves(channel_id, std::slice::from_ref(device_vk))
    }

    /// The leaves of the given devices in a channel's MLS group.
    pub fn find_devices_leaves(&self, channel_id: &[u8; 32], device_vks: &[[u8; 32]]) -> Vec<LeafNodeIndex> {
        let Some(group) = self.groups.get(channel_id) else { return vec![] };
        group
            .members()
            .filter(|m| device_vks.iter().any(|vk| m.signature_key.as_slice() == vk.as_slice()))
            .map(|m| m.index)
            .collect()
    }

    /// Get the current MLS epoch for a channel's group.
    /// The epoch of the group carrying `channel_id`.
    pub fn channel_epoch(&self, channel_id: &[u8; 32]) -> Result<u64> {
        let group = self.groups.get(&self.group_channel(channel_id)).ok_or_else(|| {
            GhostError::ServerNotLoaded(format!("channel {}", short_id(channel_id)))
        })?;
        Ok(group.epoch())
    }

    /// The group carrying `channel_id`.
    pub(super) fn group_of_channel(&self, channel_id: &[u8; 32]) -> Result<&GhostGroup> {
        self.groups.get(&self.group_channel(channel_id)).ok_or_else(|| {
            GhostError::ServerNotLoaded(format!("channel {}", short_id(channel_id)))
        })
    }

    /// Returns (channel_id, mailbox_id) for every loaded channel group.
    pub fn channel_mailboxes(&self) -> Vec<([u8; 32], [u8; 32])> {
        self.groups
            .iter()
            .map(|(cid, g)| (*cid, mls_group_mailbox_id(g.group_id())))
            .collect()
    }

    /// Returns (server_id, mailbox_id) for each server's default channel.
    /// Deduplicated by server_id — one entry per server.
    pub fn server_mailboxes(&self) -> Vec<([u8; 32], [u8; 32])> {
        let mut seen = std::collections::HashSet::new();
        let mut result = Vec::new();
        for (cid, g) in self.groups.iter() {
            if let Some(sid) = self.groups.server_of(cid) {
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
        self.groups
            .get(&ch)
            .map(|g| mls_group_mailbox_id(g.group_id()))
    }

    /// Mailbox of the group carrying a channel's traffic: its own for a private
    /// channel, its server's otherwise.
    pub fn mailbox_id_for_channel(&self, channel_id: &[u8; 32]) -> Option<[u8; 32]> {
        self.groups
            .get(&self.group_channel(channel_id))
            .map(|g| mls_group_mailbox_id(g.group_id()))
    }

    /// Reverse lookup: find channel_id for a given mailbox_id.
    pub fn channel_id_for_mailbox(&self, mailbox_id: &[u8; 32]) -> Option<[u8; 32]> {
        self.groups.channel_of_mailbox(mailbox_id)
    }

    /// Reverse lookup: find server_id for a given mailbox_id.
    pub fn server_id_for_mailbox(&self, mailbox_id: &[u8; 32]) -> Option<[u8; 32]> {
        self.groups.channel_of_mailbox(mailbox_id).and_then(|cid| self.groups.server_of(&cid))
    }

    /// The server whose own group's mailbox this is, the one its online presence goes
    /// over; `None` for a private channel's mailbox, which only some members connect to.
    pub fn server_id_for_server_mailbox(&self, mailbox_id: &[u8; 32]) -> Option<[u8; 32]> {
        let channel_id = self.groups.channel_of_mailbox(mailbox_id)?;
        let server_id = self.groups.server_of(&channel_id)?;
        (channel_id == derive_default_channel_id(&server_id)).then_some(server_id)
    }

    /// Extract fingerprints of all MLS group members from a channel's group.
    pub fn mls_member_fingerprints_for_channel(&self, channel_id: &[u8; 32]) -> Result<Vec<[u8; 32]>> {
        let group = self.groups.get(&self.group_channel(channel_id)).ok_or_else(|| {
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
}
