//! The life of a group's commits: rejoining a group this device fell out of, merging or
//! clearing a commit the relay answered, committing queued proposals, removing leaves.

use openmls::prelude::LeafNodeIndex;
use openmls_traits::OpenMlsProvider;

use crate::error::{GhostError, Result};
use crate::mls::group::GhostGroup;
use crate::wire::{mls_group_mailbox_id, Outbound};
use ghost_wire::short_id;

use super::GhostClient;

/// A channel's group as it was before a rejoin, in memory and as rows in the MLS storage.
pub(super) struct PendingRejoin {
    old: GhostGroup,
    rows: crate::crypto::provider::GroupRows,
}

impl GhostClient {
    /// Accounts whose leaves queued proposals in a channel's group would remove, so
    /// their identity logs can be fetched before the removals are judged.
    pub fn pending_removal_accounts(&self, channel_id: &[u8; 32]) -> Vec<[u8; 32]> {
        let Some(group) = self.groups.get(channel_id) else { return Vec::new() };
        group.pending_removal_accounts()
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
        let old_id = self
            .groups
            .get(channel_id)
            .map(|group| group.group_id().to_vec())
            .ok_or_else(|| GhostError::ServerNotLoaded(format!("channel {}", short_id(channel_id))))?;
        let rows = self.provider.storage().group_rows(&old_id)?;
        // The new group shares the old one's id, so writing it overwrites the old rows; a
        // build that fails leaves them as they were.
        let (old, commit_bytes, mailbox_id) = self.mls_step(&[*channel_id], |c| {
            let (new, commit_bytes) = GhostGroup::join_by_external_commit(&c.provider, &c.identity, group_info_bytes, &aad)?;
            let mailbox_id = mls_group_mailbox_id(new.group_id());
            let old = c.groups.replace(channel_id, new).expect("looked up above");
            c.record_if_server_group(channel_id)?;
            Ok((old, commit_bytes, mailbox_id))
        })?;
        self.pending_rejoins.insert(*channel_id, PendingRejoin { old, rows });
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
        self.mls_step(&[*channel_id], |c| {
            c.provider.storage().restore_group_rows(pending.old.group_id(), &pending.rows)?;
            c.groups.replace(channel_id, pending.old);
            c.record_if_server_group(channel_id)
        })
    }

    /// Remove a specific device's leaf from all channel MLS groups by its verifying key.
    /// Returns a list of (mailbox_id, commit_blob) to broadcast.
    /// One commit per channel group removing every leaf of the given devices.
    pub fn revoke_devices_leaves(&mut self, device_vks: &[[u8; 32]]) -> Vec<Outbound> {
        let channel_ids = self.groups.channel_ids();
        let mut outbound = Vec::new();
        for cid in channel_ids {
            let leaf_indices = self.find_devices_leaves(&cid, device_vks);
            if leaf_indices.is_empty() {
                continue;
            }
            if let Ok(blob) = self.remove_channel_members(&cid, &leaf_indices) {
                let mailbox_id = self.mailbox_id_for_channel(&cid).expect("the group staged the commit");
                outbound.push(Outbound { channel_id: cid, mailbox_id, blob });
            }
        }
        outbound
    }

    /// Create a remove-members commit for a specific channel's MLS group.
    pub fn remove_channel_members(
        &mut self,
        channel_id: &[u8; 32],
        members: &[LeafNodeIndex],
    ) -> Result<Vec<u8>> {
        let aad = self.commit_aad(channel_id);
        self.mls_step(&[*channel_id], |c| {
            let group = c.groups.get_mut(channel_id).ok_or_else(|| {
                GhostError::ServerNotLoaded(format!("channel {}", short_id(channel_id)))
            })?;
            group.remove_members(&c.provider, members, &aad)
        })
    }

    /// Merge a pending commit for a channel's MLS group after the relay accepted it,
    /// together with the server view it makes.
    pub fn merge_pending_commit_for_channel(&mut self, channel_id: &[u8; 32]) -> Result<()> {
        self.mls_step(&[*channel_id], |c| {
            let group = c.groups.get_mut(channel_id).ok_or_else(|| {
                GhostError::ServerNotLoaded(format!("channel {}", short_id(channel_id)))
            })?;
            group.merge_pending_commit(&c.provider)?;
            c.record_if_server_group(channel_id)
        })
    }

    /// Discard a pending commit for a channel's MLS group after the relay rejected it.
    pub fn clear_pending_commit_for_channel(&mut self, channel_id: &[u8; 32]) -> Result<()> {
        self.mls_step(&[*channel_id], |c| {
            let group = c.groups.get_mut(channel_id).ok_or_else(|| {
                GhostError::ServerNotLoaded(format!("channel {}", short_id(channel_id)))
            })?;
            group.clear_pending_commit(&c.provider)
        })
    }

    /// Commit the pending proposals of a channel's group that this device may commit
    /// (relay removals of revoked or excluded devices). `None` when there are none.
    #[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
    pub fn commit_pending_proposals(
        &mut self,
        channel_id: &[u8; 32],
    ) -> Result<Option<Outbound>> {
        let aad = self.commit_aad(channel_id);
        let excluded = self.excluded_leaves(channel_id)?;
        self.mls_step(&[*channel_id], |c| {
            let group = c.groups.get_mut(channel_id).ok_or_else(|| {
                GhostError::ServerNotLoaded(format!("channel {}", short_id(channel_id)))
            })?;
            let Some(commit) = group.commit_pending_proposals(&c.provider, &c.idlog_cache, &excluded, &aad)? else {
                return Ok(None);
            };
            Ok(Some(Outbound { channel_id: *channel_id, mailbox_id: mls_group_mailbox_id(group.group_id()), blob: commit }))
        })
    }

    /// Whether a channel's group holds queued proposals this device may yet commit, once
    /// its view of the group and server catches up.
    pub fn awaiting_proposals(&self, channel_id: &[u8; 32]) -> bool {
        self.groups.get(channel_id).is_some_and(GhostGroup::has_pending_proposals_for_others)
    }

    /// The server's groups, server and private channels, holding proposals another
    /// member's leaf is the subject of, with each group's mailbox.
    pub fn groups_awaiting_proposals(&self, server_id: &[u8; 32]) -> Vec<([u8; 32], [u8; 32])> {
        self.server_channel_ids(server_id)
            .into_iter()
            .filter(|channel_id| self.awaiting_proposals(channel_id))
            .filter_map(|channel_id| self.groups.get(&channel_id).map(|group| (channel_id, mls_group_mailbox_id(group.group_id()))))
            .collect()
    }
}
