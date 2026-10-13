//! A server's policy and the views of its group recorded as it changes: who may do what,
//! and the authenticated data every commit carries.

use crate::error::{GhostError, Result};
use crate::mls::group::GhostGroup;
use crate::wire::{derive_default_channel_id, mls_group_mailbox_id};
use ghost_wire::policy::{CommitAad, PolicyError, ServerPolicy, ServerView};
use ghost_wire::policy_mls;

use super::GhostClient;

impl GhostClient {
    /// Authenticated data for a commit to a channel's group. A private channel's
    /// commits name the server group epoch they were authorized against: the relay
    /// requires it to be current, and members judge the commit by that epoch's policy.
    pub(super) fn commit_aad(&self, channel_id: &[u8; 32]) -> CommitAad {
        if !self.is_private_channel(channel_id) {
            return CommitAad::default();
        }
        let server_epoch = self.groups.server_of(channel_id).and_then(|server_id| self.default_group(&server_id).ok()).map(GhostGroup::epoch);
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
    pub(super) fn server_view_at(&self, server_mailbox: &[u8; 32], epoch: u64) -> std::result::Result<ServerView, PolicyError> {
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
        self.provider.store()
            .server_view_at(&server_id, epoch)
            .map_err(|e| PolicyError::Denied(e.to_string()))?
            .ok_or_else(|| denied("no record of the server group at that epoch"))
    }

    /// Record the server group's current view for judging later private channel
    /// commits. Called after anything that changes the server group's epoch.
    pub(super) fn record_server_view(&self, server_id: &[u8; 32]) -> Result<()> {
        let group = self.default_group(server_id)?;
        let members: Vec<openmls::prelude::Member> = group.members().collect();
        let view = policy_mls::server_view(group.context_extensions(), &members)
            .map_err(|e| GhostError::Format(format!("server policy: {e}")))?;
        self.provider.store().record_server_view(server_id, group.epoch(), &view)
    }

    /// Record the server view if `channel_id` is a server's default channel.
    pub(super) fn record_if_server_group(&self, channel_id: &[u8; 32]) -> Result<()> {
        match self.groups.server_of(channel_id) {
            Some(server_id) if derive_default_channel_id(&server_id) == *channel_id => self.record_server_view(&server_id),
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

    /// The policy of a private channel, or `None` for a public one.
    pub fn channel_policy(&self, channel_id: &[u8; 32]) -> Result<Option<ghost_wire::policy::ChannelPolicy>> {
        match self.groups.get(channel_id) {
            Some(group) if self.is_private_channel(channel_id) => group.channel_policy(),
            _ => Ok(None),
        }
    }
}
