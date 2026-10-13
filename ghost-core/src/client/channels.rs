//! Private channels, each with a group of its own, and the channel operations announced
//! in metadata messages.

use openmls::prelude::LeafNodeIndex;

use crate::error::{GhostError, Result};
use crate::mls::group::GhostGroup;
use crate::storage::{Channel, ChannelKind, OnConflict};
use crate::wire::{mls_group_mailbox_id, Outbound};
use ghost_wire::policy::CommitAad;
use ghost_wire::policy_mls;
use ghost_wire::short_id;

use super::GhostClient;

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

impl GhostClient {
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
            .provider
            .store()
            .server_relay(server_id)?
            .or(self.relay_vk)
            .ok_or_else(|| GhostError::Network("the server's relay key is not known yet; connect to it first".into()))?;

        let mut channel_id = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut channel_id);
        let policy = ChannelPolicy { server_mailbox, channel_id, roles, accounts };
        // The group, its row and the sealed announcement land together, or none of them.
        self.mls_step(&[channel_id], |c| {
            let group = GhostGroup::create(
                &c.provider,
                &c.identity,
                server_id,
                &channel_id,
                Some(&relay_vk),
                Some(GhostExtension::Channel(policy)),
            )?;
            let group_info = group.export_group_info(&c.provider)?;
            let mailbox_id = mls_group_mailbox_id(group.group_id());

            c.provider.store().insert_channel(&Channel { channel_id, server_id: *server_id, name: name.to_string(), kind, position }, OnConflict::Fail)?;
            c.groups.insert(channel_id, *server_id, group);

            let op = crate::wire::ChannelOpPayload::Create { channel_id, name: name.to_string(), kind, position };
            let announcement = c.send_control_in(&channel_id, crate::wire::encode_channel_op(&op))?;
            Ok(NewPrivateChannel { channel_id, mailbox_id, group_info, announcement })
        })
    }

    /// Join a private channel the relay listed: stage an external commit, then check
    /// that the group belongs to this server (its id derives from the server id, which
    /// the relay never learns) and admits this account before letting the commit go.
    /// Returns (channel_id, mailbox_id, commit). The channel is unnamed until a member
    /// answers the info request this device sends once the relay accepts the commit;
    /// if the relay refuses it, call `drop_private_channel`.
    #[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
    pub fn join_private_channel(&mut self, server_id: &[u8; 32], group_info: &[u8]) -> Result<([u8; 32], [u8; 32], Vec<u8>)> {
        let server_epoch = self.default_group(server_id)?.epoch();
        let aad = CommitAad { invite: None, server_epoch: Some(server_epoch) };
        // A group refused below, or rows not kept, leave nothing behind: the step rolls
        // the staged group's rows back. The channel is in no map until the end.
        self.mls_step(&[], |c| {
            let (group, commit) = GhostGroup::join_by_external_commit(&c.provider, &c.identity, group_info, &aad)?;
            let refuse = |why: &str| Err(GhostError::PermissionDenied(format!("not joining listed channel: {why}")));
            let Some(policy) = group.channel_policy()? else {
                return refuse("it is not a private channel");
            };
            if group.group_id() != crate::wire::derive_mls_group_id(server_id, &policy.channel_id) {
                return refuse("its group does not belong to this server");
            }
            let server_group = c.default_group(server_id)?;
            if mls_group_mailbox_id(server_group.group_id()) != policy.server_mailbox {
                return refuse("it names another server");
            }
            let members: Vec<openmls::prelude::Member> = server_group.members().collect();
            let view = policy_mls::server_view(server_group.context_extensions(), &members)
                .map_err(|e| GhostError::Format(format!("server policy: {e}")))?;
            if !policy.admits(&c.identity.fingerprint, &view) {
                return refuse("its policy does not admit this account");
            }

            let channel_id = policy.channel_id;
            let mailbox_id = mls_group_mailbox_id(group.group_id());
            c.provider.store().insert_channel(&Channel {
                channel_id,
                server_id: *server_id,
                name: crate::wire::UNNAMED_PRIVATE_CHANNEL.to_string(),
                kind: ChannelKind::Text,
                position: 0,
            }, OnConflict::Keep)?;
            c.provider.store().record_group_join(&channel_id, group.epoch())?;
            c.groups.insert(channel_id, *server_id, group);
            Ok((channel_id, mailbox_id, commit))
        })
    }

    /// The server's private channels this device holds without a name and has not asked
    /// about in this run.
    pub fn unasked_unnamed_channels(&self, server_id: &[u8; 32]) -> Result<Vec<[u8; 32]>> {
        Ok(self
            .provider
            .store()
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
        let channel = self.provider.store().get_channel(channel_id)?;
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
        let server_id = self.groups.server_of(group_channel).ok_or_else(|| GhostError::ServerNotLoaded(format!("channel {}", short_id(group_channel))))?;
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
                    let unnamed = self.provider.store().get_channel(&channel_id)?.name == crate::wire::UNNAMED_PRIVATE_CHANNEL;
                    if !unnamed && !may_manage {
                        return Ok(ChannelOpOutcome::Ignored);
                    }
                    self.provider.store().upsert_channel(&Channel { channel_id, server_id, name, kind, position })?;
                    Ok(ChannelOpOutcome::Applied)
                }
                ChannelOpPayload::Rename { channel_id, name } if may_manage => {
                    self.provider.store().rename_channel(&channel_id, &name)?;
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
                self.provider.store().insert_channel(&Channel { channel_id, server_id, name, kind, position }, OnConflict::Keep)?;
            }
            ChannelOpPayload::Reorder { positions } => {
                // Private channels take their place through their own groups.
                let public: Vec<([u8; 32], i32)> = positions.into_iter().filter(|(channel_id, _)| !self.is_private_channel(channel_id)).collect();
                self.provider.store().set_channel_positions(&server_id, &public)?;
            }
            // Private channels are renamed and deleted only inside their own group.
            ChannelOpPayload::Rename { channel_id, name } if !self.is_private_channel(&channel_id) => {
                self.provider.store().rename_channel(&channel_id, &name)?;
            }
            ChannelOpPayload::Delete { channel_id } if !self.is_private_channel(&channel_id) => {
                self.provider.store().delete_channel(&channel_id)?;
            }
            _ => return Ok(ChannelOpOutcome::Ignored),
        }
        Ok(ChannelOpOutcome::Applied)
    }

    /// Forget a private channel this device is no longer in (or failed to join).
    /// Forget a deleted private channel and remember its mailbox, so discovery does not
    /// join it again while the relay still lists it; `owed` when this device deleted it
    /// and must still delete the mailbox at the relay. Returns the mailbox.
    pub fn forget_deleted_private_channel(&mut self, channel_id: &[u8; 32], owed: bool) -> Result<[u8; 32]> {
        let server_id = self.groups.server_of(channel_id).ok_or_else(|| GhostError::ServerNotLoaded(format!("channel {}", short_id(channel_id))))?;
        let group = self.groups.get(channel_id).ok_or_else(|| GhostError::ServerNotLoaded(format!("channel {}", short_id(channel_id))))?;
        let mailbox_id = mls_group_mailbox_id(group.group_id());
        self.mls_step(&[*channel_id], |c| {
            c.provider.store().record_deleted_channel(&mailbox_id, &server_id, owed)?;
            c.drop_private_channel(channel_id)
        })?;
        Ok(mailbox_id)
    }

    /// Forget a private channel: its group and its row go together.
    pub fn drop_private_channel(&mut self, channel_id: &[u8; 32]) -> Result<()> {
        self.mls_step(&[*channel_id], |c| {
            if let Some(group) = c.groups.remove(channel_id) {
                group.delete(&c.provider)?;
            }
            c.provider.store().delete_channel(channel_id)
        })
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
        let server_id = self.groups.server_of(channel_id).ok_or_else(|| GhostError::ServerNotLoaded("channel's server".into()))?;
        if !self.server_policy(&server_id)?.has(&self.identity.fingerprint, ghost_wire::policy::MANAGE_CHANNELS) {
            return Err(GhostError::PermissionDenied("changing a channel's access needs the manage channels permission".into()));
        }
        let aad = self.commit_aad(channel_id);
        self.mls_step(&[*channel_id], |c| {
            let group = c.groups.get_mut(channel_id).expect("policy read above");
            let blob = group.stage_policy(&c.provider, crate::mls::group::GhostExtension::Channel(policy.clone()), &aad)?;
            Ok(Outbound { channel_id: *channel_id, mailbox_id: mls_group_mailbox_id(group.group_id()), blob })
        })
    }

    /// Leaves of a private channel's group whose accounts its policy no longer admits
    /// under the server's current state; empty for a public channel.
    pub fn excluded_leaves(&self, channel_id: &[u8; 32]) -> Result<Vec<LeafNodeIndex>> {
        let Some(policy) = self.channel_policy(channel_id)? else { return Ok(Vec::new()) };
        let server_id = self.groups.server_of(channel_id).ok_or_else(|| GhostError::ServerNotLoaded("channel's server".into()))?;
        let server_group = self.default_group(&server_id)?;
        let server_members: Vec<openmls::prelude::Member> = server_group.members().collect();
        let view = policy_mls::server_view(server_group.context_extensions(), &server_members)
            .map_err(|e| GhostError::Format(format!("server policy: {e}")))?;
        let group = self.groups.get(channel_id).expect("policy read above");
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
        let mailbox_id = self.groups.get(channel_id).map(|g| mls_group_mailbox_id(g.group_id())).expect("checked above");
        Ok(Some(Outbound { channel_id: *channel_id, mailbox_id, blob }))
    }
}
