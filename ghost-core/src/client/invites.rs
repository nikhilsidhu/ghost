//! Invites to a server and the server-state exchange a joiner uses to catch up with the
//! channels, roles and names it cannot see in the group.

use std::collections::HashSet;

use crate::error::{GhostError, Result};
use crate::storage::{Channel, Member, ServerKind};
use crate::wire::{derive_default_channel_id, mls_group_mailbox_id, InviteChannel, InviteMember, InvitePayload, Outbound, ServerStatePayload};

use super::GhostClient;

/// A freshly created invite. The relay stores `sealed_payload` under `token`; `key`
/// opens it and must reach joiners only inside the invite link.
pub struct NewInvite {
    pub key: [u8; 32],
    pub sealed_payload: Vec<u8>,
}

/// What became of a server's state sent to this device.
#[derive(Debug, PartialEq, Eq)]
pub enum ServerStateOutcome {
    /// The channels, role names and members' names now match the sender's.
    Applied,
    /// Not waited for, not from a member who may manage channels, or answering a request
    /// made before this device's.
    Ignored,
    /// As of before a change this device saw: ask again.
    Stale,
}

impl GhostClient {
    fn build_invite_payload(
        &self,
        server_id: &[u8; 32],
        server_name: &str,
        kind: ServerKind,
        members: &[Member],
        channels: &[Channel],
        grant: &ghost_wire::policy::InviteGrant,
    ) -> Result<InvitePayload> {
        // Public channels travel as metadata; the server group's GroupInfo is read from
        // the relay at join time, since every commit makes an embedded one stale. Private
        // channels never appear in an invite: joiners find the ones they may enter through
        // the relay's discovery, and others never learn of them.
        let invite_channels: Vec<InviteChannel> = channels
            .iter()
            .filter(|c| !self.is_private_channel(&c.channel_id))
            .map(|c| InviteChannel {
                channel_id: c.channel_id,
                name: c.name.clone(),
                kind: c.kind,
                position: c.position,
                group_info_bytes: Vec::new(),
            })
            .collect();

        Ok(InvitePayload {
            server_id: *server_id,
            server_name: server_name.to_string(),
            kind,
            members: members
                .iter()
                .map(|m| InviteMember {
                    fingerprint: m.fingerprint,
                    display_name: m.display_name.clone(),
                })
                .collect(),
            channels: invite_channels,
            role_names: self.provider.store().list_role_names(server_id)?,
            grant: grant.clone(),
        })
    }

    /// Create an invite to a server: a grant signed by this device admitting whoever
    /// holds it until `expires_at`, inside a payload sealed under a fresh key that
    /// travels only in the invite link, so the relay storing it learns nothing. Needs
    /// the invite permission; the relay and members check the grant again at the join.
    pub fn create_invite(&self, server_id: &[u8; 32], expires_at: u64) -> Result<NewInvite> {
        let server_mailbox = self.check_may_invite(server_id)?;
        let mut nonce = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
        let grant = ghost_wire::policy::InviteGrant::sign(server_mailbox, self.identity.fingerprint, expires_at, nonce, &self.identity.signing_key);

        let mut key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
        let sealed_payload = self.sealed_invite_payload(server_id, &grant, &key)?;
        Ok(NewInvite { key, sealed_payload })
    }

    /// Whether this account may invite to the server: a member following it, holding the
    /// invite permission. Returns the server group's mailbox, which invites name.
    pub fn check_may_invite(&self, server_id: &[u8; 32]) -> Result<[u8; 32]> {
        self.ensure_member(server_id)?;
        self.ensure_following(server_id)?;
        if !self.server_policy(server_id)?.has(&self.identity.fingerprint, ghost_wire::policy::INVITE) {
            return Err(GhostError::PermissionDenied("creating invites needs the invite permission".into()));
        }
        Ok(mls_group_mailbox_id(self.default_group(server_id)?.group_id()))
    }

    /// Open a sealed invite payload with the key from its link.
    pub fn open_invite(&self, sealed_payload: &[u8], key: &[u8; 32]) -> Result<InvitePayload> {
        let opened = crate::crypto::aead::open(key, sealed_payload, crate::wire::INVITE_PAYLOAD_CONTEXT)?;
        InvitePayload::from_bytes(&opened)
    }

    /// Join the server an invite is into, by an external commit built on
    /// `server_group_info`: the server group's state as its relay holds it now. Returns
    /// the server id, one (channel, commit, mailbox) per group joined, and the grant.
    #[allow(clippy::type_complexity)]
    #[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
    pub fn join_by_invite(
        &mut self,
        mut payload: InvitePayload,
        server_group_info: Vec<u8>,
        timestamp: u64,
    ) -> Result<([u8; 32], Vec<([u8; 32], Vec<u8>, [u8; 32])>, ghost_wire::policy::InviteGrant)> {
        let default_channel = derive_default_channel_id(&payload.server_id);
        let server_channel = payload
            .channels
            .iter_mut()
            .find(|ch| ch.channel_id == default_channel)
            .ok_or_else(|| GhostError::Format("invite names no default channel".into()))?;
        server_channel.group_info_bytes = server_group_info;
        let channel_results = self.join_server_common(
            payload.server_id, payload.server_name, payload.kind,
            &payload.members, &payload.channels, &payload.role_names, Some(&payload.grant), timestamp, false,
        )?;
        // The payload is from when the invite was made: the server's managers tell the rest.
        self.provider.store().begin_server_state_wait(&payload.server_id)?;
        Ok((payload.server_id, channel_results, payload.grant))
    }

    /// Ask the server's members for its current state, as a device that just joined it.
    pub fn ask_server_state(&mut self, server_id: &[u8; 32]) -> Result<Outbound> {
        self.send_control(server_id, crate::wire::encode_server_state_request())
    }

    /// Answer a request for the server's state made at `request_seq`, when this account
    /// may manage the server's channels; `None` otherwise.
    pub fn server_state_reply(&mut self, server_id: &[u8; 32], request_seq: u64) -> Result<Option<Outbound>> {
        if !self.server_policy(server_id)?.has(&self.identity.fingerprint, ghost_wire::policy::MANAGE_CHANNELS) {
            return Ok(None);
        }
        let channels = self
            .provider
            .store()
            .list_channels(server_id)?
            .into_iter()
            .filter(|c| !self.is_private_channel(&c.channel_id))
            .map(|c| InviteChannel { channel_id: c.channel_id, name: c.name, kind: c.kind, position: c.position, group_info_bytes: Vec::new() })
            .collect();
        let members = self
            .provider
            .store()
            .list_members(server_id)?
            .into_iter()
            .filter(Member::has_name)
            .map(|m| InviteMember { fingerprint: m.fingerprint, display_name: m.display_name })
            .collect();
        let state = ServerStatePayload { request_seq, channels, role_names: self.provider.store().list_role_names(server_id)?, members };
        self.send_control(server_id, crate::wire::encode_server_state(&state)).map(Some)
    }

    /// Take in a server's state sent by `sender`, while this device waits for it: the
    /// public channels become those listed, role names come when the sender may manage
    /// roles, and members still unnamed here take the names listed. An answer as of before
    /// a change this device saw would undo it, so it is refused as stale.
    pub fn apply_server_state(&mut self, server_id: &[u8; 32], sender: &[u8; 32], state: ServerStatePayload) -> Result<ServerStateOutcome> {
        let Some(wait) = self.provider.store().server_state_wait(server_id)? else { return Ok(ServerStateOutcome::Ignored) };
        let Some(asked_at) = wait.request_seq else { return Ok(ServerStateOutcome::Ignored) };
        if state.request_seq < asked_at || !self.server_policy(server_id)?.has(sender, ghost_wire::policy::MANAGE_CHANNELS) {
            return Ok(ServerStateOutcome::Ignored);
        }
        if wait.last_change_seq > state.request_seq {
            return Ok(ServerStateOutcome::Stale);
        }
        let default_channel = derive_default_channel_id(server_id);
        let listed: HashSet<[u8; 32]> = state.channels.iter().map(|c| c.channel_id).collect();
        for c in state.channels.into_iter().filter(|c| !self.is_private_channel(&c.channel_id)) {
            self.provider.store().upsert_channel(&Channel { channel_id: c.channel_id, server_id: *server_id, name: c.name, kind: c.kind, position: c.position })?;
        }
        for c in self.provider.store().list_channels(server_id)? {
            let gone = !listed.contains(&c.channel_id) && c.channel_id != default_channel && !self.is_private_channel(&c.channel_id);
            if gone {
                self.provider.store().delete_channel(&c.channel_id)?;
            }
        }
        self.apply_role_names(server_id, sender, &state.role_names)?;
        let unnamed: HashSet<[u8; 32]> = self.provider.store().list_members(server_id)?.into_iter().filter(|m| !m.has_name()).map(|m| m.fingerprint).collect();
        for m in state.members.into_iter().filter(|m| unnamed.contains(&m.fingerprint)) {
            self.provider.store().update_member_name(server_id, &m.fingerprint, &m.display_name)?;
        }
        self.provider.store().end_server_state_wait(server_id)?;
        Ok(ServerStateOutcome::Applied)
    }

    fn sealed_invite_payload(
        &self,
        server_id: &[u8; 32],
        grant: &ghost_wire::policy::InviteGrant,
        key: &[u8; 32],
    ) -> Result<Vec<u8>> {
        let meta = self.provider.store().get_server(server_id)?;
        let members = self.provider.store().list_members(server_id)?;
        let channels = self.provider.store().list_channels(server_id)?;
        let payload = self.build_invite_payload(server_id, &meta.name, meta.kind, &members, &channels, grant)?;
        crate::crypto::aead::seal(key, &payload.to_bytes(), crate::wire::INVITE_PAYLOAD_CONTEXT)
    }
}
