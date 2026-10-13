//! Servers: creating one, joining one from an invite or a provision, leaving one, and the
//! commits that change a server's policy or external sender.

use std::collections::HashMap;

use crate::error::{GhostError, Result};
use crate::mls::group::GhostGroup;
use crate::storage::{Channel, ChannelKind, Member, OnConflict, Server, ServerKind};
use crate::wire::{derive_default_channel_id, mls_group_mailbox_id, InviteChannel, InviteMember, Outbound, ProvisionPayload};
use ghost_wire::policy::{CommitAad, ServerPolicy};
use ghost_wire::{now_millis, short_id};

use super::GhostClient;

impl GhostClient {
    /// Core join logic: external commit → persist metadata → register.
    /// `idempotent`: true uses `_if_not_exists` inserts (provision/sync), false uses strict inserts (invite).
    /// Join a server by joining each channel's MLS group.
    /// Returns Vec of (channel_id, commit_bytes, mailbox_id) — one per channel.
    /// `grant` admits an account that is not yet a member to the server group.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn join_server_common(
        &mut self,
        server_id: [u8; 32],
        server_name: String,
        kind: ServerKind,
        members: &[InviteMember],
        channels: &[InviteChannel],
        role_names: &[(u8, String)],
        grant: Option<&ghost_wire::policy::InviteGrant>,
        timestamp: u64,
        idempotent: bool,
    ) -> Result<Vec<([u8; 32], Vec<u8>, [u8; 32])>> {
        // Channels without GroupInfo have no MLS group: metadata only.
        let joined: Vec<[u8; 32]> = channels.iter().filter(|ch| !ch.group_info_bytes.is_empty()).map(|ch| ch.channel_id).collect();
        // The server's rows and every group joined land together, or none of them.
        self.mls_step(&joined, |c| {
            // A server this account was removed from is still here, read-only: rejoining it
            // after being let back in keeps its rows and history.
            let idempotent = idempotent || c.provider.store().server_removal(&server_id)?.is_some();
            let on_conflict = if idempotent { OnConflict::Keep } else { OnConflict::Fail };
            let server = Server { server_id, name: server_name, kind, created_at: timestamp };
            c.provider.store().insert_server(&server, on_conflict)?;

            for ch in channels {
                let channel = Channel {
                    channel_id: ch.channel_id, server_id, name: ch.name.clone(),
                    kind: ch.kind, position: ch.position,
                };
                c.provider.store().insert_channel(&channel, on_conflict)?;
            }

            for m in members {
                let member = Member {
                    server_id, fingerprint: m.fingerprint, display_name: m.display_name.clone(),
                    joined_at: timestamp, avatar_hash: None, avatar_key: None,
                };
                c.provider.store().insert_member(&member, on_conflict)?;
            }

            let self_member = Member {
                server_id, fingerprint: c.identity.fingerprint,
                display_name: c.identity.display_name.clone(),
                joined_at: timestamp, avatar_hash: None, avatar_key: None,
            };
            c.provider.store().insert_member(&self_member, on_conflict)?;

            for (role_id, name) in role_names {
                c.provider.store().set_role_name(&server_id, *role_id, name)?;
            }

            let mut results = Vec::with_capacity(channels.len());
            let aad = CommitAad { invite: grant.cloned(), server_epoch: None };
            for ch in channels.iter().filter(|ch| !ch.group_info_bytes.is_empty()) {
                let (ghost_group, commit_bytes) = GhostGroup::join_by_external_commit(
                    &c.provider,
                    &c.identity,
                    &ch.group_info_bytes,
                    &aad,
                )?;
                let mailbox_id = mls_group_mailbox_id(ghost_group.group_id());
                c.provider.store().record_group_join(&ch.channel_id, ghost_group.epoch())?;
                c.groups.insert(ch.channel_id, server_id, ghost_group);
                results.push((ch.channel_id, commit_bytes, mailbox_id));
            }
            c.record_server_view(&server_id)?;
            // Members who joined after the payload was made are in the tree; their names come
            // when they announce, or with the server's state.
            for fingerprint in c.mls_member_fingerprints(&server_id)? {
                let member = Member {
                    server_id, fingerprint, display_name: crate::storage::placeholder_name(&fingerprint),
                    joined_at: timestamp, avatar_hash: None, avatar_key: None,
                };
                c.provider.store().insert_member(&member, OnConflict::Keep)?;
            }
            Ok(results)
        })
    }

    /// Join a server from a provision payload (handles duplicates).
    /// Returns Vec of (channel_id, commit_bytes, mailbox_id) for each channel.
    pub fn join_from_provision(
        &mut self,
        payload: &ProvisionPayload,
        group_infos: &HashMap<[u8; 32], Vec<u8>>,
        timestamp: u64,
    ) -> Result<Vec<([u8; 32], Vec<u8>, [u8; 32])>> {
        // Provision payloads carry channel metadata only; each channel's GroupInfo comes
        // from that channel's mailbox on the relay. Channels without one have no MLS group
        // and are stored as metadata; the default channel must have one.
        let default_ch = derive_default_channel_id(&payload.server_id);
        if !group_infos.contains_key(&default_ch) {
            return Err(GhostError::Mls("no GroupInfo for the server's default channel".into()));
        }
        let mut channels = payload.channels.clone();
        for ch in &mut channels {
            ch.group_info_bytes = group_infos.get(&ch.channel_id).cloned().unwrap_or_default();
        }
        self.join_server_common(
            payload.server_id, payload.server_name.clone(), payload.kind,
            &payload.members, &channels, &payload.role_names, None, timestamp, true,
        )
    }

    #[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
    pub fn create_server(&mut self, name: &str, kind: ServerKind, timestamp: u64) -> Result<[u8; 32]> {
        let mut server_id = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut server_id);

        let channel_name = match kind {
            ServerKind::Dm | ServerKind::Group => "messages",
            ServerKind::Server => "general",
        };
        let channel_id = derive_default_channel_id(&server_id);

        // The relay is every group's external sender, so it can propose removals in it.
        let relay_vk = self.relay_vk.ok_or_else(|| GhostError::Network("the home relay's key is not known yet; connect to it first".into()))?;
        let server = Server { server_id, name: name.to_string(), kind, created_at: timestamp };
        let channel = Channel { channel_id, server_id, name: channel_name.to_string(), kind: ChannelKind::Text, position: 0 };
        let creator = Member {
            server_id,
            fingerprint: self.identity.fingerprint,
            display_name: self.identity.display_name.clone(),
            joined_at: timestamp,
            avatar_hash: None,
            avatar_key: None,
        };
        // The group, the server's rows and its first view land together, or none of them.
        self.mls_step(&[channel_id], |c| {
            let ghost_group = GhostGroup::create(
                &c.provider,
                &c.identity,
                &server_id,
                &channel_id,
                Some(&relay_vk),
                Some(crate::mls::group::GhostExtension::Server(ghost_wire::policy::ServerPolicy::new(c.identity.fingerprint))),
            )?;
            c.provider.store().insert_created_server(&server, &channel, &creator)?;
            c.groups.insert(channel_id, server_id, ghost_group);
            c.record_server_view(&server_id)
        })?;
        Ok(server_id)
    }

    /// Undo a server this device made whose group state the relay would not take: a
    /// server cannot exist without it.
    pub fn abandon_created_server(&mut self, server_id: &[u8; 32]) -> Result<()> {
        self.drop_server(server_id)
    }

    /// Stage, in one channel's group, a commit naming `relay_vk` as the group's
    /// external sender. Returns the commit; the caller posts it to the new relay and
    /// merges or clears it. A private channel's commit names the server group's
    /// current epoch, so the server group's own commit must be merged first.
    pub fn stage_external_sender(&mut self, channel_id: &[u8; 32], relay_vk: &[u8; 32]) -> Result<Vec<u8>> {
        let aad = self.commit_aad(channel_id);
        self.mls_step(&[*channel_id], |c| {
            let group = c.groups.get_mut(channel_id).ok_or_else(|| {
                GhostError::ServerNotLoaded(format!("channel {}", short_id(channel_id)))
            })?;
            group.set_external_sender(&c.provider, relay_vk, &aad)
        })
    }

    /// Stage a commit replacing the server's policy: its roles, their assignments, what
    /// everyone may do, or its owner. Checked here against the current policy so a
    /// refusal comes early; the relay and every member check it again. Returns the
    /// commit to post; merge or clear the server group's pending commit afterwards.
    pub fn stage_server_policy(&mut self, server_id: &[u8; 32], policy: &ServerPolicy) -> Result<Outbound> {
        self.ensure_following(server_id)?;
        use ghost_wire::policy::{authorize_server_commit, CommitSummary, Committer, GrantContext};
        let current = self.server_policy(server_id)?;
        let channel_id = derive_default_channel_id(server_id);
        let group = self.groups.get(&channel_id).ok_or_else(|| {
            GhostError::ServerNotLoaded(short_id(server_id))
        })?;
        let mailbox_id = mls_group_mailbox_id(group.group_id());
        let summary = CommitSummary {
            committer: Committer::Member(self.identity.fingerprint),
            adds: Vec::new(),
            removes: Vec::new(),
            departed: Vec::new(),
            new_server_policy: Some(policy.clone()),
            new_channel_policy: None,
            new_removed: None,
        };
        let removed = group.removed_accounts()?.unwrap_or_default();
        let no_devices = |_: &[u8; 32], _: &[u8; 32]| false;
        let ctx = GrantContext { server_mailbox: mailbox_id, now_millis: now_millis(), is_member_device: &no_devices, removed: &removed };
        authorize_server_commit(&current, &summary, &ctx).map_err(|e| GhostError::PermissionDenied(e.to_string()))?;

        let policy = crate::mls::group::GhostExtension::Server(policy.clone());
        let blob = self.mls_step(&[channel_id], |c| {
            let group = c.groups.get_mut(&channel_id).ok_or_else(|| GhostError::ServerNotLoaded(short_id(server_id)))?;
            group.stage_policy(&c.provider, policy, &CommitAad::default())
        })?;
        Ok(Outbound { channel_id, mailbox_id, blob })
    }

    /// Forget a server this account was removed from, or stopped following, with its
    /// history. A server this device is still in is left through its group, not here.
    pub fn forget_server(&mut self, server_id: &[u8; 32]) -> Result<()> {
        if self.removed_from(server_id)?.is_none() && self.provider.store().server_halt(server_id)?.is_none() {
            return Err(GhostError::PermissionDenied("only a server you were removed from or stopped following can be forgotten".into()));
        }
        self.drop_server(server_id)
    }

    /// Undo a first join the relay refused: nothing of the server stays.
    pub fn abandon_join(&mut self, server_id: &[u8; 32]) -> Result<()> {
        self.drop_server(server_id)
    }

    /// Drop a server and its groups from this device: the groups' state, and every row
    /// of the server, which go with it.
    fn drop_server(&mut self, server_id: &[u8; 32]) -> Result<()> {
        let channels: Vec<[u8; 32]> = self.groups.channels_of(server_id).collect();
        // Every group's rows and the server's go together, or all stay.
        self.mls_step(&channels, |c| {
            for channel_id in &channels {
                if let Some(group) = c.groups.remove(channel_id) {
                    group.delete(&c.provider)?;
                }
            }
            c.provider.store().delete_server(server_id)
        })
    }
}
