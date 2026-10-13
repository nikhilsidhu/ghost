//! Membership of servers: whether this device is still in one and may act, members'
//! names and roles, kicking and letting back in.

use openmls::prelude::LeafNodeIndex;

use crate::error::{GhostError, Result};
use crate::mls::group::GhostExtension;
use crate::storage::{Server, ServerKind};
use crate::wire::{derive_default_channel_id, mls_group_mailbox_id, Outbound};
use ghost_wire::policy::{CommitAad, RemovedAccount};
use ghost_wire::short_id;

use super::GhostClient;

impl GhostClient {
    /// What to call `server` here: its name, or for a DM the other member's name once this
    /// device knows it. A DM's own name is whatever its creator typed, the same for both.
    pub fn server_display_name(&self, server: &Server) -> String {
        if server.kind != ServerKind::Dm {
            return server.name.clone();
        }
        self.provider.store()
            .list_members(&server.server_id)
            .ok()
            .and_then(|members| members.into_iter().find(|m| m.fingerprint != self.identity.fingerprint && m.has_name()))
            .map_or_else(|| server.name.clone(), |other| other.display_name)
    }

    /// Record roles' display names sent by `sender`, who must be able to manage roles.
    /// Returns whether they were recorded.
    pub fn apply_role_names(&mut self, server_id: &[u8; 32], sender: &[u8; 32], names: &[(u8, String)]) -> Result<bool> {
        if !self.server_policy(server_id)?.has(sender, ghost_wire::policy::MANAGE_ROLES) {
            return Ok(false);
        }
        for (role_id, name) in names {
            self.provider.store().set_role_name(server_id, *role_id, name)?;
        }
        Ok(true)
    }

    /// Name roles: stored here and sent to the server's members in one encrypted
    /// metadata message. Needs the manage roles permission.
    pub fn name_roles(&mut self, server_id: &[u8; 32], names: &[(u8, String)]) -> Result<Outbound> {
        if !self.server_policy(server_id)?.has(&self.identity.fingerprint, ghost_wire::policy::MANAGE_ROLES) {
            return Err(GhostError::PermissionDenied("naming roles needs the manage roles permission".into()));
        }
        self.send_control(server_id, crate::wire::encode_role_names(names))
    }

    /// The name `account` goes by in the server: a member's, else a former member's.
    pub fn member_name(&self, server_id: &[u8; 32], account: &[u8; 32]) -> Option<String> {
        let members = self.provider.store().list_members(server_id).ok()?;
        match members.into_iter().find(|m| m.fingerprint == *account) {
            Some(member) => Some(member.display_name),
            None => self.provider.store().former_member_name(server_id, account).ok().flatten(),
        }
    }

    /// When, and by whom when known, this account was removed from a server it still
    /// shows read-only.
    pub fn removed_from(&self, server_id: &[u8; 32]) -> Result<Option<crate::storage::ServerRemoval>> {
        self.provider.store().server_removal(server_id)
    }

    /// Fail with `RemovedFromServer` once this account was removed from the server, so
    /// nothing is sent to a server it is no longer in.
    pub fn ensure_member(&self, server_id: &[u8; 32]) -> Result<()> {
        match self.removed_from(server_id)? {
            Some(_) => Err(GhostError::RemovedFromServer),
            None => Ok(()),
        }
    }

    /// Why this device stopped following the server, if it did.
    pub fn halt(&self, server_id: &[u8; 32]) -> Result<Option<crate::storage::ServerHalt>> {
        self.provider.store().server_halt(server_id)
    }

    /// Fail while the server is halted: its relay accepted a change the rules forbid, and
    /// nothing goes there until the person accepts the relay's state or leaves.
    pub fn ensure_following(&self, server_id: &[u8; 32]) -> Result<()> {
        match self.provider.store().server_halt(server_id)? {
            Some(halt) => Err(GhostError::PolicyRefused(format!("{}; the server is read-only until you accept the relay's state or leave", halt.reason))),
            None => Ok(()),
        }
    }

    /// `ensure_following` for the server a channel belongs to.
    pub(super) fn ensure_following_channel(&self, channel_id: &[u8; 32]) -> Result<()> {
        match self.groups.server_of(channel_id) {
            Some(server_id) => self.ensure_following(&server_id),
            None => Ok(()),
        }
    }

    /// Accounts the server keeps from rejoining, with the name each had here when known.
    pub fn kept_out(&self, server_id: &[u8; 32]) -> Result<Vec<(RemovedAccount, Option<String>)>> {
        let removed = self.default_group(server_id)?.removed_accounts()?.unwrap_or_default();
        removed
            .entries
            .into_iter()
            .map(|entry| Ok((entry, self.provider.store().former_member_name(server_id, &entry.account)?)))
            .collect()
    }

    /// Let a removed account back in, so it may rejoin with an invite. Needs the kick
    /// permission; any roles the account still held go with the same commit.
    pub fn let_back_in(&mut self, server_id: &[u8; 32], account: &[u8; 32]) -> Result<Outbound> {
        let policy = self.server_policy(server_id)?;
        if !policy.has(&self.identity.fingerprint, ghost_wire::policy::KICK) {
            return Err(GhostError::PermissionDenied("letting someone back in needs the kick permission".into()));
        }
        let channel_id = derive_default_channel_id(server_id);
        let group = self.groups.get(&channel_id).ok_or_else(|| GhostError::ServerNotLoaded(short_id(server_id)))?;
        let removed = group.removed_accounts()?.unwrap_or_default();
        if !removed.contains(account) {
            return Err(GhostError::PermissionDenied("that account is not kept out of this server".into()));
        }
        let mut updates = vec![GhostExtension::Removals(removed.without(account))];
        let pruned = policy.without_assignments(&[*account]);
        if pruned != policy {
            updates.push(GhostExtension::Server(pruned));
        }
        self.stage_server_change(server_id, &[], &updates)
    }

    /// Stage, in the server's group, one commit removing `removed` leaves and putting
    /// `updates` in place of its extensions of the same types.
    fn stage_server_change(&mut self, server_id: &[u8; 32], removed: &[LeafNodeIndex], updates: &[GhostExtension]) -> Result<Outbound> {
        let channel_id = derive_default_channel_id(server_id);
        self.mls_step(&[channel_id], |c| {
            let group = c.groups.get_mut(&channel_id).ok_or_else(|| GhostError::ServerNotLoaded(short_id(server_id)))?;
            let blob = group.stage_change(&c.provider, removed, updates, &CommitAad::default())?;
            Ok(Outbound { channel_id, mailbox_id: mls_group_mailbox_id(group.group_id()), blob })
        })
    }

    /// Remove a member from the server group: needs the kick permission and a rank above
    /// the member's. The same commit keeps the account from rejoining until someone who
    /// may kick lets it back, and drops its roles, as Signal's removal does. The relay then
    /// proposes removing the member from every private channel, whose policies admit only
    /// server members.
    pub fn kick_member(&mut self, server_id: &[u8; 32], target_fp: &[u8; 32], now: u64) -> Result<Outbound> {
        self.ensure_following(server_id)?;
        if target_fp == &self.identity.fingerprint {
            return Err(GhostError::PermissionDenied("cannot kick yourself".into()));
        }
        let policy = self.server_policy(server_id)?;
        let own = self.identity.fingerprint;
        if !policy.has(&own, ghost_wire::policy::KICK) || !policy.rank(&own).outranks(policy.rank(target_fp)) {
            return Err(GhostError::PermissionDenied(
                "kicking this member needs the kick permission and a higher rank".into(),
            ));
        }

        let channel_id = derive_default_channel_id(server_id);
        let group = self.groups.get(&channel_id).ok_or_else(|| {
            GhostError::ServerNotLoaded(short_id(server_id))
        })?;
        let leaf_indices: Vec<_> = group
            .members()
            .filter(|m| {
                crate::mls::credential::parse_credential(&m.credential)
                    .is_ok_and(|pc| pc.account_fp == *target_fp)
            })
            .map(|m| m.index)
            .collect();
        if leaf_indices.is_empty() {
            return Err(GhostError::Mls("member not found in the server group".into()));
        }
        let mut updates = vec![GhostExtension::Removals(group.removed_accounts()?.unwrap_or_default().with_removed(*target_fp, now))];
        let pruned = policy.without_assignments(&[*target_fp]);
        if pruned != policy {
            updates.push(GhostExtension::Server(pruned));
        }
        self.stage_server_change(server_id, &leaf_indices, &updates)
    }
}
