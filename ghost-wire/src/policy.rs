//! Who may change a group, decided identically by the relay (before accepting a
//! commit) and by every member (before merging one). Policies are MLS GroupContext
//! extensions, so they are part of the state all members agree on; callers summarise
//! what a commit does and these functions decide whether it is allowed.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use thiserror::Error;

/// GroupContext extension carrying a server's roles (private-use range).
pub const SERVER_POLICY_EXTENSION: u16 = 0xFF10;
/// GroupContext extension carrying a private channel's access list.
pub const CHANNEL_POLICY_EXTENSION: u16 = 0xFF11;

pub const INVITE: u32 = 1;
pub const KICK: u32 = 1 << 1;
pub const MANAGE_CHANNELS: u32 = 1 << 2;
pub const MANAGE_ROLES: u32 = 1 << 3;
/// Every defined permission; the owner holds all of them.
pub const ALL_PERMISSIONS: u32 = INVITE | KICK | MANAGE_CHANNELS | MANAGE_ROLES;

const POLICY_VERSION: u8 = 0x01;
const GRANT_VERSION: u8 = 0x01;
const GRANT_SIGN_PREFIX: &[u8] = b"ghost-invite-grant-v1:";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("policy encoding: {0}")]
    Format(String),
    #[error("not permitted: {0}")]
    Denied(String),
    /// A private channel commit was authorized against a server policy this verifier
    /// has not reached yet; process the server group, then retry.
    #[error("server group must reach epoch {epoch} first")]
    ContextBehind { server_mailbox: [u8; 32], epoch: u64 },
}

fn deny(msg: impl Into<String>) -> PolicyError {
    PolicyError::Denied(msg.into())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Role {
    pub id: u8,
    pub permissions: u32,
}

/// Roles and their holders for one server. Roles are listed by rank, highest first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerPolicy {
    pub owner: [u8; 32],
    pub everyone: u32,
    pub roles: Vec<Role>,
    pub assignments: Vec<([u8; 32], Vec<u8>)>,
}

/// How senior an account is: the owner, then roles by list position, then no role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rank {
    Owner,
    Role(usize),
    Member,
}

impl Rank {
    /// Whether `self` is strictly more senior than `other`.
    pub fn outranks(self, other: Rank) -> bool {
        match (self, other) {
            (Rank::Owner, Rank::Owner) => false,
            (Rank::Owner, _) => true,
            (Rank::Role(a), Rank::Role(b)) => a < b,
            (Rank::Role(_), Rank::Member) => true,
            _ => false,
        }
    }
}

impl ServerPolicy {
    pub fn new(owner: [u8; 32]) -> Self {
        Self { owner, everyone: INVITE, roles: Vec::new(), assignments: Vec::new() }
    }

    /// Policy of a group created before policies existed: the creator owns it and
    /// anyone may invite, which is what members could do before.
    pub fn implicit(creator: [u8; 32]) -> Self {
        Self::new(creator)
    }

    pub fn roles_of(&self, account: &[u8; 32]) -> &[u8] {
        self.assignments
            .iter()
            .find(|(a, _)| a == account)
            .map(|(_, roles)| roles.as_slice())
            .unwrap_or(&[])
    }

    fn role_index(&self, id: u8) -> Option<usize> {
        self.roles.iter().position(|r| r.id == id)
    }

    pub fn permissions(&self, account: &[u8; 32]) -> u32 {
        if *account == self.owner {
            return ALL_PERMISSIONS;
        }
        self.roles_of(account)
            .iter()
            .filter_map(|id| self.role_index(*id))
            .fold(self.everyone, |acc, i| acc | self.roles[i].permissions)
    }

    pub fn has(&self, account: &[u8; 32], permission: u32) -> bool {
        self.permissions(account) & permission == permission
    }

    pub fn rank(&self, account: &[u8; 32]) -> Rank {
        if *account == self.owner {
            return Rank::Owner;
        }
        self.roles_of(account)
            .iter()
            .filter_map(|id| self.role_index(*id))
            .min()
            .map_or(Rank::Member, Rank::Role)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![POLICY_VERSION];
        buf.extend_from_slice(&self.owner);
        buf.extend_from_slice(&self.everyone.to_be_bytes());
        buf.push(self.roles.len() as u8);
        for role in &self.roles {
            buf.push(role.id);
            buf.extend_from_slice(&role.permissions.to_be_bytes());
        }
        buf.extend_from_slice(&(self.assignments.len() as u16).to_be_bytes());
        for (account, roles) in &self.assignments {
            buf.extend_from_slice(account);
            buf.push(roles.len() as u8);
            buf.extend_from_slice(roles);
        }
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, PolicyError> {
        let mut r = Reader::new(data);
        r.version()?;
        let owner = r.array32()?;
        let everyone = r.u32()?;
        let role_count = r.u8()? as usize;
        let mut roles = Vec::with_capacity(role_count);
        for _ in 0..role_count {
            roles.push(Role { id: r.u8()?, permissions: r.u32()? });
        }
        let assign_count = r.u16()? as usize;
        let mut assignments = Vec::with_capacity(assign_count);
        for _ in 0..assign_count {
            let account = r.array32()?;
            let count = r.u8()? as usize;
            assignments.push((account, r.bytes(count)?.to_vec()));
        }
        r.finish()?;
        let policy = Self { owner, everyone, roles, assignments };
        policy.check_well_formed()?;
        Ok(policy)
    }

    /// Role ids unique, assignments name existing roles, one entry per account.
    pub fn check_well_formed(&self) -> Result<(), PolicyError> {
        let err = |m: &str| PolicyError::Format(m.into());
        for (i, role) in self.roles.iter().enumerate() {
            if self.roles[..i].iter().any(|r| r.id == role.id) {
                return Err(err("duplicate role id"));
            }
        }
        for (i, (account, roles)) in self.assignments.iter().enumerate() {
            if self.assignments[..i].iter().any(|(a, _)| a == account) {
                return Err(err("account assigned twice"));
            }
            if roles.iter().any(|id| self.role_index(*id).is_none()) {
                return Err(err("assignment names an unknown role"));
            }
        }
        Ok(())
    }
}

/// The server group as a private channel sees it: its policy and member accounts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerView {
    pub policy: ServerPolicy,
    pub members: Vec<[u8; 32]>,
}

impl ServerView {
    /// `[policy_len:4][policy][member_count:2] member_count × [account:32]`, for clients
    /// that keep the views a server group had at past epochs.
    pub fn to_bytes(&self) -> Vec<u8> {
        let policy = self.policy.to_bytes();
        let mut buf = Vec::with_capacity(4 + policy.len() + 2 + self.members.len() * 32);
        buf.extend_from_slice(&(policy.len() as u32).to_be_bytes());
        buf.extend_from_slice(&policy);
        buf.extend_from_slice(&(self.members.len() as u16).to_be_bytes());
        for account in &self.members {
            buf.extend_from_slice(account);
        }
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, PolicyError> {
        let mut r = Reader::new(data);
        let policy_len = r.u32()? as usize;
        let policy = ServerPolicy::from_bytes(r.bytes(policy_len)?)?;
        let count = r.u16()? as usize;
        let members = (0..count).map(|_| r.array32()).collect::<Result<_, _>>()?;
        r.finish()?;
        Ok(Self { policy, members })
    }
}

/// Who may be in one private channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelPolicy {
    /// Mailbox of the server group whose roles apply.
    pub server_mailbox: [u8; 32],
    /// The channel's id, from which members derive the group id together with the
    /// server id the relay never learns, so only a server member could have made it.
    pub channel_id: [u8; 32],
    pub roles: Vec<u8>,
    pub accounts: Vec<[u8; 32]>,
}

impl ChannelPolicy {
    /// Only members of the server qualify, so leaving or being kicked from the server
    /// also ends access, whatever stale assignments the policies still hold. Channel
    /// managers are always admitted: a channel must stay manageable by someone inside it.
    pub fn admits(&self, account: &[u8; 32], server: &ServerView) -> bool {
        server.members.contains(account)
            && (server.policy.has(account, MANAGE_CHANNELS)
                || self.accounts.contains(account)
                || server.policy.roles_of(account).iter().any(|id| self.roles.contains(id)))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![POLICY_VERSION];
        buf.extend_from_slice(&self.server_mailbox);
        buf.extend_from_slice(&self.channel_id);
        buf.push(self.roles.len() as u8);
        buf.extend_from_slice(&self.roles);
        buf.extend_from_slice(&(self.accounts.len() as u16).to_be_bytes());
        for account in &self.accounts {
            buf.extend_from_slice(account);
        }
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, PolicyError> {
        let mut r = Reader::new(data);
        r.version()?;
        let server_mailbox = r.array32()?;
        let channel_id = r.array32()?;
        let role_count = r.u8()? as usize;
        let roles = r.bytes(role_count)?.to_vec();
        let account_count = r.u16()? as usize;
        let mut accounts = Vec::with_capacity(account_count);
        for _ in 0..account_count {
            accounts.push(r.array32()?);
        }
        r.finish()?;
        Ok(Self { server_mailbox, channel_id, roles, accounts })
    }
}

/// The private channels a relay lists for one member of a server: each channel
/// group's mailbox with its published GroupInfo, for joining by external commit.
/// `[count:2] count × [mailbox:32][group_info_len:4][group_info]`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdmittedChannels(pub Vec<([u8; 32], Vec<u8>)>);

impl AdmittedChannels {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = (self.0.len() as u16).to_be_bytes().to_vec();
        for (mailbox, group_info) in &self.0 {
            buf.extend_from_slice(mailbox);
            buf.extend_from_slice(&(group_info.len() as u32).to_be_bytes());
            buf.extend_from_slice(group_info);
        }
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, PolicyError> {
        let mut r = Reader::new(data);
        let count = r.u16()? as usize;
        let mut channels = Vec::with_capacity(count);
        for _ in 0..count {
            let mailbox = r.array32()?;
            let len = r.u32()? as usize;
            channels.push((mailbox, r.bytes(len)?.to_vec()));
        }
        r.finish()?;
        Ok(Self(channels))
    }
}

/// Permission to join a server by external commit, signed by a member who may invite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteGrant {
    pub server_mailbox: [u8; 32],
    pub issuer_account: [u8; 32],
    pub issuer_device: [u8; 32],
    pub expires_at: u64,
    pub nonce: [u8; 16],
    pub signature: [u8; 64],
}

impl InviteGrant {
    pub fn sign(
        server_mailbox: [u8; 32],
        issuer_account: [u8; 32],
        expires_at: u64,
        nonce: [u8; 16],
        device: &SigningKey,
    ) -> Self {
        let mut grant = Self {
            server_mailbox,
            issuer_account,
            issuer_device: device.verifying_key().to_bytes(),
            expires_at,
            nonce,
            signature: [0u8; 64],
        };
        grant.signature = device.sign(&grant.signed_message()).to_bytes();
        grant
    }

    fn body(&self) -> Vec<u8> {
        let mut buf = vec![GRANT_VERSION];
        buf.extend_from_slice(&self.server_mailbox);
        buf.extend_from_slice(&self.issuer_account);
        buf.extend_from_slice(&self.issuer_device);
        buf.extend_from_slice(&self.expires_at.to_be_bytes());
        buf.extend_from_slice(&self.nonce);
        buf
    }

    fn signed_message(&self) -> Vec<u8> {
        let mut msg = GRANT_SIGN_PREFIX.to_vec();
        msg.extend_from_slice(&self.body());
        msg
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = self.body();
        buf.extend_from_slice(&self.signature);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, PolicyError> {
        let mut r = Reader::new(data);
        r.version()?;
        let grant = Self {
            server_mailbox: r.array32()?,
            issuer_account: r.array32()?,
            issuer_device: r.array32()?,
            expires_at: r.u64()?,
            nonce: r.bytes(16)?.try_into().unwrap(),
            signature: r.bytes(64)?.try_into().unwrap(),
        };
        r.finish()?;
        Ok(grant)
    }

    fn verify_signature(&self) -> Result<(), PolicyError> {
        let vk = VerifyingKey::from_bytes(&self.issuer_device).map_err(|_| deny("invite signer key is invalid"))?;
        vk.verify_strict(&self.signed_message(), &Signature::from_bytes(&self.signature))
            .map_err(|_| deny("invite signature is invalid"))
    }
}

const AAD_INVITE: u8 = 0x01;
const AAD_SERVER_EPOCH: u8 = 0x02;

/// Authenticated data a commit carries for policy checks: `[tag:1][len:2][value]…`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommitAad {
    /// For an external join of a server group.
    pub invite: Option<InviteGrant>,
    /// For any commit to a private channel group: the server group epoch whose policy
    /// authorized it, which must be the relay's current one.
    pub server_epoch: Option<u64>,
}

impl CommitAad {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut field = |tag: u8, value: &[u8]| {
            buf.push(tag);
            buf.extend_from_slice(&(value.len() as u16).to_be_bytes());
            buf.extend_from_slice(value);
        };
        if let Some(grant) = &self.invite {
            field(AAD_INVITE, &grant.to_bytes());
        }
        if let Some(epoch) = self.server_epoch {
            field(AAD_SERVER_EPOCH, &epoch.to_be_bytes());
        }
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, PolicyError> {
        let mut aad = Self::default();
        let mut r = Reader::new(data);
        while r.pos < data.len() {
            let tag = r.u8()?;
            let len = r.u16()? as usize;
            let value = r.bytes(len)?;
            match tag {
                AAD_INVITE => aad.invite = Some(InviteGrant::from_bytes(value)?),
                AAD_SERVER_EPOCH => {
                    let bytes: [u8; 8] = value.try_into().map_err(|_| PolicyError::Format("bad server epoch".into()))?;
                    aad.server_epoch = Some(u64::from_be_bytes(bytes));
                }
                other => return Err(PolicyError::Format(format!("unknown commit data tag {other:#x}"))),
            }
        }
        Ok(aad)
    }
}

/// Who made a commit.
#[derive(Debug, Clone)]
pub enum Committer {
    /// An existing member, identified by account.
    Member([u8; 32]),
    /// An external joiner. `already_member` is true when the account already had a
    /// leaf before this commit (a new device of a member).
    Joiner { account: [u8; 32], already_member: bool, grant: Option<InviteGrant> },
}

/// One leaf a commit removes.
#[derive(Debug, Clone)]
pub struct Removal {
    pub account: [u8; 32],
    /// The removal was proposed by the relay (revoked device, lost access).
    pub proposed_by_relay: bool,
}

/// What a commit does, extracted from MLS by the caller.
#[derive(Debug, Clone)]
pub struct CommitSummary {
    pub committer: Committer,
    /// Accounts added through Add proposals.
    pub adds: Vec<[u8; 32]>,
    pub removes: Vec<Removal>,
    /// The ServerPolicy after this commit, when the commit changes it.
    pub new_server_policy: Option<ServerPolicy>,
    /// The ChannelPolicy after this commit, when the commit changes it.
    pub new_channel_policy: Option<ChannelPolicy>,
}

impl CommitSummary {
    fn committer_account(&self) -> [u8; 32] {
        match &self.committer {
            Committer::Member(a) => *a,
            Committer::Joiner { account, .. } => *account,
        }
    }
}

/// Facts about the group the policy check needs but cannot see itself.
pub struct GrantContext<'a> {
    /// Mailbox of the server group being joined.
    pub server_mailbox: [u8; 32],
    pub now_millis: u64,
    /// Whether `device` is the signature key of a leaf of `account` in the group.
    pub is_member_device: &'a dyn Fn(&[u8; 32], &[u8; 32]) -> bool,
}

/// Decide whether a commit to a server group is allowed under `policy`, the policy
/// in force before the commit.
pub fn authorize_server_commit(policy: &ServerPolicy, commit: &CommitSummary, ctx: &GrantContext) -> Result<(), PolicyError> {
    let committer = commit.committer_account();

    if let Committer::Joiner { already_member, grant, .. } = &commit.committer {
        if !already_member {
            let grant = grant.as_ref().ok_or_else(|| deny("joining needs an invite"))?;
            check_grant(policy, grant, ctx)?;
        }
    }

    if !commit.adds.is_empty() && !policy.has(&committer, INVITE) {
        return Err(deny("adding members needs the invite permission"));
    }

    for removal in &commit.removes {
        if removal.proposed_by_relay || removal.account == committer {
            continue;
        }
        if removal.account == policy.owner {
            return Err(deny("the owner cannot be removed"));
        }
        if !policy.has(&committer, KICK) {
            return Err(deny("removing others needs the kick permission"));
        }
        if !policy.rank(&committer).outranks(policy.rank(&removal.account)) {
            return Err(deny("cannot remove a member of equal or higher rank"));
        }
    }

    if let Some(new) = &commit.new_server_policy {
        authorize_policy_change(policy, new, &committer)?;
    }
    if commit.new_channel_policy.is_some() {
        return Err(deny("a server group carries no channel policy"));
    }
    Ok(())
}

fn check_grant(policy: &ServerPolicy, grant: &InviteGrant, ctx: &GrantContext) -> Result<(), PolicyError> {
    if grant.server_mailbox != ctx.server_mailbox {
        return Err(deny("invite is for another server"));
    }
    if grant.expires_at <= ctx.now_millis {
        return Err(deny("invite has expired"));
    }
    grant.verify_signature()?;
    if !(ctx.is_member_device)(&grant.issuer_account, &grant.issuer_device) {
        return Err(deny("invite was not signed by a current member's device"));
    }
    if !policy.has(&grant.issuer_account, INVITE) {
        return Err(deny("invite issuer may not invite"));
    }
    Ok(())
}

/// A ServerPolicy change by `committer`: only with MANAGE_ROLES, the owner field only
/// by the owner, and a non-owner only below its own rank and within its own permissions.
fn authorize_policy_change(old: &ServerPolicy, new: &ServerPolicy, committer: &[u8; 32]) -> Result<(), PolicyError> {
    // A commit that replaces the extension list restates an unchanged policy.
    if new == old {
        return Ok(());
    }
    new.check_well_formed()?;
    if *committer == old.owner {
        return Ok(());
    }
    if new.owner != old.owner {
        return Err(deny("only the owner can transfer ownership"));
    }
    if !old.has(committer, MANAGE_ROLES) {
        return Err(deny("changing roles needs the manage roles permission"));
    }
    let own = old.permissions(committer);
    if new.everyone & !own != 0 {
        return Err(deny("cannot give everyone permissions you do not hold"));
    }
    // Roles at or above the committer's rank must stay exactly as they are.
    let protected = match old.rank(committer) {
        Rank::Role(i) => i + 1,
        _ => 0,
    };
    if new.roles.len() < protected || new.roles[..protected] != old.roles[..protected] {
        return Err(deny("cannot change roles at or above your own rank"));
    }
    if new.roles[protected..].iter().any(|r| r.permissions & !own != 0) {
        return Err(deny("cannot give a role permissions you do not hold"));
    }
    // Members whose roles change must rank below the committer, and only lower roles move.
    let accounts = old.assignments.iter().chain(new.assignments.iter()).map(|(a, _)| *a);
    for account in accounts {
        let (before, after) = (old.roles_of(&account), new.roles_of(&account));
        if before == after {
            continue;
        }
        let changed = before.iter().filter(|id| !after.contains(id)).chain(after.iter().filter(|id| !before.contains(id)));
        for id in changed {
            let at = new.role_index(*id).or_else(|| old.role_index(*id)).unwrap_or(usize::MAX);
            if at < protected {
                return Err(deny("cannot assign or remove a role at or above your own rank"));
            }
        }
        if account != *committer && !old.rank(committer).outranks(old.rank(&account)) {
            return Err(deny("cannot change the roles of a member of equal or higher rank"));
        }
    }
    Ok(())
}

/// Decide whether a commit to a private channel group is allowed under its policy,
/// evaluated against the server's current roles.
pub fn authorize_channel_commit(
    policy: &ChannelPolicy,
    server: &ServerView,
    commit: &CommitSummary,
) -> Result<(), PolicyError> {
    let committer = commit.committer_account();

    // A member who lost access may only leave: anything else would let it ratchet
    // into epochs it must not read before its pending removal is committed.
    let leaving = commit.removes.iter().any(|r| r.account == committer);
    if !policy.admits(&committer, server) && !leaving {
        return Err(deny("not permitted in this channel"));
    }
    if !commit.adds.is_empty() {
        return Err(deny("private channels are joined, not added to"));
    }
    for removal in &commit.removes {
        let allowed = removal.proposed_by_relay
            || removal.account == committer
            || server.policy.has(&committer, MANAGE_CHANNELS)
            || !policy.admits(&removal.account, server);
        if !allowed {
            return Err(deny("cannot remove a permitted member from this channel"));
        }
    }
    let changes_policy = commit.new_channel_policy.as_ref().is_some_and(|new| new != policy);
    if changes_policy && !server.policy.has(&committer, MANAGE_CHANNELS) {
        return Err(deny("changing who may join needs the manage channels permission"));
    }
    let retargets = commit
        .new_channel_policy
        .as_ref()
        .is_some_and(|new| new.server_mailbox != policy.server_mailbox || new.channel_id != policy.channel_id);
    if retargets {
        return Err(deny("a channel's server and id are fixed"));
    }
    if commit.new_server_policy.is_some() {
        return Err(deny("a channel group carries no server policy"));
    }
    Ok(())
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn bytes(&mut self, n: usize) -> Result<&'a [u8], PolicyError> {
        let end = self.pos.checked_add(n).filter(|end| *end <= self.data.len());
        let end = end.ok_or_else(|| PolicyError::Format("truncated".into()))?;
        let out = &self.data[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, PolicyError> {
        Ok(self.bytes(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, PolicyError> {
        Ok(u16::from_be_bytes(self.bytes(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32, PolicyError> {
        Ok(u32::from_be_bytes(self.bytes(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64, PolicyError> {
        Ok(u64::from_be_bytes(self.bytes(8)?.try_into().unwrap()))
    }

    fn array32(&mut self) -> Result<[u8; 32], PolicyError> {
        Ok(self.bytes(32)?.try_into().unwrap())
    }

    fn version(&mut self) -> Result<(), PolicyError> {
        match self.u8()? {
            POLICY_VERSION => Ok(()),
            v => Err(PolicyError::Format(format!("unknown version {v:#x}"))),
        }
    }

    fn finish(&self) -> Result<(), PolicyError> {
        if self.pos == self.data.len() {
            Ok(())
        } else {
            Err(PolicyError::Format("trailing bytes".into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNER: [u8; 32] = [1; 32];
    const MOD: [u8; 32] = [2; 32];
    const HELPER: [u8; 32] = [3; 32];
    const MEMBER: [u8; 32] = [4; 32];
    const MAILBOX: [u8; 32] = [9; 32];

    /// Owner; "mod" role (id 10, kick + manage roles + manage channels) above "helper" (id 20, invite).
    fn policy() -> ServerPolicy {
        ServerPolicy {
            owner: OWNER,
            everyone: 0,
            roles: vec![
                Role { id: 10, permissions: KICK | MANAGE_ROLES | MANAGE_CHANNELS | INVITE },
                Role { id: 20, permissions: INVITE },
            ],
            assignments: vec![(MOD, vec![10]), (HELPER, vec![20])],
        }
    }

    fn by(committer: [u8; 32]) -> CommitSummary {
        CommitSummary {
            committer: Committer::Member(committer),
            adds: vec![],
            removes: vec![],
            new_server_policy: None,
            new_channel_policy: None,
        }
    }

    fn removing(committer: [u8; 32], target: [u8; 32]) -> CommitSummary {
        let mut c = by(committer);
        c.removes.push(Removal { account: target, proposed_by_relay: false });
        c
    }

    fn ctx<'a>(member_device: &'a dyn Fn(&[u8; 32], &[u8; 32]) -> bool) -> GrantContext<'a> {
        GrantContext { server_mailbox: MAILBOX, now_millis: 1000, is_member_device: member_device }
    }

    fn any_device(_: &[u8; 32], _: &[u8; 32]) -> bool {
        true
    }

    #[test]
    fn codecs_roundtrip_and_reject_malformed() {
        let p = policy();
        assert_eq!(ServerPolicy::from_bytes(&p.to_bytes()).unwrap(), p);
        let mut bytes = p.to_bytes();
        bytes.push(0);
        assert!(ServerPolicy::from_bytes(&bytes).is_err());
        let mut dup = p.clone();
        dup.roles.push(Role { id: 10, permissions: 0 });
        assert!(ServerPolicy::from_bytes(&dup.to_bytes()).is_err());

        let c = ChannelPolicy { server_mailbox: MAILBOX, channel_id: [7; 32], roles: vec![10], accounts: vec![MEMBER] };
        assert_eq!(ChannelPolicy::from_bytes(&c.to_bytes()).unwrap(), c);
        let key = SigningKey::from_bytes(&[5; 32]);
        let g = InviteGrant::sign(MAILBOX, HELPER, 2000, [7; 16], &key);
        assert_eq!(InviteGrant::from_bytes(&g.to_bytes()).unwrap(), g);
    }

    #[test]
    fn admitted_channels_roundtrip() {
        let listing = AdmittedChannels(vec![([1; 32], vec![9, 9]), ([2; 32], vec![])]);
        assert_eq!(AdmittedChannels::from_bytes(&listing.to_bytes()).unwrap(), listing);
        assert!(AdmittedChannels::from_bytes(&[0, 1]).is_err(), "truncated");
    }

    #[test]
    fn server_view_roundtrip() {
        let view = ServerView { policy: policy(), members: vec![OWNER, MOD] };
        assert_eq!(ServerView::from_bytes(&view.to_bytes()).unwrap(), view);
    }

    #[test]
    fn commit_aad_roundtrip() {
        assert_eq!(CommitAad::from_bytes(&[]).unwrap(), CommitAad::default());
        let key = SigningKey::from_bytes(&[5; 32]);
        let aad = CommitAad { invite: Some(InviteGrant::sign(MAILBOX, HELPER, 2000, [7; 16], &key)), server_epoch: Some(42) };
        assert_eq!(CommitAad::from_bytes(&aad.to_bytes()).unwrap(), aad);
        assert!(CommitAad::from_bytes(&[0x09, 0, 0]).is_err(), "unknown tag");
    }

    #[test]
    fn permissions_and_rank() {
        let p = policy();
        assert_eq!(p.permissions(&OWNER), ALL_PERMISSIONS);
        assert!(p.has(&MOD, KICK));
        assert!(!p.has(&HELPER, KICK));
        assert!(!p.has(&MEMBER, INVITE), "everyone holds nothing here");
        assert!(p.rank(&OWNER).outranks(p.rank(&MOD)));
        assert!(p.rank(&MOD).outranks(p.rank(&HELPER)));
        assert!(p.rank(&HELPER).outranks(p.rank(&MEMBER)));
        assert!(!p.rank(&MEMBER).outranks(p.rank(&MEMBER)));
        assert!(ServerPolicy::implicit(OWNER).has(&MEMBER, INVITE), "legacy servers let anyone invite");
    }

    #[test]
    fn removals_need_kick_and_rank() {
        let p = policy();
        let c = ctx(&any_device);
        authorize_server_commit(&p, &removing(MOD, HELPER), &c).unwrap();
        authorize_server_commit(&p, &removing(OWNER, MOD), &c).unwrap();
        assert!(authorize_server_commit(&p, &removing(HELPER, MEMBER), &c).is_err(), "no kick permission");
        assert!(authorize_server_commit(&p, &removing(MOD, OWNER), &c).is_err(), "owner is protected");
        let mut peer = p.clone();
        peer.assignments.push((MEMBER, vec![10]));
        assert!(authorize_server_commit(&peer, &removing(MOD, MEMBER), &c).is_err(), "equal rank");
        // Leaving or removing one's own device, and relay removals, need nothing.
        authorize_server_commit(&p, &removing(MEMBER, MEMBER), &c).unwrap();
        let mut relay = by(MEMBER);
        relay.removes.push(Removal { account: MOD, proposed_by_relay: true });
        authorize_server_commit(&p, &relay, &c).unwrap();
    }

    #[test]
    fn external_joins_need_a_valid_invite_unless_already_member() {
        let p = policy();
        let helper_key = SigningKey::from_bytes(&[5; 32]);
        let helper_vk = helper_key.verifying_key().to_bytes();
        let member_device = move |a: &[u8; 32], d: &[u8; 32]| *a == HELPER && *d == helper_vk;
        let c = ctx(&member_device);
        let join = |grant: Option<InviteGrant>, already_member: bool| CommitSummary {
            committer: Committer::Joiner { account: [8; 32], already_member, grant },
            ..by([8; 32])
        };

        authorize_server_commit(&p, &join(None, true), &c).unwrap();
        assert!(authorize_server_commit(&p, &join(None, false), &c).is_err());

        let good = InviteGrant::sign(MAILBOX, HELPER, 2000, [1; 16], &helper_key);
        authorize_server_commit(&p, &join(Some(good.clone()), false), &c).unwrap();

        let expired = InviteGrant::sign(MAILBOX, HELPER, 500, [1; 16], &helper_key);
        assert!(authorize_server_commit(&p, &join(Some(expired), false), &c).is_err());
        let other_server = InviteGrant::sign([0; 32], HELPER, 2000, [1; 16], &helper_key);
        assert!(authorize_server_commit(&p, &join(Some(other_server), false), &c).is_err());
        let mut tampered = good.clone();
        tampered.expires_at = 9999;
        assert!(authorize_server_commit(&p, &join(Some(tampered), false), &c).is_err());
        // Signed by a key that is not a member device, or by someone who may not invite.
        let stranger = SigningKey::from_bytes(&[6; 32]);
        let foreign = InviteGrant::sign(MAILBOX, HELPER, 2000, [1; 16], &stranger);
        assert!(authorize_server_commit(&p, &join(Some(foreign), false), &c).is_err());
        let mut no_invite = p.clone();
        no_invite.roles[1].permissions = 0;
        assert!(authorize_server_commit(&no_invite, &join(Some(good), false), &c).is_err());
    }

    #[test]
    fn adds_need_invite() {
        let p = policy();
        let c = ctx(&any_device);
        let mut add = by(HELPER);
        add.adds.push([8; 32]);
        authorize_server_commit(&p, &add, &c).unwrap();
        let mut add = by(MEMBER);
        add.adds.push([8; 32]);
        assert!(authorize_server_commit(&p, &add, &c).is_err());
    }

    #[test]
    fn role_changes_stay_below_the_committer() {
        let p = policy();
        let c = ctx(&any_device);
        let change = |committer, new: ServerPolicy| {
            let mut s = by(committer);
            s.new_server_policy = Some(new);
            authorize_server_commit(&p, &s, &c)
        };

        // The mod may grant the helper role to a member and edit the helper role.
        let mut grant = p.clone();
        grant.assignments.push((MEMBER, vec![20]));
        change(MOD, grant).unwrap();
        let mut edit = p.clone();
        edit.roles[1].permissions = INVITE | KICK;
        change(MOD, edit).unwrap();

        // ...but not touch its own role, give permissions it lacks, or promote to its rank.
        let mut own = p.clone();
        own.roles[0].permissions = ALL_PERMISSIONS & !KICK;
        assert!(change(MOD, own).is_err());
        let mut promote = p.clone();
        promote.assignments.push((MEMBER, vec![10]));
        assert!(change(MOD, promote).is_err());
        let mut transfer = p.clone();
        transfer.owner = MOD;
        assert!(change(MOD, transfer).is_err());
        assert!(change(HELPER, p.clone()).is_ok(), "an unchanged policy is no change");
        let mut by_helper = p.clone();
        by_helper.assignments.push((MEMBER, vec![20]));
        assert!(change(HELPER, by_helper).is_err(), "no manage roles");

        // The owner may do anything well-formed.
        let mut anything = p.clone();
        anything.owner = MOD;
        change(OWNER, anything).unwrap();
    }

    #[test]
    fn private_channel_rules() {
        let server = ServerView { policy: policy(), members: vec![OWNER, MOD, HELPER, MEMBER] };
        let channel = ChannelPolicy { server_mailbox: MAILBOX, channel_id: [7; 32], roles: vec![20], accounts: vec![] };
        let join = |account| CommitSummary {
            committer: Committer::Joiner { account, already_member: false, grant: None },
            ..by(account)
        };
        authorize_channel_commit(&channel, &server, &join(HELPER)).unwrap();
        authorize_channel_commit(&channel, &server, &join(OWNER)).unwrap();
        assert!(authorize_channel_commit(&channel, &server, &join(MEMBER)).is_err());
        let listed = ChannelPolicy { accounts: vec![MEMBER], ..channel.clone() };
        authorize_channel_commit(&listed, &server, &join(MEMBER)).unwrap();
        let kicked = ServerView { members: vec![OWNER, MOD, HELPER], ..server.clone() };
        assert!(authorize_channel_commit(&listed, &kicked, &join(MEMBER)).is_err(), "server members only");

        // Someone who lost access may leave but not commit anything else.
        assert!(authorize_channel_commit(&channel, &server, &by(MEMBER)).is_err());
        authorize_channel_commit(&channel, &server, &removing(MEMBER, MEMBER)).unwrap();

        // Anyone may remove someone the policy no longer admits; others need manage channels.
        authorize_channel_commit(&channel, &server, &removing(HELPER, MEMBER)).unwrap();
        assert!(authorize_channel_commit(&listed, &server, &removing(HELPER, MEMBER)).is_err());
        authorize_channel_commit(&listed, &server, &removing(MOD, MEMBER)).unwrap();

        let mut add = by(HELPER);
        add.adds.push(MEMBER);
        assert!(authorize_channel_commit(&channel, &server, &add).is_err());
        let mut retarget = by(HELPER);
        retarget.new_channel_policy = Some(listed.clone());
        assert!(authorize_channel_commit(&channel, &server, &retarget).is_err());
        let mut retarget = by(MOD);
        retarget.new_channel_policy = Some(listed.clone());
        authorize_channel_commit(&channel, &server, &retarget).unwrap();
        retarget.new_channel_policy = Some(ChannelPolicy { server_mailbox: [8; 32], ..listed.clone() });
        assert!(authorize_channel_commit(&channel, &server, &retarget).is_err(), "server is fixed");
        retarget.new_channel_policy = Some(ChannelPolicy { channel_id: [8; 32], ..listed });
        assert!(authorize_channel_commit(&channel, &server, &retarget).is_err(), "channel id is fixed");
    }
}
