//! Who may change a group, decided identically by the relay (before accepting a
//! commit) and by every member (before merging one). Policies are MLS GroupContext
//! extensions, so they are part of the state all members agree on; callers summarise
//! what a commit does and these functions decide whether it is allowed.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use thiserror::Error;

use crate::bytes::{put_prefixed16, put_prefixed32, ReadError, Reader};

/// GroupContext extension carrying a server's roles (private-use range).
pub const SERVER_POLICY_EXTENSION: u16 = 0xFF10;
/// GroupContext extension carrying a private channel's access list.
pub const CHANNEL_POLICY_EXTENSION: u16 = 0xFF11;
/// GroupContext extension listing accounts removed from a server, which may not rejoin
/// until someone who may kick lets them back in.
pub const SERVER_REMOVALS_EXTENSION: u16 = 0xFF12;
/// Most accounts a server's removed list holds; the oldest give way to newer ones, as in
/// Signal. The list travels in the group state every member republishes after each
/// change, so it stays small: about 40 bytes an entry.
pub const MAX_REMOVED: usize = 256;
/// How far a removal's time may run ahead of the verifier's clock.
pub const REMOVAL_CLOCK_SKEW_MS: u64 = 10 * 60 * 1000;

pub const INVITE: u32 = 1;
pub const KICK: u32 = 1 << 1;
pub const MANAGE_CHANNELS: u32 = 1 << 2;
pub const MANAGE_ROLES: u32 = 1 << 3;
/// Every defined permission; the owner holds all of them.
pub const ALL_PERMISSIONS: u32 = INVITE | KICK | MANAGE_CHANNELS | MANAGE_ROLES;

const POLICY_VERSION: u8 = 0x01;
const REMOVALS_VERSION: u8 = 0x01;
const GRANT_VERSION: u8 = 0x01;
const GRANT_SIGN_PREFIX: &[u8] = b"ghost-invite-grant-v1:";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("policy encoding: {0}")]
    Format(String),
    #[error("not permitted: {0}")]
    Denied(String),
    /// The account was removed from the server and has not been let back in.
    #[error("removed from this server: someone who may kick must let them back in")]
    Removed,
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

    /// This policy without any role assignments for `accounts`.
    pub fn without_assignments(&self, accounts: &[[u8; 32]]) -> Self {
        let mut policy = self.clone();
        policy.assignments.retain(|(account, _)| !accounts.contains(account));
        policy
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
        expect_version(&mut r, POLICY_VERSION)?;
        let owner = r.array()?;
        let everyone = r.u32()?;
        let role_count = r.u8()? as usize;
        let mut roles = Vec::with_capacity(role_count);
        for _ in 0..role_count {
            roles.push(Role { id: r.u8()?, permissions: r.u32()? });
        }
        let assign_count = r.u16()? as usize;
        let mut assignments = Vec::with_capacity(assign_count);
        for _ in 0..assign_count {
            let account = r.array()?;
            let count = r.u8()? as usize;
            assignments.push((account, r.take(count)?.to_vec()));
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

/// One account removed from a server, and when.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemovedAccount {
    pub account: [u8; 32],
    pub removed_at: u64,
}

/// Accounts removed from a server that may not rejoin, oldest first.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RemovedAccounts {
    pub entries: Vec<RemovedAccount>,
}

impl RemovedAccounts {
    pub fn contains(&self, account: &[u8; 32]) -> bool {
        self.entries.iter().any(|e| e.account == *account)
    }

    /// This list with `account` added as removed at `removed_at`, the oldest entries
    /// giving way when it is full.
    pub fn with_removed(&self, account: [u8; 32], removed_at: u64) -> Self {
        let mut entries: Vec<RemovedAccount> = self.entries.iter().filter(|e| e.account != account).copied().collect();
        entries.push(RemovedAccount { account, removed_at });
        entries.sort_by_key(|e| e.removed_at);
        let excess = entries.len().saturating_sub(MAX_REMOVED);
        entries.drain(..excess);
        Self { entries }
    }

    /// This list with `account` let back in.
    pub fn without(&self, account: &[u8; 32]) -> Self {
        Self { entries: self.entries.iter().filter(|e| e.account != *account).copied().collect() }
    }

    /// `[version][count:2] count × [account:32][removed_at:8]`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(3 + self.entries.len() * 40);
        buf.push(REMOVALS_VERSION);
        buf.extend_from_slice(&(self.entries.len() as u16).to_be_bytes());
        for entry in &self.entries {
            buf.extend_from_slice(&entry.account);
            buf.extend_from_slice(&entry.removed_at.to_be_bytes());
        }
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, PolicyError> {
        let mut r = Reader::new(data);
        expect_version(&mut r, REMOVALS_VERSION)?;
        let count = r.u16()? as usize;
        let entries = (0..count)
            .map(|_| Ok(RemovedAccount { account: r.array()?, removed_at: r.u64()? }))
            .collect::<Result<_, PolicyError>>()?;
        r.finish()?;
        let list = Self { entries };
        list.check_well_formed()?;
        Ok(list)
    }

    /// At most `MAX_REMOVED` entries, one per account.
    pub fn check_well_formed(&self) -> Result<(), PolicyError> {
        if self.entries.len() > MAX_REMOVED {
            return Err(PolicyError::Format("removed list too long".into()));
        }
        for (i, entry) in self.entries.iter().enumerate() {
            if self.entries[..i].iter().any(|e| e.account == entry.account) {
                return Err(PolicyError::Format("account removed twice".into()));
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
        put_prefixed32(&mut buf, &policy);
        buf.extend_from_slice(&(self.members.len() as u16).to_be_bytes());
        for account in &self.members {
            buf.extend_from_slice(account);
        }
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, PolicyError> {
        let mut r = Reader::new(data);
        let policy = ServerPolicy::from_bytes(r.prefixed32()?)?;
        let count = r.u16()? as usize;
        let members = (0..count).map(|_| r.array()).collect::<Result<_, _>>()?;
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
        expect_version(&mut r, POLICY_VERSION)?;
        let server_mailbox = r.array()?;
        let channel_id = r.array()?;
        let role_count = r.u8()? as usize;
        let roles = r.take(role_count)?.to_vec();
        let account_count = r.u16()? as usize;
        let mut accounts = Vec::with_capacity(account_count);
        for _ in 0..account_count {
            accounts.push(r.array()?);
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
            put_prefixed32(&mut buf, group_info);
        }
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, PolicyError> {
        let mut r = Reader::new(data);
        let count = r.u16()? as usize;
        let mut channels = Vec::with_capacity(count);
        for _ in 0..count {
            let mailbox = r.array()?;
            channels.push((mailbox, r.prefixed32()?.to_vec()));
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
        expect_version(&mut r, POLICY_VERSION)?;
        let grant = Self {
            server_mailbox: r.array()?,
            issuer_account: r.array()?,
            issuer_device: r.array()?,
            expires_at: r.u64()?,
            nonce: r.array()?,
            signature: r.array()?,
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
            put_prefixed16(&mut buf, value);
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
        while !r.is_empty() {
            let tag = r.u8()?;
            let value = r.prefixed16()?;
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
    /// Accounts with no leaf left once this commit is merged.
    pub departed: Vec<[u8; 32]>,
    /// The ServerPolicy after this commit, when the commit changes it.
    pub new_server_policy: Option<ServerPolicy>,
    /// The ChannelPolicy after this commit, when the commit changes it.
    pub new_channel_policy: Option<ChannelPolicy>,
    /// The server's removed list after this commit, when the group carries one.
    pub new_removed: Option<RemovedAccounts>,
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
    /// The server's removed list before the commit; empty when it carries none.
    pub removed: &'a RemovedAccounts,
}

/// Decide whether a commit to a server group is allowed under `policy`, the policy
/// in force before the commit.
pub fn authorize_server_commit(policy: &ServerPolicy, commit: &CommitSummary, ctx: &GrantContext) -> Result<(), PolicyError> {
    let committer = commit.committer_account();
    let removed_after = commit.new_removed.as_ref().unwrap_or(ctx.removed);

    if let Committer::Joiner { account, already_member, grant } = &commit.committer {
        if !already_member {
            if ctx.removed.contains(account) {
                return Err(PolicyError::Removed);
            }
            let grant = grant.as_ref().ok_or_else(|| deny("joining needs an invite"))?;
            check_grant(policy, grant, ctx)?;
        }
    }

    // Someone with the right to let a removed account back in can re-add it in the same
    // commit that clears it; otherwise it stays out.
    if commit.adds.iter().any(|account| removed_after.contains(account)) {
        return Err(PolicyError::Removed);
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

    if let Some(new) = &commit.new_removed {
        authorize_removed_change(policy, ctx.removed, new, commit, &committer, ctx.now_millis)?;
    }
    if let Some(new) = &commit.new_server_policy {
        // The roles of an account leaving with this commit, or let back in by it, go with
        // it, so a returning member never quietly regains them.
        let cleared = ctx.removed.entries.iter().map(|e| e.account).filter(|a| !removed_after.contains(a));
        let gone: Vec<[u8; 32]> = commit.departed.iter().copied().chain(cleared).collect();
        authorize_policy_change(&policy.without_assignments(&gone), new, &committer)?;
    }
    if commit.new_channel_policy.is_some() {
        return Err(deny("a server group carries no channel policy"));
    }
    Ok(())
}

/// A change to the removed list by `committer`: only with KICK; an account may be added
/// only by the commit that removes it, and at a time that is not ahead of the clock.
/// Entries may go (let back in, or dropped for room) with KICK alone.
fn authorize_removed_change(
    policy: &ServerPolicy,
    old: &RemovedAccounts,
    new: &RemovedAccounts,
    commit: &CommitSummary,
    committer: &[u8; 32],
    now_millis: u64,
) -> Result<(), PolicyError> {
    if new == old {
        return Ok(());
    }
    new.check_well_formed()?;
    if !policy.has(committer, KICK) {
        return Err(deny("changing who may rejoin needs the kick permission"));
    }
    for entry in new.entries.iter().filter(|e| !old.entries.contains(e)) {
        let kicked = commit.removes.iter().any(|r| r.account == entry.account && !r.proposed_by_relay && r.account != *committer);
        if !kicked || !commit.departed.contains(&entry.account) {
            return Err(deny("only an account this commit removes can be kept from rejoining"));
        }
        if entry.removed_at > now_millis.saturating_add(REMOVAL_CLOCK_SKEW_MS) {
            return Err(deny("removal time is ahead of the clock"));
        }
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
        // Nobody but the owner changes their own roles: with the manage roles permission
        // held through `everyone`, a plain member could otherwise take the top role.
        if account == *committer {
            return Err(deny("cannot change your own roles"));
        }
        if !old.rank(committer).outranks(old.rank(&account)) {
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

/// The version byte a policy encoding starts with.
fn expect_version(r: &mut Reader, expected: u8) -> Result<(), PolicyError> {
    match r.u8()? {
        v if v == expected => Ok(()),
        v => Err(PolicyError::Format(format!("unknown version {v:#x}"))),
    }
}

impl From<ReadError> for PolicyError {
    fn from(e: ReadError) -> Self {
        PolicyError::Format(e.to_string())
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
            departed: vec![],
            new_server_policy: None,
            new_channel_policy: None,
            new_removed: None,
        }
    }

    fn removing(committer: [u8; 32], target: [u8; 32]) -> CommitSummary {
        let mut c = by(committer);
        c.removes.push(Removal { account: target, proposed_by_relay: false });
        c.departed.push(target);
        c
    }

    const NONE_REMOVED: &RemovedAccounts = &RemovedAccounts { entries: Vec::new() };

    fn ctx<'a>(member_device: &'a dyn Fn(&[u8; 32], &[u8; 32]) -> bool) -> GrantContext<'a> {
        GrantContext { server_mailbox: MAILBOX, now_millis: 1000, is_member_device: member_device, removed: NONE_REMOVED }
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
        assert!(ServerPolicy::new(OWNER).has(&MEMBER, INVITE), "a new server lets anyone invite");
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
    fn nobody_but_the_owner_changes_their_own_roles() {
        let mut p = policy();
        p.everyone |= MANAGE_ROLES;
        let c = ctx(&any_device);
        let change = |committer, new: ServerPolicy| {
            let mut s = by(committer);
            s.new_server_policy = Some(new);
            authorize_server_commit(&p, &s, &c)
        };
        // A plain member holding manage roles through `everyone` outranks nobody, so it
        // changes nobody's roles: not another member's, and not its own.
        let mut grant = p.clone();
        grant.assignments.push(([8; 32], vec![20]));
        assert!(change(MEMBER, grant).is_err());
        let mut promote_self = p.clone();
        promote_self.assignments.push((MEMBER, vec![10]));
        assert!(change(MEMBER, promote_self).is_err());
        // Nor may a mod drop or add one of its own roles.
        let mut demote_self = p.clone();
        demote_self.assignments.retain(|(account, _)| *account != MOD);
        assert!(change(MOD, demote_self).is_err());
    }

    fn removed(accounts: &[[u8; 32]]) -> RemovedAccounts {
        accounts.iter().fold(RemovedAccounts::default(), |list, account| list.with_removed(*account, 900))
    }

    #[test]
    fn removed_lists_round_trip_and_name_each_account_once() {
        let list = removed(&[MEMBER, HELPER]);
        assert_eq!(RemovedAccounts::from_bytes(&list.to_bytes()).unwrap(), list);
        let twice = RemovedAccounts { entries: vec![RemovedAccount { account: MEMBER, removed_at: 1 }; 2] };
        assert!(twice.check_well_formed().is_err());
    }

    #[test]
    fn a_full_removed_list_drops_its_oldest_entry() {
        let account = |i: usize| {
            let mut a = [0u8; 32];
            a[..8].copy_from_slice(&(i as u64).to_be_bytes());
            a
        };
        let full = (0..MAX_REMOVED).fold(RemovedAccounts::default(), |list, i| list.with_removed(account(i), i as u64));
        let newer = full.with_removed([0xEE; 32], MAX_REMOVED as u64);
        assert_eq!(newer.entries.len(), MAX_REMOVED);
        assert!(newer.contains(&[0xEE; 32]));
        assert!(!newer.contains(&account(0)), "the oldest gave way");
    }

    #[test]
    fn a_kick_can_keep_only_the_account_it_removes_out() {
        let p = policy();
        let c = ctx(&any_device);
        let mut kick = removing(MOD, MEMBER);
        kick.new_removed = Some(removed(&[MEMBER]));
        authorize_server_commit(&p, &kick, &c).unwrap();

        let mut not_removed = by(MOD);
        not_removed.new_removed = Some(removed(&[MEMBER]));
        assert!(authorize_server_commit(&p, &not_removed, &c).is_err(), "only whom the commit removes");
        let mut no_kick = removing(MEMBER, MEMBER);
        no_kick.new_removed = Some(removed(&[MEMBER]));
        assert!(authorize_server_commit(&p, &no_kick, &c).is_err(), "leaving is no kick");
        let mut ahead = removing(MOD, MEMBER);
        ahead.new_removed = Some(RemovedAccounts::default().with_removed(MEMBER, 1000 + REMOVAL_CLOCK_SKEW_MS + 1));
        assert!(authorize_server_commit(&p, &ahead, &c).is_err(), "time ahead of the clock");
    }

    #[test]
    fn a_removed_account_stays_out_until_someone_who_may_kick_lets_it_back() {
        let p = policy();
        let list = removed(&[[8; 32]]);
        let c = GrantContext { removed: &list, ..ctx(&any_device) };
        let helper_key = SigningKey::from_bytes(&[5; 32]);
        let grant = InviteGrant::sign(MAILBOX, HELPER, 2000, [1; 16], &helper_key);
        let join = CommitSummary { committer: Committer::Joiner { account: [8; 32], already_member: false, grant: Some(grant) }, ..by([8; 32]) };
        assert_eq!(authorize_server_commit(&p, &join, &c), Err(PolicyError::Removed), "a valid invite is not enough");
        let mut add = by(HELPER);
        add.adds.push([8; 32]);
        assert_eq!(authorize_server_commit(&p, &add, &c), Err(PolicyError::Removed));

        let mut let_back_by_helper = by(HELPER);
        let_back_by_helper.new_removed = Some(RemovedAccounts::default());
        assert!(authorize_server_commit(&p, &let_back_by_helper, &c).is_err(), "needs the kick permission");
        let mut let_back_and_add = by(MOD);
        let_back_and_add.adds.push([8; 32]);
        let_back_and_add.new_removed = Some(RemovedAccounts::default());
        authorize_server_commit(&p, &let_back_and_add, &c).unwrap();
    }

    #[test]
    fn a_kick_takes_the_members_roles_with_them() {
        let mut p = policy();
        p.roles[0].permissions = KICK;
        let c = ctx(&any_device);
        let mut kick = removing(MOD, HELPER);
        kick.new_server_policy = Some(p.without_assignments(&[HELPER]));
        authorize_server_commit(&p, &kick, &c).unwrap();

        let mut and_more = removing(MOD, HELPER);
        let mut grant = p.without_assignments(&[HELPER]);
        grant.assignments.push((MEMBER, vec![20]));
        and_more.new_server_policy = Some(grant);
        assert!(authorize_server_commit(&p, &and_more, &c).is_err(), "other role changes still need manage roles");
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
