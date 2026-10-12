//! Policy checks over OpenMLS commits: turn a staged commit into a `CommitSummary`
//! and decide it. The relay runs this before accepting a commit and every client
//! before merging one, so both enforce exactly the same rules.

use openmls::prelude::*;

use crate::policy::{
    authorize_channel_commit, authorize_server_commit, ChannelPolicy, CommitAad, CommitSummary, Committer,
    GrantContext, PolicyError, Removal, RemovedAccounts, ServerPolicy, ServerView, CHANNEL_POLICY_EXTENSION,
    SERVER_POLICY_EXTENSION, SERVER_REMOVALS_EXTENSION,
};

/// Account fingerprint carried in a Ghost credential (its first 32 bytes).
pub fn account_of(credential: &Credential) -> Option<[u8; 32]> {
    let basic = BasicCredential::try_from(credential.clone()).ok()?;
    basic.identity().get(..32)?.try_into().ok()
}

/// The policies a group's context extensions carry.
pub fn policies(ext: &Extensions<GroupContext>) -> Result<(Option<ServerPolicy>, Option<ChannelPolicy>), PolicyError> {
    let server = ext.unknown(SERVER_POLICY_EXTENSION).map(|e| ServerPolicy::from_bytes(&e.0)).transpose()?;
    let channel = ext.unknown(CHANNEL_POLICY_EXTENSION).map(|e| ChannelPolicy::from_bytes(&e.0)).transpose()?;
    Ok((server, channel))
}

/// The removed list a server group's context extensions carry.
pub fn removed_accounts(ext: &Extensions<GroupContext>) -> Result<Option<RemovedAccounts>, PolicyError> {
    ext.unknown(SERVER_REMOVALS_EXTENSION).map(|e| RemovedAccounts::from_bytes(&e.0)).transpose()
}

/// Accounts in the group, each once.
pub fn member_accounts(members: &[Member]) -> Vec<[u8; 32]> {
    let mut accounts: Vec<[u8; 32]> = Vec::new();
    for account in members.iter().filter_map(|m| account_of(&m.credential)) {
        if !accounts.contains(&account) {
            accounts.push(account);
        }
    }
    accounts
}

/// The policy a server group is governed by: every server group carries one from its
/// creation.
pub fn server_policy(extensions: &Extensions<GroupContext>, _members: &[Member]) -> Result<ServerPolicy, PolicyError> {
    match policies(extensions)? {
        (Some(policy), _) => Ok(policy),
        (None, _) => Err(denied("the group carries no server policy")),
    }
}

/// A server group's policy and members, for judging its private channels.
pub fn server_view(extensions: &Extensions<GroupContext>, members: &[Member]) -> Result<ServerView, PolicyError> {
    Ok(ServerView { policy: server_policy(extensions, members)?, members: member_accounts(members) })
}

/// Leaves of a private channel group whose accounts its policy no longer admits.
pub fn excluded_leaves(channel: &ChannelPolicy, server: &ServerView, members: &[Member]) -> Vec<LeafNodeIndex> {
    members
        .iter()
        .filter(|m| account_of(&m.credential).is_none_or(|account| !channel.admits(&account, server)))
        .map(|m| m.index)
        .collect()
}

/// Looks up a server group's view at an epoch of it, for judging private channel
/// commits; fails with `ContextBehind` when the caller has not reached that epoch.
pub type ServerAt<'a> = &'a dyn Fn(&[u8; 32], u64) -> Result<ServerView, PolicyError>;

/// What the check needs to know about the group as it was before the commit.
pub struct GroupFacts<'a> {
    pub extensions: &'a Extensions<GroupContext>,
    pub members: &'a [Member],
    /// This group's mailbox, which invite grants for it name.
    pub mailbox: [u8; 32],
    pub now_millis: u64,
}

fn denied(msg: &str) -> PolicyError {
    PolicyError::Denied(msg.into())
}

fn member_account(members: &[Member], index: LeafNodeIndex) -> Result<[u8; 32], PolicyError> {
    members
        .iter()
        .find(|m| m.index == index)
        .and_then(|m| account_of(&m.credential))
        .ok_or_else(|| denied("commit references an unknown leaf"))
}

fn summarize(
    sender: &Sender,
    staged: &StagedCommit,
    facts: &GroupFacts,
    aad: &CommitAad,
) -> Result<CommitSummary, PolicyError> {
    let committer = match sender {
        Sender::Member(index) => Committer::Member(member_account(facts.members, *index)?),
        Sender::NewMemberCommit => {
            let leaf = staged.update_path_leaf_node().ok_or_else(|| denied("external commit without a leaf"))?;
            let account = account_of(leaf.credential()).ok_or_else(|| denied("joiner has no Ghost credential"))?;
            let already_member = facts.members.iter().any(|m| account_of(&m.credential) == Some(account));
            Committer::Joiner { account, already_member, grant: aad.invite.clone() }
        }
        _ => return Err(denied("unexpected committer")),
    };
    let adds = staged
        .add_proposals()
        .map(|p| account_of(p.add_proposal().key_package().leaf_node().credential()).ok_or_else(|| denied("added member has no Ghost credential")))
        .collect::<Result<Vec<_>, _>>()?;
    let removes = staged
        .remove_proposals()
        .map(|p| {
            Ok(Removal {
                account: member_account(facts.members, p.remove_proposal().removed())?,
                proposed_by_relay: matches!(p.sender(), Sender::External(_)),
            })
        })
        .collect::<Result<Vec<_>, PolicyError>>()?;
    // An account departs when every one of its leaves is removed.
    let removed_leaves: Vec<LeafNodeIndex> = staged.remove_proposals().map(|p| p.remove_proposal().removed()).collect();
    let mut departed: Vec<[u8; 32]> = Vec::new();
    for removal in &removes {
        let every_leaf_removed = facts
            .members
            .iter()
            .filter(|m| account_of(&m.credential) == Some(removal.account))
            .all(|m| removed_leaves.contains(&m.index));
        if every_leaf_removed && !departed.contains(&removal.account) {
            departed.push(removal.account);
        }
    }
    Ok(CommitSummary { committer, adds, removes, departed, new_server_policy: None, new_channel_policy: None, new_removed: None })
}

/// Decide a staged commit under the group's policy; `server_at` serves private
/// channel groups.
pub fn check_commit(
    sender: &Sender,
    staged: &StagedCommit,
    aad_bytes: &[u8],
    facts: &GroupFacts,
    server_at: ServerAt,
) -> Result<(), PolicyError> {
    let aad = CommitAad::from_bytes(aad_bytes)?;
    // The only external sender is the group's relay, which removes revoked or excluded devices.
    let external_non_remove = staged
        .queued_proposals()
        .any(|p| matches!(p.sender(), Sender::External(_)) && !matches!(p.proposal(), Proposal::Remove(_)));
    if external_non_remove {
        return Err(denied("the relay may only propose removals"));
    }
    let mut summary = summarize(sender, staged, facts, &aad)?;
    let (old_server, old_channel) = policies(facts.extensions)?;
    let (new_server, new_channel) = policies(staged.group_context().extensions())?;
    let old_removed = removed_accounts(facts.extensions)?;
    let new_removed = removed_accounts(staged.group_context().extensions())?;

    if let Some(channel) = old_channel {
        if new_removed.is_some() {
            return Err(denied("a channel group carries no removed list"));
        }
        let Some(new_channel) = new_channel else {
            return Err(denied("a channel policy cannot be removed"));
        };
        let epoch = aad.server_epoch.ok_or_else(|| denied("channel commits must name the server epoch"))?;
        let server = server_at(&channel.server_mailbox, epoch)?;
        summary.new_channel_policy = Some(new_channel);
        summary.new_server_policy = new_server;
        return authorize_channel_commit(&channel, &server, &summary);
    }

    if old_server.is_some() && new_server.is_none() {
        return Err(denied("a server policy cannot be removed"));
    }
    if old_removed.is_some() && new_removed.is_none() {
        return Err(denied("a removed list cannot be dropped"));
    }
    let policy = server_policy(facts.extensions, facts.members)?;
    let removed = old_removed.unwrap_or_default();
    summary.new_server_policy = new_server;
    summary.new_channel_policy = new_channel;
    summary.new_removed = new_removed;
    let is_member_device = |account: &[u8; 32], device: &[u8; 32]| {
        facts
            .members
            .iter()
            .any(|m| m.signature_key.as_slice() == device && account_of(&m.credential).as_ref() == Some(account))
    };
    let ctx = GrantContext { server_mailbox: facts.mailbox, now_millis: facts.now_millis, is_member_device: &is_member_device, removed: &removed };
    authorize_server_commit(&policy, &summary, &ctx)
}
