# Ghost roles, channels and private channels

Status: implemented 2026-10-07. Policy is carried in MLS group state, enforced by the relay and verified by every member; private channels are hidden from members they do not admit.

## 1. Goals

- Every channel works: text and voice, created at any time.
- Roles with permissions, Discord-style: granting a role grants access, revoking it removes access.
- Private channels: only permitted accounts can read them, and members without access never learn they exist.
- Every rule is enforced twice. The relay refuses unauthorized commits (an infrastructure barrier). Every member's device refuses to merge them (a cryptographic barrier: commits are signed by members and the policy is part of the agreed group state, so a relay cannot forge an authorized change).
- The relay learns no names: server, channel and role names travel only inside encrypted messages and encrypted invite payloads.

Precedents (verified, see the research notes in `.claude/HYBRID_IMPLEMENTATION.md` §P):
- RFC 9420 §12.4: receivers reject commits the sender was not permitted to make.
- RFC 9420 §16.11: the delivery service may also enforce.
- draft-ietf-mimi-room-policy-04: roles and capabilities carried in group state.
- XMTP: permissions in a custom GroupContext extension, checked by every client.
- Wire: server-enforced roles; external joins only for new devices of existing members.

## 2. Groups

| Space | MLS group | Mailbox |
|---|---|---|
| Server, all public channels | one group per server (the default channel's group id) | `H(group_id)` |
| Private channel | one group per private channel, id `derive_mls_group_id(server_id, channel_id)` | `H(group_id)` |

Public channels carry no group of their own:
- Messages name their channel inside the encrypted payload (`ApplicationMessage.channel_id`).
- Voice keys mix the channel id into their derivation, so each voice channel is keyed separately.

## 3. Policy objects

Both objects are MLS GroupContext extensions in the private-use range.
- Every Ghost leaf advertises support for both types in its capabilities.
- Every policy-carrying group lists them in `required_capabilities` (RFC 9420 §11.1), which OpenMLS requires before a group may carry them.
- A group never carries both.

### 3.1 ServerPolicy (extension 0xFF10, in the server group)

```
[version:1 = 0x01]
[owner:32]                         account fingerprint; may do everything
[everyone:4]                       permission bits every member holds
[role_count:1]  role_count × Role  listed by rank, highest first
[assign_count:2] assign_count × Assignment

Role:       [role_id:1][permissions:4]
Assignment: [account:32][count:1] count × [role_id:1]
```

Permission bits: `INVITE = 1`, `KICK = 2`, `MANAGE_CHANNELS = 4`, `MANAGE_ROLES = 8`.
- An account's permissions are `everyone` together with its roles' permissions.
- The owner holds all permissions.
- An account's rank is the rank of its highest role. The owner outranks everyone; having no role ranks lowest.
- A new server's policy is `{owner: creator, everyone: INVITE, no roles}`.

Role names are not in the policy. They travel as encrypted `RoleName` metadata messages in the server group, accepted only from senders holding MANAGE_ROLES. Invite, provisioning and sync payloads also carry them.

**Groups made before policies.** Such a group is treated as carrying the implicit policy `{owner: account at the group's leftmost leaf, everyone: INVITE, no roles}`.
- The leftmost leaf is the creator's first device unless that device was removed.
- Every verifier derives the same owner from the same tree.
- The implicit policy lasts until the migration in §6.5.

### 3.2 ChannelPolicy (extension 0xFF11, in a private channel group)

```
[version:1 = 0x01]
[server_mailbox:32]                mailbox of the server group whose roles apply
[channel_id:32]                    the channel; with the server id it derives the group id
[role_count:1]  role_count × [role_id:1]
[account_count:2] account_count × [account:32]
```

An account is admitted if it is a member of the server group and any of the following holds:
- it holds MANAGE_CHANNELS (so every channel stays manageable from inside);
- it is listed;
- it holds a listed role.

Leaving or being kicked from the server therefore ends access, whatever stale assignments remain.

`server_mailbox` and `channel_id` never change. The relay already sees channel ids (voice routing). The channel id lets a joiner check that `group_id = derive_mls_group_id(server_id, channel_id)`. The relay never learns the server id, so neither it nor an outsider can fabricate a channel that passes this check.

## 4. Authorization rules

`ghost-wire/src/policy.rs` holds the rules and `ghost-wire/src/policy_mls.rs` applies them to OpenMLS commits.
- The relay runs `check_commit` before accepting a commit; every client runs it before merging one.
- A commit is checked against the policy in force before it; a commit that changes the policy is checked against the old policy.
- The group's relay is its only external sender, and it may only propose removals.

### 4.1 Server group

- **Add proposals:** the committer holds INVITE.
- **Remove proposals:** each removal is allowed if any of the following holds:
  - it removes a leaf of the committer's own account (leaving, or removing one's own device);
  - the committer holds KICK, the target is not the owner, and the committer outranks the target;
  - the relay proposed it (revoked devices).
- **External join:** allowed if the joiner's account already has a leaf (a new device of a member), or the commit's authenticated data carries a valid InviteGrant (§5).
- **ServerPolicy change:** the committer holds MANAGE_ROLES. A restated, unchanged policy is not a change. Beyond that:
  - only the owner changes the owner;
  - a non-owner may only create, change, assign or unassign roles ranked below its own;
  - a non-owner may not give a role or `everyone` permissions it does not hold itself.

### 4.2 Private channel group

- **Committer:** must be admitted, except to remove its own account's leaves. This keeps a member who lost access from ratcheting into epochs it must not read before its removal is committed.
- **External join:** the joiner is admitted.
- **Add proposals:** refused; joins are by external commit only.
- **Remove proposals:** each removal is allowed if any of the following holds:
  - it removes the committer's own account;
  - the committer holds MANAGE_CHANNELS;
  - the removed account is no longer admitted;
  - the relay proposed it.
- **ChannelPolicy change:** the committer holds MANAGE_CHANNELS. The server mailbox and channel id stay fixed.
- **Creation:** the relay builds a private channel group from its first uploaded GroupInfo only if the uploader holds MANAGE_CHANNELS in the server group it names, and that server group is on the same relay.

### 4.3 Judging a channel commit by the right server state

A private channel commit is judged by the server group's state, which lives in another group and advances independently.
- Every commit to a private channel carries, as authenticated data, the server group epoch it was made at.
- The relay accepts it only if that is the server group's current epoch. Otherwise it answers 409, and the committer catches up and retries.
- Each client records the server group's policy and member list at every epoch where they change, and judges a channel commit by the state at the epoch it names.
- A client whose server group is behind that epoch holds the channel's blobs back, in order, until the server group catches up. Mailboxes arrive independently, so a channel commit can overtake the server commit that granted the access it relies on.

Commit authenticated data: `[tag:1][len:2][value]…`, tag 1 = InviteGrant, tag 2 = server epoch (u64).

## 5. Invites

```
InviteGrant:
  [version:1 = 0x01]
  [server_mailbox:32]
  [issuer_account:32][issuer_device:32]
  [expires_at:8]                     milliseconds
  [nonce:16]
  [signature:64]                     by issuer_device over "ghost-invite-grant-v1:" ‖ preceding bytes
```

A grant is valid when all of the following hold:
- the signature verifies;
- `issuer_device` is a leaf of `issuer_account` in the server group;
- the issuer holds INVITE under the current policy;
- it has not expired: the relay checks against its clock, members against the relay's receive time.

An issuer who loses INVITE, or leaves, voids its invites. Deleting the invite token on the relay also ends an invite: joining needs current GroupInfo, which non-members can only get through the token.

The invite payload stored on the relay holds the server's name, members, public channels, role names and the grant.
- It is sealed with a 32-byte key that travels only in the link: `ghost://join?relay=…&r=…&token=…&k=<key>`.
- The relay therefore never sees those names.
- Each joiner re-seals the payload with fresh GroupInfo and the same grant for the next joiner.

## 6. Lifecycle

### 6.1 Creating a server
The group is created with `required_capabilities` and the ServerPolicy `{owner: creator, everyone: INVITE}`.

### 6.2 Creating a private channel
1. The creator (MANAGE_CHANNELS) creates the channel group with a ChannelPolicy and uploads its GroupInfo. The relay authorizes it (§4.2).
2. The creator sends the channel's name and kind as a metadata message inside the channel group.
3. Nothing is sent to the server group, so members without access learn nothing.
4. The creator's other devices are told through the sync group and join through discovery.

### 6.3 Discovering and joining
`GET /servers/{server_mailbox}/channels` (device-authenticated, members of the server group only) returns the private channel groups whose policy admits the requesting account, with their GroupInfo.

Devices query it at these points:
- at start;
- after every server group commit;
- when a linked device announces a change;
- before moving a server.

They join what they may by external commit, after checking the group id derivation and their own admission.

A joiner cannot read anything sent before it joined, the channel's name included.
1. After joining, it sends an `InfoRequest` inside the channel group.
2. Members who know the name answer with `Create`.
3. Until one does, the channel shows as "private channel".
4. A `Create` is applied from anyone while the channel is unnamed, and from channel managers otherwise.

Public channel creates, renames and deletes are applied only from senders holding MANAGE_CHANNELS. Private channels are renamed and deleted only inside their own group.

### 6.4 Losing access
After every commit, the relay finds the leaves the affected channels no longer admit and issues external Remove proposals for them, using the removal key it already holds. Affected channels are:
- for a server group commit, every private channel of that server;
- for a private channel commit, that channel.

Members commit pending proposals. A device accepts an external Remove only if the target device is revoked in its identity log, or the target's leaf is one the channel's policy excludes.

Before sending to a private channel, a device first removes any member the policy excludes, and it never encrypts to a group that still contains one.

A device removed from a group may still read that group's mailbox up to the commit that removed it, and no further. That is how a device that was offline learns of its removal. A device removed from a private channel forgets the channel; its server membership is unaffected.

### 6.5 Migrating existing groups
Leaves created before this specification do not advertise the policy extensions, and a group may only require them once every leaf does.
1. On start, each device commits an update of its own leaf with the new capabilities.
2. When every leaf of a server group advertises them, the implicit owner's device commits `required_capabilities` and an explicit ServerPolicy equal to the implicit one.
3. Until then the implicit policy (§3.1) applies, and the member list shows how many members have not yet updated.

### 6.6 Moving a server
- Moves and move records follow the ServerPolicy owner, so ownership transfers carry the right to move.
- Before moving, the owner joins every private channel it is admitted to (all of them, through MANAGE_CHANNELS).
- The server group is moved first. The target relay admits private channel groups only under a server group it holds, and their external-sender commits name the moved server group's epoch.

## 7. What this does not prevent

- A relay can refuse service or split a group; members detect a split, as today.
- A member can leak what it can read.
- Policy changes take effect from the commit that makes them; messages sent before are readable by whoever was in the group then.
- A relay that colludes with a member who lacks MANAGE_CHANNELS can create a private channel group that admits whoever it lists. Members accept it only if its id derives from the server id, so the colluding member must be a member who knows the server id. That member could post in public channels anyway.
- In a group made before policies whose creator's first device was removed before migration, the implicit owner is whoever holds the leftmost leaf until the explicit policy is committed.
