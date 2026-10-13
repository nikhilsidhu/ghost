//! End-to-end tests for roles and private channels against an in-process relay: the
//! relay refuses what the server policy forbids, members refuse it too, and private
//! channels stay hidden from members they do not admit.

mod common;

use std::collections::VecDeque;
use std::time::Duration;

use common::{create_account, create_server, Account};
use ghost_core::client::ReceiveResult;
use ghost_core::deferred::DeferredBlobs;
use ghost_core::error::GhostError;
use ghost_core::flows;
use ghost_core::relay::{RelayClient, RelayEvent};
use ghost_core::storage::ChannelKind;
use ghost_core::wire::{derive_default_channel_id, encode_channel_op, ChannelOpPayload, UNNAMED_PRIVATE_CHANNEL};
use ghost_wire::policy::{Role, ServerPolicy, KICK, MANAGE_CHANNELS};

/// How long a mailbox must stay quiet before `drain` stops waiting.
const IDLE: Duration = Duration::from_millis(1500);

/// Process every blob on `mailboxes` for `account` from its last seen sequence until
/// none arrives for a while, as the application does: private channel commits that
/// need a newer server group are held in `deferred` and retried once it catches up,
/// channel operations are applied, and info requests are answered. Returns what each
/// blob did, in processing order.
async fn drain(account: &Account, relay_url: &str, mailboxes: &[[u8; 32]], deferred: &mut DeferredBlobs) -> Vec<String> {
    let (reader, mut events) = RelayClient::new(relay_url);
    reader.copy_auth_from(&account.relay);
    for mailbox_id in mailboxes {
        let since = account.client.lock().await.store().get_last_seen_seq(mailbox_id).unwrap_or(0);
        reader.subscribe(*mailbox_id, since);
    }
    let mut seen = Vec::new();
    let mut ready = VecDeque::new();
    loop {
        let blob = match ready.pop_front() {
            Some(blob) => blob,
            None => match tokio::time::timeout(IDLE, events.recv()).await {
                Ok(Some(RelayEvent::Blob(blob))) => blob,
                Ok(Some(_)) => continue,
                Ok(None) | Err(_) => break,
            },
        };
        if deferred.is_waiting(&blob.mailbox_id) {
            deferred.queue(blob);
            continue;
        }
        let Some(channel_id) = account.client.lock().await.channel_id_for_mailbox(&blob.mailbox_id) else { continue };
        let result = common::receive_like_session(&account.client, &account.relay, &channel_id, &blob).await;
        let c = account.client.lock().await;
        let mut reply = None;
        let outcome = match result {
            Err(GhostError::PolicyBehind { server_mailbox, epoch }) => {
                deferred.hold(blob, server_mailbox, epoch);
                seen.push("deferred".to_string());
                continue;
            }
            // Applied by the client as it read it, as the session's is.
            Ok(ReceiveResult::Metadata(applied)) => match applied.reply {
                Some(out) => {
                    reply = Some(out);
                    "info request".to_string()
                }
                None if applied.channel_changed => "channel op".to_string(),
                None => "metadata".to_string(),
            },
            Ok(ReceiveResult::Message(m)) => format!("message {}", String::from_utf8_lossy(&m.content)),
            Ok(ReceiveResult::CommitProcessed) | Ok(ReceiveResult::MembersRemoved(_)) => "commit".to_string(),
            Ok(ReceiveResult::ProposalProcessed) => "proposal".to_string(),
            Ok(ReceiveResult::ChannelAccessLost(_)) => "access lost".to_string(),
            Ok(ReceiveResult::Kicked { by }) => {
                // As the session does: the server stays, read-only, naming the remover.
                let server_id = c.server_id_for_mailbox(&blob.mailbox_id).unwrap();
                c.store().mark_server_removed(&server_id, Some(&by), 7000).unwrap();
                "kicked".to_string()
            }
            Ok(ReceiveResult::DeviceRemoved) => "device removed".to_string(),
            Ok(ReceiveResult::Skipped) => "skipped".to_string(),
            Ok(ReceiveResult::Unreadable) => "unreadable".to_string(),
            Err(e) => format!("error: {e}"),
        };
        let _ = c.store().set_last_seen_seq(&blob.mailbox_id, blob.seq);
        ready.extend(deferred.take_ready(&c));
        drop(c);
        if let Some(out) = reply {
            account.relay.post_blob(&out.mailbox_id, out.blob).await.unwrap();
        }
        seen.push(outcome);
    }
    seen
}

/// Join `joiner` to the server through an invite from `inviter`, who first catches up
/// so the invite carries the server group's current GroupInfo.
async fn invite(inviter: &Account, relay_url: &str, joiner: &Account, server_id: &[u8; 32]) {
    let server_mailbox = inviter.client.lock().await.server_mailbox(server_id).unwrap();
    drain(inviter, relay_url, &[server_mailbox], &mut DeferredBlobs::default()).await;
    let invite = flows::invite::create(&inviter.client, &inviter.relay, server_id, None).await.unwrap();
    flows::invite::join(&joiner.client, &joiner.relay, &joiner.relay, &invite.token, &invite.key, 2000).await.unwrap();
}

fn assert_refused<T>(result: Result<T, GhostError>, status: u16) {
    match result {
        Err(GhostError::RelayStatus { status: got, .. }) if got == status => {}
        Err(e) => panic!("expected HTTP {status}, got {e}"),
        Ok(_) => panic!("expected HTTP {status}, but the relay accepted"),
    }
}

#[tokio::test]
async fn relay_refuses_a_join_whose_grant_expired() {
    let relay_url = common::start_relay().await;
    let owner = create_account(&relay_url, "owner").await;
    let outsider = create_account(&relay_url, "outsider").await;
    let server_id = create_server(&owner, "club").await;

    let expired = owner.client.lock().await.create_invite(&server_id, 1).unwrap();
    let payload = outsider.client.lock().await.open_invite(&expired.sealed_payload, &expired.key).unwrap();
    let group_info = owner.client.lock().await.export_server_info(&server_id).unwrap();
    let (_, commits, _) = outsider.client.lock().await.join_by_invite(payload, group_info, 2000).unwrap();
    let (_, commit, mailbox_id) = &commits[0];
    assert_refused(outsider.relay.post_blob(mailbox_id, commit.clone()).await, 403);
}

#[tokio::test]
async fn invites_stop_working_when_their_issuer_loses_the_invite_permission() {
    let relay_url = common::start_relay().await;
    let owner = create_account(&relay_url, "owner").await;
    let bob = create_account(&relay_url, "bob").await;
    let carol = create_account(&relay_url, "carol").await;
    let server_id = create_server(&owner, "club").await;
    invite(&owner, &relay_url, &bob, &server_id).await;

    // Everyone may invite under a new server's policy, so Bob's invite is valid when made.
    let bobs = flows::invite::create(&bob.client, &bob.relay, &server_id, None).await.unwrap();

    let mut deferred = DeferredBlobs::default();
    let server_mailbox = owner.client.lock().await.server_mailbox(&server_id).unwrap();
    drain(&owner, &relay_url, &[server_mailbox], &mut deferred).await;
    let mut policy = owner.client.lock().await.server_policy(&server_id).unwrap();
    policy.everyone = 0;
    flows::roles::set_server_policy(&owner.client, &owner.relay, &server_id, &policy).await.unwrap();

    let err = flows::invite::join(&carol.client, &carol.relay, &carol.relay, &bobs.token, &bobs.key, 3000).await.unwrap_err();
    assert!(matches!(err, GhostError::RelayStatus { status: 403, .. }), "{err}");
}

#[tokio::test]
async fn kicking_needs_the_permission_and_a_higher_rank() {
    let relay_url = common::start_relay().await;
    let owner = create_account(&relay_url, "owner").await;
    let bob = create_account(&relay_url, "bob").await;
    let carol = create_account(&relay_url, "carol").await;
    let server_id = create_server(&owner, "club").await;
    invite(&owner, &relay_url, &bob, &server_id).await;
    invite(&owner, &relay_url, &carol, &server_id).await;
    let server_mailbox = owner.client.lock().await.server_mailbox(&server_id).unwrap();
    let default_channel = derive_default_channel_id(&server_id);

    // Bob becomes a moderator who may kick.
    let mut deferred = DeferredBlobs::default();
    drain(&owner, &relay_url, &[server_mailbox], &mut deferred).await;
    let mut policy = owner.client.lock().await.server_policy(&server_id).unwrap();
    policy.roles.push(Role { id: 1, permissions: KICK });
    policy.assignments.push((bob.fp, vec![1]));
    flows::roles::set_server_policy(&owner.client, &owner.relay, &server_id, &policy).await.unwrap();
    drain(&bob, &relay_url, &[server_mailbox], &mut DeferredBlobs::default()).await;
    drain(&carol, &relay_url, &[server_mailbox], &mut DeferredBlobs::default()).await;

    // Carol may not kick: her client refuses, and a commit built anyway is refused by
    // the relay and by every member.
    let err = flows::members::kick(&carol.client, &carol.relay, &server_id, &bob.fp).await.unwrap_err();
    assert!(matches!(err, GhostError::PermissionDenied(_)), "{err}");
    let forged = {
        let mut c = carol.client.lock().await;
        let bob_leaves = c.find_device_leaves(&default_channel, &bob.device_vk);
        c.remove_channel_members(&default_channel, &bob_leaves).unwrap()
    };
    let refused = owner.client.lock().await.receive_any(&default_channel, &forged, Some(4000));
    assert!(matches!(refused, Err(GhostError::PolicyRefused(_))), "a member merged a forbidden kick");
    assert_refused(carol.relay.post_blob(&server_mailbox, forged).await, 403);
    carol.client.lock().await.clear_pending_commit_for_channel(&default_channel).unwrap();

    // Bob may not kick the owner, who outranks him, but may kick Carol. A message Carol
    // had queued is not sent again once she is out.
    let err = flows::members::kick(&bob.client, &bob.relay, &server_id, &owner.fp).await.unwrap_err();
    assert!(matches!(err, GhostError::PermissionDenied(_)), "{err}");
    let (_, queued) = carol.client.lock().await.send_message(&server_id, &default_channel, b"late".to_vec(), vec![], 6500).unwrap();
    flows::members::kick(&bob.client, &bob.relay, &server_id, &carol.fp).await.unwrap();
    let seen = drain(&carol, &relay_url, &[server_mailbox], &mut DeferredBlobs::default()).await;
    assert!(seen.contains(&"kicked".to_string()), "{seen:?}");

    // The owner, not caught up with Bob's kick, is told the server changed meanwhile.
    let err = flows::members::kick(&owner.client, &owner.relay, &server_id, &bob.fp).await.unwrap_err();
    assert!(matches!(err, GhostError::GroupMoved), "{err}");
    let err = flows::messages::resend(&carol.client, &carol.relay, queued).await.unwrap_err();
    assert!(matches!(err, GhostError::RemovedFromServer), "{err}");
}

#[tokio::test]
async fn private_channels_admit_by_role_and_stay_hidden_from_everyone_else() {
    let relay_url = common::start_relay().await;
    let owner = create_account(&relay_url, "owner").await;
    let bob = create_account(&relay_url, "bob").await;
    let carol = create_account(&relay_url, "carol").await;
    let server_id = create_server(&owner, "club").await;
    invite(&owner, &relay_url, &bob, &server_id).await;
    invite(&owner, &relay_url, &carol, &server_id).await;
    let server_mailbox = owner.client.lock().await.server_mailbox(&server_id).unwrap();
    let (mut owner_deferred, mut bob_deferred, mut carol_deferred) =
        (DeferredBlobs::default(), DeferredBlobs::default(), DeferredBlobs::default());

    // A "staff" role (no permissions of its own) for Bob, and a channel for that role.
    drain(&owner, &relay_url, &[server_mailbox], &mut owner_deferred).await;
    let mut policy = owner.client.lock().await.server_policy(&server_id).unwrap();
    policy.roles.push(Role { id: 1, permissions: 0 });
    policy.assignments.push((bob.fp, vec![1]));
    flows::roles::set_server_policy(&owner.client, &owner.relay, &server_id, &policy).await.unwrap();
    let channel_id = flows::channels::create_private(
        &owner.client, &owner.relay, &owner.relay, &server_id, "staff", ChannelKind::Text, vec![1], vec![],
    )
    .await
    .unwrap();
    let channel_mailbox = owner.client.lock().await.mailbox_id_for_channel(&channel_id).unwrap();

    // Carol is not admitted: the relay lists nothing and refuses the channel's state.
    drain(&carol, &relay_url, &[server_mailbox], &mut carol_deferred).await;
    assert!(flows::channels::join_admitted(&carol.client, &carol.relay, &server_id).await.unwrap().is_empty());
    assert_refused(carol.relay.get_server_info(&channel_mailbox).await, 403);

    // Bob is: he joins, asks for the name, and the owner's device answers.
    drain(&bob, &relay_url, &[server_mailbox], &mut bob_deferred).await;
    assert_eq!(flows::channels::join_admitted(&bob.client, &bob.relay, &server_id).await.unwrap(), vec![channel_id]);
    assert_eq!(bob.client.lock().await.store().get_channel(&channel_id).unwrap().name, UNNAMED_PRIVATE_CHANNEL);
    let seen = drain(&owner, &relay_url, &[channel_mailbox], &mut owner_deferred).await;
    assert!(seen.contains(&"info request".to_string()), "{seen:?}");
    drain(&bob, &relay_url, &[channel_mailbox], &mut bob_deferred).await;
    assert_eq!(bob.client.lock().await.store().get_channel(&channel_id).unwrap().name, "staff");

    // Carol gets the role. Bob reads her channel join before the server commit that
    // admitted her, so he holds it back until his server group catches up.
    drain(&owner, &relay_url, &[server_mailbox], &mut owner_deferred).await;
    let mut policy = owner.client.lock().await.server_policy(&server_id).unwrap();
    policy.assignments.push((carol.fp, vec![1]));
    flows::roles::set_server_policy(&owner.client, &owner.relay, &server_id, &policy).await.unwrap();
    drain(&carol, &relay_url, &[server_mailbox], &mut carol_deferred).await;
    assert_eq!(flows::channels::join_admitted(&carol.client, &carol.relay, &server_id).await.unwrap(), vec![channel_id]);
    let seen = drain(&bob, &relay_url, &[channel_mailbox], &mut bob_deferred).await;
    assert_eq!(seen.first().map(String::as_str), Some("deferred"), "{seen:?}");
    let seen = drain(&bob, &relay_url, &[server_mailbox], &mut bob_deferred).await;
    assert!(seen.iter().filter(|s| *s == "commit").count() >= 2, "server commit, then the held channel join: {seen:?}");
    assert!(!bob_deferred.is_waiting(&channel_mailbox));

    // Bob loses the role while the owner has a message queued. The relay proposes his
    // removal; until a member commits it, nobody encrypts to the channel, and sending the
    // queued message again removes him first.
    drain(&owner, &relay_url, &[server_mailbox, channel_mailbox], &mut owner_deferred).await;
    let (_, queued) = owner.client.lock().await.send_message(&server_id, &channel_id, b"queued".to_vec(), vec![], 5900).unwrap();
    let mut policy = owner.client.lock().await.server_policy(&server_id).unwrap();
    policy.assignments.retain(|(account, _)| *account != bob.fp);
    flows::roles::set_server_policy(&owner.client, &owner.relay, &server_id, &policy).await.unwrap();
    let seen = drain(&owner, &relay_url, &[channel_mailbox], &mut owner_deferred).await;
    assert!(seen.contains(&"proposal".to_string()), "{seen:?}");
    let refused = owner.client.lock().await.send_message(&server_id, &channel_id, b"secret".to_vec(), vec![], 6000);
    assert!(matches!(refused, Err(GhostError::PermissionDenied(_))), "sent to a channel holding an excluded member");
    assert!(!owner.client.lock().await.excluded_leaves(&channel_id).unwrap().is_empty());
    flows::messages::resend(&owner.client, &owner.relay, queued).await.unwrap();
    assert!(owner.client.lock().await.excluded_leaves(&channel_id).unwrap().is_empty(), "the resend left Bob in the channel");
    let (message, _) = owner.client.lock().await.send_message(&server_id, &channel_id, b"secret".to_vec(), vec![], 6000).unwrap();
    owner.relay.post_blob(&message.mailbox_id, message.blob).await.unwrap();

    let seen = drain(&bob, &relay_url, &[server_mailbox, channel_mailbox], &mut bob_deferred).await;
    assert!(seen.contains(&"access lost".to_string()), "{seen:?}");
    assert!(!seen.iter().any(|s| s.contains("secret")), "Bob read a message after losing access: {seen:?}");
    assert!(bob.client.lock().await.store().get_channel(&channel_id).is_err(), "Bob forgot the channel");
    let seen = drain(&carol, &relay_url, &[server_mailbox, channel_mailbox], &mut carol_deferred).await;
    assert!(seen.contains(&"message secret".to_string()), "{seen:?}");
}

#[tokio::test]
async fn relay_refuses_a_private_channel_from_someone_who_lost_manage_channels() {
    let relay_url = common::start_relay().await;
    let owner = create_account(&relay_url, "owner").await;
    let bob = create_account(&relay_url, "bob").await;
    let server_id = create_server(&owner, "club").await;
    invite(&owner, &relay_url, &bob, &server_id).await;
    let server_mailbox = owner.client.lock().await.server_mailbox(&server_id).unwrap();

    drain(&owner, &relay_url, &[server_mailbox], &mut DeferredBlobs::default()).await;
    let granted = {
        let mut p = owner.client.lock().await.server_policy(&server_id).unwrap();
        p.roles.push(Role { id: 1, permissions: MANAGE_CHANNELS });
        p.assignments.push((bob.fp, vec![1]));
        p
    };
    flows::roles::set_server_policy(&owner.client, &owner.relay, &server_id, &granted).await.unwrap();

    // A member without the permission is refused before anything is sent.
    let refused = owner.client.lock().await.server_policy(&server_id).unwrap();
    assert!(refused.has(&bob.fp, MANAGE_CHANNELS));
    let err = flows::channels::create_private(
        &bob.client, &bob.relay, &bob.relay, &server_id, "early", ChannelKind::Text, vec![], vec![],
    )
    .await
    .unwrap_err();
    assert!(matches!(err, GhostError::PermissionDenied(_)), "Bob's device has not seen the grant yet: {err}");

    // Bob's device learns of the grant and builds a channel, but the owner revokes the
    // permission before Bob uploads it: the relay refuses the group.
    drain(&bob, &relay_url, &[server_mailbox], &mut DeferredBlobs::default()).await;
    let created = bob
        .client
        .lock()
        .await
        .create_private_channel(&server_id, "late", ChannelKind::Text, 1, vec![], vec![])
        .unwrap();
    let revoked = ServerPolicy { roles: Vec::new(), assignments: Vec::new(), ..granted };
    flows::roles::set_server_policy(&owner.client, &owner.relay, &server_id, &revoked).await.unwrap();
    assert_refused(bob.relay.put_server_info(&created.mailbox_id, created.group_info).await, 403);
}

/// A server where Bob holds a role a private "staff" channel admits, and has joined that
/// channel and learned its name.
struct StaffServer {
    owner: Account,
    bob: Account,
    server_id: [u8; 32],
    channel_id: [u8; 32],
    server_mailbox: [u8; 32],
    channel_mailbox: [u8; 32],
}

async fn server_with_a_staff_channel(relay_url: &str) -> StaffServer {
    let owner = create_account(relay_url, "owner").await;
    let bob = create_account(relay_url, "bob").await;
    let server_id = create_server(&owner, "club").await;
    invite(&owner, relay_url, &bob, &server_id).await;
    let server_mailbox = owner.client.lock().await.server_mailbox(&server_id).unwrap();
    drain(&owner, relay_url, &[server_mailbox], &mut DeferredBlobs::default()).await;
    let mut policy = owner.client.lock().await.server_policy(&server_id).unwrap();
    policy.roles.push(Role { id: 1, permissions: 0 });
    policy.assignments.push((bob.fp, vec![1]));
    flows::roles::set_server_policy(&owner.client, &owner.relay, &server_id, &policy).await.unwrap();
    let channel_id = flows::channels::create_private(&owner.client, &owner.relay, &owner.relay, &server_id, "staff", ChannelKind::Text, vec![1], vec![])
        .await
        .unwrap();
    let channel_mailbox = owner.client.lock().await.mailbox_id_for_channel(&channel_id).unwrap();
    drain(&bob, relay_url, &[server_mailbox], &mut DeferredBlobs::default()).await;
    assert_eq!(flows::channels::join_admitted(&bob.client, &bob.relay, &server_id).await.unwrap(), vec![channel_id]);
    drain(&owner, relay_url, &[channel_mailbox], &mut DeferredBlobs::default()).await;
    drain(&bob, relay_url, &[channel_mailbox], &mut DeferredBlobs::default()).await;
    assert_eq!(bob.client.lock().await.store().get_channel(&channel_id).unwrap().name, "staff");
    StaffServer { owner, bob, server_id, channel_id, server_mailbox, channel_mailbox }
}

async fn position_of(account: &Account, channel_id: &[u8; 32]) -> i32 {
    account.client.lock().await.store().get_channel(channel_id).unwrap().position
}

/// Every member stores the place the manager gave each channel, the private channel among
/// the public ones included, and a channel made after a deletion shares its place with none.
#[tokio::test]
async fn members_place_channels_where_the_manager_put_them() {
    let relay_url = common::start_relay().await;
    let s = server_with_a_staff_channel(&relay_url).await;
    let general = derive_default_channel_id(&s.server_id);
    let news = flows::channels::create(&s.owner.client, &s.owner.relay, &s.server_id, "news", ChannelKind::Text).await.unwrap();
    let events = flows::channels::create(&s.owner.client, &s.owner.relay, &s.server_id, "events", ChannelKind::Text).await.unwrap();

    let order = [news, s.channel_id, general, events];
    flows::channels::reorder(&s.owner.client, &s.owner.relay, &s.server_id, &order).await.unwrap();
    drain(&s.bob, &relay_url, &[s.server_mailbox, s.channel_mailbox], &mut DeferredBlobs::default()).await;
    for (position, channel_id) in order.iter().enumerate() {
        assert_eq!(position_of(&s.owner, channel_id).await, position as i32);
        assert_eq!(position_of(&s.bob, channel_id).await, position as i32, "Bob placed a channel elsewhere");
    }

    flows::channels::delete(&s.owner.client, &s.owner.relay, &news).await.unwrap();
    let later = flows::channels::create(&s.owner.client, &s.owner.relay, &s.server_id, "later", ChannelKind::Text).await.unwrap();
    drain(&s.bob, &relay_url, &[s.server_mailbox], &mut DeferredBlobs::default()).await;
    assert!(s.bob.client.lock().await.store().get_channel(&news).is_err(), "Bob kept the deleted channel");
    let owner_places: Vec<([u8; 32], i32)> = s.owner.client.lock().await.store().list_channels(&s.server_id).unwrap().iter().map(|c| (c.channel_id, c.position)).collect();
    let bob_places: Vec<([u8; 32], i32)> = s.bob.client.lock().await.store().list_channels(&s.server_id).unwrap().iter().map(|c| (c.channel_id, c.position)).collect();
    assert_eq!(bob_places, owner_places);
    let mut positions: Vec<i32> = owner_places.iter().map(|(_, position)| *position).collect();
    positions.dedup();
    assert_eq!(positions.len(), owner_places.len(), "two channels share a place: {owner_places:?}");
    assert_eq!(owner_places.last().map(|(channel_id, _)| *channel_id), Some(later));
}

/// A private channel deleted while its mailbox is still at the relay, as when deleting
/// it there failed, is not joined again from the relay's listing by a member who read
/// the deletion, and the deleting device deletes the mailbox at its next discovery.
#[tokio::test]
async fn a_deleted_private_channel_is_not_joined_again_and_its_mailbox_goes_at_the_next_discovery() {
    let relay_url = common::start_relay().await;
    let s = server_with_a_staff_channel(&relay_url).await;
    let delete = s
        .owner
        .client
        .lock()
        .await
        .send_control_in(&s.channel_id, encode_channel_op(&ChannelOpPayload::Delete { channel_id: s.channel_id }))
        .unwrap();
    s.owner.relay.post_blob(&delete.mailbox_id, delete.blob).await.unwrap();
    s.owner.client.lock().await.forget_deleted_private_channel(&s.channel_id, true).unwrap();

    let seen = drain(&s.bob, &relay_url, &[s.channel_mailbox], &mut DeferredBlobs::default()).await;
    assert!(seen.contains(&"channel op".to_string()), "{seen:?}");
    let listed = |listing: &ghost_wire::policy::AdmittedChannels| listing.0.iter().any(|(mailbox_id, _)| *mailbox_id == s.channel_mailbox);
    assert!(listed(&s.bob.relay.get_admitted_channels(&s.server_mailbox).await.unwrap()), "the relay still lists the channel");
    assert!(flows::channels::join_admitted(&s.bob.client, &s.bob.relay, &s.server_id).await.unwrap().is_empty());
    assert!(s.bob.client.lock().await.store().get_channel(&s.channel_id).is_err(), "Bob joined the deleted channel again");

    assert!(flows::channels::join_admitted(&s.owner.client, &s.owner.relay, &s.server_id).await.unwrap().is_empty());
    assert!(s.owner.client.lock().await.store().owed_channel_deletions(&s.server_id).unwrap().is_empty());
    assert!(!listed(&s.bob.relay.get_admitted_channels(&s.server_mailbox).await.unwrap()), "the relay lists the channel after its deletion");
}

/// A channel op from a device two commits behind is refused as stale. Never catching up,
/// it fails as the group having moved and nothing is created; catching up meanwhile, as
/// the session does, it is sealed again and lands.
#[tokio::test]
async fn a_channel_op_from_a_device_behind_lands_once_it_catches_up() {
    let relay_url = common::start_relay().await;
    let owner = create_account(&relay_url, "owner").await;
    let bob = create_account(&relay_url, "bob").await;
    let carol = create_account(&relay_url, "carol").await;
    let server_id = create_server(&owner, "club").await;
    invite(&owner, &relay_url, &bob, &server_id).await;
    invite(&bob, &relay_url, &carol, &server_id).await;
    let server_mailbox = owner.client.lock().await.server_mailbox(&server_id).unwrap();

    let err = flows::channels::create(&owner.client, &owner.relay, &server_id, "news", ChannelKind::Text).await.unwrap_err();
    assert!(matches!(err, GhostError::GroupMoved), "{err}");
    assert_eq!(owner.client.lock().await.store().list_channels(&server_id).unwrap().len(), 1, "a refused channel was kept");

    let catch_up = async {
        tokio::time::sleep(Duration::from_millis(300)).await;
        drain(&owner, &relay_url, &[server_mailbox], &mut DeferredBlobs::default()).await
    };
    let (created, _) = tokio::join!(flows::channels::create(&owner.client, &owner.relay, &server_id, "news", ChannelKind::Text), catch_up);
    let news = created.unwrap();
    drain(&bob, &relay_url, &[server_mailbox], &mut DeferredBlobs::default()).await;
    assert_eq!(bob.client.lock().await.store().get_channel(&news).unwrap().name, "news");
    assert_eq!(position_of(&bob, &news).await, position_of(&owner, &news).await);
}
