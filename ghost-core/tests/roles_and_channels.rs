//! End-to-end tests for roles and private channels against an in-process relay: the
//! relay refuses what the server policy forbids, members refuse it too, and private
//! channels stay hidden from members they do not admit.

mod common;

use std::collections::VecDeque;
use std::time::Duration;

use common::{create_account, create_server, Account};
use ghost_core::client::{ChannelOpOutcome, ReceiveResult};
use ghost_core::deferred::DeferredBlobs;
use ghost_core::error::GhostError;
use ghost_core::flows;
use ghost_core::relay::{RelayClient, RelayEvent};
use ghost_core::storage::ChannelKind;
use ghost_core::wire::{decode_metadata, derive_default_channel_id, MetadataPayload, UNNAMED_PRIVATE_CHANNEL};
use ghost_wire::policy::{Role, ServerPolicy, KICK, MANAGE_CHANNELS};

/// How long a mailbox must stay quiet before `drain` stops waiting.
const IDLE: Duration = Duration::from_millis(1500);

/// Process every blob on `mailboxes` for `account` from its last seen sequence until
/// none arrives for a while, as the application does: private channel commits that
/// need a newer server group are held in `deferred` and retried once it catches up,
/// channel operations are applied, and info requests are answered. Returns what each
/// blob did, in processing order.
async fn drain(account: &Account, relay_url: &str, mailboxes: &[[u8; 32]], deferred: &mut DeferredBlobs) -> Vec<String> {
    let (mut reader, mut events) = RelayClient::new(relay_url);
    reader.copy_auth_from(&*account.relay.lock().await);
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
        let mut c = account.client.lock().await;
        let Some(channel_id) = c.channel_id_for_mailbox(&blob.mailbox_id) else { continue };
        let result = c.receive_any(&channel_id, &blob.payload, Some(blob.received_at));
        let mut reply = None;
        let outcome = match result {
            Err(GhostError::PolicyBehind { server_mailbox, epoch }) => {
                deferred.hold(blob, server_mailbox, epoch);
                seen.push("deferred".to_string());
                continue;
            }
            Ok(ReceiveResult::Message(m)) | Ok(ReceiveResult::MessageWithKtWarning(m)) => match decode_metadata(&m.content) {
                Ok(MetadataPayload::ChannelOp(op)) if m.message_type == ghost_core::crypto::MessageType::Metadata => {
                    match c.apply_channel_op(&channel_id, &m.sender_fp, op).unwrap() {
                        ChannelOpOutcome::Applied => "channel op".to_string(),
                        ChannelOpOutcome::Ignored => "channel op ignored".to_string(),
                        ChannelOpOutcome::Reply(out) => {
                            reply = Some(out);
                            "info request".to_string()
                        }
                    }
                }
                _ => format!("message {}", String::from_utf8_lossy(&m.content)),
            },
            Ok(ReceiveResult::CommitProcessed) | Ok(ReceiveResult::MembersRemoved(_)) => "commit".to_string(),
            Ok(ReceiveResult::ProposalProcessed) => "proposal".to_string(),
            Ok(ReceiveResult::ChannelAccessLost(_)) => "access lost".to_string(),
            Ok(ReceiveResult::Kicked) => "kicked".to_string(),
            Ok(ReceiveResult::DeviceRemoved) => "device removed".to_string(),
            Ok(ReceiveResult::Skipped) => "skipped".to_string(),
            Err(e) => format!("error: {e}"),
        };
        let _ = c.store().set_last_seen_seq(&blob.mailbox_id, blob.seq);
        ready.extend(deferred.take_ready(&c));
        drop(c);
        if let Some(out) = reply {
            account.relay.lock().await.post_blob(&out.mailbox_id, out.blob).await.unwrap();
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
    let invite = flows::invite::create(&inviter.client, &inviter.relay, server_id, u64::MAX).await.unwrap();
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
    let (_, commits, _) = outsider.client.lock().await.join_by_invite(&expired.sealed_payload, &expired.key, 2000).unwrap();
    let (_, commit, mailbox_id) = &commits[0];
    assert_refused(outsider.relay.lock().await.post_blob(mailbox_id, commit.clone()).await, 403);
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
    let bobs = flows::invite::create(&bob.client, &bob.relay, &server_id, u64::MAX).await.unwrap();

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
    assert!(matches!(refused, Err(GhostError::PermissionDenied(_))), "a member merged a forbidden kick");
    assert_refused(carol.relay.lock().await.post_blob(&server_mailbox, forged).await, 403);
    carol.client.lock().await.clear_pending_commit_for_channel(&default_channel).unwrap();

    // Bob may not kick the owner, who outranks him, but may kick Carol.
    let err = flows::members::kick(&bob.client, &bob.relay, &server_id, &owner.fp).await.unwrap_err();
    assert!(matches!(err, GhostError::PermissionDenied(_)), "{err}");
    assert!(flows::members::kick(&bob.client, &bob.relay, &server_id, &carol.fp).await.unwrap());
    let seen = drain(&carol, &relay_url, &[server_mailbox], &mut DeferredBlobs::default()).await;
    assert!(seen.contains(&"kicked".to_string()), "{seen:?}");
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
    assert_refused(carol.relay.lock().await.get_server_info(&channel_mailbox).await, 403);

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

    // Bob loses the role. The relay proposes his removal; until a member commits it,
    // nobody encrypts to the channel.
    drain(&owner, &relay_url, &[server_mailbox, channel_mailbox], &mut owner_deferred).await;
    let mut policy = owner.client.lock().await.server_policy(&server_id).unwrap();
    policy.assignments.retain(|(account, _)| *account != bob.fp);
    flows::roles::set_server_policy(&owner.client, &owner.relay, &server_id, &policy).await.unwrap();
    let seen = drain(&owner, &relay_url, &[channel_mailbox], &mut owner_deferred).await;
    assert!(seen.contains(&"proposal".to_string()), "{seen:?}");
    let refused = owner.client.lock().await.send_message(&server_id, &channel_id, b"secret".to_vec(), vec![], 6000);
    assert!(matches!(refused, Err(GhostError::PermissionDenied(_))), "sent to a channel holding an excluded member");
    let commit = owner.client.lock().await.commit_pending_proposals(&channel_id).unwrap().expect("the relay's removal is committable");
    owner.relay.lock().await.post_blob(&commit.mailbox_id, commit.blob).await.unwrap();
    owner.client.lock().await.merge_pending_commit_for_channel(&channel_id).unwrap();
    let (message, _) = owner.client.lock().await.send_message(&server_id, &channel_id, b"secret".to_vec(), vec![], 6000).unwrap();
    owner.relay.lock().await.post_blob(&message.mailbox_id, message.blob).await.unwrap();

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
    assert_refused(bob.relay.lock().await.put_server_info(&created.mailbox_id, created.group_info).await, 403);
}
