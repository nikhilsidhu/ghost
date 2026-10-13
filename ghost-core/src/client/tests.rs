use super::testing::*;

use crate::error::GhostError;
use crate::identity::Identity;
use crate::mls::group::GhostGroup;
use crate::storage::{Channel, ChannelKind, Delivery, Member, OnConflict, ServerKind};
use crate::wire::{derive_default_channel_id, InviteChannel, InviteMember, ServerStatePayload};
use ghost_wire::now_millis;
use super::*;

#[test]
fn imported_clocks_from_the_future_are_clamped_and_own_writes_still_get_ahead() {
    use crate::sync::clock::{from_millis, millis_of, MAX_CLOCK_SKEW_MS};
    let client = test_client([0x42; 32]);
    let far = from_millis(now_millis() + 3_600_000);
    client.sync_import(&[("pref:a".into(), Some(b"1".to_vec()), far)]).unwrap();
    let (_, stored) = client.sync_get("pref:a").unwrap().unwrap();
    assert!(stored < far && millis_of(stored) <= now_millis() + MAX_CLOCK_SKEW_MS);
    client.sync_observe(stored).unwrap();
    let own = client.sync_tick().unwrap();
    assert!(own > stored, "a write made here orders after the clamped clock");
    assert!(client.sync_set("pref:a", b"2", own).unwrap());
}

#[test]
fn open_deterministic_and_stores_accessible() {
    let a = test_client([0x01; 32]);
    let b = test_client([0x01; 32]);
    assert_eq!(a.fingerprint(), b.fingerprint());

    let c = test_client([0x02; 32]);
    assert_ne!(a.fingerprint(), c.fingerprint());

    // Store is functional
    assert!(a.store().list_servers().unwrap().is_empty());
}

#[test]
fn create_server_stores_records() {
    let mut client = test_client([0x01; 32]);
    let server_id = client.create_server("test-server", ServerKind::Server, 1000).unwrap();

    let server = client.store().get_server(&server_id).unwrap();
    assert_eq!(server.name, "test-server");
    assert_eq!(server.created_at, 1000);

    let channels = client.store().list_channels(&server_id).unwrap();
    assert_eq!(channels.len(), 1);
    assert_eq!(channels[0].name, "general");
    assert_eq!(channels[0].kind, ChannelKind::Text);
    assert_eq!(channels[0].channel_id, derive_default_channel_id(&server_id));

    let members = client.store().list_members(&server_id).unwrap();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].fingerprint, *client.fingerprint());
}

/// A server made here is unpublished until the relay holds it; undone, nothing of it
/// stays: no rows, no group in memory or in storage, no mailbox routed to it.
#[test]
fn a_server_made_here_is_unpublished_until_published_and_undone_whole() {
    let mut client = test_client([0x01; 32]);
    let server_id = client.create_server("club", ServerKind::Server, 1000).unwrap();
    let mailbox_id = client.mailbox_id_for_server(&server_id).unwrap();
    assert_eq!(client.store().unpublished_servers().unwrap(), vec![server_id]);

    client.abandon_created_server(&server_id).unwrap();
    assert!(client.store().get_server(&server_id).is_err());
    assert!(client.store().list_channels(&server_id).unwrap().is_empty());
    assert!(client.store().list_members(&server_id).unwrap().is_empty());
    assert!(client.store().unpublished_servers().unwrap().is_empty());
    assert!(client.mailbox_id_for_server(&server_id).is_none());
    assert!(client.channel_id_for_mailbox(&mailbox_id).is_none());
    let stored = GhostGroup::load(&client.provider, &client.identity, &server_id, &derive_default_channel_id(&server_id)).unwrap();
    assert!(stored.is_none(), "the group's state stayed in storage");

    let kept = client.create_server("club", ServerKind::Server, 2000).unwrap();
    client.store().server_published(&kept).unwrap();
    assert!(client.store().unpublished_servers().unwrap().is_empty());
}

#[test]
fn send_to_unknown_server_fails() {
    let mut client = test_client([0x01; 32]);
    let result = client.send_message(&[0xFF; 32], &[0xAA; 32], b"hi".to_vec(), vec![], 1000);
    assert!(matches!(result, Err(GhostError::ServerNotLoaded(_))));
}

#[test]
fn receive_from_unknown_server_fails() {
    let mut client = test_client([0x01; 32]);
    let result = client.receive_blob(&[0xFF; 32], &[0x00; 64], None);
    assert!(matches!(result, Err(GhostError::ServerNotLoaded(_))));
}

#[test]
fn no_group_is_made_without_the_relay_as_its_external_sender() {
    let identity = Identity::from_seed([0x05; 32]).unwrap();
    let mut client = GhostClient::open_in_memory(identity, [0x05; 32]).unwrap();
    assert!(matches!(client.create_server("early", ServerKind::Server, 1000), Err(GhostError::Network(_))));
    assert!(client.store().list_servers().unwrap().is_empty(), "a refused server left rows behind");
    client.set_relay_vk(TEST_RELAY_VK);
    client.create_server("later", ServerKind::Server, 1000).unwrap();
}

#[test]
fn a_message_sent_in_an_earlier_run_is_pending_again_at_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ghost.db");
    let identity = || Identity::from_seed([0x06; 32]).unwrap();
    let message_id = {
        let mut client = GhostClient::open(identity(), [0x06; 32], [0x16; 32], &path).unwrap();
        register_identity_in_cache(&mut client, &identity());
        client.set_relay_vk(TEST_RELAY_VK);
        let server_id = client.create_server("club", ServerKind::Server, 1000).unwrap();
        let (_, message_id) = client.send_message(&server_id, &derive_default_channel_id(&server_id), b"hi".to_vec(), vec![], 2000).unwrap();
        client.store().set_delivery(&message_id, Delivery::Sent).unwrap();
        message_id
    };
    let client = GhostClient::open(identity(), [0x06; 32], [0x16; 32], &path).unwrap();
    assert_eq!(client.store().get_message(&message_id).unwrap().delivery, Delivery::Pending);
}

#[test]
fn send_message_stores_in_db() {
    let (mut c1, _c2, server_id) = setup_two_clients();
    let channel_id = derive_default_channel_id(&server_id);

    let (_outbound, msg_id) = c1
        .send_message(&server_id, &channel_id, b"hello".to_vec(), vec![], 2000)
        .unwrap();

    let stored = c1.store().get_message(&msg_id).unwrap();
    assert_eq!(stored.content, b"hello");
    assert_eq!(stored.sender_fp, *c1.fingerprint());
    assert_eq!(stored.timestamp, 2000);
}

#[test]
fn send_receive_roundtrip() {
    let (mut c1, mut c2, server_id) = setup_two_clients();
    let channel_id = derive_default_channel_id(&server_id);

    let (outbound, msg_id) = c1
        .send_message(&server_id, &channel_id, b"hello".to_vec(), vec![], 2000)
        .unwrap();

    let received = c2.receive_blob(&channel_id, &outbound.blob, None).unwrap();
    assert_eq!(received.content, b"hello");
    assert_eq!(received.sender_fp, *c1.fingerprint());
    assert_eq!(received.message_id, msg_id);

    let stored = c2.store().get_message(&msg_id).unwrap();
    assert_eq!(stored.content, b"hello");
}

/// A rejoin the relay refuses leaves the group exactly as it was, in memory and in
/// storage; one the relay takes moves it on and leaves nothing of the old copy behind.
#[test]
fn a_refused_rejoin_leaves_the_group_as_it_was_and_an_accepted_one_moves_it_on() {
    let (mut c1, mut c2, server_id) = setup_two_clients();
    let channel_id = derive_default_channel_id(&server_id);
    let before = c2.channel_epoch(&channel_id).unwrap();

    // Refused: the test plays a relay that does not take the commit.
    let info = c1.export_channel_group_info(&channel_id).unwrap();
    c2.stage_rejoin(&channel_id, &info).unwrap();
    assert!(c2.channel_epoch(&channel_id).unwrap() > before);
    c2.abandon_rejoin(&channel_id).unwrap();
    assert_eq!(c2.channel_epoch(&channel_id).unwrap(), before);
    c2.reload_group(&channel_id);
    assert_eq!(c2.channel_epoch(&channel_id).unwrap(), before, "the storage holds a different group than memory");
    let (out, _) = c1.send_message(&server_id, &channel_id, b"still here".to_vec(), vec![], 2000).unwrap();
    assert_eq!(c2.receive_blob(&channel_id, &out.blob, None).unwrap().content, b"still here");
    let (out, _) = c2.send_message(&server_id, &channel_id, b"and you".to_vec(), vec![], 2001).unwrap();
    assert_eq!(c1.receive_blob(&channel_id, &out.blob, None).unwrap().content, b"and you");

    // Accepted: the other member merges the external commit, and both go on.
    let info = c1.export_channel_group_info(&channel_id).unwrap();
    let (commit, _) = c2.stage_rejoin(&channel_id, &info).unwrap();
    assert!(matches!(c1.receive_any(&channel_id, &commit, Some(3000)).unwrap(), ReceiveResult::CommitProcessed));
    c2.confirm_rejoin(&channel_id).unwrap();
    let after = c2.channel_epoch(&channel_id).unwrap();
    assert!(after > before);
    c2.reload_group(&channel_id);
    assert_eq!(c2.channel_epoch(&channel_id).unwrap(), after, "the storage holds a different group than memory");
    let (out, _) = c1.send_message(&server_id, &channel_id, b"moved on".to_vec(), vec![], 2002).unwrap();
    assert_eq!(c2.receive_blob(&channel_id, &out.blob, None).unwrap().content, b"moved on");
    let (out, _) = c2.send_message(&server_id, &channel_id, b"with you".to_vec(), vec![], 2003).unwrap();
    assert_eq!(c1.receive_blob(&channel_id, &out.blob, None).unwrap().content, b"with you");
}

/// Reading a message spends its key, and keeping it is part of the same write: a
/// message that could not be kept leaves its key unspent, in storage as in memory,
/// so the same blob reads once keeping works again.
#[test]
fn a_message_that_could_not_be_kept_reads_again() {
    let (mut c1, mut c2, server_id) = setup_two_clients();
    let channel_id = derive_default_channel_id(&server_id);
    let (out, _) = c1.send_message(&server_id, &channel_id, b"kept at last".to_vec(), vec![], 2000).unwrap();

    let refuse = "CREATE TRIGGER refuse_messages BEFORE INSERT ON messages BEGIN SELECT RAISE(ABORT, 'the disk is full'); END;";
    c2.store().conn().execute_batch(refuse).unwrap();
    assert!(c2.receive_any(&channel_id, &out.blob, Some(3000)).is_err());
    c2.store().conn().execute_batch("DROP TRIGGER refuse_messages").unwrap();
    assert!(matches!(c2.receive_any(&channel_id, &out.blob, Some(3000)).unwrap(), ReceiveResult::Message(ref m) if m.content == b"kept at last"));

    // The group as storage holds it, as a restart reads it, goes on reading.
    c2.reload_group(&channel_id);
    let (out, _) = c1.send_message(&server_id, &channel_id, b"and after".to_vec(), vec![], 2001).unwrap();
    assert!(matches!(c2.receive_any(&channel_id, &out.blob, Some(3001)).unwrap(), ReceiveResult::Message(ref m) if m.content == b"and after"));
}

/// What a metadata message changes lands in the write that spends its key: a change
/// that could not be kept leaves the key unspent, and applies when read again.
#[test]
fn a_metadata_change_that_could_not_be_kept_applies_when_read_again() {
    let (mut c1, mut c2, server_id) = setup_two_clients();
    let channel_id = derive_default_channel_id(&server_id);
    let out = c1.send_control(&server_id, crate::wire::encode_member_announce("Alicia")).unwrap();
    let alice = c1.identity.fingerprint;

    let refuse = "CREATE TRIGGER refuse_names BEFORE UPDATE ON members BEGIN SELECT RAISE(ABORT, 'the disk is full'); END;";
    c2.store().conn().execute_batch(refuse).unwrap();
    assert!(c2.receive_any(&channel_id, &out.blob, Some(3000)).is_err());
    c2.store().conn().execute_batch("DROP TRIGGER refuse_names").unwrap();
    assert!(matches!(c2.receive_any(&channel_id, &out.blob, Some(3000)).unwrap(), ReceiveResult::Metadata(ref m) if m.sender == alice));
    assert_eq!(c2.store().get_member(&server_id, &alice).unwrap().display_name, "Alicia");
}

/// A message from a device this client's log does not list yet fails with
/// `UnknownDevice` and spends nothing: once the log lists the device, the same blob
/// reads, as the session reads it again after fetching the sender's log.
#[test]
fn a_message_from_an_unlisted_device_reads_once_its_log_lists_it() {
    let mut c1 = test_client([0x01; 32]);
    let mut c2 = test_client([0x02; 32]);
    register_identity_in_cache(&mut c1, &Identity::from_seed([0x02; 32]).unwrap());
    let server_id = c1.create_server("test", ServerKind::Server, 1000).unwrap();
    join_through_invite(&mut c1, &mut c2, &server_id);
    let channel_id = derive_default_channel_id(&server_id);
    let (out, _) = c1.send_message(&server_id, &channel_id, b"who sent this".to_vec(), vec![], 2000).unwrap();

    let sender = c1.identity.fingerprint;
    assert!(matches!(c2.receive_any(&channel_id, &out.blob, Some(3000)), Err(GhostError::UnknownDevice { account_fp }) if account_fp == sender));
    register_identity_in_cache(&mut c2, &Identity::from_seed([0x01; 32]).unwrap());
    assert!(matches!(c2.receive_any(&channel_id, &out.blob, Some(3000)).unwrap(), ReceiveResult::Message(ref m) if m.content == b"who sent this"));
}

#[test]
fn two_client_full_flow() {
    let mut c1 = test_client([0x01; 32]);
    let mut c2 = test_client([0x02; 32]);

    // Register identities for credential validation
    let id1 = Identity::from_seed([0x01; 32]).unwrap();
    let id2 = Identity::from_seed([0x02; 32]).unwrap();
    register_identity_in_cache(&mut c1, &id2);
    register_identity_in_cache(&mut c2, &id1);

    let server_id = c1.create_server("full-flow", ServerKind::Server, 1000).unwrap();
    let channel_id = derive_default_channel_id(&server_id);
    join_through_invite(&mut c1, &mut c2, &server_id);

    // c1 sends, c2 receives
    let (out1, id1) = c1
        .send_message(&server_id, &channel_id, b"from c1".to_vec(), vec![], 2000)
        .unwrap();
    let recv1 = c2.receive_blob(&channel_id, &out1.blob, None).unwrap();
    assert_eq!(recv1.content, b"from c1");
    assert_eq!(recv1.sender_fp, *c1.fingerprint());

    // c2 sends, c1 receives
    let (out2, id2) = c2
        .send_message(&server_id, &channel_id, b"from c2".to_vec(), vec![], 3000)
        .unwrap();
    let recv2 = c1.receive_blob(&channel_id, &out2.blob, None).unwrap();
    assert_eq!(recv2.content, b"from c2");
    assert_eq!(recv2.sender_fp, *c2.fingerprint());

    // Both stores have both messages
    assert_eq!(c1.store().get_message(&id1).unwrap().content, b"from c1");
    assert_eq!(c1.store().get_message(&id2).unwrap().content, b"from c2");
    assert_eq!(c2.store().get_message(&id1).unwrap().content, b"from c1");
    assert_eq!(c2.store().get_message(&id2).unwrap().content, b"from c2");
}

/// A joiner takes the first server state a manager sends for its request or a later
/// one, unless a change it saw since would be undone; the public channels become those
/// listed, the role names arrive, and only members still unnamed take the names listed.
#[test]
fn a_joiner_takes_in_a_managers_server_state_unless_a_later_change_would_be_undone() {
    let (creator, mut joiner, server_id) = setup_two_clients();
    let owner = *creator.fingerprint();
    let default_channel = derive_default_channel_id(&server_id);
    let channel = |channel_id: [u8; 32], name: &str, position: i32| InviteChannel { channel_id, name: name.into(), kind: ChannelKind::Text, position, group_info_bytes: Vec::new() };
    let stale_channel = [0x51; 32];
    joiner.store().insert_channel(&Channel { channel_id: stale_channel, server_id, name: "old".into(), kind: ChannelKind::Text, position: 1 }, OnConflict::Fail).unwrap();
    let newcomer = [0x77; 32];
    joiner.store().insert_member(&Member { server_id, fingerprint: newcomer, display_name: crate::storage::placeholder_name(&newcomer), joined_at: 0, avatar_hash: None, avatar_key: None }, OnConflict::Fail).unwrap();
    let state = |request_seq: u64| ServerStatePayload {
        request_seq,
        channels: vec![channel(default_channel, "lobby", 0), channel([0x52; 32], "news", 1)],
        role_names: vec![(1, "staff".into())],
        members: vec![InviteMember { fingerprint: newcomer, display_name: "dana".into() }, InviteMember { fingerprint: owner, display_name: "renamed".into() }],
    };

    assert_eq!(joiner.apply_server_state(&server_id, &owner, state(12)).unwrap(), ServerStateOutcome::Ignored, "taken before the request was");
    joiner.store().server_state_requested(&server_id, 10).unwrap();
    assert_eq!(joiner.apply_server_state(&server_id, &owner, state(9)).unwrap(), ServerStateOutcome::Ignored, "answers an earlier request");
    assert_eq!(joiner.apply_server_state(&server_id, &[0x99; 32], state(12)).unwrap(), ServerStateOutcome::Ignored, "from someone who may not manage channels");
    joiner.store().note_server_change(&server_id, 12).unwrap();
    assert_eq!(joiner.apply_server_state(&server_id, &owner, state(11)).unwrap(), ServerStateOutcome::Stale);

    assert_eq!(joiner.apply_server_state(&server_id, &owner, state(12)).unwrap(), ServerStateOutcome::Applied);
    let channels: Vec<(String, i32)> = joiner.store().list_channels(&server_id).unwrap().into_iter().map(|c| (c.name, c.position)).collect();
    assert_eq!(channels, vec![("lobby".to_string(), 0), ("news".to_string(), 1)]);
    assert_eq!(joiner.store().list_role_names(&server_id).unwrap(), vec![(1, "staff".to_string())]);
    let name_of = |fp: &[u8; 32]| joiner.store().list_members(&server_id).unwrap().into_iter().find(|m| m.fingerprint == *fp).unwrap().display_name;
    assert_eq!(name_of(&newcomer), "dana");
    assert_ne!(name_of(&owner), "renamed", "a name this device knew was replaced");
    assert_eq!(joiner.apply_server_state(&server_id, &owner, state(13)).unwrap(), ServerStateOutcome::Ignored, "taken after the wait ended");
}

#[test]
fn create_invite_needs_the_invite_permission() {
    let (mut c1, mut c2, server_id) = setup_two_clients();

    // Everyone may invite under a new server's policy.
    assert!(c1.create_invite(&server_id, u64::MAX).is_ok());
    assert!(c2.create_invite(&server_id, u64::MAX).is_ok());

    // Once the owner takes the permission away, the member cannot.
    let mut policy = c1.server_policy(&server_id).unwrap();
    policy.everyone = 0;
    let out = c1.stage_server_policy(&server_id, &policy).unwrap();
    c1.merge_pending_commit_for_channel(&derive_default_channel_id(&server_id)).unwrap();
    c2.receive_any(&out.channel_id, &out.blob, Some(1500)).unwrap();
    assert!(matches!(c2.create_invite(&server_id, u64::MAX), Err(GhostError::PermissionDenied(_))));
    assert!(c1.create_invite(&server_id, u64::MAX).is_ok(), "the owner holds every permission");
}

#[test]
fn member_cannot_stage_a_policy_change_it_may_not_make() {
    let (_c1, mut c2, server_id) = setup_two_clients();
    let mut policy = c2.server_policy(&server_id).unwrap();
    policy.owner = *c2.fingerprint();
    assert!(matches!(c2.stage_server_policy(&server_id, &policy), Err(GhostError::PermissionDenied(_))));
}

#[test]
fn invite_full_roundtrip() {
    let mut c1 = test_client([0x01; 32]);
    let mut c2 = test_client([0x02; 32]);

    // Register each other's identities for credential validation
    let id1 = Identity::from_seed([0x01; 32]).unwrap();
    let id2 = Identity::from_seed([0x02; 32]).unwrap();
    register_identity_in_cache(&mut c1, &id2);
    register_identity_in_cache(&mut c2, &id1);

    let server_id = c1.create_server("test", ServerKind::Server, 1000).unwrap();

    let invite = c1.create_invite(&server_id, u64::MAX).unwrap();

    let payload = c2.open_invite(&invite.sealed_payload, &invite.key).unwrap();
    let group_info = c1.export_server_info(&server_id).unwrap();
    let (joined_server_id, channel_results, _grant) = c2.join_by_invite(payload, group_info, 2000).unwrap();
    assert_eq!(joined_server_id, server_id);

    // c2 should have the server, channel, and members in their store
    let server = c2.store().get_server(&server_id).unwrap();
    assert_eq!(server.name, "test");
    let channels = c2.store().list_channels(&server_id).unwrap();
    assert_eq!(channels.len(), 1);
    assert_eq!(channels[0].name, "general");
    let members = c2.store().list_members(&server_id).unwrap();
    assert_eq!(members.len(), 2); // c1 + c2

    // c1 processes the external commit for the default channel
    let (channel_id, commit, _mailbox_id) = &channel_results[0];
    let result = c1.receive_any(channel_id, commit, Some(2000)).unwrap();
    assert!(matches!(result, ReceiveResult::CommitProcessed));

    // After merging, c1's MLS group should include c2
    let mls_fps = c1.mls_member_fingerprints(&server_id).unwrap();
    assert_eq!(mls_fps.len(), 2, "MLS group should have both members after external commit");
    assert!(mls_fps.contains(c1.fingerprint()));
    assert!(mls_fps.contains(c2.fingerprint()));
}
