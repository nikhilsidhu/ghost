//! End-to-end tests for the protocol flows in `ghost_core::flows`, run against an
//! in-process relay. These are the acceptance tests for moving the flows out of the
//! desktop application: pairing a second device, recovering an account, revoking a
//! device, and joining a server through an invite.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{create_account, create_server, pair_second_device};
use ed25519_dalek::SigningKey;
use ghost_core::account_keys::{DeviceEncryptionKey, RecoveryKey};
use ghost_core::flows::pairing::{PairingCode, PairingOffer};
use ghost_core::client::GhostClient;
use ghost_core::error::GhostError;
use ghost_core::flows::{self, SharedClient};
use ghost_core::relay::{RelayClient, RelayEvent};
use ghost_core::wire::{SyncReceiveResult, SYNC_KEY_DISPLAY_NAME};
use ghost_wire::batch::LogBatch;
use tokio::sync::Mutex;

#[tokio::test]
async fn pairing_links_second_device_and_provisions_servers() {
    let relay_url = common::start_relay().await;
    let account = create_account(&relay_url, "desktop").await;
    let server_id = create_server(&account, "home").await;
    {
        let c = account.client.lock().await;
        c.sync_set(SYNC_KEY_DISPLAY_NAME, b"Alice", 1000).unwrap();
    }

    let (client_b, relay_b, device_b_vk) = pair_second_device(&relay_url, &account).await;

    {
        let c = client_b.lock().await;
        assert!(c.store().get_server(&server_id).is_ok(), "linked device joined the provisioned server");
        let b_seed = c.sealing_seed().unwrap();
        let a_seed = account.client.lock().await.sealing_seed().unwrap();
        assert_eq!(b_seed.generation(), 2, "pairing added a generation covering the new device");
        assert_eq!(b_seed.bytes(), a_seed.bytes(), "both devices hold the current account key");
        assert_eq!(c.identity().display_name, "Alice", "synced display name applied on the linked device");
    }

    // Both devices are active in the identity log.
    // Read as device A, which the relay admits.
    let (_, state) = flows::idlog::fetch_chain(&account.relay, &account.fp).await.unwrap();
    assert!(state.is_active_device(&account.device_vk));
    assert!(state.is_active_device(&device_b_vk));

    // A setting changed on A reaches B through the sync channel.
    let mailbox = account.client.lock().await.account_sync_mailbox();
    let (reader, mut events) = RelayClient::new(&relay_url);
    reader.copy_auth_from(&relay_b);
    let since = client_b.lock().await.store().get_last_seen_seq(&mailbox).unwrap_or(0);
    reader.subscribe(mailbox, since);
    let mut payload = vec![ghost_core::wire::SyncMessageType::MutationSync as u8];
    payload.extend_from_slice(&ghost_core::wire::encode_mutation(ghost_core::wire::MUTATION_SET, 9000, "read:ch1", &77u64.to_be_bytes()));
    let outbound = account.client.lock().await.send_sync(&payload).unwrap();
    account.relay.post_blob(&outbound.mailbox_id, outbound.blob).await.unwrap();
    let delivered = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while let Some(event) = events.recv().await {
            let RelayEvent::Blob(blob) = event else { continue };
            if let Ok(SyncReceiveResult::Application { plaintext, .. }) = client_b.lock().await.receive_sync(&blob.payload) {
                return plaintext;
            }
        }
        panic!("event stream ended");
    })
    .await
    .expect("B never received the mutation");
    let (_, _, key, value) = ghost_core::wire::decode_mutation(&delivered[1..]).unwrap();
    assert_eq!((key.as_str(), value), ("read:ch1", 77u64.to_be_bytes().to_vec()));
}

#[tokio::test]
async fn revoked_device_loses_relay_access() {
    let relay_url = common::start_relay().await;
    let account = create_account(&relay_url, "desktop").await;
    create_server(&account, "home").await;
    let (_client_b, relay_b, device_b_vk) = pair_second_device(&relay_url, &account).await;

    let outcome = flows::devices::revoke(&account.client, &account.relay, &device_b_vk).await.unwrap();
    assert_eq!(outcome, flows::devices::RevokeOutcome::Complete);

    // Read as device A, which remains active.
    let (_, state) = flows::idlog::fetch_chain(&account.relay, &account.fp).await.unwrap();
    assert!(!state.is_active_device(&device_b_vk), "revoked device is inactive in the log");
    assert!(state.is_active_device(&account.device_vk));

    // The relay refuses authenticated requests from the revoked key.
    match relay_b.put_sync_state(&account.fp, 1, vec![0u8; 16]).await {
        Err(GhostError::DeviceRevoked(_)) => {}
        other => panic!("expected the relay to say the device was removed, got {other:?}"),
    }
}

#[tokio::test]
async fn revoke_rejects_current_device() {
    let relay_url = common::start_relay().await;
    let account = create_account(&relay_url, "desktop").await;
    let own_vk = account.device_vk;
    let err = flows::devices::revoke(&account.client, &account.relay, &own_vk).await.unwrap_err();
    assert!(matches!(err, GhostError::PermissionDenied(_)));
}

#[tokio::test]
async fn recovery_replaces_devices_and_restores_sync_state() {
    let relay_url = common::start_relay().await;
    let account = create_account(&relay_url, "desktop").await;
    let server_id = create_server(&account, "home").await;
    {
        let c = account.client.lock().await;
        c.sync_set(SYNC_KEY_DISPLAY_NAME, b"Alice", 1000).unwrap();
    }
    flows::sync::server_entry(&account.client, &account.relay, &server_id).await;
    flows::sync::push_snapshot(&account.client, &account.relay).await;

    let new_key = RecoveryKey::generate();
    let (client_n, relay_n, material) = recover(&relay_url, &account, &new_key).await;
    assert_eq!(material.prior_devices, vec![account.device_vk]);
    let new_vk = material.device_key.verifying_key().to_bytes();

    let finished = flows::recovery::finish(&client_n, &relay_n, &material).await.unwrap();
    assert_eq!(finished.snapshot, flows::recovery::SnapshotRestore::Restored);
    assert_eq!(finished.settings.display_name.as_deref(), Some("Alice"));

    {
        let c = client_n.lock().await;
        assert!(c.store().get_server(&server_id).is_ok(), "recovered device rejoined the server");
        assert_eq!(c.sealing_seed().unwrap().generation(), 2, "recovery added a generation for the new device");
    }

    // The old device is revoked, so the recovered device reads the log.
    let (_, state) = flows::idlog::fetch_chain(&relay_n, &account.fp).await.unwrap();
    assert!(!state.is_active_device(&account.device_vk), "old device revoked by the Recovery entry");
    assert!(state.is_active_device(&new_vk));
    assert_eq!(state.root_verifying_key, Some(new_key.root().unwrap().verifying_key().to_bytes()));

    // The old recovery key neither finds nor recovers the account any more.
    let (guest, _) = RelayClient::new(&relay_url);
    assert!(flows::recovery::find_account(&guest, &account.recovery_key).await.unwrap().is_none());
    let intruder = flows::recovery::begin(&guest, account.fp, &account.recovery_key, &RecoveryKey::generate(), "intruder").await;
    assert!(intruder.is_err(), "the replaced key still recovered the account");
}

/// A new device with nothing but the recovery key and the relay: the account found and
/// the recovery batch landed, `new_key` replacing the key; `finish` is the caller's.
async fn recover(relay_url: &str, account: &common::Account, new_key: &RecoveryKey) -> (Arc<SharedClient>, Arc<RelayClient>, flows::recovery::RecoveryMaterial) {
    let (guest, _) = RelayClient::new(relay_url);
    let found = flows::recovery::find_account(&guest, &account.recovery_key).await.unwrap().unwrap();
    assert_eq!(found.account_fp, account.fp);
    let material = flows::recovery::begin(&guest, found.account_fp, &account.recovery_key, new_key, "laptop").await.unwrap();
    let mut client = GhostClient::open_in_memory(material.identity(), [0x33; 32]).unwrap();
    client.set_relay_vk(guest.get_relay_info().await.unwrap().relay_vk);
    let (relay, _) = RelayClient::new(relay_url);
    relay.set_auth(account.fp, material.device_key.verifying_key().to_bytes(), material.device_key.clone());
    (Arc::new(Mutex::new(client)), Arc::new(relay), material)
}

#[tokio::test]
async fn a_recovery_says_when_there_was_no_snapshot_to_restore() {
    let relay_url = common::start_relay().await;
    let account = create_account(&relay_url, "desktop").await;
    let (client_n, relay_n, material) = recover(&relay_url, &account, &RecoveryKey::generate()).await;
    let finished = flows::recovery::finish(&client_n, &relay_n, &material).await.unwrap();
    assert_eq!(finished.snapshot, flows::recovery::SnapshotRestore::Missing);
}

/// A snapshot no key of the account opens any more restores nothing, says so, and the
/// recovered device's own replaces it, so the account's next device reads one.
#[tokio::test]
async fn a_recovery_says_when_the_snapshot_was_unreadable_and_replaces_it() {
    let relay_url = common::start_relay().await;
    let account = create_account(&relay_url, "desktop").await;
    let mut damaged = 1u32.to_be_bytes().to_vec();
    damaged.extend_from_slice(&[0x5A; 64]);
    account.relay.put_sync_state(&account.fp, 1, damaged).await.unwrap();

    let (client_n, relay_n, material) = recover(&relay_url, &account, &RecoveryKey::generate()).await;
    let finished = flows::recovery::finish(&client_n, &relay_n, &material).await.unwrap();
    assert_eq!(finished.snapshot, flows::recovery::SnapshotRestore::Unreadable);
    let (_, body) = relay_n.get_sync_state(&account.fp).await.unwrap().unwrap();
    assert!(flows::sync::open_snapshot(&*client_n.lock().await, &body).is_ok(), "the recovered device's snapshot replaced it");
}

#[tokio::test]
async fn recovery_rejects_a_wrong_recovery_key() {
    let relay_url = common::start_relay().await;
    let account = create_account(&relay_url, "desktop").await;
    let (guest, _) = RelayClient::new(&relay_url);
    let stranger = RecoveryKey::generate();
    assert!(flows::recovery::find_account(&guest, &stranger).await.unwrap().is_none());
    assert!(flows::recovery::begin(&guest, account.fp, &stranger, &RecoveryKey::generate(), "laptop").await.is_err());

    // Nothing was appended: the log is still the creation batch.
    let (log, state) = flows::idlog::fetch_chain(&account.relay, &account.fp).await.unwrap();
    assert_eq!(log.entries.len(), 5);
    assert!(state.is_active_device(&account.device_vk));
}

#[tokio::test]
async fn invite_joins_build_on_the_relays_group_state() {
    let relay_url = common::start_relay().await;
    let creator = create_account(&relay_url, "creator").await;
    let joiner = create_account(&relay_url, "joiner").await;
    let second = create_account(&relay_url, "second").await;
    let server_id = create_server(&creator, "club").await;

    let invite = flows::invite::create(&creator.client, &creator.relay, &server_id, None).await.unwrap();
    assert_eq!(invite.relay_url, relay_url);

    let joined = flows::invite::join(&joiner.client, &joiner.relay, &joiner.relay, &invite.token, &invite.key, 2000).await.unwrap();
    assert_eq!(joined, server_id);

    {
        let c = joiner.client.lock().await;
        assert!(c.store().get_server(&server_id).is_ok());
        let members = c.store().list_members(&server_id).unwrap();
        assert!(members.iter().any(|m| m.fingerprint == joiner.fp), "joiner recorded itself as a member");
        assert!(members.iter().any(|m| m.fingerprint == creator.fp));
    }

    // A join builds its commit on the group state the relay holds, so the next joiner
    // gets in after the group moved on without anyone touching the invite.
    let joined = flows::invite::join(&second.client, &second.relay, &second.relay, &invite.token, &invite.key, 3000).await.unwrap();
    assert_eq!(joined, server_id);
}

/// A join built on GroupInfo a commit has outdated, as when the committer's upload of the
/// new one failed, is refused as stale; built again once a member publishes the current
/// GroupInfo, it lands.
#[tokio::test]
async fn a_join_on_a_stale_group_info_is_built_again_once_a_member_publishes_it() {
    let relay_url = common::start_relay().await;
    let creator = create_account(&relay_url, "creator").await;
    let joiner = create_account(&relay_url, "joiner").await;
    let server_id = create_server(&creator, "club").await;
    let mailbox_id = creator.client.lock().await.mailbox_id_for_server(&server_id).unwrap();

    let mut policy = creator.client.lock().await.server_policy(&server_id).unwrap();
    policy.roles.push(ghost_wire::policy::Role { id: 1, permissions: 0 });
    let commit = creator.client.lock().await.stage_server_policy(&server_id, &policy).unwrap();
    creator.relay.post_blob(&commit.mailbox_id, commit.blob).await.unwrap();
    creator.client.lock().await.merge_pending_commit_for_channel(&commit.channel_id).unwrap();

    let invite = flows::invite::create(&creator.client, &creator.relay, &server_id, None).await.unwrap();
    let publish_later = async {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        flows::publish_server_info(&creator.client, &creator.relay, &mailbox_id).await;
    };
    let (joined, _) = tokio::join!(flows::invite::join(&joiner.client, &joiner.relay, &joiner.relay, &invite.token, &invite.key, 2000), publish_later);
    assert_eq!(joined.unwrap(), server_id);
}

/// A join whose commit landed but whose answer was lost leaves a leaf the device does
/// not hold; the join made again removes it, so the device has one leaf in the group.
#[tokio::test]
async fn a_join_made_again_after_a_lost_answer_leaves_one_leaf_for_the_device() {
    let relay_url = common::start_relay().await;
    let creator = create_account(&relay_url, "creator").await;
    let joiner = create_account(&relay_url, "joiner").await;
    let server_id = create_server(&creator, "club").await;
    let default_channel = ghost_core::wire::derive_default_channel_id(&server_id);
    let mailbox_id = creator.client.lock().await.mailbox_id_for_server(&server_id).unwrap();
    let invite = flows::invite::create(&creator.client, &creator.relay, &server_id, None).await.unwrap();

    // The first commit lands; the device, never told, drops the join.
    let lost = {
        let sealed = joiner.relay.get_invite_payload(&invite.token).await.unwrap().unwrap();
        let payload = joiner.client.lock().await.open_invite(&sealed, &invite.key).unwrap();
        let group_info = joiner.relay.get_server_info_as_joiner(&mailbox_id, &invite.token).await.unwrap();
        let (_, commits, _) = joiner.client.lock().await.join_by_invite(payload, group_info, 2000).unwrap();
        let (_, commit, _) = commits.into_iter().next().unwrap();
        joiner.relay.post_blob(&mailbox_id, commit.clone()).await.unwrap();
        joiner.client.lock().await.abandon_join(&server_id).unwrap();
        commit
    };
    // A member takes in the lost join and publishes the GroupInfo, as members do.
    flows::idlog::fetch_and_verify(&creator.client, &creator.relay, &joiner.fp).await.unwrap();
    creator.client.lock().await.receive_any(&default_channel, &lost, Some(2000)).unwrap();
    flows::publish_server_info(&creator.client, &creator.relay, &mailbox_id).await;
    assert_eq!(creator.client.lock().await.find_device_leaves(&default_channel, &joiner.device_vk).len(), 1);

    flows::invite::join(&joiner.client, &joiner.relay, &joiner.relay, &invite.token, &invite.key, 3000).await.unwrap();
    assert_eq!(joiner.client.lock().await.find_device_leaves(&default_channel, &joiner.device_vk).len(), 1, "the lost join's leaf stayed");
}

/// A server whose upload never happened, the process having ended after making it, is
/// published at the next start, and others can join it.
#[tokio::test]
async fn a_server_whose_upload_never_happened_is_published_at_the_next_start() {
    let relay_url = common::start_relay().await;
    let creator = create_account(&relay_url, "creator").await;
    let joiner = create_account(&relay_url, "joiner").await;
    let server_id = creator.client.lock().await.create_server("club", ghost_core::storage::ServerKind::Server, 1000).unwrap();
    let mailbox_id = creator.client.lock().await.mailbox_id_for_server(&server_id).unwrap();
    assert!(matches!(creator.relay.get_server_info(&mailbox_id).await, Err(GhostError::RelayStatus { status: 404, .. })));

    flows::server::publish_unpublished(&creator.client, &creator.relay).await;
    assert!(creator.client.lock().await.store().unpublished_servers().unwrap().is_empty());
    let invite = flows::invite::create(&creator.client, &creator.relay, &server_id, None).await.unwrap();
    let joined = flows::invite::join(&joiner.client, &joiner.relay, &joiner.relay, &invite.token, &invite.key, 2000).await.unwrap();
    assert_eq!(joined, server_id);
}

#[tokio::test]
async fn invite_join_fails_cleanly_for_unknown_token() {
    let relay_url = common::start_relay().await;
    let joiner = create_account(&relay_url, "joiner").await;
    let err = flows::invite::join(&joiner.client, &joiner.relay, &joiner.relay, "no-such-token", &[0u8; 32], 2000).await.unwrap_err();
    assert!(matches!(err, GhostError::RelayStatus { status: 404, .. }), "got {err:?}");
    let c = joiner.client.lock().await;
    assert!(c.store().list_servers().unwrap().is_empty());
}

#[tokio::test]
async fn member_can_refresh_group_info_only_for_current_state() {
    let relay_url = common::start_relay().await;
    let creator = create_account(&relay_url, "creator").await;
    let joiner = create_account(&relay_url, "joiner").await;
    let server_id = create_server(&creator, "club").await;
    let (mailbox_id, stale) = {
        let c = creator.client.lock().await;
        (c.mailbox_id_for_server(&server_id).unwrap(), c.export_server_info(&server_id).unwrap())
    };

    let invite = flows::invite::create(&creator.client, &creator.relay, &server_id, None).await.unwrap();
    flows::invite::join(&joiner.client, &joiner.relay, &joiner.relay, &invite.token, &invite.key, 2000).await.unwrap();

    // The joiner's GroupInfo describes the relay's current state, so it is accepted.
    let current = joiner.client.lock().await.export_server_info(&server_id).unwrap();
    joiner.relay.put_server_info(&mailbox_id, current.clone()).await.unwrap();
    assert_eq!(joiner.relay.get_server_info(&mailbox_id).await.unwrap(), current);

    // GroupInfo from before the join no longer matches, so a member cannot publish it.
    let err = joiner.relay.put_server_info(&mailbox_id, stale).await.unwrap_err();
    assert!(matches!(err, GhostError::RelayStatus { status: 403, .. }), "{err}");
}

#[tokio::test]
async fn receiver_rejects_messages_from_a_device_its_log_shows_revoked() {
    use ghost_core::client::ReceiveResult;
    use ghost_core::relay::RelayEvent;
    use ghost_core::wire::derive_default_channel_id;
    use std::time::Duration;

    let relay_url = common::start_relay().await;
    let alice = create_account(&relay_url, "alice").await;
    let carol = create_account(&relay_url, "carol").await;
    let server_id = create_server(&alice, "club").await;
    let invite = flows::invite::create(&alice.client, &alice.relay, &server_id, None).await.unwrap();
    flows::invite::join(&carol.client, &carol.relay, &carol.relay, &invite.token, &invite.key, 2000).await.unwrap();
    let (client_b, relay_b, device_b_vk) = pair_second_device(&relay_url, &alice).await;
    let channel_id = derive_default_channel_id(&server_id);
    let mailbox_id = alice.client.lock().await.mailbox_id_for_server(&server_id).unwrap();

    // Carol processes the mailbox until device B's leaf is in her group.
    let (reader, mut events) = RelayClient::new(&relay_url);
    reader.copy_auth_from(&carol.relay);
    let carol_seen = carol.client.lock().await.store().get_last_seen_seq(&mailbox_id).unwrap_or(0);
    reader.subscribe(mailbox_id, carol_seen);
    let mut last_seq = carol_seen;
    let caught_up = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(event) = events.recv().await {
            let RelayEvent::Blob(b) = event else { continue };
            let _ = common::receive_like_session(&carol.client, &carol.relay, &channel_id, &b).await;
            last_seq = b.seq;
            if !carol.client.lock().await.find_device_leaves(&channel_id, &device_b_vk).is_empty() {
                return;
            }
        }
    })
    .await;
    assert!(caught_up.is_ok(), "Carol never saw device B join");
    drop(reader);

    // Device B posts while still active; Carol has not read it yet.
    let outbound = {
        let mut c = client_b.lock().await;
        c.send_message(&server_id, &channel_id, b"from B".to_vec(), vec![], 5000).unwrap().0
    };
    relay_b.post_blob(&outbound.mailbox_id, outbound.blob).await.unwrap();

    // Alice's account revokes B in its log only: no MLS removal has happened.
    let state = flows::idlog::fetch_and_verify(&alice.client, &alice.relay, &alice.fp).await.unwrap();
    let signer = alice.client.lock().await.signing_key_clone();
    let revoke = ghost_core::identity::log::create_revoke_device(&state, &signer, &device_b_vk);
    let batch = LogBatch { entries: vec![revoke], key_sets: Vec::new() };
    alice.relay.post_idlog_batch(&alice.fp, &batch).await.unwrap();
    flows::idlog::fetch_and_verify(&carol.client, &carol.relay, &alice.fp).await.unwrap();

    // B's leaf is still in the group, but Carol's log says the device is revoked.
    let (reader, mut events) = RelayClient::new(&relay_url);
    reader.copy_auth_from(&carol.relay);
    reader.subscribe(mailbox_id, last_seq);
    let outcome = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(event) = events.recv().await {
            let RelayEvent::Blob(b) = event else { continue };
            let mut c = carol.client.lock().await;
            match c.receive_any(&channel_id, &b.payload, Some(b.received_at)) {
                Ok(ReceiveResult::Message(m)) if m.content == b"from B" => {
                    return Err("Carol accepted a message from a revoked device".to_string());
                }
                Err(e) if e.to_string().contains("revoked") => return Ok(()),
                _ => continue,
            }
        }
        Err("event stream ended".to_string())
    })
    .await
    .expect("Carol never processed device B's message");
    outcome.unwrap();
}

#[tokio::test]
async fn linked_device_rejoins_a_server_with_a_metadata_only_channel() {
    use ghost_core::storage::{Channel, ChannelKind, OnConflict};
    use ghost_core::wire::{channel_mailbox_id, derive_default_channel_id};

    let relay_url = common::start_relay().await;
    let account = create_account(&relay_url, "desktop").await;
    let server_id = create_server(&account, "home").await;
    {
        let c = account.client.lock().await;
        // The derived mailbox of the default channel is the one the client uses.
        assert_eq!(
            Some(channel_mailbox_id(&server_id, &derive_default_channel_id(&server_id))),
            c.mailbox_id_for_server(&server_id)
        );
        // Channels added in the app are rows without an MLS group of their own.
        c.store()
            .insert_channel(&Channel {
                channel_id: [0x77; 32],
                server_id,
                name: "random".into(),
                kind: ChannelKind::Text,
                position: 1,
            }, OnConflict::Fail)
            .unwrap();
    }

    let (client_b, _relay_b, _vk) = pair_second_device(&relay_url, &account).await;
    let c = client_b.lock().await;
    assert!(c.store().get_server(&server_id).is_ok(), "rejoined despite the extra channel");
    let channels = c.store().list_channels(&server_id).unwrap();
    assert_eq!(channels.len(), 2, "the metadata-only channel is kept");
}

#[tokio::test]
async fn channels_created_after_the_server_share_its_group() {
    use ghost_core::client::ReceiveResult;
    use ghost_core::relay::RelayEvent;
    use ghost_core::storage::{Channel, ChannelKind, OnConflict};
    use ghost_core::wire::derive_default_channel_id;
    use std::time::Duration;

    let relay_url = common::start_relay().await;
    let creator = create_account(&relay_url, "creator").await;
    let joiner = create_account(&relay_url, "joiner").await;
    let server_id = create_server(&creator, "club").await;
    let (text_id, voice_id) = ([0x71; 32], [0x72; 32]);
    {
        let c = creator.client.lock().await;
        for (channel_id, kind, position) in [(text_id, ChannelKind::Text, 1), (voice_id, ChannelKind::Voice, 2)] {
            c.store()
                .insert_channel(&Channel { channel_id, server_id, name: "extra".into(), kind, position }, OnConflict::Fail)
                .unwrap();
        }
    }

    // Invites work for a server with extra channels, and carry them.
    let invite = flows::invite::create(&creator.client, &creator.relay, &server_id, None).await.unwrap();
    flows::invite::join(&joiner.client, &joiner.relay, &joiner.relay, &invite.token, &invite.key, 2000).await.unwrap();
    assert_eq!(joiner.client.lock().await.store().list_channels(&server_id).unwrap().len(), 3);

    // Voice keys exist for the new voice channel and differ from another channel's.
    {
        let c = creator.client.lock().await;
        let fp = *c.fingerprint();
        let vk = c.verifying_key_bytes();
        let voice = c.derive_voice_key(&voice_id, &fp, &vk, &[1; 32]).unwrap();
        let general = c.derive_voice_key(&derive_default_channel_id(&server_id), &fp, &vk, &[1; 32]).unwrap();
        assert_ne!(voice, general);
    }

    // The creator catches up on the join, then posts in the new text channel.
    let mailbox_id = creator.client.lock().await.mailbox_id_for_server(&server_id).unwrap();
    let default_channel = derive_default_channel_id(&server_id);
    let (reader, mut events) = RelayClient::new(&relay_url);
    reader.copy_auth_from(&creator.relay);
    reader.subscribe(mailbox_id, 0);
    let joiner_fp = joiner.fp;
    tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(event) = events.recv().await {
            let RelayEvent::Blob(b) = event else { continue };
            let _ = common::receive_like_session(&creator.client, &creator.relay, &default_channel, &b).await;
            if creator.client.lock().await.mls_member_fingerprints(&server_id).unwrap_or_default().contains(&joiner_fp) {
                return;
            }
        }
    })
    .await
    .expect("creator never saw the joiner");
    let outbound = {
        let mut c = creator.client.lock().await;
        c.send_message(&server_id, &text_id, b"in the new channel".to_vec(), vec![], 5000).unwrap().0
    };
    assert_eq!(outbound.mailbox_id, mailbox_id, "public channels use the server's mailbox");
    creator.relay.post_blob(&outbound.mailbox_id, outbound.blob).await.unwrap();

    let (joiner_reader, mut joiner_events) = RelayClient::new(&relay_url);
    joiner_reader.copy_auth_from(&joiner.relay);
    let since = joiner.client.lock().await.store().get_last_seen_seq(&mailbox_id).unwrap_or(0);
    joiner_reader.subscribe(mailbox_id, since);
    let message = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(event) = joiner_events.recv().await {
            let RelayEvent::Blob(b) = event else { continue };
            if let Ok(ReceiveResult::Message(m)) = common::receive_like_session(&joiner.client, &joiner.relay, &default_channel, &b).await {
                if m.content == b"in the new channel" {
                    return m;
                }
            }
        }
        panic!("event stream ended");
    })
    .await
    .expect("joiner never received the message");
    assert_eq!(message.channel_id, text_id);
}

#[tokio::test]
async fn the_device_list_is_the_last_verified_one_while_the_home_is_down() {
    let home = common::start_switched_relay().await;
    let account = create_account(&home.url(), "desktop").await;
    assert!(flows::devices::list(&account.client, &account.relay).await.unwrap().current);

    home.go_down();
    let list = flows::devices::list(&account.client, &account.relay).await.unwrap();
    assert!(!list.current, "the home did not answer");
    assert!(list.state.is_active_device(&account.device_vk), "the cached log still lists the device");
}

/// A waiting removal the home refuses for a reason a retry does not change stays
/// waiting, with sync paused, and the refusal is told once.
#[tokio::test]
async fn a_waiting_removal_the_home_refuses_keeps_its_reason_and_is_told_once() {
    let config = common::relay_config(1);
    let refusing = config.revoked_devices_for_tests.clone();
    let relay = common::start_relay_with(config).await;
    let account = create_account(&relay.url(), "desktop").await;
    let (_client_b, _relay_b, device_b_vk) = pair_second_device(&relay.url(), &account).await;
    account.client.lock().await.store().add_pending_revocation(&device_b_vk, 1).unwrap();

    refusing.write().unwrap().insert(account.device_vk);
    let told = flows::devices::finish_pending(&account.client, &account.relay).await.unwrap();
    assert_eq!(told.iter().map(|r| r.device_vk).collect::<Vec<_>>(), vec![device_b_vk]);
    assert!(flows::devices::finish_pending(&account.client, &account.relay).await.unwrap().is_empty(), "the same refusal is told once");
    let c = account.client.lock().await;
    assert!(flows::sync::paused(&c), "sync stays paused while the removal waits");
    assert!(c.store().pending_removals().unwrap()[0].refused.is_some(), "the reason is kept for the device list");
}

/// The existing device's side of a pairing up to the new device's answer: the code, the
/// new device's keys, and its unauthenticated relay client.
async fn answered_pairing(relay_url: &str, account: &common::Account) -> (PairingCode, SigningKey, RelayClient) {
    let offer = PairingOffer { relay_url: relay_url.to_string(), display_name: "Alice".into(), avatar_hash: None, avatar_key: None };
    let code = flows::pairing::start(&account.client, &account.relay, &offer).await.unwrap();
    let (guest, _events) = RelayClient::new(&code.relay_url);
    let device = SigningKey::generate(&mut rand::rngs::OsRng);
    flows::pairing::respond(&guest, &code, &device, &DeviceEncryptionKey::generate(), "phone").await.unwrap();
    (code, device, guest)
}

/// The existing device cancels: the new device stops waiting at once instead of at its
/// timeout, and is told the pairing ended.
#[tokio::test]
async fn a_cancelled_pairing_ends_the_new_devices_wait() {
    let relay_url = common::start_relay().await;
    let account = create_account(&relay_url, "desktop").await;
    let (code, device, guest) = answered_pairing(&relay_url, &account).await;

    account.relay.close_pairing(&code.account_fp, &code.token).await.unwrap();
    let waited = flows::pairing::wait_for_device(&guest, &code, &device, "phone", 50, Duration::from_millis(20)).await;
    assert!(matches!(waited, Err(GhostError::RelayStatus { status: 404, .. })), "{waited:?}");
}

/// A draft that does not add this device ends the wait with why, rather than spinning
/// until the timeout.
#[tokio::test]
async fn a_draft_for_another_device_ends_the_new_devices_wait() {
    let relay_url = common::start_relay().await;
    let account = create_account(&relay_url, "desktop").await;
    let (code, device, guest) = answered_pairing(&relay_url, &account).await;
    let pending = common::poll(|| flows::pairing::await_response(&account.relay, &code)).await;
    flows::pairing::post_draft(&account.client, &account.relay, &account.relay, &code, &pending).await.unwrap();

    // The draft names the device as it answered, "phone"; this one waits as "tablet".
    let waited = flows::pairing::wait_for_device(&guest, &code, &device, "tablet", 50, Duration::from_millis(20)).await;
    assert!(matches!(waited, Err(GhostError::IdentityLog(_))), "{waited:?}");
}
