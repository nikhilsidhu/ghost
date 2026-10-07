//! End-to-end tests for the protocol flows in `ghost_core::flows`, run against an
//! in-process relay. These are the acceptance tests for moving the flows out of the
//! desktop application: pairing a second device, recovering an account, revoking a
//! device, and joining a server through an invite.

mod common;

use std::sync::Arc;

use common::{create_account, create_server, pair_second_device};
use ed25519_dalek::SigningKey;
use ghost_core::client::GhostClient;
use ghost_core::error::GhostError;
use ghost_core::flows;
use ghost_core::relay::RelayClient;
use ghost_core::wire::SYNC_KEY_DISPLAY_NAME;
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

    let (client_b, _relay_b, device_b_vk) = pair_second_device(&relay_url, &account).await;

    {
        let c = client_b.lock().await;
        assert!(c.store().get_server(&server_id).is_ok(), "linked device joined the provisioned server");
        assert!(c.has_sync_group(), "linked device joined the sync group");
        assert_eq!(c.sync_key(), account.client.lock().await.sync_key());
        assert_eq!(c.identity().display_name, "Alice", "synced display name applied on the linked device");
    }

    // Both devices are active in the identity log.
    // Read as device A, which the relay admits.
    let (_, state) = flows::idlog::fetch_chain(&*account.relay.lock().await, &account.fp).await.unwrap();
    assert!(state.is_active_device(&account.device_vk));
    assert!(state.is_active_device(&device_b_vk));
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
    let (_, state) = flows::idlog::fetch_chain(&*account.relay.lock().await, &account.fp).await.unwrap();
    assert!(!state.is_active_device(&device_b_vk), "revoked device is inactive in the log");
    assert!(state.is_active_device(&account.device_vk));

    // The relay refuses authenticated requests from the revoked key.
    let r = relay_b.lock().await;
    match r.put_sync_state(&account.fp, 1, vec![0u8; 16]).await {
        Err(GhostError::RelayStatus { status: 401, .. }) => {}
        other => panic!("expected 401 for a revoked device, got {other:?}"),
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

    let passphrase = "correct horse battery staple";
    let code = flows::recovery::set_passphrase(&account.client, &account.relay, &account.seed, passphrase)
        .await
        .unwrap();
    assert_eq!(code.account_fp, account.fp);
    assert!(flows::recovery::has_blob(&account.client, &account.relay).await.unwrap());

    // A new device with nothing but the recovery code and passphrase.
    let (guest, _) = RelayClient::new(&code.relay_url);
    let material = flows::recovery::begin(&guest, account.fp, passphrase, "laptop").await.unwrap();
    assert_eq!(material.prior_devices, vec![account.device_vk]);
    let sync_key = material.sync_key.expect("v3 blob carries the sync key");

    let relay_vk = guest.get_relay_info().await.unwrap().relay_vk;
    let mut client_n = GhostClient::open_in_memory(material.identity(), [0x33; 32]).unwrap();
    client_n.set_relay_vk(relay_vk);
    client_n.set_sync_key(sync_key).unwrap();
    client_n.create_sync_group().unwrap();
    let new_vk = material.device_key().verifying_key().to_bytes();
    let (mut relay_n, _) = RelayClient::new(&relay_url);
    relay_n.set_auth(account.fp, new_vk, SigningKey::from_bytes(&material.device_key().to_bytes()));
    let client_n = Arc::new(Mutex::new(client_n));
    let relay_n = Arc::new(Mutex::new(relay_n));

    let settings = flows::recovery::finish(&client_n, &relay_n, &material, sync_key, "a different passphrase")
        .await
        .unwrap();
    assert_eq!(settings.display_name.as_deref(), Some("Alice"));

    {
        let c = client_n.lock().await;
        assert!(c.store().get_server(&server_id).is_ok(), "recovered device rejoined the server");
    }

    // The old device is revoked, so the recovered device reads the log.
    let (_, state) = flows::idlog::fetch_chain(&*relay_n.lock().await, &account.fp).await.unwrap();
    assert!(!state.is_active_device(&account.device_vk), "old device revoked by the Recovery entry");
    assert!(state.is_active_device(&new_vk));

    // The old passphrase no longer opens the re-uploaded blob.
    assert!(flows::recovery::begin(&guest, account.fp, passphrase, "intruder").await.is_err());
}

#[tokio::test]
async fn recovery_rejects_wrong_passphrase() {
    let relay_url = common::start_relay().await;
    let account = create_account(&relay_url, "desktop").await;
    flows::recovery::set_passphrase(&account.client, &account.relay, &account.seed, "correct horse battery staple")
        .await
        .unwrap();
    let (guest, _) = RelayClient::new(&relay_url);
    assert!(flows::recovery::begin(&guest, account.fp, "wrong passphrase here", "laptop").await.is_err());

    // No Recovery entry was appended: the log is still genesis plus the home entry.
    let (log, state) = flows::idlog::fetch_chain(&*account.relay.lock().await, &account.fp).await.unwrap();
    assert_eq!(log.entries.len(), 2);
    assert!(state.is_active_device(&account.device_vk));
}

#[tokio::test]
async fn invite_join_adds_server_for_joiner_and_refreshes_payload() {
    let relay_url = common::start_relay().await;
    let creator = create_account(&relay_url, "creator").await;
    let joiner = create_account(&relay_url, "joiner").await;
    let server_id = create_server(&creator, "club").await;

    let invite = flows::invite::create(&creator.client, &creator.relay, &server_id, u64::MAX).await.unwrap();
    assert_eq!(invite.relay_url, relay_url);

    let joined = flows::invite::join(&joiner.client, &joiner.relay, &joiner.relay, &invite.token, 2000).await.unwrap();
    assert_eq!(joined, server_id);

    {
        let c = joiner.client.lock().await;
        assert!(c.store().get_server(&server_id).is_ok());
        let members = c.store().list_members(&server_id).unwrap();
        assert!(members.iter().any(|m| m.fingerprint == joiner.fp), "joiner recorded itself as a member");
        assert!(members.iter().any(|m| m.fingerprint == creator.fp));
    }

    // The payload was refreshed for the next joiner, so its sequence advanced past the upload.
    let r = joiner.relay.lock().await;
    let (seq, _) = r.get_invite_payload(&invite.token).await.unwrap().unwrap();
    assert_eq!(seq, 2);
}

#[tokio::test]
async fn invite_join_fails_cleanly_for_unknown_token() {
    let relay_url = common::start_relay().await;
    let joiner = create_account(&relay_url, "joiner").await;
    let err = flows::invite::join(&joiner.client, &joiner.relay, &joiner.relay, "no-such-token", 2000).await.unwrap_err();
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

    let invite = flows::invite::create(&creator.client, &creator.relay, &server_id, u64::MAX).await.unwrap();
    flows::invite::join(&joiner.client, &joiner.relay, &joiner.relay, &invite.token, 2000).await.unwrap();

    // The joiner's GroupInfo describes the relay's current state, so it is accepted.
    let current = joiner.client.lock().await.export_server_info(&server_id).unwrap();
    joiner.relay.lock().await.put_server_info(&mailbox_id, current.clone()).await.unwrap();
    assert_eq!(joiner.relay.lock().await.get_server_info(&mailbox_id).await.unwrap(), current);

    // GroupInfo from before the join no longer matches, so a member cannot publish it.
    let err = joiner.relay.lock().await.put_server_info(&mailbox_id, stale).await.unwrap_err();
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
    let invite = flows::invite::create(&alice.client, &alice.relay, &server_id, u64::MAX).await.unwrap();
    flows::invite::join(&carol.client, &carol.relay, &carol.relay, &invite.token, 2000).await.unwrap();
    let (client_b, relay_b, device_b_vk) = pair_second_device(&relay_url, &alice).await;
    let channel_id = derive_default_channel_id(&server_id);
    let mailbox_id = alice.client.lock().await.mailbox_id_for_server(&server_id).unwrap();

    // Carol processes the mailbox until device B's leaf is in her group.
    let (mut reader, mut events) = RelayClient::new(&relay_url);
    reader.copy_auth_from(&*carol.relay.lock().await);
    let carol_seen = carol.client.lock().await.store().get_last_seen_seq(&mailbox_id).unwrap_or(0);
    reader.subscribe(mailbox_id, carol_seen);
    let mut last_seq = carol_seen;
    let caught_up = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(event) = events.recv().await {
            let RelayEvent::Blob(b) = event else { continue };
            let mut c = carol.client.lock().await;
            let _ = c.receive_any(&channel_id, &b.payload, Some(b.received_at));
            last_seq = b.seq;
            if !c.find_device_leaves(&channel_id, &device_b_vk).is_empty() {
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
    relay_b.lock().await.post_blob(&outbound.mailbox_id, outbound.blob).await.unwrap();

    // Alice's account revokes B in its log only: no MLS removal has happened.
    let state = flows::idlog::fetch_and_verify(&alice.client, &alice.relay, &alice.fp).await.unwrap();
    let signer = alice.client.lock().await.signing_key_clone();
    let revoke = ghost_core::identity::log::create_revoke_device(&state, &signer, &device_b_vk);
    alice.relay.lock().await.put_idlog_entry(&alice.fp, revoke.to_bytes()).await.unwrap();
    flows::idlog::cache_member(&carol.client, &carol.relay, &alice.fp).await;

    // B's leaf and delegation are still valid, but Carol's log says the device is revoked.
    let (mut reader, mut events) = RelayClient::new(&relay_url);
    reader.copy_auth_from(&*carol.relay.lock().await);
    reader.subscribe(mailbox_id, last_seq);
    let outcome = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(event) = events.recv().await {
            let RelayEvent::Blob(b) = event else { continue };
            let mut c = carol.client.lock().await;
            match c.receive_any(&channel_id, &b.payload, Some(b.received_at)) {
                Ok(ReceiveResult::Message(m)) | Ok(ReceiveResult::MessageWithKtWarning(m)) if m.content == b"from B" => {
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
