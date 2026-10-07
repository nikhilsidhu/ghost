//! Acceptance tests for accounts that use servers on more than one relay. Each
//! test runs two in-process relays: the account's home and a foreign relay that
//! mirrors the account's identity log.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{create_account, create_server, pair_second_device, Account};
use ghost_core::client::ReceiveResult;
use ghost_core::crypto::MessageType;
use ghost_core::error::GhostError;
use ghost_core::flows;
use ghost_core::relay::{RelayClient, RelayEvent};
use ghost_core::wire::derive_default_channel_id;
use ghost_wire::idlog::EntryBody;
use tokio::sync::Mutex;

/// A view of the device's relay client onto `relay_url`, as the application uses:
/// same credentials, shared subscriptions and mailbox routes.
fn device_client_for(account_relay: &RelayClient, relay_url: &str) -> Arc<Mutex<RelayClient>> {
    Arc::new(Mutex::new(account_relay.at(relay_url)))
}

/// A client for `relay_url` that signs with the account's master key.
async fn master_client(account: &Account, relay_url: &str) -> RelayClient {
    let master = ed25519_dalek::SigningKey::from_bytes(&account.client.lock().await.identity().master_sk.to_bytes());
    let (mut client, _) = RelayClient::new(relay_url);
    client.set_auth(account.fp, master.verifying_key().to_bytes(), master);
    client
}

/// An invite to the server on the account's relay: (token, key that opens its payload).
async fn invite_on(account: &Account, server_id: &[u8; 32]) -> (String, [u8; 32]) {
    let invite = flows::invite::create(&account.client, &account.relay, server_id, u64::MAX).await.unwrap();
    (invite.token, invite.key)
}

#[tokio::test]
async fn accept_p6_sethomerelay_required_at_seq2_for_v2_accounts() {
    let home_url = common::start_relay().await;
    let foreign_url = common::start_relay().await;
    let alice = create_account(&home_url, "alice").await;

    let home_vk = alice.relay.lock().await.get_relay_info().await.unwrap().relay_vk;
    let (log, state) = flows::idlog::fetch_chain(&*alice.relay.lock().await, &alice.fp).await.unwrap();
    assert_eq!(log.entries.len(), 2);
    match &log.entries[1].entry.body {
        EntryBody::SetHomeRelay { relay_vk, relay_ref, .. } => {
            assert_eq!(*relay_vk, home_vk);
            assert_eq!(relay_ref.primary_https_url(), Some(home_url.as_str()));
        }
        other => panic!("seq 2 is not SetHomeRelay: {other:?}"),
    }
    assert_eq!(state.home_relay_vk, Some(home_vk));

    // An account whose chain names no home cannot be mirrored, even with a valid invite.
    let host = create_account(&foreign_url, "host").await;
    let server_id = create_server(&host, "club").await;
    let (token, _key) = invite_on(&host, &server_id).await;
    let legacy = ghost_core::identity::Identity::create_account("legacy").unwrap();
    let legacy_fp = legacy.identity.fingerprint;
    let (legacy_home, _) = RelayClient::new(&home_url);
    let genesis_anchor = legacy_home.put_idlog_entry(&legacy_fp, legacy.genesis_entry.to_bytes()).await.unwrap();
    let (foreign, _) = RelayClient::new(&foreign_url);
    let err = foreign.put_anchored_entries(&legacy_fp, &[genesis_anchor], Some(&token)).await.unwrap_err();
    assert!(matches!(err, GhostError::RelayStatus { status: 422, .. }), "{err}");
}

#[tokio::test]
async fn accept_p6_account_intro_requires_invite_token() {
    let home_url = common::start_relay().await;
    let foreign_url = common::start_relay().await;
    let alice = create_account(&home_url, "alice").await;
    let chain = alice.client.lock().await.store().get_cached_anchored_entries(&alice.fp).unwrap();
    let (foreign, _) = RelayClient::new(&foreign_url);

    let err = foreign.put_anchored_entries(&alice.fp, &chain, None).await.unwrap_err();
    assert!(matches!(err, GhostError::RelayStatus { status: 403, .. }), "{err}");
    let err = foreign.put_anchored_entries(&alice.fp, &chain, Some("no-such-token")).await.unwrap_err();
    assert!(matches!(err, GhostError::RelayStatus { status: 404, .. }), "{err}");
}

#[tokio::test]
async fn accept_p6_account_intro_populates_device_keys_and_allows_deviceauth() {
    let home_url = common::start_relay().await;
    let foreign_url = common::start_relay().await;
    let alice = create_account(&home_url, "alice").await;
    let host = create_account(&foreign_url, "host").await;
    let server_id = create_server(&host, "club").await;
    let (token, _key) = invite_on(&host, &server_id).await;

    let foreign = device_client_for(&*alice.relay.lock().await, &foreign_url);
    // Unknown to the foreign relay: authenticated requests are refused.
    let err = foreign.lock().await.get_account(&alice.fp).await.unwrap_err();
    assert!(matches!(err, GhostError::RelayStatus { status: 401, .. }), "{err}");

    let info = flows::account::register_at(&alice.client, &foreign, Some(&token)).await.unwrap();
    let account = foreign.lock().await.get_account(&alice.fp).await.unwrap();
    let home_vk = alice.relay.lock().await.get_relay_info().await.unwrap().relay_vk;
    assert_eq!(account.home_relay_vk, home_vk);
    assert!(!account.is_home);
    assert_eq!(account.head_seq, 2);
    assert_ne!(info.relay_vk, home_vk);

    // The foreign relay serves the mirrored chain with the home's anchors intact.
    let (log, state) = flows::idlog::fetch_chain(&*foreign.lock().await, &alice.fp).await.unwrap();
    assert_eq!(log.home_relay_vk, home_vk);
    assert!(state.is_active_device(&alice.device_vk));
}

#[tokio::test]
async fn accept_p6_anchored_entry_rejected_without_valid_home_checkpoint() {
    let home_url = common::start_relay().await;
    let foreign_url = common::start_relay().await;
    let alice = create_account(&home_url, "alice").await;
    let host = create_account(&foreign_url, "host").await;
    let server_id = create_server(&host, "club").await;
    let (token, _key) = invite_on(&host, &server_id).await;

    // Re-sign the SetHomeRelay checkpoint with a key that is not the home's.
    let mut chain = alice.client.lock().await.store().get_cached_anchored_entries(&alice.fp).unwrap();
    let impostor = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let cp = &chain[1].checkpoint;
    chain[1].checkpoint = ghost_wire::merkle::Checkpoint::sign(cp.tree_size, cp.root_hash, cp.timestamp, &impostor);

    let (foreign, _) = RelayClient::new(&foreign_url);
    let err = foreign.put_anchored_entries(&alice.fp, &chain, Some(&token)).await.unwrap_err();
    assert!(matches!(err, GhostError::RelayStatus { status: 422, .. }), "{err}");
}

#[tokio::test]
async fn accept_p6_join_server_on_foreign_relay_end_to_end() {
    let home_url = common::start_relay().await;
    let foreign_url = common::start_relay().await;
    let alice = create_account(&home_url, "alice").await;
    let host = create_account(&foreign_url, "host").await;
    let server_id = create_server(&host, "club").await;
    let (token, key) = invite_on(&host, &server_id).await;

    let foreign = device_client_for(&*alice.relay.lock().await, &foreign_url);
    let joined = flows::invite::join(&alice.client, &alice.relay, &foreign, &token, &key, 2000).await.unwrap();
    assert_eq!(joined, server_id);

    // The server is recorded as living on the foreign relay.
    let foreign_vk = foreign.lock().await.get_relay_info().await.unwrap().relay_vk;
    {
        let c = alice.client.lock().await;
        assert_eq!(c.store().server_relay(&server_id).unwrap(), Some(foreign_vk));
        let known = c.store().server_relays().unwrap();
        assert_eq!(known.len(), 1);
        assert_eq!(known[0].relay_vk, foreign_vk);
    }

    // Alice is now a member there: her device keeps authenticating after joining.
    foreign.lock().await.get_account(&alice.fp).await.unwrap();

    // A message from Alice through the foreign relay reaches the host.
    let channel_id = derive_default_channel_id(&server_id);
    let outbound = {
        let mut c = alice.client.lock().await;
        c.send_message(&server_id, &channel_id, b"hi from elsewhere".to_vec(), vec![], 3000).unwrap().0
    };
    foreign.lock().await.post_blob(&outbound.mailbox_id, outbound.blob).await.unwrap();

    let (mut host_relay, mut events) = RelayClient::new(&foreign_url);
    host_relay.copy_auth_from(&*host.relay.lock().await);
    host_relay.subscribe(outbound.mailbox_id, 0);
    let mut host_client = host.client.lock().await;
    let message = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match events.recv().await {
                Some(RelayEvent::Blob(b)) => {
                    match host_client.receive_any(&channel_id, &b.payload, Some(b.received_at)).unwrap() {
                        // Skip the join announcement; it is a control message.
                        ReceiveResult::Message(m) | ReceiveResult::MessageWithKtWarning(m)
                            if m.message_type == MessageType::Text => break m,
                        _ => continue,
                    }
                }
                Some(_) => continue,
                None => panic!("event channel closed"),
            }
        }
    })
    .await
    .expect("host never saw Alice's message");
    assert_eq!(message.content, b"hi from elsewhere");
    assert_eq!(message.sender_fp, alice.fp);
}

#[tokio::test]
async fn accept_p6_revocation_pushed_to_mirror_closes_sessions_and_emits_removes() {
    let home_url = common::start_relay().await;
    let foreign_url = common::start_relay().await;
    let alice = create_account(&home_url, "alice").await;
    let host = create_account(&foreign_url, "host").await;
    let server_id = create_server(&host, "club").await;
    let (token, key) = invite_on(&host, &server_id).await;

    let foreign = device_client_for(&*alice.relay.lock().await, &foreign_url);
    flows::invite::join(&alice.client, &alice.relay, &foreign, &token, &key, 2000).await.unwrap();

    // Pairing pushes the new device's AddDevice to the foreign relay.
    let (_client_b, relay_b, device_b_vk) = pair_second_device(&home_url, &alice).await;
    let foreign_b = device_client_for(&*relay_b.lock().await, &foreign_url);
    foreign_b.lock().await.get_account(&alice.fp).await.unwrap();

    // Revoking device B at the home reaches the foreign relay immediately.
    let outcome = flows::devices::revoke(&alice.client, &alice.relay, &device_b_vk).await.unwrap();
    assert_eq!(outcome, flows::devices::RevokeOutcome::Complete);
    let err = foreign_b.lock().await.get_account(&alice.fp).await.unwrap_err();
    assert!(matches!(err, GhostError::RelayStatus { status: 401, .. }), "{err}");
    let account = foreign.lock().await.get_account(&alice.fp).await.unwrap();
    assert_eq!(account.head_seq, 4, "genesis, home, add, revoke");
}

/// Alice (home relay) joins Host's server on the foreign relay; returns the server id,
/// a device client for the foreign relay, and the foreign relay's key.
async fn join_foreign_server(alice: &Account, foreign_url: &str) -> ([u8; 32], Arc<Mutex<RelayClient>>, [u8; 32], Account) {
    let host = create_account(foreign_url, "host").await;
    let server_id = create_server(&host, "club").await;
    let (token, key) = invite_on(&host, &server_id).await;
    let foreign = device_client_for(&*alice.relay.lock().await, foreign_url);
    flows::invite::join(&alice.client, &alice.relay, &foreign, &token, &key, 2000).await.unwrap();
    let foreign_vk = foreign.lock().await.get_relay_info().await.unwrap().relay_vk;
    (server_id, foreign, foreign_vk, host)
}

#[tokio::test]
async fn accept_p6_linked_device_rejoins_server_on_foreign_relay() {
    let home_url = common::start_relay().await;
    let foreign_url = common::start_relay().await;
    let alice = create_account(&home_url, "alice").await;
    let (server_id, _foreign, foreign_vk, _host) = join_foreign_server(&alice, &foreign_url).await;

    // The provision blob names the foreign relay, so device B rejoins there.
    let (client_b, relay_b, _device_b_vk) = pair_second_device(&home_url, &alice).await;
    {
        let c = client_b.lock().await;
        assert!(c.store().get_server(&server_id).is_ok(), "linked device rejoined the server");
        assert_eq!(c.store().server_relay(&server_id).unwrap(), Some(foreign_vk));
    }
    let foreign_b = device_client_for(&*relay_b.lock().await, &foreign_url);
    foreign_b.lock().await.get_account(&alice.fp).await.unwrap();
}

#[tokio::test]
async fn accept_p6_recovery_rejoins_servers_on_foreign_relays() {
    let home_url = common::start_relay().await;
    let foreign_url = common::start_relay().await;
    let alice = create_account(&home_url, "alice").await;
    let (server_id, foreign, foreign_vk, _host) = join_foreign_server(&alice, &foreign_url).await;

    // The sync snapshot records the server together with the relay that hosts it.
    flows::sync::server_entry(&alice.client, &alice.relay, &server_id).await;
    flows::sync::push_snapshot(&alice.client, &alice.relay).await;
    let passphrase = "correct horse battery staple";
    flows::recovery::set_passphrase(&alice.client, &alice.relay, &alice.seed, passphrase).await.unwrap();

    let (guest, _) = RelayClient::new(&home_url);
    let material = flows::recovery::begin(&guest, alice.fp, passphrase, "laptop").await.unwrap();
    let sync_key = material.sync_key.unwrap();
    let home_vk = guest.get_relay_info().await.unwrap().relay_vk;
    let mut client_n = ghost_core::client::GhostClient::open_in_memory(material.identity(), [0x33; 32]).unwrap();
    client_n.set_relay_vk(home_vk);
    client_n.set_sync_key(sync_key).unwrap();
    client_n.create_sync_group().unwrap();
    let new_vk = material.device_key().verifying_key().to_bytes();
    let (mut relay_n, _) = RelayClient::new(&home_url);
    relay_n.set_auth(alice.fp, new_vk, ed25519_dalek::SigningKey::from_bytes(&material.device_key().to_bytes()));
    let client_n = Arc::new(Mutex::new(client_n));
    let relay_n = Arc::new(Mutex::new(relay_n));

    flows::recovery::finish(&client_n, &relay_n, &material, sync_key, "a different passphrase").await.unwrap();

    {
        let c = client_n.lock().await;
        assert!(c.store().get_server(&server_id).is_ok(), "recovered device rejoined the foreign server");
        assert_eq!(c.store().server_relay(&server_id).unwrap(), Some(foreign_vk));
    }
    // The foreign relay applied the Recovery entry: old device out, new device in.
    let err = foreign.lock().await.get_account(&alice.fp).await.unwrap_err();
    assert!(matches!(err, GhostError::RelayStatus { status: 401, .. }), "{err}");
    let foreign_n = device_client_for(&*relay_n.lock().await, &foreign_url);
    foreign_n.lock().await.get_account(&alice.fp).await.unwrap();
}

#[tokio::test]
async fn accept_p6_revocation_pulled_by_mirror_within_refresh_interval() {
    let home_url = common::start_relay().await;
    let foreign_url = common::start_relay().await;
    let alice = create_account(&home_url, "alice").await;
    let (_server_id, _foreign, _foreign_vk, _host) = join_foreign_server(&alice, &foreign_url).await;
    let (_client_b, relay_b, device_b_vk) = pair_second_device(&home_url, &alice).await;
    let foreign_b = device_client_for(&*relay_b.lock().await, &foreign_url);
    foreign_b.lock().await.get_account(&alice.fp).await.unwrap();

    // Revoke at the home only, as a device that never reaches the foreign relay would.
    let state = flows::idlog::fetch_and_verify(&alice.client, &alice.relay, &alice.fp).await.unwrap();
    let signer = alice.client.lock().await.signing_key_clone();
    let revoke = ghost_core::identity::log::create_revoke_device(&state, &signer, &device_b_vk);
    alice.relay.lock().await.put_idlog_entry(&alice.fp, revoke.to_bytes()).await.unwrap();

    // The test relays refresh every second; allow a few intervals.
    let mut revoked = false;
    for _ in 0..50 {
        match foreign_b.lock().await.get_account(&alice.fp).await {
            Err(GhostError::RelayStatus { status: 401, .. }) => {
                revoked = true;
                break;
            }
            _ => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    assert!(revoked, "foreign relay never pulled the revocation from the home");
}

#[tokio::test]
async fn accept_p6_rehome_import_anchors_whole_chain_and_mirrors_switch() {
    let old_url = common::start_relay().await;
    let foreign_url = common::start_relay().await;
    let new_url = common::start_relay().await;
    let alice = create_account(&old_url, "alice").await;
    let (_server_id, foreign, _foreign_vk, _host) = join_foreign_server(&alice, &foreign_url).await;

    let new_home = device_client_for(&*alice.relay.lock().await, &new_url);
    let new_vk = flows::account::rehome(&alice.client, &new_home, Some(&alice.relay)).await.unwrap();

    // The new home sequences the account and serves a chain whose first entries
    // still carry the old home's anchors; a fresh fetch validates all of it.
    let account = new_home.lock().await.get_account(&alice.fp).await.unwrap();
    assert!(account.is_home);
    assert_eq!(account.head_seq, 3);
    let state = flows::idlog::fetch_and_verify(&alice.client, &new_home, &alice.fp).await.unwrap();
    assert_eq!(state.home_relay_vk, Some(new_vk));
    assert_eq!(state.home_set_at_seq, 3);

    // The foreign relay switched without any device pushing to it explicitly.
    let mirrored = foreign.lock().await.get_account(&alice.fp).await.unwrap();
    assert_eq!(mirrored.home_relay_vk, new_vk);
    assert!(!mirrored.is_home);

    // New entries now go to the new home.
    let devices = flows::devices::list(&alice.client, &new_home).await.unwrap();
    assert!(devices.is_active_device(&alice.device_vk));
}

#[tokio::test]
async fn accept_p6_old_home_marks_account_moved_and_rejects_appends() {
    let old_url = common::start_relay().await;
    let new_url = common::start_relay().await;
    let alice = create_account(&old_url, "alice").await;
    let new_home = device_client_for(&*alice.relay.lock().await, &new_url);
    let new_vk = flows::account::rehome(&alice.client, &new_home, Some(&alice.relay)).await.unwrap();

    // The old home now reports the new one and serves the move. Alice's device is no
    // longer admitted there, so read with the master key, as a recovering device would.
    let (guest, _) = RelayClient::new(&old_url);
    let (log, state) = flows::idlog::fetch_chain(&master_client(&alice, &old_url).await, &alice.fp).await.unwrap();
    assert_eq!(log.home_relay_vk, new_vk);
    assert_eq!(state.home_relay_vk, Some(new_vk));

    // It refuses to sequence anything further for the account. A device append
    // fails authentication: the account is neither homed nor a member there.
    let signer = alice.client.lock().await.signing_key_clone();
    let stray = ghost_core::identity::log::create_set_home_relay(
        &state,
        &signer,
        ghost_wire::relay_ref::RelayRef::https(guest.get_relay_info().await.unwrap().relay_vk, &old_url),
    );
    let err = alice.relay.lock().await.put_idlog_entry(&alice.fp, stray.to_bytes()).await.unwrap_err();
    assert!(matches!(err, GhostError::RelayStatus { status: 401, .. }), "{err}");

    // A Recovery entry needs no credentials, so the old home must refuse it on
    // the moved account itself, or it could fork the log.
    let master = ed25519_dalek::SigningKey::from_bytes(&alice.client.lock().await.identity().master_sk.to_bytes());
    let new_device = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let recovery = ghost_core::identity::log::create_recovery(&state, &master, &new_device, "fork");
    let err = guest.put_idlog_entry(&alice.fp, recovery.to_bytes()).await.unwrap_err();
    assert!(matches!(err, GhostError::RelayStatus { status: 409, .. }), "{err}");
}

#[tokio::test]
async fn accept_p6_recovery_bundle_replicated_to_all_member_relays_and_rollback_rejected() {
    let home_url = common::start_relay().await;
    let foreign_url = common::start_relay().await;
    let alice = create_account(&home_url, "alice").await;
    let (_server_id, foreign, _foreign_vk, _host) = join_foreign_server(&alice, &foreign_url).await;

    let passphrase = "correct horse battery staple";
    flows::recovery::set_passphrase(&alice.client, &alice.relay, &alice.seed, passphrase).await.unwrap();
    let (home_guest, _) = RelayClient::new(&home_url);
    let (foreign_guest, _) = RelayClient::new(&foreign_url);
    let at_home = home_guest.get_recovery_bundle(&alice.fp).await.unwrap().unwrap();
    let at_foreign = foreign_guest.get_recovery_bundle(&alice.fp).await.unwrap().unwrap();
    assert_eq!(at_home, at_foreign, "member relay holds the same bundle");

    // A passphrase change supersedes both copies.
    flows::recovery::change_passphrase(&alice.client, &alice.relay, passphrase, "a brand new passphrase").await.unwrap();
    let changed = foreign_guest.get_recovery_bundle(&alice.fp).await.unwrap().unwrap();
    assert!(changed.generation > at_foreign.generation);
    assert_ne!(changed.recovery_blob, at_foreign.recovery_blob);

    // Replaying the old bundle, at the member relay or the home, is refused.
    let err = foreign.lock().await.put_recovery_bundle(&alice.fp, &at_foreign).await.unwrap_err();
    assert!(matches!(err, GhostError::RelayStatus { status: 409, .. }), "{err}");
    let err = alice.relay.lock().await.put_recovery_bundle(&alice.fp, &at_home).await.unwrap_err();
    assert!(matches!(err, GhostError::RelayStatus { status: 409, .. }), "{err}");
}

#[tokio::test]
async fn accept_p6_recover_with_dead_home_via_import_batch() {
    let (home_url, home_server) = common::start_relay_with_handle().await;
    let foreign_url = common::start_relay().await;
    let new_home_url = common::start_relay().await;
    let alice = create_account(&home_url, "alice").await;
    let (server_id, foreign, foreign_vk, _host) = join_foreign_server(&alice, &foreign_url).await;

    // Replicated state a recovering device needs: server list and recovery bundle.
    flows::sync::server_entry(&alice.client, &alice.relay, &server_id).await;
    flows::sync::push_snapshot(&alice.client, &alice.relay).await;
    let passphrase = "correct horse battery staple";
    flows::recovery::set_passphrase(&alice.client, &alice.relay, &alice.seed, passphrase).await.unwrap();

    // The home relay disappears, and every device is lost.
    home_server.abort();
    let _ = home_server.await;
    let (dead, _) = RelayClient::new(&home_url);
    assert!(dead.get_relay_info().await.is_err(), "home relay is unreachable");

    let (source, _) = RelayClient::new(&foreign_url);
    let (new_home, _) = RelayClient::new(&new_home_url);
    let material = flows::recovery::begin_with_new_home(&source, &new_home, alice.fp, passphrase, "laptop")
        .await
        .unwrap();
    let sync_key = material.sync_key.unwrap();
    let new_home_vk = new_home.get_relay_info().await.unwrap().relay_vk;

    let mut client_n = ghost_core::client::GhostClient::open_in_memory(material.identity(), [0x44; 32]).unwrap();
    client_n.set_relay_vk(new_home_vk);
    client_n.set_sync_key(sync_key).unwrap();
    client_n.create_sync_group().unwrap();
    let new_vk = material.device_key().verifying_key().to_bytes();
    let (mut relay_n, _) = RelayClient::new(&new_home_url);
    relay_n.set_auth(alice.fp, new_vk, ed25519_dalek::SigningKey::from_bytes(&material.device_key().to_bytes()));
    let client_n = Arc::new(Mutex::new(client_n));
    let relay_n = Arc::new(Mutex::new(relay_n));

    flows::recovery::finish(&client_n, &relay_n, &material, sync_key, "a different passphrase").await.unwrap();

    // The account now lives at the new home, and the chain validates end to end.
    let state = flows::idlog::fetch_and_verify(&client_n, &relay_n, &alice.fp).await.unwrap();
    assert_eq!(state.home_relay_vk, Some(new_home_vk));
    assert!(state.is_active_device(&new_vk));
    assert!(!state.is_active_device(&alice.device_vk));
    assert!(relay_n.lock().await.get_account(&alice.fp).await.unwrap().is_home);

    // The server on the foreign relay was rejoined from the replicated snapshot.
    {
        let c = client_n.lock().await;
        assert!(c.store().get_server(&server_id).is_ok(), "rejoined the foreign server");
        assert_eq!(c.store().server_relay(&server_id).unwrap(), Some(foreign_vk));
    }
    // The foreign relay switched home and revoked the lost device.
    let foreign_n = device_client_for(&*relay_n.lock().await, &foreign_url);
    let account = foreign_n.lock().await.get_account(&alice.fp).await.unwrap();
    assert_eq!(account.home_relay_vk, new_home_vk);
    let err = foreign.lock().await.get_account(&alice.fp).await.unwrap_err();
    assert!(matches!(err, GhostError::RelayStatus { status: 401, .. }), "{err}");
}

#[tokio::test]
async fn accept_p6_revoked_device_cannot_decrypt_after_remaining_devices_commit_while_home_partitioned() {
    let (home_url, home_server) = common::start_relay_with_handle().await;
    let foreign_url = common::start_relay().await;
    let alice = create_account(&home_url, "alice").await;
    let (server_id, foreign, _foreign_vk, _host) = join_foreign_server(&alice, &foreign_url).await;
    let (client_b, relay_b, device_b_vk) = pair_second_device(&home_url, &alice).await;
    let channel_id = derive_default_channel_id(&server_id);
    let mailbox_id = alice.client.lock().await.mailbox_id_for_server(&server_id).unwrap();
    let b_seen = client_b.lock().await.store().get_last_seen_seq(&mailbox_id).unwrap_or(0);

    // Alice's device processes device B's join so its group holds B's leaf, as
    // its live connection would have done.
    {
        let a_seen = alice.client.lock().await.store().get_last_seen_seq(&mailbox_id).unwrap_or(0);
        let (mut reader, mut events) = RelayClient::new(&foreign_url);
        reader.copy_auth_from(&*alice.relay.lock().await);
        reader.subscribe(mailbox_id, a_seen);
        let caught_up = tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(event) = events.recv().await {
                if let RelayEvent::Blob(b) = event {
                    let mut c = alice.client.lock().await;
                    let _ = c.receive_any(&channel_id, &b.payload, Some(b.received_at));
                    let _ = c.store().set_last_seen_seq(&mailbox_id, b.seq);
                    if !c.find_device_leaves(&channel_id, &device_b_vk).is_empty() {
                        return;
                    }
                }
            }
        })
        .await;
        assert!(caught_up.is_ok(), "Alice never saw device B join");
    }

    // The home relay becomes unreachable before the revocation.
    home_server.abort();
    let _ = home_server.await;

    let outcome = flows::devices::revoke(&alice.client, &alice.relay, &device_b_vk).await.unwrap();
    assert_eq!(outcome, flows::devices::RevokeOutcome::LogPending);

    // No relay has heard of the revocation, so device B still authenticates at the
    // foreign relay; only the MLS removal stands between it and new messages.
    let outbound = {
        let mut c = alice.client.lock().await;
        c.send_message(&server_id, &channel_id, b"after revoke".to_vec(), vec![], 5000).unwrap().0
    };
    foreign.lock().await.post_blob(&outbound.mailbox_id, outbound.blob).await.unwrap();

    let (mut reader, mut events) = RelayClient::new(&foreign_url);
    reader.copy_auth_from(&*relay_b.lock().await);
    reader.subscribe(mailbox_id, b_seen);
    let mut kicked = false; // set when device B learns it was removed
    let mut seen = Vec::new();
    let mut c = client_b.lock().await;
    let _ = tokio::time::timeout(Duration::from_secs(3), async {
        while let Some(event) = events.recv().await {
            if let RelayEvent::Blob(b) = event {
                let result = c.receive_any(&channel_id, &b.payload, Some(b.received_at));
                seen.push(format!("seq {}: {}", b.seq, match &result {
                    Ok(ReceiveResult::Message(m)) | Ok(ReceiveResult::MessageWithKtWarning(m)) => format!("message {:?}", m.message_type),
                    Ok(ReceiveResult::CommitProcessed) => "commit".into(),
                    Ok(ReceiveResult::Kicked) => "kicked".into(),
                    Ok(ReceiveResult::DeviceRemoved) => "device removed".into(),
                    Ok(ReceiveResult::MembersRemoved(fps)) => format!("members removed: {}", fps.len()),
                    Ok(ReceiveResult::ProposalProcessed) => "proposal".into(),
                    Ok(ReceiveResult::ChannelAccessLost(_)) => "channel access lost".into(),
                    Ok(ReceiveResult::Skipped) => "skipped".into(),
                    Err(e) => format!("error: {e}"),
                }));
                match result {
                    // Only this device was removed; Alice's other device stays in the group.
                    Ok(ReceiveResult::DeviceRemoved) => kicked = true,
                    Ok(ReceiveResult::Message(m)) | Ok(ReceiveResult::MessageWithKtWarning(m)) => {
                        assert_ne!(m.content, b"after revoke", "revoked device decrypted a later message");
                    }
                    _ => {}
                }
            }
        }
    })
    .await;
    assert!(kicked, "device B never processed its removal; it saw: {seen:#?}");
}

#[tokio::test]
async fn accept_p6_home_client_routes_foreign_server_traffic_across_restart() {
    let home_url = common::start_relay().await;
    let foreign_url = common::start_relay().await;
    let alice = create_account(&home_url, "alice").await;
    let (server_id, _foreign, _foreign_vk, host) = join_foreign_server(&alice, &foreign_url).await;
    let channel_id = derive_default_channel_id(&server_id);

    // The application only holds its home client; requests for the foreign server's
    // mailboxes follow the routes recorded when it joined.
    let outbound = {
        let mut c = alice.client.lock().await;
        c.send_message(&server_id, &channel_id, b"via home client".to_vec(), vec![], 3000).unwrap().0
    };
    alice.relay.lock().await.post_blob(&outbound.mailbox_id, outbound.blob).await.unwrap();

    // After a restart: a fresh home client, startup subscriptions, one event stream.
    let (mut restarted, mut events) = RelayClient::new(&home_url);
    restarted.copy_auth_from(&*alice.relay.lock().await);
    {
        let c = alice.client.lock().await;
        flows::subscribe_known_mailboxes(&c, &mut restarted);
    }
    let reply = {
        let mut c = host.client.lock().await;
        // The host first catches up on Alice's join so it can encrypt to her.
        let (mut catch_up, mut host_events) = RelayClient::new(&foreign_url);
        catch_up.copy_auth_from(&*host.relay.lock().await);
        catch_up.subscribe(outbound.mailbox_id, 0);
        let caught_up = tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(event) = host_events.recv().await {
                // Connection-state events come first; only blobs matter here.
                let RelayEvent::Blob(b) = event else { continue };
                if let Ok(ReceiveResult::Message(m)) = c.receive_any(&channel_id, &b.payload, Some(b.received_at)) {
                    if m.content == b"via home client" {
                        return;
                    }
                }
            }
        })
        .await;
        assert!(caught_up.is_ok(), "the host never received the message Alice sent through her home client");
        c.send_message(&server_id, &channel_id, b"hello back".to_vec(), vec![], 4000).unwrap().0
    };
    host.relay.lock().await.at(&foreign_url).post_blob(&reply.mailbox_id, reply.blob).await.unwrap();

    let mut c = alice.client.lock().await;
    let got = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match events.recv().await {
                Some(RelayEvent::Blob(b)) => {
                    if let Ok(ReceiveResult::Message(m)) | Ok(ReceiveResult::MessageWithKtWarning(m)) =
                        c.receive_any(&channel_id, &b.payload, Some(b.received_at))
                    {
                        if m.content == b"hello back" {
                            return m;
                        }
                    }
                }
                Some(_) => continue,
                None => panic!("event stream closed"),
            }
        }
    })
    .await
    .expect("the restarted home client never delivered the foreign server's message");
    assert_eq!(got.sender_fp, host.fp);
}

#[tokio::test]
async fn accept_p6_pairing_via_member_relay_with_token() {
    let home_url = common::start_relay().await;
    let foreign_url = common::start_relay().await;
    let alice = create_account(&home_url, "alice").await;
    let (server_id, foreign, foreign_vk, _host) = join_foreign_server(&alice, &foreign_url).await;

    // The rendezvous is on the member relay; the code names it, not the home.
    let offer = flows::pairing::PairingOffer {
        relay_url: foreign_url.clone(),
        display_name: "Alice".into(),
        avatar_hash: None,
        status_message: None,
    };
    let code = flows::pairing::start(&alice.client, &foreign, &offer).await.unwrap();
    assert_eq!(code.relay_url, foreign_url);
    let code = flows::pairing::PairingCode::parse(&code.encode()).unwrap();

    let (guest, _) = RelayClient::new(&code.relay_url);
    flows::pairing::fetch_offer(&guest, &code).await.unwrap();
    let device_b = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let device_b_vk = device_b.verifying_key().to_bytes();
    flows::pairing::respond(&guest, &code, &device_b, "phone").await.unwrap();

    // Another token does not reach the session.
    let mut wrong = code.clone();
    wrong.token = [0u8; 16];
    assert!(flows::pairing::fetch_offer(&guest, &wrong).await.is_err());

    // AddDevice goes to the home and reaches the member relay before B looks there.
    let label = flows::pairing::check(&alice.client, &alice.relay, &foreign, &code, None).await.unwrap();
    assert_eq!(label.as_deref(), Some("phone"));
    let log_state =
        flows::pairing::wait_for_device(&guest, &alice.fp, &device_b, common::POLL_ATTEMPTS, common::POLL_INTERVAL)
            .await
            .unwrap();
    let blob = flows::pairing::fetch_provision(&guest, &code, common::POLL_ATTEMPTS, common::POLL_INTERVAL).await.unwrap();

    // The new device learns its home from the chain, not from the code.
    let home_ref = log_state.home_relay_ref.clone().expect("chain names a home");
    assert_eq!(home_ref.primary_https_url(), Some(home_url.as_str()));
    let identity_b = flows::pairing::linked_identity(alice.fp, device_b.clone(), &log_state, &blob);
    let mut client_b = ghost_core::client::GhostClient::open_in_memory(identity_b, [0x55; 32]).unwrap();
    client_b.set_relay_vk(home_ref.relay_vk);
    let (mut relay_b, _) = RelayClient::new(home_ref.primary_https_url().unwrap());
    relay_b.set_auth(alice.fp, device_b_vk, device_b);
    let client_b = Arc::new(Mutex::new(client_b));
    let relay_b = Arc::new(Mutex::new(relay_b));
    flows::provision::consume(&client_b, &relay_b, &blob, 2000).await.unwrap();

    let c = client_b.lock().await;
    assert!(c.store().get_server(&server_id).is_ok());
    assert_eq!(c.store().server_relay(&server_id).unwrap(), Some(foreign_vk));
}

#[tokio::test]
async fn accept_p6_identity_log_reads_require_authorization() {
    let home_url = common::start_relay().await;
    let foreign_url = common::start_relay().await;
    let alice = create_account(&home_url, "alice").await;
    let outsider = create_account(&foreign_url, "outsider").await;

    // Anonymous readers learn nothing about the account's devices.
    let (anonymous, _) = RelayClient::new(&home_url);
    let err = anonymous.get_idlog(&alice.fp, 0).await.unwrap_err();
    assert!(matches!(err, GhostError::RelayStatus { status: 401, .. }), "{err}");

    // A device of an account this relay does not admit is refused too.
    let stranger = outsider.relay.lock().await.at(&home_url);
    let err = stranger.get_idlog(&alice.fp, 0).await.unwrap_err();
    assert!(matches!(err, GhostError::RelayStatus { status: 401, .. }), "{err}");

    // The account's own device and its master key may read.
    alice.relay.lock().await.get_idlog(&alice.fp, 0).await.unwrap();
    master_client(&alice, &home_url).await.get_idlog(&alice.fp, 0).await.unwrap();

    // A relay may pull only once the account granted it.
    let pull = |sk: &ed25519_dalek::SigningKey| {
        let path = format!("/idlog/{}", hex::encode(alice.fp));
        let header = ghost_wire::auth::sign_relay_auth("GET", &path, sk);
        let url = format!("{home_url}{path}");
        async move { reqwest::Client::new().get(url).header(ghost_wire::auth::RELAY_AUTH_HEADER, header).send().await.unwrap().status() }
    };
    let some_relay = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    assert_eq!(pull(&some_relay).await, reqwest::StatusCode::FORBIDDEN);
    alice
        .relay
        .lock()
        .await
        .put_mirror_grants(&alice.fp, &[some_relay.verifying_key().to_bytes()])
        .await
        .unwrap();
    assert_eq!(pull(&some_relay).await, reqwest::StatusCode::OK);
}

// ── Server moves ──────────────────────────────────────────────────────

/// A device's own relay client with a readable event stream, as the application holds it.
async fn app_client(account: &Account, home_url: &str) -> (Arc<Mutex<RelayClient>>, tokio::sync::mpsc::Receiver<RelayEvent>) {
    let (mut client, events) = RelayClient::new(home_url);
    client.copy_auth_from(&*account.relay.lock().await);
    (Arc::new(Mutex::new(client)), events)
}

/// Feed a device's events to its client until `pick` returns a value.
async fn receive_until<T>(
    client: &Arc<Mutex<ghost_core::client::GhostClient>>,
    events: &mut tokio::sync::mpsc::Receiver<RelayEvent>,
    channel_id: &[u8; 32],
    mut pick: impl FnMut(ReceiveResult) -> Option<T>,
) -> Option<T> {
    tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(event) = events.recv().await {
            let RelayEvent::Blob(b) = event else { continue };
            let result = client.lock().await.receive_any(channel_id, &b.payload, Some(b.received_at));
            if let Some(value) = result.ok().and_then(&mut pick) {
                return Some(value);
            }
        }
        None
    })
    .await
    .ok()
    .flatten()
}

fn text(content: &'static [u8]) -> impl FnMut(ReceiveResult) -> Option<()> {
    move |r| match r {
        ReceiveResult::Message(m) | ReceiveResult::MessageWithKtWarning(m) if m.content == content => Some(()),
        _ => None,
    }
}

/// Host creates a server on `old_url`; Alice (home `alice_url`) joins it through her
/// app client; the host's device catches up on her join, as its live connection would.
struct HostedServer {
    host: Account,
    alice: Account,
    server_id: [u8; 32],
    channel_id: [u8; 32],
    alice_app: Arc<Mutex<RelayClient>>,
    alice_events: tokio::sync::mpsc::Receiver<RelayEvent>,
    alice_old_view: Arc<Mutex<RelayClient>>,
}

async fn host_server_with_alice(old_url: &str, alice_url: &str) -> HostedServer {
    let host = create_account(old_url, "host").await;
    let alice = create_account(alice_url, "alice").await;
    let server_id = create_server(&host, "club").await;
    let channel_id = derive_default_channel_id(&server_id);
    let mailbox_id = host.client.lock().await.mailbox_id_for_server(&server_id).unwrap();
    // The host's application is subscribed to its server, which routes it to this relay.
    host.relay.lock().await.subscribe(mailbox_id, 0);

    let (alice_app, alice_events) = app_client(&alice, alice_url).await;
    let alice_old_view = Arc::new(Mutex::new(alice_app.lock().await.at(old_url)));
    let (token, key) = invite_on(&host, &server_id).await;
    flows::invite::join(&alice.client, &alice_app, &alice_old_view, &token, &key, 2000).await.unwrap();

    let (mut reader, mut events) = RelayClient::new(old_url);
    reader.copy_auth_from(&*host.relay.lock().await);
    reader.subscribe(mailbox_id, 0);
    let alice_fp = alice.fp;
    let caught_up = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(event) = events.recv().await {
            let RelayEvent::Blob(b) = event else { continue };
            let mut c = host.client.lock().await;
            let _ = c.receive_any(&channel_id, &b.payload, Some(b.received_at));
            let _ = c.store().set_last_seen_seq(&mailbox_id, b.seq);
            if c.mls_member_fingerprints(&server_id).unwrap_or_default().contains(&alice_fp) {
                return;
            }
        }
    })
    .await;
    assert!(caught_up.is_ok(), "host never saw Alice join");
    HostedServer { host, alice, server_id, channel_id, alice_app, alice_events, alice_old_view }
}

async fn relay_vk_at(url: &str) -> [u8; 32] {
    RelayClient::new(url).0.get_relay_info().await.unwrap().relay_vk
}

async fn host_sends(s: &HostedServer, home: &Arc<Mutex<RelayClient>>, content: &[u8]) {
    let outbound = {
        let mut c = s.host.client.lock().await;
        c.send_message(&s.server_id, &s.channel_id, content.to_vec(), vec![], 9000).unwrap().0
    };
    home.lock().await.post_blob(&outbound.mailbox_id, outbound.blob).await.unwrap();
}

#[tokio::test]
async fn accept_p6_server_move_followed_through_announcement() {
    let old_url = common::start_relay().await;
    let new_url = common::start_relay().await;
    let alice_url = common::start_relay().await;
    let mut s = host_server_with_alice(&old_url, &alice_url).await;

    // The host's account moves to the new relay, then the server follows it.
    let host_home = Arc::new(Mutex::new(s.host.relay.lock().await.at(&new_url)));
    flows::account::rehome(&s.host.client, &host_home, Some(&s.host.relay)).await.unwrap();
    let location = flows::server::move_server(&s.host.client, &host_home, &s.server_id, &new_url).await.unwrap();

    // Alice's live connection delivers the announcement; following it moves her.
    let announced = receive_until(&s.alice.client, &mut s.alice_events, &s.channel_id, |r| match r {
        ReceiveResult::Message(m) | ReceiveResult::MessageWithKtWarning(m) if m.message_type == MessageType::Metadata => {
            match ghost_core::wire::decode_metadata(&m.content) {
                Ok(ghost_core::wire::MetadataPayload::ServerMoved(location)) => Some(location),
                _ => None,
            }
        }
        _ => None,
    })
    .await
    .expect("Alice never received the move announcement");
    assert_eq!(announced, location);
    assert!(flows::server::follow_move(&s.alice.client, &s.alice_app, &s.server_id, &announced).await.unwrap());
    let new_vk = relay_vk_at(&new_url).await;
    assert_eq!(s.alice.client.lock().await.store().server_relay(&s.server_id).unwrap(), Some(new_vk));

    // Messages now flow through the new relay; a repeated announcement changes nothing.
    host_sends(&s, &host_home, b"after the move").await;
    receive_until(&s.alice.client, &mut s.alice_events, &s.channel_id, text(b"after the move"))
        .await
        .expect("Alice never received a message through the new relay");
    assert!(!flows::server::follow_move(&s.alice.client, &s.alice_app, &s.server_id, &announced).await.unwrap());
}

#[tokio::test]
async fn server_move_carries_private_channels_to_the_new_relay() {
    use ghost_core::storage::ChannelKind;

    let old_url = common::start_relay().await;
    let new_url = common::start_relay().await;
    let alice_url = common::start_relay().await;
    let s = host_server_with_alice(&old_url, &alice_url).await;
    let channel_id = flows::channels::create_private(
        &s.host.client, &s.host.relay, &s.host.relay, &s.server_id, "staff", ChannelKind::Text, vec![], vec![s.alice.fp],
    )
    .await
    .unwrap();

    let host_home = Arc::new(Mutex::new(s.host.relay.lock().await.at(&new_url)));
    flows::account::rehome(&s.host.client, &host_home, Some(&s.host.relay)).await.unwrap();
    flows::server::move_server(&s.host.client, &host_home, &s.server_id, &new_url).await.unwrap();

    // The new relay holds the channel's group under the moved server group: it accepts
    // the channel's traffic and lists the channel for the members it admits.
    let outbound = {
        let mut c = s.host.client.lock().await;
        c.send_message(&s.server_id, &channel_id, b"still private".to_vec(), vec![], 9000).unwrap().0
    };
    host_home.lock().await.post_blob(&outbound.mailbox_id, outbound.blob).await.unwrap();
    let server_mailbox = s.host.client.lock().await.server_mailbox(&s.server_id).unwrap();
    let (mut reader, _events) = RelayClient::new(&new_url);
    reader.copy_auth_from(&*s.host.relay.lock().await);
    let listing = reader.get_admitted_channels(&server_mailbox).await.unwrap();
    assert_eq!(listing.0.iter().map(|(mailbox, _)| *mailbox).collect::<Vec<_>>(), vec![outbound.mailbox_id]);
}

#[tokio::test]
async fn accept_p6_server_move_found_at_creator_home_after_relay_dies() {
    let (old_url, old_server) = common::start_relay_with_handle().await;
    let new_url = common::start_relay().await;
    let alice_url = common::start_relay().await;
    let mut s = host_server_with_alice(&old_url, &alice_url).await;

    // While the old relay is still up, the host re-homes its account and Alice's
    // device refreshes the host's log there, learning the new home.
    let host_home = Arc::new(Mutex::new(s.host.relay.lock().await.at(&new_url)));
    flows::account::rehome(&s.host.client, &host_home, Some(&s.host.relay)).await.unwrap();
    flows::idlog::cache_member(&s.alice.client, &s.alice_old_view, &s.host.fp).await;

    old_server.abort();
    let _ = old_server.await;

    // The announcement cannot reach anyone; the record at the host's home can.
    flows::server::move_server(&s.host.client, &host_home, &s.server_id, &new_url).await.unwrap();
    assert!(flows::server::check_location(&s.alice.client, &s.alice_app, &s.server_id).await.unwrap());

    host_sends(&s, &host_home, b"we survived").await;
    receive_until(&s.alice.client, &mut s.alice_events, &s.channel_id, text(b"we survived"))
        .await
        .expect("Alice never received a message after the relay died");
}

#[tokio::test]
async fn accept_p6_server_move_link_followed_when_no_shared_relay_survives() {
    let (old_url, old_server) = common::start_relay_with_handle().await;
    let new_url = common::start_relay().await;
    let alice_url = common::start_relay().await;
    let mut s = host_server_with_alice(&old_url, &alice_url).await;

    // The old relay dies before Alice learns anything about the host's new home.
    let host_home = Arc::new(Mutex::new(s.host.relay.lock().await.at(&new_url)));
    flows::account::rehome(&s.host.client, &host_home, Some(&s.host.relay)).await.unwrap();
    old_server.abort();
    let _ = old_server.await;

    let location = flows::server::move_server(&s.host.client, &host_home, &s.server_id, &new_url).await.unwrap();
    assert!(flows::server::check_location(&s.alice.client, &s.alice_app, &s.server_id).await.is_err());

    // The link carries the same signed record, verified against the host's cached log.
    let link = flows::server::move_link(&location);
    let parsed = flows::server::parse_move_link(&link).unwrap();
    assert!(flows::server::follow_move(&s.alice.client, &s.alice_app, &s.server_id, &parsed).await.unwrap());

    host_sends(&s, &host_home, b"found you").await;
    receive_until(&s.alice.client, &mut s.alice_events, &s.channel_id, text(b"found you"))
        .await
        .expect("Alice never received a message after following the link");
}

#[tokio::test]
async fn accept_p6_server_move_refuses_records_not_signed_by_the_owner() {
    let old_url = common::start_relay().await;
    let alice_url = common::start_relay().await;
    let s = host_server_with_alice(&old_url, &alice_url).await;

    // Alice is a member, not the owner: her signature cannot move the server.
    let alice_key = s.alice.client.lock().await.signing_key_clone();
    let forged = ghost_wire::server_location::ServerLocation::sign(
        s.server_id,
        99,
        ghost_wire::relay_ref::RelayRef::https([0x66; 32], "https://evil.example"),
        &alice_key,
    );
    let err = flows::server::follow_move(&s.alice.client, &s.alice_app, &s.server_id, &forged).await.unwrap_err();
    assert!(err.to_string().contains("owner"), "{err}");

    // Only the owner may move it at all.
    let err = flows::server::move_server(&s.alice.client, &s.alice_app, &s.server_id, &alice_url).await.unwrap_err();
    assert!(matches!(err, GhostError::PermissionDenied(_)), "{err}");
}
