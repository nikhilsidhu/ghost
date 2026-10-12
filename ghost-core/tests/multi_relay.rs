//! Acceptance tests for accounts that use servers on more than one relay. Each
//! test runs two in-process relays: the account's home and a foreign relay that
//! mirrors the account's identity log.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{create_account, create_server, pair_second_device, Account};
use ghost_core::account_keys::RecoveryKey;
use ghost_core::client::ReceiveResult;
use ghost_core::crypto::MessageType;
use ghost_core::error::GhostError;
use ghost_core::flows;
use ghost_core::relay::{RelayClient, RelayEvent};
use ghost_core::wire::derive_default_channel_id;
use ghost_wire::batch::LogBatch;
use ghost_wire::idlog::EntryBody;
use ghost_wire::RevocationCause;
use tokio::sync::Mutex;

/// A view of the device's relay client onto `relay_url`, as the application uses:
/// same credentials, shared subscriptions and mailbox routes.
fn device_client_for(account_relay: &RelayClient, relay_url: &str) -> RelayClient {
    account_relay.at(relay_url)
}

/// A client for `relay_url` that signs with the root of `recovery_key`, which relays
/// accept for reading the account's log while it is the current root.
fn root_client(account: &Account, recovery_key: &RecoveryKey, relay_url: &str) -> RelayClient {
    let root = recovery_key.root().unwrap();
    let (client, _) = RelayClient::new(relay_url);
    client.set_auth(account.fp, root.verifying_key().to_bytes(), root);
    client
}

/// Open the device a recovery produced, on `relay_url`, as the application does.
fn recovered_device(material: &flows::recovery::RecoveryMaterial, relay_vk: [u8; 32], relay_url: &str) -> (Arc<Mutex<ghost_core::client::GhostClient>>, Arc<RelayClient>, [u8; 32]) {
    let mut client = ghost_core::client::GhostClient::open_in_memory(material.identity(), [0x33; 32]).unwrap();
    client.set_relay_vk(relay_vk);
    let device_vk = material.device_key.verifying_key().to_bytes();
    let (relay, _) = RelayClient::new(relay_url);
    relay.set_auth(material.account_fp, device_vk, material.device_key.clone());
    (Arc::new(Mutex::new(client)), Arc::new(relay), device_vk)
}

/// An invite to the server on the account's relay: (token, key that opens its payload).
async fn invite_on(account: &Account, server_id: &[u8; 32]) -> (String, [u8; 32]) {
    let invite = flows::invite::create(&account.client, &account.relay, server_id, None).await.unwrap();
    (invite.token, invite.key)
}

#[tokio::test]
async fn accept_p6_sethomerelay_required_at_seq2_for_v2_accounts() {
    let home_url = common::start_relay().await;
    let foreign_url = common::start_relay().await;
    let alice = create_account(&home_url, "alice").await;

    let home_vk = alice.relay.get_relay_info().await.unwrap().relay_vk;
    let (log, state) = flows::idlog::fetch_chain(&alice.relay, &alice.fp).await.unwrap();
    assert_eq!(log.entries.len(), 5, "the creation batch");
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
    let legacy_genesis = ghost_core::identity::log::create_genesis(
        &ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
        &ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
        "legacy",
    );
    let legacy_fp = legacy_genesis.account_fp;
    let (legacy_home, _) = RelayClient::new(&home_url);
    let genesis_anchor = legacy_home.put_idlog_entry(&legacy_fp, legacy_genesis.to_bytes()).await.unwrap();
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

    let foreign = device_client_for(&alice.relay, &foreign_url);
    // Unknown to the foreign relay: authenticated requests are refused.
    let err = foreign.get_account(&alice.fp).await.unwrap_err();
    assert!(matches!(err, GhostError::RelayStatus { status: 401, .. }), "{err}");

    let info = flows::account::register_at(&alice.client, &alice.relay, &foreign, Some(&token)).await.unwrap();
    let account = foreign.get_account(&alice.fp).await.unwrap();
    let home_vk = alice.relay.get_relay_info().await.unwrap().relay_vk;
    assert_eq!(account.home_relay_vk, home_vk);
    assert!(!account.is_home);
    assert_eq!(account.head_seq, 5, "the creation batch");
    assert_ne!(info.relay_vk, home_vk);

    // The foreign relay serves the mirrored chain with the home's anchors intact.
    let (log, state) = flows::idlog::fetch_chain(&foreign, &alice.fp).await.unwrap();
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

    let foreign = device_client_for(&alice.relay, &foreign_url);
    let joined = flows::invite::join(&alice.client, &alice.relay, &foreign, &token, &key, 2000).await.unwrap();
    assert_eq!(joined, server_id);

    // The server is recorded as living on the foreign relay.
    let foreign_vk = foreign.get_relay_info().await.unwrap().relay_vk;
    {
        let c = alice.client.lock().await;
        assert_eq!(c.store().server_relay(&server_id).unwrap(), Some(foreign_vk));
        let known = c.store().server_relays().unwrap();
        assert_eq!(known.len(), 1);
        assert_eq!(known[0].relay_vk, foreign_vk);
    }

    // Alice is now a member there: her device keeps authenticating after joining.
    foreign.get_account(&alice.fp).await.unwrap();

    // A message from Alice through the foreign relay reaches the host.
    let channel_id = derive_default_channel_id(&server_id);
    let outbound = {
        let mut c = alice.client.lock().await;
        c.send_message(&server_id, &channel_id, b"hi from elsewhere".to_vec(), vec![], 3000).unwrap().0
    };
    foreign.post_blob(&outbound.mailbox_id, outbound.blob).await.unwrap();

    let (host_relay, mut events) = RelayClient::new(&foreign_url);
    host_relay.copy_auth_from(&host.relay);
    host_relay.subscribe(outbound.mailbox_id, 0);
    let message = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match events.recv().await {
                Some(RelayEvent::Blob(b)) => {
                    match common::receive_like_session(&host.client, &host.relay, &channel_id, &b).await.unwrap() {
                        // Skip the join announcement; it is a control message.
                        ReceiveResult::Message(m) if m.message_type == MessageType::Text => break m,
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

    let foreign = device_client_for(&alice.relay, &foreign_url);
    flows::invite::join(&alice.client, &alice.relay, &foreign, &token, &key, 2000).await.unwrap();

    // Pairing pushes the new device's AddDevice to the foreign relay.
    let (_client_b, relay_b, device_b_vk) = pair_second_device(&home_url, &alice).await;
    let foreign_b = device_client_for(&relay_b, &foreign_url);
    foreign_b.get_account(&alice.fp).await.unwrap();

    // Revoking device B at the home reaches the foreign relay immediately.
    let outcome = flows::devices::revoke(&alice.client, &alice.relay, &device_b_vk).await.unwrap();
    assert_eq!(outcome, flows::devices::RevokeOutcome::Complete);
    let err = foreign_b.get_account(&alice.fp).await.unwrap_err();
    assert!(matches!(&err, GhostError::DeviceRevoked(Some(RevocationCause::Device(by))) if by == "alice"), "the mirror names the remover: {err:?}");
    let account = foreign.get_account(&alice.fp).await.unwrap();
    assert_eq!(account.head_seq, 10, "creation (5), pairing (3), revocation (2)");
}

/// Alice's device processes another device's join of the server's default channel, so
/// its group holds that device's leaf, as its live connection would have done.
async fn see_device_join(alice: &Account, relay_url: &str, server_id: &[u8; 32], device_vk: &[u8; 32]) {
    let channel_id = derive_default_channel_id(server_id);
    let mailbox_id = alice.client.lock().await.mailbox_id_for_server(server_id).unwrap();
    let a_seen = alice.client.lock().await.store().get_last_seen_seq(&mailbox_id).unwrap_or(0);
    let (reader, mut events) = RelayClient::new(relay_url);
    reader.copy_auth_from(&alice.relay);
    reader.subscribe(mailbox_id, a_seen);
    let caught_up = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(event) = events.recv().await {
            if let RelayEvent::Blob(b) = event {
                let _ = common::receive_like_session(&alice.client, &alice.relay, &channel_id, &b).await;
                let c = alice.client.lock().await;
                let _ = c.store().set_last_seen_seq(&mailbox_id, b.seq);
                if !c.find_device_leaves(&channel_id, device_vk).is_empty() {
                    return;
                }
            }
        }
    })
    .await;
    assert!(caught_up.is_ok(), "Alice never saw the device join");
}

/// Alice (home relay) joins Host's server on the foreign relay; returns the server id,
/// a device client for the foreign relay, and the foreign relay's key.
async fn join_foreign_server(alice: &Account, foreign_url: &str) -> ([u8; 32], RelayClient, [u8; 32], Account) {
    let host = create_account(foreign_url, "host").await;
    let server_id = create_server(&host, "club").await;
    let (token, key) = invite_on(&host, &server_id).await;
    let foreign = device_client_for(&alice.relay, foreign_url);
    flows::invite::join(&alice.client, &alice.relay, &foreign, &token, &key, 2000).await.unwrap();
    let foreign_vk = foreign.get_relay_info().await.unwrap().relay_vk;
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
    let foreign_b = device_client_for(&relay_b, &foreign_url);
    foreign_b.get_account(&alice.fp).await.unwrap();
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

    let (guest, _) = RelayClient::new(&home_url);
    let material = flows::recovery::begin(&guest, alice.fp, &alice.recovery_key, &RecoveryKey::generate(), "laptop").await.unwrap();
    let home_vk = guest.get_relay_info().await.unwrap().relay_vk;
    let (client_n, relay_n, _new_vk) = recovered_device(&material, home_vk, &home_url);

    flows::recovery::finish(&client_n, &relay_n, &material).await.unwrap();

    {
        let c = client_n.lock().await;
        assert!(c.store().get_server(&server_id).is_ok(), "recovered device rejoined the foreign server");
        assert_eq!(c.store().server_relay(&server_id).unwrap(), Some(foreign_vk));
    }
    // The foreign relay applied the Recovery entry: old device out, new device in.
    let err = foreign.get_account(&alice.fp).await.unwrap_err();
    assert!(matches!(err, GhostError::DeviceRevoked(Some(RevocationCause::Recovery))), "the old device hears of the recovery: {err:?}");
    let foreign_n = device_client_for(&relay_n, &foreign_url);
    foreign_n.get_account(&alice.fp).await.unwrap();
}

#[tokio::test]
async fn accept_p6_revocation_pulled_by_mirror_within_refresh_interval() {
    let home_url = common::start_relay().await;
    let foreign_url = common::start_relay().await;
    let alice = create_account(&home_url, "alice").await;
    let (_server_id, _foreign, _foreign_vk, _host) = join_foreign_server(&alice, &foreign_url).await;
    let (_client_b, relay_b, device_b_vk) = pair_second_device(&home_url, &alice).await;
    let foreign_b = device_client_for(&relay_b, &foreign_url);
    foreign_b.get_account(&alice.fp).await.unwrap();

    // Revoke at the home only, as a device that never reaches the foreign relay would.
    let state = flows::idlog::fetch_and_verify(&alice.client, &alice.relay, &alice.fp).await.unwrap();
    let signer = alice.client.lock().await.signing_key_clone();
    let revoke = ghost_core::identity::log::create_revoke_device(&state, &signer, &device_b_vk);
    alice.relay.post_idlog_batch(&alice.fp, &LogBatch { entries: vec![revoke], key_sets: Vec::new() }).await.unwrap();

    // The test relays refresh every second; allow a few intervals.
    let mut revoked = false;
    for _ in 0..50 {
        match foreign_b.get_account(&alice.fp).await {
            Err(GhostError::DeviceRevoked(_)) => {
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
    create_server(&alice, "alice's own").await;
    let (_server_id, foreign, _foreign_vk, _host) = join_foreign_server(&alice, &foreign_url).await;

    let new_home = device_client_for(&alice.relay, &new_url);
    let new_vk = flows::account::rehome(&alice.client, &new_home, Some(&alice.relay), &alice.recovery_key).await.unwrap();

    // The new home sequences the account and serves a chain whose first entries
    // still carry the old home's anchors; a fresh fetch validates all of it.
    let account = new_home.get_account(&alice.fp).await.unwrap();
    assert!(account.is_home);
    assert_eq!(account.head_seq, 6);
    let state = flows::idlog::fetch_and_verify(&alice.client, &new_home, &alice.fp).await.unwrap();
    assert_eq!(state.home_relay_vk, Some(new_vk));
    assert_eq!(state.home_set_at_seq, 6);

    // The foreign relay switched without any device pushing to it explicitly.
    let mirrored = foreign.get_account(&alice.fp).await.unwrap();
    assert_eq!(mirrored.home_relay_vk, new_vk);
    assert!(!mirrored.is_home);

    // New entries now go to the new home.
    let devices = flows::devices::list(&alice.client, &new_home).await.unwrap();
    assert!(devices.current, "the new home answered");
    let devices = devices.state;
    assert!(devices.is_active_device(&alice.device_vk));

    // The old home still hosts Alice's own server, so the new home grants it: an entry
    // sequenced at the new home reaches the old home by the home's push alone.
    let entry = {
        let c = alice.client.lock().await;
        ghost_wire::log_entries::create_rename_device(&devices, &c.signing_key_clone(), &alice.device_vk, "renamed")
    };
    new_home.post_idlog_batch(&alice.fp, &LogBatch { entries: vec![entry], key_sets: Vec::new() }).await.unwrap();
    common::poll(|| async { Ok((alice.relay.get_account(&alice.fp).await?.head_seq >= 7).then_some(())) }).await;
}

#[tokio::test]
async fn accept_p6_old_home_marks_account_moved_and_rejects_appends() {
    let old_url = common::start_relay().await;
    let new_url = common::start_relay().await;
    let alice = create_account(&old_url, "alice").await;
    let new_home = device_client_for(&alice.relay, &new_url);
    let new_vk = flows::account::rehome(&alice.client, &new_home, Some(&alice.relay), &alice.recovery_key).await.unwrap();

    // The old home now reports the new one and serves the move. Alice's device is no
    // longer admitted there, so read with the root, as a recovering device would.
    let (guest, _) = RelayClient::new(&old_url);
    let (log, state) = flows::idlog::fetch_chain(&root_client(&alice, &alice.recovery_key, &old_url), &alice.fp).await.unwrap();
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
    let stray = LogBatch { entries: vec![stray], key_sets: Vec::new() };
    let err = alice.relay.post_idlog_batch(&alice.fp, &stray).await.unwrap_err();
    assert!(matches!(err, GhostError::RelayStatus { status: 401, .. }), "{err}");

    // A Recovery entry needs no credentials, so the old home must refuse it on
    // the moved account itself, or it could fork the log.
    let root = alice.recovery_key.root().unwrap();
    let new_device = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let recovery = ghost_core::identity::log::create_recovery(&state, &root, &new_device, "fork");
    let err = guest.post_idlog_batch(&alice.fp, &LogBatch { entries: vec![recovery], key_sets: Vec::new() }).await.unwrap_err();
    assert!(matches!(err, GhostError::RelayStatus { status: 421, .. }), "{err}");
}

/// A connection the old home admitted before the move ends once it holds the move, and
/// the reconnect gets the refusal that sends a device to follow; it does not stay open
/// on grounds the relay no longer accepts.
#[tokio::test]
async fn the_old_home_drops_the_connections_it_no_longer_admits() {
    let old_url = common::start_relay().await;
    let new_url = common::start_relay().await;
    let alice = create_account(&old_url, "alice").await;
    let sync_mailbox = alice.client.lock().await.account_sync_mailbox();
    let (watcher, mut events) = RelayClient::new(&old_url);
    watcher.copy_auth_from(&alice.relay);
    watcher.subscribe(sync_mailbox, 0);
    expect_event(&mut events, "the sync mailbox to connect", |e| matches!(e, RelayEvent::ConnectionState { connected: true, .. })).await;

    let new_home = device_client_for(&alice.relay, &new_url);
    flows::account::rehome(&alice.client, &new_home, Some(&alice.relay), &alice.recovery_key).await.unwrap();

    expect_event(&mut events, "the old home to refuse the reconnect", |e| matches!(e, RelayEvent::Unauthorized { .. })).await;
}

/// Wait for an event `wanted` accepts, failing the test after five seconds.
async fn expect_event(events: &mut tokio::sync::mpsc::Receiver<RelayEvent>, what: &str, wanted: impl Fn(&RelayEvent) -> bool) {
    let found = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match events.recv().await {
                Some(event) if wanted(&event) => break,
                Some(_) => continue,
                None => panic!("event channel closed"),
            }
        }
    })
    .await;
    assert!(found.is_ok(), "timed out waiting for {what}");
}

#[tokio::test]
async fn a_move_carries_every_key_set_to_the_new_home() {
    let old_url = common::start_relay().await;
    let new_url = common::start_relay().await;
    let alice = create_account(&old_url, "alice").await;
    pair_second_device(&old_url, &alice).await;

    let new_home = device_client_for(&alice.relay, &new_url);
    flows::account::rehome(&alice.client, &new_home, Some(&alice.relay), &alice.recovery_key).await.unwrap();

    let sets = new_home.get_key_sets(&alice.fp, 1).await.unwrap();
    let generations: Vec<u32> = sets.iter().map(|s| s.generation).collect();
    assert_eq!(generations, [1, 2], "recovery and later relays read every generation at the home");
}

#[tokio::test]
async fn moving_back_to_the_old_home_makes_it_home_again() {
    let old_url = common::start_relay().await;
    let new_url = common::start_relay().await;
    let alice = create_account(&old_url, "alice").await;
    let old_vk = relay_vk_at(&old_url).await;

    let new_home = device_client_for(&alice.relay, &new_url);
    let new_vk = flows::account::rehome(&alice.client, &new_home, Some(&alice.relay), &alice.recovery_key).await.unwrap();
    let back = flows::account::rehome(&alice.client, &alice.relay, Some(&new_home), &alice.recovery_key).await.unwrap();
    assert_eq!(back, old_vk);

    // The old home sequences the account again, over the entries the other home added.
    let account = alice.relay.get_account(&alice.fp).await.unwrap();
    assert!(account.is_home);
    assert_eq!(account.head_seq, 7, "creation, the move away and the move back");
    let state = flows::idlog::fetch_and_verify(&alice.client, &alice.relay, &alice.fp).await.unwrap();
    assert_eq!(state.home_relay_vk, Some(old_vk));
    let sets = alice.relay.get_key_sets(&alice.fp, 1).await.unwrap();
    assert_eq!(sets.len(), 1);

    // The other home learned it is no longer home.
    let (log, _) = flows::idlog::fetch_chain(&root_client(&alice, &alice.recovery_key, &new_url), &alice.fp).await.unwrap();
    assert_eq!(log.home_relay_vk, old_vk);
    assert_ne!(log.home_relay_vk, new_vk);

    // And the account changes there as before.
    pair_second_device(&old_url, &alice).await;
    let state = flows::idlog::fetch_and_verify(&alice.client, &alice.relay, &alice.fp).await.unwrap();
    assert_eq!(state.active_devices().count(), 2);
}

#[tokio::test]
async fn accept_p6_account_key_sets_reach_member_relays() {
    let home_url = common::start_relay().await;
    let foreign_url = common::start_relay().await;
    let alice = create_account(&home_url, "alice").await;
    let (_server_id, foreign, _foreign_vk, _host) = join_foreign_server(&alice, &foreign_url).await;

    // Pairing adds generation 2 at the home and pushes its set to every member relay.
    pair_second_device(&home_url, &alice).await;
    let mut generations = Vec::new();
    for _ in 0..50 {
        generations = foreign.get_key_sets(&alice.fp, 1).await.unwrap().iter().map(|s| s.generation).collect();
        if generations == [1, 2] {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(generations, [1, 2], "the member relay holds every generation's copies");
}

/// The home pushes a new generation's key set to every granted relay with the entry
/// that commits to it, so a mirror that never pulls is complete even when the device
/// told only the home.
#[tokio::test]
async fn the_home_pushes_key_sets_with_the_entries_to_mirrors() {
    let home_url = common::start_relay().await;
    let mirror = common::start_relay_refreshing_every(3600).await;
    let alice = create_account(&home_url, "alice").await;
    let (_server_id, foreign, _foreign_vk, _host) = join_foreign_server(&alice, &mirror.url()).await;

    // A new generation posted to the home alone, as no device pushes it anywhere else.
    let state = flows::idlog::fetch_and_verify(&alice.client, &alice.relay, &alice.fp).await.unwrap();
    let batch = {
        let c = alice.client.lock().await;
        let previous = c.sealing_seed().unwrap();
        let mut batch = ghost_core::identity::batch::BatchBuilder::new(state);
        batch.push_rekey(&c.signing_key_clone(), Some(&previous)).unwrap();
        batch.finish()
    };
    alice.relay.post_idlog_batch(&alice.fp, &batch).await.unwrap();

    let mut generations = Vec::new();
    for _ in 0..50 {
        generations = foreign.get_key_sets(&alice.fp, 1).await.unwrap().iter().map(|s| s.generation).collect();
        if generations == [1, 2] {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(generations, [1, 2], "the mirror holds the set the home pushed");
}

#[tokio::test]
async fn recovery_through_a_new_home_wins_over_a_device_entry_the_owner_never_saw() {
    let home_url = common::start_relay().await;
    // A mirror that pulls rarely, and is unreachable while the home pushes.
    let lagging = ghost_relay::outage::SwitchedRelay::start(common::relay_config(3600), ghost_relay::storage::Storage::open_ephemeral().unwrap())
        .await
        .unwrap();
    let mirror_url = lagging.url();
    let new_home_url = common::start_relay().await;
    let alice = create_account(&home_url, "alice").await;
    join_foreign_server(&alice, &mirror_url).await;

    // A thief's device is added at the home and nowhere else: the home's push to the
    // mirror finds it down.
    let state = flows::idlog::fetch_and_verify(&alice.client, &alice.relay, &alice.fp).await.unwrap();
    let thief = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let signer = alice.client.lock().await.signing_key_clone();
    let add = ghost_core::identity::log::create_add_device(&state, &signer, &thief, "thief");
    lagging.go_down();
    alice.relay.post_idlog_batch(&alice.fp, &LogBatch { entries: vec![add.clone()], key_sets: Vec::new() }).await.unwrap();
    // The push runs off the request; it has long failed before the mirror is back.
    tokio::time::sleep(Duration::from_millis(500)).await;
    lagging.come_back();

    // The owner recovers through a new home from the mirror, which never saw that entry.
    let (source, _) = RelayClient::new(&mirror_url);
    let (new_home, _) = RelayClient::new(&new_home_url);
    let new_key = RecoveryKey::generate();
    flows::recovery::begin_with_new_home(&source, &new_home, alice.fp, &alice.recovery_key, &new_key, "laptop").await.unwrap();

    // The old home learns the recovery and takes the root-signed branch over the
    // thief's device entry at the same position.
    let chain = root_client(&alice, &new_key, &new_home_url).get_idlog(&alice.fp, 0).await.unwrap().entries;
    let (old_home, _) = RelayClient::new(&home_url);
    old_home.put_anchored_entries(&alice.fp, &chain, None).await.unwrap();
    let (log, state) = flows::idlog::fetch_chain(&root_client(&alice, &new_key, &home_url), &alice.fp).await.unwrap();
    assert!(!state.devices.contains_key(&thief.verifying_key().to_bytes()), "the thief's entry was replaced");
    let thief_entry = ghost_core::identity::log::entry_hash(&add);
    assert!(log.entries.iter().all(|a| ghost_core::identity::log::entry_hash(&a.entry) != thief_entry));
    assert_eq!(state.home_relay_vk, Some(new_home.get_relay_info().await.unwrap().relay_vk));
}

#[tokio::test]
async fn accept_p6_recover_with_dead_home_via_import_batch() {
    let home_server = common::start_relay_with_handle().await;
    let home_url = home_server.url();
    let foreign_url = common::start_relay().await;
    let new_home_url = common::start_relay().await;
    let alice = create_account(&home_url, "alice").await;
    let (server_id, foreign, foreign_vk, _host) = join_foreign_server(&alice, &foreign_url).await;

    // Replicated state a recovering device needs: the server list in the snapshot.
    flows::sync::server_entry(&alice.client, &alice.relay, &server_id).await;
    flows::sync::push_snapshot(&alice.client, &alice.relay).await;

    // The home relay disappears, and every device is lost.
    home_server.stop().await;
    let (dead, _) = RelayClient::new(&home_url);
    assert!(dead.get_relay_info().await.is_err(), "home relay is unreachable");

    let (source, _) = RelayClient::new(&foreign_url);
    let (new_home, _) = RelayClient::new(&new_home_url);
    let material = flows::recovery::begin_with_new_home(&source, &new_home, alice.fp, &alice.recovery_key, &RecoveryKey::generate(), "laptop")
        .await
        .unwrap();
    let new_home_vk = new_home.get_relay_info().await.unwrap().relay_vk;
    let (client_n, relay_n, new_vk) = recovered_device(&material, new_home_vk, &new_home_url);

    flows::recovery::finish(&client_n, &relay_n, &material).await.unwrap();

    // The account now lives at the new home, and the chain validates end to end.
    let state = flows::idlog::fetch_and_verify(&client_n, &relay_n, &alice.fp).await.unwrap();
    assert_eq!(state.home_relay_vk, Some(new_home_vk));
    assert!(state.is_active_device(&new_vk));
    assert!(!state.is_active_device(&alice.device_vk));
    assert!(relay_n.get_account(&alice.fp).await.unwrap().is_home);
    let generations: Vec<u32> = relay_n.get_key_sets(&alice.fp, 1).await.unwrap().iter().map(|s| s.generation).collect();
    assert_eq!(generations, [1, 2], "the new home holds the sets from before the recovery too");

    // The server on the foreign relay was rejoined from the replicated snapshot.
    {
        let c = client_n.lock().await;
        assert!(c.store().get_server(&server_id).is_ok(), "rejoined the foreign server");
        assert_eq!(c.store().server_relay(&server_id).unwrap(), Some(foreign_vk));
    }
    // The foreign relay switched home and revoked the lost device.
    let foreign_n = device_client_for(&relay_n, &foreign_url);
    let account = foreign_n.get_account(&alice.fp).await.unwrap();
    assert_eq!(account.home_relay_vk, new_home_vk);
    let err = foreign.get_account(&alice.fp).await.unwrap_err();
    assert!(matches!(err, GhostError::DeviceRevoked(Some(RevocationCause::Recovery))), "{err:?}");
}

#[tokio::test]
async fn accept_p6_revoked_device_cannot_decrypt_after_remaining_devices_commit_while_home_partitioned() {
    let home_server = common::start_relay_with_handle().await;
    let home_url = home_server.url();
    let foreign_url = common::start_relay().await;
    let alice = create_account(&home_url, "alice").await;
    let (server_id, foreign, _foreign_vk, _host) = join_foreign_server(&alice, &foreign_url).await;
    let (client_b, relay_b, device_b_vk) = pair_second_device(&home_url, &alice).await;
    let channel_id = derive_default_channel_id(&server_id);
    let mailbox_id = alice.client.lock().await.mailbox_id_for_server(&server_id).unwrap();
    let b_seen = client_b.lock().await.store().get_last_seen_seq(&mailbox_id).unwrap_or(0);
    see_device_join(&alice, &foreign_url, &server_id, &device_b_vk).await;

    // The home relay becomes unreachable before the revocation.
    home_server.stop().await;

    let outcome = flows::devices::revoke(&alice.client, &alice.relay, &device_b_vk).await.unwrap();
    assert_eq!(outcome, flows::devices::RevokeOutcome::LogPending);

    // No relay has heard of the revocation, so device B still authenticates at the
    // foreign relay; only the MLS removal stands between it and new messages.
    let outbound = {
        let mut c = alice.client.lock().await;
        c.send_message(&server_id, &channel_id, b"after revoke".to_vec(), vec![], 5000).unwrap().0
    };
    foreign.post_blob(&outbound.mailbox_id, outbound.blob).await.unwrap();

    let (reader, mut events) = RelayClient::new(&foreign_url);
    reader.copy_auth_from(&relay_b);
    reader.subscribe(mailbox_id, b_seen);
    let mut kicked = false; // set when device B learns it was removed
    let mut seen = Vec::new();
    let mut c = client_b.lock().await;
    let _ = tokio::time::timeout(Duration::from_secs(3), async {
        while let Some(event) = events.recv().await {
            if let RelayEvent::Blob(b) = event {
                let result = c.receive_any(&channel_id, &b.payload, Some(b.received_at));
                seen.push(format!("seq {}: {}", b.seq, match &result {
                    Ok(ReceiveResult::Message(m)) => format!("message {:?}", m.message_type),
                    Ok(ReceiveResult::CommitProcessed) => "commit".into(),
                    Ok(ReceiveResult::Kicked { .. }) => "kicked".into(),
                    Ok(ReceiveResult::DeviceRemoved) => "device removed".into(),
                    Ok(ReceiveResult::MembersRemoved(fps)) => format!("members removed: {}", fps.len()),
                    Ok(ReceiveResult::ProposalProcessed) => "proposal".into(),
                    Ok(ReceiveResult::ChannelAccessLost(_)) => "channel access lost".into(),
                    Ok(ReceiveResult::Skipped) => "skipped".into(),
                    Ok(ReceiveResult::Unreadable) => "unreadable".into(),
                    Ok(ReceiveResult::Unverified { .. }) => "unverified".into(),
                    Err(e) => format!("error: {e}"),
                }));
                match result {
                    // Only this device was removed; Alice's other device stays in the group.
                    Ok(ReceiveResult::DeviceRemoved) => kicked = true,
                    Ok(ReceiveResult::Message(m)) => {
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
    alice.relay.post_blob(&outbound.mailbox_id, outbound.blob).await.unwrap();

    // After a restart: a fresh home client, startup subscriptions, one event stream.
    let (restarted, mut events) = RelayClient::new(&home_url);
    restarted.copy_auth_from(&alice.relay);
    {
        let c = alice.client.lock().await;
        flows::subscribe_known_mailboxes(&c, &restarted);
    }
    let reply = {
        // The host first catches up on Alice's join so it can encrypt to her.
        let (catch_up, mut host_events) = RelayClient::new(&foreign_url);
        catch_up.copy_auth_from(&host.relay);
        catch_up.subscribe(outbound.mailbox_id, 0);
        let caught_up = tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(event) = host_events.recv().await {
                // Connection-state events come first; only blobs matter here.
                let RelayEvent::Blob(b) = event else { continue };
                if let Ok(ReceiveResult::Message(m)) = common::receive_like_session(&host.client, &host.relay, &channel_id, &b).await {
                    if m.content == b"via home client" {
                        return;
                    }
                }
            }
        })
        .await;
        assert!(caught_up.is_ok(), "the host never received the message Alice sent through her home client");
        let mut c = host.client.lock().await;
        c.send_message(&server_id, &channel_id, b"hello back".to_vec(), vec![], 4000).unwrap().0
    };
    host.relay.at(&foreign_url).post_blob(&reply.mailbox_id, reply.blob).await.unwrap();

    let got = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match events.recv().await {
                Some(RelayEvent::Blob(b)) => {
                    if let Ok(ReceiveResult::Message(m)) = common::receive_like_session(&alice.client, &alice.relay, &channel_id, &b).await
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
    let stranger = outsider.relay.at(&home_url);
    let err = stranger.get_idlog(&alice.fp, 0).await.unwrap_err();
    assert!(matches!(err, GhostError::RelayStatus { status: 401, .. }), "{err}");

    // The account's own device and its current root may read.
    alice.relay.get_idlog(&alice.fp, 0).await.unwrap();
    root_client(&alice, &alice.recovery_key, &home_url).get_idlog(&alice.fp, 0).await.unwrap();

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
        .put_mirror_grants(&alice.fp, &[ghost_wire::relay_ref::RelayRef::key_only(some_relay.verifying_key().to_bytes())])
        .await
        .unwrap();
    assert_eq!(pull(&some_relay).await, reqwest::StatusCode::OK);
}

// ── Server moves ──────────────────────────────────────────────────────

/// A device's own relay client with a readable event stream, as the application holds it.
async fn app_client(account: &Account, home_url: &str) -> (Arc<RelayClient>, tokio::sync::mpsc::Receiver<RelayEvent>) {
    let (client, events) = RelayClient::new(home_url);
    client.copy_auth_from(&account.relay);
    (Arc::new(client), events)
}

/// Feed a device's events to its client until `pick` returns a value, fetching the
/// logs of devices it does not know yet through `relay`, as the session does.
async fn receive_until<T>(
    client: &Arc<Mutex<ghost_core::client::GhostClient>>,
    relay: &RelayClient,
    events: &mut tokio::sync::mpsc::Receiver<RelayEvent>,
    channel_id: &[u8; 32],
    mut pick: impl FnMut(ReceiveResult) -> Option<T>,
) -> Option<T> {
    tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(event) = events.recv().await {
            let RelayEvent::Blob(b) = event else { continue };
            let result = common::receive_like_session(client, relay, channel_id, &b).await;
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
        ReceiveResult::Message(m) if m.content == content => Some(()),
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
    alice_app: Arc<RelayClient>,
    alice_events: tokio::sync::mpsc::Receiver<RelayEvent>,
    alice_old_view: RelayClient,
}

async fn host_server_with_alice(old_url: &str, alice_url: &str) -> HostedServer {
    let host = create_account(old_url, "host").await;
    let alice = create_account(alice_url, "alice").await;
    let server_id = create_server(&host, "club").await;
    let channel_id = derive_default_channel_id(&server_id);
    let mailbox_id = host.client.lock().await.mailbox_id_for_server(&server_id).unwrap();
    // The host's application is subscribed to its server, which routes it to this relay.
    host.relay.subscribe(mailbox_id, 0);

    let (alice_app, alice_events) = app_client(&alice, alice_url).await;
    let alice_old_view = alice_app.at(old_url);
    let (token, key) = invite_on(&host, &server_id).await;
    flows::invite::join(&alice.client, &alice_app, &alice_old_view, &token, &key, 2000).await.unwrap();

    let (reader, mut events) = RelayClient::new(old_url);
    reader.copy_auth_from(&host.relay);
    reader.subscribe(mailbox_id, 0);
    let alice_fp = alice.fp;
    let caught_up = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(event) = events.recv().await {
            let RelayEvent::Blob(b) = event else { continue };
            let _ = common::receive_like_session(&host.client, &host.relay, &channel_id, &b).await;
            let c = host.client.lock().await;
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

async fn host_sends(s: &HostedServer, home: &RelayClient, content: &[u8]) {
    let outbound = {
        let mut c = s.host.client.lock().await;
        c.send_message(&s.server_id, &s.channel_id, content.to_vec(), vec![], 9000).unwrap().0
    };
    home.post_blob(&outbound.mailbox_id, outbound.blob).await.unwrap();
}

#[tokio::test]
async fn accept_p6_server_move_followed_through_announcement() {
    let old_url = common::start_relay().await;
    let new_url = common::start_relay().await;
    let alice_url = common::start_relay().await;
    let mut s = host_server_with_alice(&old_url, &alice_url).await;

    // The host's account moves to the new relay, then the server follows it.
    let host_home = s.host.relay.at(&new_url);
    flows::account::rehome(&s.host.client, &host_home, Some(&s.host.relay), &s.host.recovery_key).await.unwrap();
    let location = flows::server::move_server(&s.host.client, &host_home, &s.server_id, &new_url).await.unwrap();

    // Alice's live connection delivers the announcement; following it moves her.
    let announced = receive_until(&s.alice.client, &s.alice_app, &mut s.alice_events, &s.channel_id, |r| match r {
        ReceiveResult::Message(m) if m.message_type == MessageType::Metadata => {
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
    receive_until(&s.alice.client, &s.alice_app, &mut s.alice_events, &s.channel_id, text(b"after the move"))
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

    let host_home = s.host.relay.at(&new_url);
    flows::account::rehome(&s.host.client, &host_home, Some(&s.host.relay), &s.host.recovery_key).await.unwrap();
    flows::server::move_server(&s.host.client, &host_home, &s.server_id, &new_url).await.unwrap();

    // The new relay holds the channel's group under the moved server group: it accepts
    // the channel's traffic and lists the channel for the members it admits.
    let outbound = {
        let mut c = s.host.client.lock().await;
        c.send_message(&s.server_id, &channel_id, b"still private".to_vec(), vec![], 9000).unwrap().0
    };
    host_home.post_blob(&outbound.mailbox_id, outbound.blob).await.unwrap();
    let server_mailbox = s.host.client.lock().await.server_mailbox(&s.server_id).unwrap();
    let (reader, _events) = RelayClient::new(&new_url);
    reader.copy_auth_from(&s.host.relay);
    let listing = reader.get_admitted_channels(&server_mailbox).await.unwrap();
    assert_eq!(listing.0.iter().map(|(mailbox, _)| *mailbox).collect::<Vec<_>>(), vec![outbound.mailbox_id]);
}

#[tokio::test]
async fn accept_p6_server_move_found_at_creator_home_after_relay_dies() {
    let old_server = common::start_relay_with_handle().await;
    let old_url = old_server.url();
    let new_url = common::start_relay().await;
    let alice_url = common::start_relay().await;
    let mut s = host_server_with_alice(&old_url, &alice_url).await;

    // While the old relay is still up, the host re-homes its account and Alice's
    // device refreshes the host's log there, learning the new home.
    let host_home = s.host.relay.at(&new_url);
    flows::account::rehome(&s.host.client, &host_home, Some(&s.host.relay), &s.host.recovery_key).await.unwrap();
    flows::idlog::fetch_and_verify(&s.alice.client, &s.alice_old_view, &s.host.fp).await.unwrap();

    old_server.stop().await;

    // The announcement cannot reach anyone; the record at the host's home can.
    flows::server::move_server(&s.host.client, &host_home, &s.server_id, &new_url).await.unwrap();
    assert!(flows::server::check_location(&s.alice.client, &s.alice_app, &s.server_id).await.unwrap());

    host_sends(&s, &host_home, b"we survived").await;
    receive_until(&s.alice.client, &s.alice_app, &mut s.alice_events, &s.channel_id, text(b"we survived"))
        .await
        .expect("Alice never received a message after the relay died");
}

#[tokio::test]
async fn accept_p6_server_move_link_followed_when_no_shared_relay_survives() {
    let old_server = common::start_relay_with_handle().await;
    let old_url = old_server.url();
    let new_url = common::start_relay().await;
    let alice_url = common::start_relay().await;
    let mut s = host_server_with_alice(&old_url, &alice_url).await;

    // The old relay dies before Alice learns anything about the host's new home.
    let host_home = s.host.relay.at(&new_url);
    flows::account::rehome(&s.host.client, &host_home, Some(&s.host.relay), &s.host.recovery_key).await.unwrap();
    old_server.stop().await;

    let location = flows::server::move_server(&s.host.client, &host_home, &s.server_id, &new_url).await.unwrap();
    assert!(flows::server::check_location(&s.alice.client, &s.alice_app, &s.server_id).await.is_err());

    // The link carries the same signed record, verified against the host's cached log.
    let link = flows::server::move_link(&location);
    let parsed = flows::server::parse_move_link(&link).unwrap();
    assert!(flows::server::follow_move(&s.alice.client, &s.alice_app, &s.server_id, &parsed).await.unwrap());

    host_sends(&s, &host_home, b"found you").await;
    receive_until(&s.alice.client, &s.alice_app, &mut s.alice_events, &s.channel_id, text(b"found you"))
        .await
        .expect("Alice never received a message after following the link");
}

/// A device of the owner's account revoked since this member last read the owner's log
/// cannot move the server: the owner's home never stored its record, so the member
/// refuses it however fresh the signature looks.
#[tokio::test]
async fn a_move_signed_by_a_revoked_owner_device_is_refused() {
    let old_url = common::start_relay().await;
    let alice_url = common::start_relay().await;
    let s = host_server_with_alice(&old_url, &alice_url).await;

    // The host links a phone, which Alice's device learns of.
    let (phone, _phone_relay, phone_vk) = pair_second_device(&old_url, &s.host).await;
    flows::idlog::fetch_and_verify(&s.alice.client, &s.alice_old_view, &s.host.fp).await.unwrap();
    assert!(s.alice.client.lock().await.cached_identity_log(&s.host.fp).unwrap().unwrap().is_active_device(&phone_vk));

    // The host revokes the phone; the phone, still holding its key, signs a move.
    flows::devices::revoke(&s.host.client, &s.host.relay, &phone_vk).await.unwrap();
    let phone_key = phone.lock().await.signing_key_clone();
    let forged = ghost_wire::server_location::ServerLocation::sign(
        s.server_id,
        99,
        ghost_wire::relay_ref::RelayRef::https([0x66; 32], "https://evil.example"),
        &phone_key,
    );
    let err = flows::server::follow_move(&s.alice.client, &s.alice_app, &s.server_id, &forged).await.unwrap_err();
    assert!(err.to_string().contains("does not confirm"), "{err}");
    assert_eq!(s.alice.client.lock().await.store().server_relay(&s.server_id).unwrap(), Some(relay_vk_at(&old_url).await));
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

/// A server whose relay cannot be reached keeps the removed device's leaf; the removal
/// says which, rather than that it is complete.
#[tokio::test]
async fn a_removal_names_the_servers_whose_groups_still_hold_the_device() {
    let home_url = common::start_relay().await;
    let foreign = common::start_switched_relay().await;
    let alice = create_account(&home_url, "alice").await;
    let (server_id, _foreign, _foreign_vk, _host) = join_foreign_server(&alice, &foreign.url()).await;
    let (_client_b, _relay_b, device_b_vk) = pair_second_device(&home_url, &alice).await;
    see_device_join(&alice, &foreign.url(), &server_id, &device_b_vk).await;

    foreign.go_down();
    let outcome = flows::devices::revoke(&alice.client, &alice.relay, &device_b_vk).await.unwrap();
    assert_eq!(outcome, flows::devices::RevokeOutcome::LeavesLeft(vec![server_id]));
}

/// Wait until `relay` holds the account's log up to `head`.
async fn mirror_reaches(relay: &RelayClient, account_fp: &[u8; 32], head: u64) {
    common::poll(|| async { Ok((relay.get_account(account_fp).await?.head_seq >= head).then_some(())) }).await;
}

/// A device that has not synced a server yet names only the relays it knows; the home
/// keeps the grant another device made, so it still pushes the log there.
#[tokio::test]
async fn a_device_that_does_not_know_a_server_leaves_its_relays_grant_alone() {
    let home_url = common::start_relay().await;
    let foreign_url = common::start_relay().await;
    let alice = create_account(&home_url, "alice").await;
    let (client_b, relay_b, device_b_vk) = pair_second_device(&home_url, &alice).await;
    let (_server_id, foreign, _foreign_vk, _host) = join_foreign_server(&alice, &foreign_url).await;

    // The laptop knows no server on the foreign relay and grants what it knows.
    flows::account::update_mirror_grants(&client_b, &relay_b).await.unwrap();
    flows::devices::rename(&client_b, &relay_b, &device_b_vk, "laptop").await.unwrap();
    let head = client_b.lock().await.own_log().unwrap().head_seq;
    mirror_reaches(&foreign, &alice.fp, head).await;
}

/// A mirror that missed a push, and pulls rarely, is brought up to date by the account
/// check of a device that sees its copy behind.
#[tokio::test]
async fn the_account_check_catches_up_a_mirror_behind_on_the_log() {
    let home_url = common::start_relay().await;
    let foreign = ghost_relay::outage::SwitchedRelay::start(common::relay_config(3600), ghost_relay::storage::Storage::open_ephemeral().unwrap())
        .await
        .unwrap();
    let alice = create_account(&home_url, "alice").await;
    let (_server_id, foreign_client, _foreign_vk, _host) = join_foreign_server(&alice, &foreign.url()).await;

    foreign.go_down();
    flows::devices::rename(&alice.client, &alice.relay, &alice.device_vk, "desktop at home").await.unwrap();
    foreign.come_back();
    let head = alice.client.lock().await.own_log().unwrap().head_seq;
    assert!(foreign_client.get_account(&alice.fp).await.unwrap().head_seq < head, "the mirror missed the push");

    flows::account::keep_mirrors_current(&alice.client, &alice.relay).await;
    assert_eq!(foreign_client.get_account(&alice.fp).await.unwrap().head_seq, head);
}

/// A former home hosting none of the account's servers is granted at the new one, so it
/// keeps receiving the log rather than being refused its pulls.
#[tokio::test]
async fn a_former_home_keeps_receiving_the_log() {
    let old_url = common::start_relay().await;
    let new_url = common::start_relay().await;
    let alice = create_account(&old_url, "alice").await;
    let new_home = device_client_for(&alice.relay, &new_url);
    flows::account::rehome(&alice.client, &new_home, Some(&alice.relay), &alice.recovery_key).await.unwrap();
    flows::account::follow_home(&alice.client, &alice.relay).await.unwrap();

    flows::devices::rename(&alice.client, &alice.relay, &alice.device_vk, "desktop at home").await.unwrap();
    let head = alice.client.lock().await.own_log().unwrap().head_seq;
    // The old home admits the account's devices no more, but serves them its log.
    let old_home = device_client_for(&alice.relay, &old_url);
    common::poll(|| async { Ok((flows::idlog::fetch_chain(&old_home, &alice.fp).await?.1.head_seq >= head).then_some(())) }).await;
}

/// A move stopped right after the new home imported the chain, as a crash would leave
/// it: trying the move again finishes it rather than signing a second move, and this
/// device's copy of the log then names the new home.
#[tokio::test]
async fn a_move_stopped_after_the_import_is_finished_not_made_twice() {
    let old_url = common::start_relay().await;
    let new_url = common::start_relay().await;
    let alice = create_account(&old_url, "alice").await;
    let new_home = device_client_for(&alice.relay, &new_url);

    let new_vk = flows::account::begin_move(&alice.client, &new_home, Some(&alice.relay), &alice.recovery_key).await.unwrap();
    let head_after_import = new_home.get_account(&alice.fp).await.unwrap().head_seq;
    assert_ne!(alice.client.lock().await.own_log().unwrap().home_relay_vk, Some(new_vk), "the device's copy still names the old home");

    flows::account::rehome(&alice.client, &new_home, Some(&alice.relay), &alice.recovery_key).await.unwrap();
    assert_eq!(new_home.get_account(&alice.fp).await.unwrap().head_seq, head_after_import, "no second move was signed");
    assert_eq!(alice.client.lock().await.own_log().unwrap().home_relay_vk, Some(new_vk));
}

/// The account check finishes a move whose follow-up did not run.
#[tokio::test]
async fn the_account_check_finishes_a_move_left_part_way() {
    let old_url = common::start_relay().await;
    let new_url = common::start_relay().await;
    let alice = create_account(&old_url, "alice").await;
    let new_home = device_client_for(&alice.relay, &new_url);
    let new_vk = flows::account::begin_move(&alice.client, &new_home, Some(&alice.relay), &alice.recovery_key).await.unwrap();

    flows::account::resume_move(&alice.client, &alice.relay).await.unwrap();
    assert_eq!(alice.client.lock().await.own_log().unwrap().home_relay_vk, Some(new_vk));
    // The old home was told, so it serves the move to a device that missed it.
    let (_, state) = flows::idlog::fetch_chain(&device_client_for(&alice.relay, &old_url), &alice.fp).await.unwrap();
    assert_eq!(state.home_relay_vk, Some(new_vk));
    assert_eq!(flows::account::follow_home(&alice.client, &alice.relay).await.unwrap().map(|u| u.trim_end_matches('/').to_string()), Some(new_url.trim_end_matches('/').to_string()));
}

/// The owner's second device, which missed a move of the owner's own server, finds it at
/// its own home, where the owner's record is kept.
#[tokio::test]
async fn the_owners_other_device_finds_a_move_it_missed() {
    let home_url = common::start_relay().await;
    let elsewhere_url = common::start_relay().await;
    let alice = create_account(&home_url, "alice").await;
    // Alice is a member of a server on the other relay, which admits her device.
    let (_their_server, _elsewhere, elsewhere_vk, _host) = join_foreign_server(&alice, &elsewhere_url).await;
    let server_id = create_server(&alice, "alice's own").await;
    let (client_b, relay_b, _device_b_vk) = pair_second_device(&home_url, &alice).await;

    flows::server::move_server(&alice.client, &alice.relay, &server_id, &elsewhere_url).await.unwrap();
    assert!(flows::server::check_location(&client_b, &relay_b, &server_id).await.unwrap(), "the laptop followed");
    assert_eq!(client_b.lock().await.store().server_relay(&server_id).unwrap(), Some(elsewhere_vk));
}

/// A move link whose relay cannot be reached now is kept, and followed once it can.
#[tokio::test]
async fn a_move_link_not_followed_now_is_kept_and_followed_later() {
    let home_url = common::start_relay().await;
    let elsewhere = common::start_switched_relay().await;
    let alice = create_account(&home_url, "alice").await;
    let (_their_server, _elsewhere, elsewhere_vk, _host) = join_foreign_server(&alice, &elsewhere.url()).await;
    let server_id = create_server(&alice, "alice's own").await;
    let bob = create_account(&home_url, "bob").await;
    let (token, key) = invite_on(&alice, &server_id).await;
    flows::invite::join(&bob.client, &bob.relay, &bob.relay, &token, &key, 2000).await.unwrap();
    // The group state the move uploads lists Bob, which admits him at the new relay.
    see_device_join(&alice, &home_url, &server_id, &bob.device_vk).await;

    let location = flows::server::move_server(&alice.client, &alice.relay, &server_id, &elsewhere.url()).await.unwrap();
    elsewhere.go_down();
    assert!(flows::server::follow_move_link(&bob.client, &bob.relay, &location).await.is_err());
    assert!(bob.client.lock().await.store().shown_move(&server_id).unwrap().is_some(), "the link is kept");

    elsewhere.come_back();
    assert_eq!(flows::server::retry_shown_moves(&bob.client, &bob.relay).await, 1);
    let c = bob.client.lock().await;
    assert_eq!(c.store().server_relay(&server_id).unwrap(), Some(elsewhere_vk));
    assert!(c.store().shown_move(&server_id).unwrap().is_none(), "followed, it is not kept");
}
