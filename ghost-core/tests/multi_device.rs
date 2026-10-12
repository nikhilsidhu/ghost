mod common;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

use ghost_core::account_keys::{AccountSeed, DeviceEncryptionKey, RecoveryKey};
use ghost_core::client::GhostClient;
use ghost_core::crypto::keys::derive_ed25519_seed;
use ghost_core::error::GhostError;
use ghost_core::identity::batch::BatchBuilder;
use ghost_core::identity::log::{
    create_add_device, create_device_key, create_genesis, create_revoke_device, create_rotate_root, validate_chain,
    LogEntry, LogState,
};
use ghost_core::identity::{Addition, Identity};
use ghost_core::relay::RelayClient;
use ghost_core::wire::{decode_mutation, encode_mutation, SyncReceiveResult, MUTATION_SET, SYNC_KEY_SERVER_ORDER};

/// An account as clients before account keys made it: a seed-derived master key.
/// Returns (master_key, device_key, genesis, account_fp).
fn make_account(label: &str) -> (SigningKey, SigningKey, LogEntry, [u8; 32]) {
    let mut seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut OsRng, &mut seed);
    let ed_bytes = derive_ed25519_seed(&seed).unwrap();
    let master_key = SigningKey::from_bytes(&ed_bytes);
    let device_key = SigningKey::generate(&mut OsRng);
    let genesis = create_genesis(&master_key, &device_key, label);
    let account_fp = genesis.account_fp;
    (master_key, device_key, genesis, account_fp)
}

/// A client with an identity of its own, for tests of local sync state.
fn make_ghost_client() -> GhostClient {
    let mut db_key = [0u8; 32];
    rand::RngCore::fill_bytes(&mut OsRng, &mut db_key);
    GhostClient::open_in_memory(Identity::generate().unwrap(), db_key).unwrap()
}

/// Push a full chain to relay and validate it client-side.
async fn push_and_validate(
    relay: &RelayClient,
    fp: &[u8; 32],
    entries: &[LogEntry],
) -> ghost_core::identity::log::LogState {
    for e in entries {
        relay.put_idlog_entry(fp, e.to_bytes()).await.unwrap();
    }
    let resp = relay.get_idlog(fp, 0).await.unwrap();
    let parsed: Vec<LogEntry> = resp.entries.iter().map(|a| a.entry.clone()).collect();
    validate_chain(&parsed).unwrap()
}

// ── Identity log: real chain through relay ──────────────────────────

#[tokio::test]
async fn idlog_genesis_add_revoke_full_lifecycle() {
    let relay_url = common::start_relay().await;
    let (relay, _) = RelayClient::new(&relay_url);
    let (_master, device1, genesis, fp) = make_account("desktop");
    relay.set_auth(fp, device1.verifying_key().to_bytes(), device1.clone());
    let device2 = SigningKey::generate(&mut OsRng);
    let device3 = SigningKey::generate(&mut OsRng);

    // Genesis: 1 active device
    let s1 = push_and_validate(&relay, &fp, &[genesis.clone()]).await;
    assert_eq!(s1.active_devices().count(), 1);

    // Add device2: 2 active devices
    let add2 = create_add_device(&s1, &device1, &device2, "phone");
    let resp = relay.get_idlog(&fp, 0).await.unwrap();
    relay.put_idlog_entry(&fp, add2.to_bytes()).await.unwrap();
    let resp2 = relay.get_idlog(&fp, 0).await.unwrap();
    assert_eq!(resp2.entries.len(), resp.entries.len() + 1);

    let entries: Vec<LogEntry> = resp2.entries.iter().map(|a| a.entry.clone()).collect();
    let s2 = validate_chain(&entries).unwrap();
    assert_eq!(s2.active_devices().count(), 2);

    // Add device3 authorized by device2 (not just device1)
    let add3 = create_add_device(&s2, &device2, &device3, "tablet");
    relay.put_idlog_entry(&fp, add3.to_bytes()).await.unwrap();

    let resp3 = relay.get_idlog(&fp, 0).await.unwrap();
    let entries3: Vec<LogEntry> = resp3.entries.iter().map(|a| a.entry.clone()).collect();
    let s3 = validate_chain(&entries3).unwrap();
    assert_eq!(s3.active_devices().count(), 3);

    // Revoke device2, authorized by device1
    let revoke2 = create_revoke_device(&s3, &device1, &device2.verifying_key().to_bytes());
    relay
        .put_idlog_entry(&fp, revoke2.to_bytes())
        .await
        .unwrap();

    let resp4 = relay.get_idlog(&fp, 0).await.unwrap();
    let entries4: Vec<LogEntry> = resp4.entries.iter().map(|a| a.entry.clone()).collect();
    let s4 = validate_chain(&entries4).unwrap();
    assert_eq!(s4.active_devices().count(), 2);
    assert!(!s4.is_active_device(&device2.verifying_key().to_bytes()));
    assert!(s4.is_active_device(&device1.verifying_key().to_bytes()));
    assert!(s4.is_active_device(&device3.verifying_key().to_bytes()));
}

// ── GhostClient sync state ─────────────────────────────────────────

#[test]
fn sync_set_older_timestamp_rejected() {
    let client = make_ghost_client();

    // Set at ts=100
    assert!(client.sync_set("pref:test", &42u64.to_be_bytes(), 100).unwrap());

    // Try to overwrite with older ts=50 — should fail
    assert!(!client.sync_set("pref:test", &99u64.to_be_bytes(), 50).unwrap());

    // Value unchanged
    let (val, ts) = client.sync_get("pref:test").unwrap().unwrap();
    assert_eq!(ts, 100);
    assert_eq!(val.unwrap(), 42u64.to_be_bytes());
}

#[test]
fn read_positions_merge_by_how_far_was_read_not_by_clock() {
    let client = make_ghost_client();
    assert!(client.sync_set("read:ch1", &500u64.to_be_bytes(), 100).unwrap());
    // Read further on a device whose clock is behind: the further position wins.
    assert!(client.sync_set("read:ch1", &900u64.to_be_bytes(), 50).unwrap());
    // Read less far on a device whose clock is ahead: the channel does not go back to unread.
    assert!(!client.sync_set("read:ch1", &700u64.to_be_bytes(), 200).unwrap());
    let (val, _) = client.sync_get("read:ch1").unwrap().unwrap();
    assert_eq!(val.unwrap(), 900u64.to_be_bytes());
}

#[test]
fn sync_set_newer_timestamp_overwrites() {
    let client = make_ghost_client();

    client.sync_set("read:ch1", &42u64.to_be_bytes(), 100).unwrap();
    assert!(client.sync_set("read:ch1", &99u64.to_be_bytes(), 200).unwrap());

    let (val, ts) = client.sync_get("read:ch1").unwrap().unwrap();
    assert_eq!(ts, 200);
    assert_eq!(val.unwrap(), 99u64.to_be_bytes());
}

#[test]
fn sync_remove_older_than_set_is_rejected() {
    let client = make_ghost_client();

    client.sync_set("read:ch1", &42u64.to_be_bytes(), 100).unwrap();

    // Remove at ts=50 — older, should fail
    assert!(!client.sync_remove("read:ch1", 50).unwrap());

    // Value still present
    let (val, _) = client.sync_get("read:ch1").unwrap().unwrap();
    assert!(val.is_some());
}

#[test]
fn sync_remove_newer_than_set_creates_tombstone() {
    let client = make_ghost_client();

    client.sync_set("read:ch1", &42u64.to_be_bytes(), 100).unwrap();

    // Remove at ts=200 — newer, should create tombstone
    assert!(client.sync_remove("read:ch1", 200).unwrap());

    let (val, ts) = client.sync_get("read:ch1").unwrap().unwrap();
    assert!(val.is_none()); // tombstone
    assert_eq!(ts, 200);
}

#[test]
fn sync_set_cannot_overwrite_newer_tombstone() {
    let client = make_ghost_client();

    client.sync_set("read:ch1", &1u64.to_be_bytes(), 50).unwrap();
    client.sync_remove("read:ch1", 200).unwrap(); // tombstone at 200

    // Try to set at ts=100 — older than tombstone
    assert!(!client.sync_set("read:ch1", &2u64.to_be_bytes(), 100).unwrap());

    // Still a tombstone
    let (val, ts) = client.sync_get("read:ch1").unwrap().unwrap();
    assert!(val.is_none());
    assert_eq!(ts, 200);
}

#[test]
fn sync_import_preserves_newer_local_state() {
    let client = make_ghost_client();

    // Local state at ts=500
    client.sync_set("pref:test", &100u64.to_be_bytes(), 500).unwrap();

    // Import older state at ts=300 — should NOT overwrite
    client
        .sync_import(&[("pref:test".to_string(), Some(200u64.to_be_bytes().to_vec()), 300)])
        .unwrap();

    let (val, ts) = client.sync_get("pref:test").unwrap().unwrap();
    assert_eq!(ts, 500);
    assert_eq!(val.unwrap(), 100u64.to_be_bytes());

    // Import newer state at ts=600 — should overwrite
    client
        .sync_import(&[("pref:test".to_string(), Some(300u64.to_be_bytes().to_vec()), 600)])
        .unwrap();

    let (val, ts) = client.sync_get("pref:test").unwrap().unwrap();
    assert_eq!(ts, 600);
    assert_eq!(val.unwrap(), 300u64.to_be_bytes());
}

#[test]
fn sync_dump_import_between_clients() {
    let client_a = make_ghost_client();

    client_a
        .sync_set(SYNC_KEY_SERVER_ORDER, b"[\"s1\",\"s2\"]", 100)
        .unwrap();
    client_a
        .sync_set("read:ch1", &5000u64.to_be_bytes(), 200)
        .unwrap();
    client_a
        .sync_set("read:ch2", &8000u64.to_be_bytes(), 300)
        .unwrap();
    client_a.sync_remove("read:ch2", 400).unwrap(); // tombstone

    let dump = client_a.sync_dump().unwrap();
    assert_eq!(dump.entries.len(), 3);

    // Import into a fresh client
    let client_b = make_ghost_client();
    client_b.sync_import(&dump.entries).unwrap();

    // Verify identical state
    let dump_b = client_b.sync_dump().unwrap();
    assert_eq!(dump_b.entries.len(), 3);

    let (val, ts) = client_b.sync_get(SYNC_KEY_SERVER_ORDER).unwrap().unwrap();
    assert_eq!(val.unwrap(), b"[\"s1\",\"s2\"]");
    assert_eq!(ts, 100);

    let (val, ts) = client_b.sync_get("read:ch1").unwrap().unwrap();
    assert_eq!(val.unwrap(), 5000u64.to_be_bytes());
    assert_eq!(ts, 200);

    // Tombstone preserved
    let (val, ts) = client_b.sync_get("read:ch2").unwrap().unwrap();
    assert!(val.is_none());
    assert_eq!(ts, 400);
}

// ── Sync channel ────────────────────────────────────────────────────

/// Two devices of one account whose root has rotated: both hold the first account key
/// generation and have the account's chain cached, all a sync message needs.
struct TwoDevices {
    a: GhostClient,
    b: GhostClient,
    a_key: SigningKey,
    b_vk: [u8; 32],
    chain: Vec<LogEntry>,
    seed: AccountSeed,
}

fn two_devices() -> TwoDevices {
    let genesis_key = SigningKey::generate(&mut OsRng);
    let (a_key, b_key) = (SigningKey::generate(&mut OsRng), SigningKey::generate(&mut OsRng));
    let (a_enc, b_enc) = (DeviceEncryptionKey::generate(), DeviceEncryptionKey::generate());
    let recovery = RecoveryKey::generate();

    let genesis = create_genesis(&genesis_key, &a_key, "desktop");
    let fp = genesis.account_fp;
    let mut batch = BatchBuilder::new(LogState::empty(fp));
    batch.push(genesis.clone()).unwrap();
    batch.push(create_device_key(batch.state(), &a_key, &a_key, a_enc.key_pair().unwrap().public())).unwrap();
    let add = create_add_device(batch.state(), &a_key, &b_key, "phone");
    batch.push(add.clone()).unwrap();
    batch.push(create_device_key(batch.state(), &a_key, &b_key, b_enc.key_pair().unwrap().public())).unwrap();
    let root = recovery.root().unwrap();
    batch.push(create_rotate_root(batch.state(), &genesis_key, &root, recovery.recovery_box().unwrap().public(), &a_key)).unwrap();
    let seed = batch.push_rekey(&a_key, None).unwrap();
    let chain = batch.finish().entries;

    let b_vk = b_key.verifying_key().to_bytes();
    let mut a = GhostClient::open_in_memory(Identity::from_device(fp, a_key.clone(), a_enc, Addition::of(&genesis)), [0x01; 32]).unwrap();
    let mut b = GhostClient::open_in_memory(Identity::from_device(fp, b_key, b_enc, Addition::of(&add)), [0x02; 32]).unwrap();
    for client in [&mut a, &mut b] {
        client.cache_identity_chain(&chain).unwrap();
        client.store_account_seed(&AccountSeed::from_bytes(seed.generation(), *seed.bytes())).unwrap();
    }
    TwoDevices { a, b, a_key, b_vk, chain, seed }
}

fn mutation(key: &str, value: u64) -> Vec<u8> {
    let mut payload = vec![ghost_core::wire::SyncMessageType::MutationSync as u8];
    payload.extend_from_slice(&encode_mutation(MUTATION_SET, 9000, key, &value.to_be_bytes()));
    payload
}

#[test]
fn a_copy_of_a_sync_message_from_another_relay_is_seen_once() {
    let mut devices = two_devices();
    let outbound = devices.a.send_sync(&mutation("read:ch1", 77)).unwrap();
    assert!(matches!(devices.b.receive_sync(&outbound.blob).unwrap(), SyncReceiveResult::Application { .. }));
    // The same bytes from a second relay, or replayed later: nothing to open.
    assert!(matches!(devices.b.receive_sync(&outbound.blob).unwrap(), SyncReceiveResult::Seen));
    assert!(matches!(devices.a.receive_sync(&outbound.blob).unwrap(), SyncReceiveResult::Seen), "a device's own message back");
}

#[test]
fn sync_messages_arriving_out_of_order_report_the_gap_and_open_once_each() {
    let mut devices = two_devices();
    let first = devices.a.send_sync(&mutation("read:ch1", 1)).unwrap();
    let second = devices.a.send_sync(&mutation("read:ch1", 2)).unwrap();
    let third = devices.a.send_sync(&mutation("read:ch1", 3)).unwrap();
    match devices.b.receive_sync(&third.blob).unwrap() {
        SyncReceiveResult::Application { gap, .. } => assert_eq!(gap, 2, "two earlier messages are missing"),
        other => panic!("expected Application, got {other:?}"),
    }
    match devices.b.receive_sync(&first.blob).unwrap() {
        SyncReceiveResult::Application { gap, .. } => assert_eq!(gap, 0),
        other => panic!("expected Application, got {other:?}"),
    }
    assert!(matches!(devices.b.receive_sync(&second.blob).unwrap(), SyncReceiveResult::Application { .. }));
    assert!(matches!(devices.b.receive_sync(&second.blob).unwrap(), SyncReceiveResult::Seen));
}

#[test]
fn a_message_that_could_not_be_opened_is_not_counted_as_seen() {
    let devices = two_devices();
    let outbound = devices.a.send_sync(&mutation("read:ch1", 1)).unwrap();
    // B has not cached the account's log yet: the sender is unknown, and a retry after
    // fetching the log must still open the message.
    let mut fresh = GhostClient::open_in_memory(
        Identity::from_device(*devices.b.fingerprint(), SigningKey::generate(&mut OsRng), DeviceEncryptionKey::generate(), Addition { seq: 3, entry_hash: [9; 32] }),
        [0x04; 32],
    )
    .unwrap();
    fresh.store_account_seed(&AccountSeed::from_bytes(devices.seed.generation(), *devices.seed.bytes())).unwrap();
    assert!(matches!(fresh.receive_sync(&outbound.blob), Err(GhostError::IdentityLog(_))), "no log cached yet");
    fresh.cache_identity_chain(&devices.chain).unwrap();
    assert!(matches!(fresh.receive_sync(&outbound.blob).unwrap(), SyncReceiveResult::Application { .. }));
}

#[test]
fn sync_mutations_reach_the_accounts_other_device() {
    let mut devices = two_devices();
    let outbound = devices.a.send_sync(&mutation("read:ch1", 77)).unwrap();
    match devices.b.receive_sync(&outbound.blob).unwrap() {
        SyncReceiveResult::Application { plaintext, .. } => {
            let (op, ts, key, value) = decode_mutation(&plaintext[1..]).unwrap();
            assert_eq!((op, ts, key.as_str()), (MUTATION_SET, 9000, "read:ch1"));
            assert_eq!(u64::from_be_bytes(value.try_into().unwrap()), 77);
        }
        other => panic!("expected Application, got {other:?}"),
    }
}

#[test]
fn a_tampered_sync_message_is_refused() {
    let mut devices = two_devices();
    let mut outbound = devices.a.send_sync(&mutation("read:ch1", 77)).unwrap();
    let last = outbound.blob.len() - 1;
    outbound.blob[last] ^= 1;
    assert!(devices.b.receive_sync(&outbound.blob).is_err());
}

#[test]
fn after_a_revocation_the_revoked_device_cannot_read_the_sync_channel() {
    let mut devices = two_devices();

    // A revokes B together with a generation that leaves B out.
    let state = validate_chain(&devices.chain).unwrap();
    let mut batch = BatchBuilder::new(state);
    batch.push(create_revoke_device(batch.state(), &devices.a_key, &devices.b_vk)).unwrap();
    let next = batch.push_rekey(&devices.a_key, Some(&devices.seed)).unwrap();
    let chain: Vec<LogEntry> = devices.chain.iter().cloned().chain(batch.finish().entries).collect();
    devices.a.cache_identity_chain(&chain).unwrap();
    devices.a.store_account_seed(&next).unwrap();

    let outbound = devices.a.send_sync(&mutation("read:ch2", 99)).unwrap();
    let opened = devices.b.receive_sync(&outbound.blob);
    assert!(matches!(opened, Err(GhostError::AccountKeyUnavailable(_))), "{opened:?}");
}

#[test]
fn sync_state_survives_dump_import_cycle() {
    let client_a = make_ghost_client();

    // Set some sync state
    client_a.sync_set("read:ch1", &42u64.to_be_bytes(), 100).unwrap();
    client_a.sync_set(SYNC_KEY_SERVER_ORDER, b"[\"s1\"]", 200).unwrap();

    // Dump it
    let dump = client_a.sync_dump().unwrap();
    assert_eq!(dump.entries.len(), 2);

    // Import into a fresh client — all state should arrive
    let client_b = make_ghost_client();
    client_b.sync_import(&dump.entries).unwrap();

    let (val, ts) = client_b.sync_get("read:ch1").unwrap().unwrap();
    assert_eq!(val.unwrap(), 42u64.to_be_bytes());
    assert_eq!(ts, 100);
}
