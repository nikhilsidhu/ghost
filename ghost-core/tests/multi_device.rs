mod common;

use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;

use ghost_core::client::GhostClient;
use ghost_core::crypto::keys::derive_ed25519_seed;
use ghost_core::identity::export::{export_recovery_blob, import_recovery_blob};
use ghost_core::identity::log::{
    create_add_device, create_genesis, create_recovery, create_revoke_device, validate_chain,
    LogEntry,
};
use ghost_core::identity::Identity;
use ghost_core::relay::{RelayClient, RelayEvent};
use ghost_core::wire::{
    decode_mutation, encode_mutation, encode_sync_state_dump, sync_open,
    sync_seal, SyncReceiveResult, MUTATION_SET, SYNC_KEY_SERVER_ORDER,
};

/// Create account using the real Identity::create_account flow.
/// Returns (master_key, device_key, genesis, account_fp, seed).
fn make_account(label: &str) -> (SigningKey, SigningKey, LogEntry, [u8; 32], [u8; 32]) {
    let mut seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut OsRng, &mut seed);
    let ed_bytes = derive_ed25519_seed(&seed).unwrap();
    let master_key = SigningKey::from_bytes(&ed_bytes);
    let device_key = SigningKey::generate(&mut OsRng);
    let genesis = create_genesis(&master_key, &device_key, label);
    let account_fp = genesis.account_fp;
    (master_key, device_key, genesis, account_fp, seed)
}

async fn recv_blob(
    events: &mut tokio::sync::mpsc::Receiver<RelayEvent>,
    mailbox: [u8; 32],
) -> ghost_core::relay::IncomingBlob {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match events.recv().await {
                Some(RelayEvent::Blob(b)) if b.mailbox_id == mailbox => break b,
                Some(_) => continue,
                None => panic!("channel closed"),
            }
        }
    })
    .await
    .expect("timed out waiting for sync blob")
}

/// Create a GhostClient from Identity::create_account, extracting fields before drop.
fn make_ghost_client(label: &str) -> (GhostClient, [u8; 32], SigningKey) {
    let acct = Identity::create_account(label).unwrap();
    let fp = acct.identity.fingerprint;
    let sk = acct.identity.signing_key.clone();
    let db_key = acct.db_key;
    let identity = Identity::from_device(fp, sk.clone(), 1);
    drop(acct);
    (GhostClient::open_in_memory(identity, db_key).unwrap(), fp, sk)
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
    let blobs = relay.get_idlog(fp, 0).await.unwrap();
    let parsed: Vec<LogEntry> = blobs
        .iter()
        .map(|b| LogEntry::from_bytes(&b.payload).unwrap())
        .collect();
    validate_chain(&parsed).unwrap()
}

// ── Identity log: real chain through relay ──────────────────────────

#[tokio::test]
async fn idlog_genesis_add_revoke_full_lifecycle() {
    let relay_url = common::start_relay().await;
    let (relay, _) = RelayClient::new(&relay_url);
    let (_master, device1, genesis, fp, _seed) = make_account("desktop");
    let device2 = SigningKey::generate(&mut OsRng);
    let device3 = SigningKey::generate(&mut OsRng);

    // Genesis: 1 active device
    let s1 = push_and_validate(&relay, &fp, &[genesis.clone()]).await;
    assert_eq!(s1.active_devices().count(), 1);

    // Add device2: 2 active devices
    let add2 = create_add_device(&s1, &device1, &device2, "phone");
    let blobs = relay.get_idlog(&fp, 0).await.unwrap();
    relay.put_idlog_entry(&fp, add2.to_bytes()).await.unwrap();
    let blobs2 = relay.get_idlog(&fp, 0).await.unwrap();
    assert_eq!(blobs2.len(), blobs.len() + 1);

    let entries: Vec<LogEntry> = blobs2
        .iter()
        .map(|b| LogEntry::from_bytes(&b.payload).unwrap())
        .collect();
    let s2 = validate_chain(&entries).unwrap();
    assert_eq!(s2.active_devices().count(), 2);

    // Add device3 authorized by device2 (not just device1)
    let add3 = create_add_device(&s2, &device2, &device3, "tablet");
    relay.put_idlog_entry(&fp, add3.to_bytes()).await.unwrap();

    let blobs3 = relay.get_idlog(&fp, 0).await.unwrap();
    let entries3: Vec<LogEntry> = blobs3
        .iter()
        .map(|b| LogEntry::from_bytes(&b.payload).unwrap())
        .collect();
    let s3 = validate_chain(&entries3).unwrap();
    assert_eq!(s3.active_devices().count(), 3);

    // Revoke device2, authorized by device1
    let revoke2 = create_revoke_device(&s3, &device1, &device2.verifying_key().to_bytes());
    relay
        .put_idlog_entry(&fp, revoke2.to_bytes())
        .await
        .unwrap();

    let blobs4 = relay.get_idlog(&fp, 0).await.unwrap();
    let entries4: Vec<LogEntry> = blobs4
        .iter()
        .map(|b| LogEntry::from_bytes(&b.payload).unwrap())
        .collect();
    let s4 = validate_chain(&entries4).unwrap();
    assert_eq!(s4.active_devices().count(), 2);
    assert!(!s4.is_active_device(&device2.verifying_key().to_bytes()));
    assert!(s4.is_active_device(&device1.verifying_key().to_bytes()));
    assert!(s4.is_active_device(&device3.verifying_key().to_bytes()));
}

// ── GhostClient sync state ─────────────────────────────────────────

#[test]
fn sync_set_older_timestamp_rejected() {
    let (client, _, _) = make_ghost_client("test");

    // Set at ts=100
    assert!(client.sync_set("read:ch1", &42u64.to_be_bytes(), 100).unwrap());

    // Try to overwrite with older ts=50 — should fail
    assert!(!client.sync_set("read:ch1", &99u64.to_be_bytes(), 50).unwrap());

    // Value unchanged
    let (val, ts) = client.sync_get("read:ch1").unwrap().unwrap();
    assert_eq!(ts, 100);
    assert_eq!(val.unwrap(), 42u64.to_be_bytes());
}

#[test]
fn sync_set_newer_timestamp_overwrites() {
    let (client, _, _) = make_ghost_client("test");

    client.sync_set("read:ch1", &42u64.to_be_bytes(), 100).unwrap();
    assert!(client.sync_set("read:ch1", &99u64.to_be_bytes(), 200).unwrap());

    let (val, ts) = client.sync_get("read:ch1").unwrap().unwrap();
    assert_eq!(ts, 200);
    assert_eq!(val.unwrap(), 99u64.to_be_bytes());
}

#[test]
fn sync_remove_older_than_set_is_rejected() {
    let (client, _, _) = make_ghost_client("test");

    client.sync_set("read:ch1", &42u64.to_be_bytes(), 100).unwrap();

    // Remove at ts=50 — older, should fail
    assert!(!client.sync_remove("read:ch1", 50).unwrap());

    // Value still present
    let (val, _) = client.sync_get("read:ch1").unwrap().unwrap();
    assert!(val.is_some());
}

#[test]
fn sync_remove_newer_than_set_creates_tombstone() {
    let (client, _, _) = make_ghost_client("test");

    client.sync_set("read:ch1", &42u64.to_be_bytes(), 100).unwrap();

    // Remove at ts=200 — newer, should create tombstone
    assert!(client.sync_remove("read:ch1", 200).unwrap());

    let (val, ts) = client.sync_get("read:ch1").unwrap().unwrap();
    assert!(val.is_none()); // tombstone
    assert_eq!(ts, 200);
}

#[test]
fn sync_set_cannot_overwrite_newer_tombstone() {
    let (client, _, _) = make_ghost_client("test");

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
    let (client, _, _) = make_ghost_client("test");

    // Local state at ts=500
    client.sync_set("read:ch1", &100u64.to_be_bytes(), 500).unwrap();

    // Import older state at ts=300 — should NOT overwrite
    client
        .sync_import(&[("read:ch1".to_string(), Some(200u64.to_be_bytes().to_vec()), 300)])
        .unwrap();

    let (val, ts) = client.sync_get("read:ch1").unwrap().unwrap();
    assert_eq!(ts, 500);
    assert_eq!(val.unwrap(), 100u64.to_be_bytes());

    // Import newer state at ts=600 — should overwrite
    client
        .sync_import(&[("read:ch1".to_string(), Some(300u64.to_be_bytes().to_vec()), 600)])
        .unwrap();

    let (val, ts) = client.sync_get("read:ch1").unwrap().unwrap();
    assert_eq!(ts, 600);
    assert_eq!(val.unwrap(), 300u64.to_be_bytes());
}

#[test]
fn sync_dump_import_between_clients() {
    let (client_a, _, _) = make_ghost_client("device-a");

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
    assert_eq!(dump.len(), 3);

    // Import into a fresh client
    let (client_b, _, _) = make_ghost_client("device-b");
    client_b.sync_import(&dump).unwrap();

    // Verify identical state
    let dump_b = client_b.sync_dump().unwrap();
    assert_eq!(dump_b.len(), 3);

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

// ── Pairing: crypto through relay ───────────────────────────────────

#[tokio::test]
async fn pairing_offer_response_encrypted_roundtrip() {
    let relay_url = common::start_relay().await;
    let (relay_a, _) = RelayClient::new(&relay_url);
    let (relay_b, _) = RelayClient::new(&relay_url);
    let (_master, _device1, _genesis, fp, _seed) = make_account("desktop");

    let secret = [0x42u8; 32];
    let offer_pt = b"relay_url|display_name|avatar_hash";
    let offer_sealed = sync_seal(&secret, offer_pt).unwrap();
    relay_a.post_pairing_offer(&fp, offer_sealed).await.unwrap();

    // No response yet
    assert!(relay_b.get_pairing_response(&fp).await.unwrap().is_none());

    // Fetch offer via HTTP (simulating QR code scan)
    let http = reqwest::Client::new();
    let offer_blob = http
        .get(format!("{}/pair/{}", relay_url, hex::encode(fp)))
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap()
        .to_vec();
    let offer_opened = sync_open(&secret, &offer_blob).unwrap();
    assert_eq!(offer_opened, offer_pt);

    // Device B responds with its key
    let device_b_key = SigningKey::generate(&mut OsRng);
    let mut response_pt = Vec::new();
    response_pt.extend_from_slice(&device_b_key.to_bytes());
    response_pt.extend_from_slice(b"phone");
    let response_sealed = sync_seal(&secret, &response_pt).unwrap();
    relay_b
        .post_pairing_response(&fp, response_sealed)
        .await
        .unwrap();

    // Device A decrypts response, recovers device B's key
    let response_blob = relay_a.get_pairing_response(&fp).await.unwrap().unwrap();
    let response_opened = sync_open(&secret, &response_blob).unwrap();
    let recovered_key: [u8; 32] = response_opened[..32].try_into().unwrap();
    assert_eq!(recovered_key, device_b_key.to_bytes());
    assert_eq!(&response_opened[32..], b"phone");
}

// ── Sync MLS group ──────────────────────────────────────────────────

#[test]
fn sync_group_produces_joinable_group_info() {
    let (mut client_a, fp_a, _) = make_ghost_client("desktop");
    assert!(!client_a.has_sync_group());
    client_a.create_sync_group().unwrap();

    // Verify the GroupInfo is valid by having another device successfully join
    let gi = client_a.sync_group_info().unwrap();
    assert!(!gi.is_empty());

    let acct_b = Identity::create_account("phone").unwrap();
    let identity_b = Identity::from_device(fp_a, acct_b.identity.signing_key.clone(), 2);
    drop(acct_b);
    let mut client_b = GhostClient::open_in_memory(identity_b, [0x02; 32]).unwrap();
    let (_commit, mailbox_b) = client_b.join_sync_group(&gi).unwrap();
    assert_eq!(mailbox_b, client_a.sync_mailbox_id().unwrap());
}

#[test]
fn sync_group_add_device_via_external_commit() {
    let (mut client_a, fp_a, _) = make_ghost_client("desktop");
    client_a.create_sync_group().unwrap();

    // Export GroupInfo for pairing
    let gi = client_a.sync_group_info().unwrap();

    // Device B joins via external commit
    let acct_b = Identity::create_account("phone").unwrap();
    let identity_b = Identity::from_device(fp_a, acct_b.identity.signing_key.clone(), 2);
    drop(acct_b);
    let mut client_b = GhostClient::open_in_memory(identity_b, [0x02; 32]).unwrap();
    let (commit, mailbox_b) = client_b.join_sync_group(&gi).unwrap();
    assert_eq!(mailbox_b, client_a.sync_mailbox_id().unwrap());

    // Device A processes the commit
    match client_a.receive_sync(&commit).unwrap() {
        SyncReceiveResult::CommitProcessed => {}
        other => panic!("expected CommitProcessed, got {:?}", other),
    }

    // Both devices are now in the same group
    assert_eq!(client_a.sync_mailbox_id(), client_b.sync_mailbox_id());
}

#[test]
fn sync_mutation_encrypted_decrypted() {
    let (mut client_a, fp_a, _) = make_ghost_client("desktop");
    client_a.create_sync_group().unwrap();
    let gi = client_a.sync_group_info().unwrap();

    // Device B joins
    let acct_b = Identity::create_account("phone").unwrap();
    let identity_b = Identity::from_device(fp_a, acct_b.identity.signing_key.clone(), 2);
    drop(acct_b);
    let mut client_b = GhostClient::open_in_memory(identity_b, [0x02; 32]).unwrap();
    let (commit, _) = client_b.join_sync_group(&gi).unwrap();
    client_a.receive_sync(&commit).unwrap();

    // Device A sends a mutation
    let mutation = encode_mutation(MUTATION_SET, 9000, "read:ch1", &77u64.to_be_bytes());
    let mut payload = Vec::with_capacity(1 + mutation.len());
    payload.push(0x04); // MutationSync
    payload.extend_from_slice(&mutation);
    let outbound = client_a.send_sync(&payload).unwrap();

    // Device B decrypts it
    match client_b.receive_sync(&outbound.blob).unwrap() {
        SyncReceiveResult::Application(plaintext) => {
            assert_eq!(plaintext[0], 0x04); // MutationSync
            let (op, ts, key, value) = decode_mutation(&plaintext[1..]).unwrap();
            assert_eq!(op, MUTATION_SET);
            assert_eq!(ts, 9000);
            assert_eq!(key, "read:ch1");
            assert_eq!(u64::from_be_bytes(value.try_into().unwrap()), 77);
        }
        other => panic!("expected Application, got {:?}", other),
    }
}

#[test]
fn sync_revocation_prevents_decryption() {
    let (mut client_a, fp_a, _) = make_ghost_client("desktop");
    client_a.create_sync_group().unwrap();
    let gi = client_a.sync_group_info().unwrap();

    // Device B joins
    let acct_b = Identity::create_account("phone").unwrap();
    let b_vk = acct_b.identity.signing_key.verifying_key().to_bytes();
    let identity_b = Identity::from_device(fp_a, acct_b.identity.signing_key.clone(), 2);
    drop(acct_b);
    let mut client_b = GhostClient::open_in_memory(identity_b, [0x02; 32]).unwrap();
    let (commit, _) = client_b.join_sync_group(&gi).unwrap();
    client_a.receive_sync(&commit).unwrap();

    // Device A removes Device B from sync group
    let removal_commit = client_a.remove_device_from_sync_group(&b_vk).unwrap();

    // Device A sends a post-removal mutation
    let mutation = encode_mutation(MUTATION_SET, 10000, "read:ch2", &99u64.to_be_bytes());
    let mut payload = Vec::with_capacity(1 + mutation.len());
    payload.push(0x04);
    payload.extend_from_slice(&mutation);
    let outbound = client_a.send_sync(&payload).unwrap();

    // Device B can process the removal commit (already envelope-wrapped)...
    // But after removal, Device B cannot decrypt the new message
    let _ = client_b.receive_sync(&removal_commit);
    assert!(client_b.receive_sync(&outbound.blob).is_err());
}

#[test]
fn sync_state_survives_dump_import_cycle() {
    let (client_a, _, _) = make_ghost_client("desktop");

    // Set some sync state
    client_a.sync_set("read:ch1", &42u64.to_be_bytes(), 100).unwrap();
    client_a.sync_set(SYNC_KEY_SERVER_ORDER, b"[\"s1\"]", 200).unwrap();

    // Dump it
    let dump = client_a.sync_dump().unwrap();
    assert_eq!(dump.len(), 2);

    // Import into a fresh client — all state should arrive
    let (client_b, _, _) = make_ghost_client("phone");
    client_b.sync_import(&dump).unwrap();

    let (val, ts) = client_b.sync_get("read:ch1").unwrap().unwrap();
    assert_eq!(val.unwrap(), 42u64.to_be_bytes());
    assert_eq!(ts, 100);
}

// ── Full pairing → identity log → MLS sync exchange ────────────────

#[tokio::test]
async fn full_pairing_then_sync_exchange() {
    let relay_url = common::start_relay().await;
    let http = reqwest::Client::new();

    // 1. Device A creates account
    let (_master, device_a, genesis, fp, _seed) = make_account("desktop");
    let fp_hex = hex::encode(fp);
    let (relay_a, _) = RelayClient::new(&relay_url);
    relay_a
        .put_idlog_entry(&fp, genesis.to_bytes())
        .await
        .unwrap();

    // 2. Device A creates GhostClient, sync key, and sync MLS group
    let mut client_a = GhostClient::open_in_memory(
        Identity::from_device(fp, device_a.clone(), 1),
        [0x01; 32],
    )
    .unwrap();
    let sync_key: [u8; 32] = {
        let mut k = [0u8; 32];
        rand::RngCore::fill_bytes(&mut OsRng, &mut k);
        k
    };
    client_a.set_sync_key(sync_key).unwrap();
    client_a.create_sync_group().unwrap();

    // 3. Device A posts pairing offer
    let secret = [0x42u8; 32];
    let offer = sync_seal(&secret, b"offer-data").unwrap();
    http.post(format!("{}/pair/{}", relay_url, fp_hex))
        .body(offer)
        .send()
        .await
        .unwrap();

    // 4. Device B responds with its key
    let device_b = SigningKey::generate(&mut OsRng);
    let mut response_pt = device_b.to_bytes().to_vec();
    response_pt.extend_from_slice(b"phone");
    let response = sync_seal(&secret, &response_pt).unwrap();
    http.post(format!("{}/pair/{}/respond", relay_url, fp_hex))
        .body(response)
        .send()
        .await
        .unwrap();

    // 5. Device A gets response, builds provision blob with sync_key + GroupInfo + sync state
    let resp_blob = http
        .get(format!("{}/pair/{}/response", relay_url, fp_hex))
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap()
        .to_vec();
    let resp_pt = sync_open(&secret, &resp_blob).unwrap();
    let b_key_bytes: [u8; 32] = resp_pt[..32].try_into().unwrap();
    let b_signing_key = SigningKey::from_bytes(&b_key_bytes);

    // Build provision: [sync_key:32][gi_len:u32][group_info][count:u16][servers...][sync_dump]
    let actual_sync_key = client_a.sync_key().unwrap();
    let group_info = client_a.sync_group_info().unwrap();
    client_a
        .sync_set("read:ch1", &77u64.to_be_bytes(), 1000)
        .unwrap();
    let sync_dump = client_a.sync_dump().unwrap();

    let mut provision_pt = Vec::new();
    provision_pt.extend_from_slice(&actual_sync_key);
    provision_pt.extend_from_slice(&(group_info.len() as u32).to_be_bytes());
    provision_pt.extend_from_slice(&group_info);
    provision_pt.extend_from_slice(&0u16.to_be_bytes()); // 0 servers
    provision_pt.extend_from_slice(&encode_sync_state_dump(&sync_dump));
    let provision_sealed = sync_seal(&secret, &provision_pt).unwrap();

    // put_provision requires auth — sign as device_a
    let prov_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let da_vk = device_a.verifying_key().to_bytes();
    let prov_msg = ghost_wire::auth::auth_message(&fp, &da_vk, prov_timestamp);
    let prov_sig = device_a.sign(&prov_msg);

    http.put(format!("{}/pair/{}/provision", relay_url, fp_hex))
        .header("x-ghost-account", hex::encode(fp))
        .header("x-ghost-device", hex::encode(da_vk))
        .header("x-ghost-timestamp", prov_timestamp.to_string())
        .header("x-ghost-signature", hex::encode(prov_sig.to_bytes()))
        .body(provision_sealed)
        .send()
        .await
        .unwrap();

    // Push AddDevice to identity log
    let chain_state = validate_chain(&[genesis.clone()]).unwrap();
    let add_entry = create_add_device(&chain_state, &device_a, &b_signing_key, "phone");
    relay_a
        .put_idlog_entry(&fp, add_entry.to_bytes())
        .await
        .unwrap();

    // 6. Device B: validate chain, fetch provision, join sync group
    let all_blobs = relay_a.get_idlog(&fp, 0).await.unwrap();
    let all_entries: Vec<LogEntry> = all_blobs
        .iter()
        .map(|b| LogEntry::from_bytes(&b.payload).unwrap())
        .collect();
    let state = validate_chain(&all_entries).unwrap();
    assert_eq!(state.active_devices().count(), 2);
    assert!(state.is_active_device(&device_b.verifying_key().to_bytes()));

    let prov_blob = http
        .get(format!("{}/pair/{}/provision", relay_url, fp_hex))
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap()
        .to_vec();
    let prov_pt = sync_open(&secret, &prov_blob).unwrap();
    let recovered_sync_key: [u8; 32] = prov_pt[..32].try_into().unwrap();
    let gi_len = u32::from_be_bytes(prov_pt[32..36].try_into().unwrap()) as usize;
    let recovered_gi = &prov_pt[36..36 + gi_len];

    // Device B creates GhostClient, stores sync key, joins sync group
    let mut client_b = GhostClient::open_in_memory(
        Identity::from_device(fp, device_b.clone(), 2),
        [0x02; 32],
    )
    .unwrap();
    client_b.set_sync_key(recovered_sync_key).unwrap();
    assert_eq!(client_b.sync_key().unwrap(), sync_key);

    let (commit, sync_mb) = client_b.join_sync_group(recovered_gi).unwrap();
    assert_eq!(sync_mb, client_a.sync_mailbox_id().unwrap());

    // Device A processes the join commit
    match client_a.receive_sync(&commit).unwrap() {
        SyncReceiveResult::CommitProcessed => {}
        other => panic!("expected CommitProcessed, got {:?}", other),
    }

    // 7. Both subscribe to sync mailbox, A sends mutation via MLS, B receives
    let mailbox = client_a.sync_mailbox_id().unwrap();
    let (mut relay_a2, _events_a) = RelayClient::new(&relay_url);
    let (mut relay_b2, mut events_b) = RelayClient::new(&relay_url);
    relay_a2.set_auth(fp, device_a.verifying_key().to_bytes(), device_a.clone());
    relay_b2.set_auth(fp, device_b.verifying_key().to_bytes(), device_b.clone());
    relay_a2.subscribe(mailbox, 0);
    relay_b2.subscribe(mailbox, 0);
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mutation = encode_mutation(MUTATION_SET, 9000, "read:ch1", &77u64.to_be_bytes());
    let mut sync_payload = Vec::with_capacity(1 + mutation.len());
    sync_payload.push(0x04); // MutationSync
    sync_payload.extend_from_slice(&mutation);
    let outbound = client_a.send_sync(&sync_payload).unwrap();
    relay_a2
        .send(&mailbox, outbound.blob)
        .await
        .unwrap();

    let blob = recv_blob(&mut events_b, mailbox).await;
    match client_b.receive_sync(&blob.payload).unwrap() {
        SyncReceiveResult::Application(plaintext) => {
            assert_eq!(plaintext[0], 0x04);
            let (op, ts, key, value) = decode_mutation(&plaintext[1..]).unwrap();
            assert_eq!(op, MUTATION_SET);
            assert_eq!(ts, 9000);
            assert_eq!(key, "read:ch1");
            assert_eq!(u64::from_be_bytes(value.try_into().unwrap()), 77);
        }
        other => panic!("expected Application, got {:?}", other),
    }
}

// ── Recovery: full flow ─────────────────────────────────────────────

#[tokio::test]
async fn recovery_full_flow() {
    let relay_url = common::start_relay().await;
    let (mut relay, _) = RelayClient::new(&relay_url);

    // 1. Create account with 2 devices
    let (master, device1, genesis, fp, seed) = make_account("desktop");
    let device2 = SigningKey::generate(&mut OsRng);

    relay
        .put_idlog_entry(&fp, genesis.to_bytes())
        .await
        .unwrap();
    let s1 = validate_chain(&[genesis.clone()]).unwrap();
    let add = create_add_device(&s1, &device1, &device2, "phone");
    relay.put_idlog_entry(&fp, add.to_bytes()).await.unwrap();

    // Set auth as device1 for subsequent authenticated calls
    relay.set_auth(fp, device1.verifying_key().to_bytes(), device1.clone());

    // Both devices had a sync key
    let old_sync_key = [0xAA; 32];

    // 2. Export seed + sync_key encrypted with passphrase, store on relay
    let recovery_blob = export_recovery_blob(&seed, &old_sync_key, "my-recovery-passphrase").unwrap();
    relay
        .put_recovery_blob(&fp, recovery_blob.clone())
        .await
        .unwrap();

    // 3. All devices lost. New device fetches recovery blob.
    let fetched = relay.get_recovery_blob(&fp).await.unwrap().unwrap();
    assert_eq!(fetched, recovery_blob);

    // 4. Decrypt → derive master key
    let recovered = import_recovery_blob(&fetched, "my-recovery-passphrase").unwrap();
    assert_eq!(recovered.seed, seed);
    assert_eq!(recovered.sync_key.unwrap(), old_sync_key);
    let recovered_seed = recovered.seed;
    let recovered_ed = derive_ed25519_seed(&recovered_seed).unwrap();
    let recovered_master = SigningKey::from_bytes(&recovered_ed);
    assert_eq!(
        recovered_master.verifying_key().to_bytes(),
        master.verifying_key().to_bytes()
    );

    // 5. Create Recovery entry, push to relay
    let recovery_device = SigningKey::generate(&mut OsRng);
    let chain_blobs = relay.get_idlog(&fp, 0).await.unwrap();
    let chain_entries: Vec<LogEntry> = chain_blobs
        .iter()
        .map(|b| LogEntry::from_bytes(&b.payload).unwrap())
        .collect();
    let chain_state = validate_chain(&chain_entries).unwrap();
    assert_eq!(chain_state.active_devices().count(), 2);

    let recovery_entry =
        create_recovery(&chain_state, &recovered_master, &recovery_device, "new-phone");
    relay
        .put_idlog_entry(&fp, recovery_entry.to_bytes())
        .await
        .unwrap();

    // 6. Validate: only recovery device is active
    let final_blobs = relay.get_idlog(&fp, 0).await.unwrap();
    let final_entries: Vec<LogEntry> = final_blobs
        .iter()
        .map(|b| LogEntry::from_bytes(&b.payload).unwrap())
        .collect();
    let final_state = validate_chain(&final_entries).unwrap();
    assert_eq!(final_state.active_devices().count(), 1);
    assert!(final_state.is_active_device(&recovery_device.verifying_key().to_bytes()));
    assert!(!final_state.is_active_device(&device1.verifying_key().to_bytes()));
    assert!(!final_state.is_active_device(&device2.verifying_key().to_bytes()));

    // 7. Recovery device creates GhostClient with sync key + fresh sync group
    let recovery_identity = Identity::from_device(fp, recovery_device.clone(), 3);
    let mut recovery_client =
        GhostClient::open_in_memory(recovery_identity, [0x99; 32]).unwrap();
    assert!(recovery_client.sync_key().is_none());
    assert!(!recovery_client.has_sync_group());

    recovery_client.set_sync_key(old_sync_key).unwrap();
    recovery_client.create_sync_group().unwrap();
    assert!(recovery_client.has_sync_group());
    assert!(recovery_client.sync_mailbox_id().is_some());

    // 8. Old sync key still works for durable snapshot decryption
    let snapshot_data = b"server-metadata-snapshot";
    let sealed = sync_seal(&old_sync_key, snapshot_data).unwrap();
    assert_eq!(sync_open(&old_sync_key, &sealed).unwrap(), snapshot_data);

    // 9. MLS sync group is fresh — only recovery device is a member
    // (any future devices added via pairing will join via GroupInfo)
    let gi = recovery_client.sync_group_info().unwrap();
    assert!(!gi.is_empty());
}

