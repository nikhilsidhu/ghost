//! Account keys end to end against an in-process relay: revoked devices cut off from
//! everything written after, devices proven only by the log, migration away from the
//! master key, coverage repair, bad copies, and the recovery key's own operations.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{create_account, create_server, pair_second_device};
use ed25519_dalek::SigningKey;
use ghost_core::account_keys::{holders, seal_key_set, AccountSeed, DeviceEncryptionKey, RecoveryKey};
use ghost_core::client::GhostClient;
use ghost_core::error::GhostError;
use ghost_core::flows;
use ghost_core::identity::batch::BatchBuilder;
use ghost_core::identity::log::{create_account_key, create_add_device, create_device_key, create_rename_device};
use ghost_core::identity::{Addition, Identity};
use ghost_core::relay::{RelayClient, RelayEvent};
use ghost_core::wire::{encode_mutation, SyncMessageType, MUTATION_SET};
use ghost_wire::batch::LogBatch;
use ghost_wire::idlog::Recipient;
use tokio::sync::Mutex;

fn mutation_payload(key: &str) -> Vec<u8> {
    let mut payload = vec![SyncMessageType::MutationSync as u8];
    payload.extend_from_slice(&encode_mutation(MUTATION_SET, 9000, key, &[1]));
    payload
}

#[tokio::test]
async fn a_revoked_device_cannot_read_sync_written_after_its_revocation() {
    let relay_url = common::start_relay().await;
    let account = create_account(&relay_url, "desktop").await;
    let (client_b, relay_b, device_b_vk) = pair_second_device(&relay_url, &account).await;

    let outcome = flows::devices::revoke(&account.client, &account.relay, &device_b_vk).await.unwrap();
    assert_eq!(outcome, flows::devices::RevokeOutcome::Complete);

    // The revocation landed with a generation that holds no copy for B.
    let seed = account.client.lock().await.sealing_seed().unwrap();
    assert_eq!(seed.generation(), 3, "created, paired, revoked");
    let sets = account.relay.get_key_sets(&account.fp, seed.generation()).await.unwrap();
    assert!(sets[0].copy_for(&Recipient::device(device_b_vk)).is_none());

    // What A seals now opens for nothing B holds, and B cannot even fetch the set.
    let outbound = account.client.lock().await.send_sync(&mutation_payload("after")).unwrap();
    let opened = client_b.lock().await.receive_sync(&outbound.blob);
    assert!(matches!(opened, Err(GhostError::AccountKeyUnavailable(_))), "{opened:?}");
    let fetch = relay_b.get_key_sets(&account.fp, seed.generation()).await;
    assert!(
        matches!(&fetch, Err(GhostError::DeviceRevoked(Some(ghost_wire::RevocationCause::Device(by)))) if by == "desktop"),
        "the relay tells the device it was removed, and by which device: {fetch:?}"
    );
}

#[tokio::test]
async fn a_revoked_device_cannot_inject_sync_messages() {
    let relay_url = common::start_relay().await;
    let account = create_account(&relay_url, "desktop").await;
    let (client_b, _relay_b, device_b_vk) = pair_second_device(&relay_url, &account).await;
    let forged = client_b.lock().await.send_sync(&mutation_payload("from the thief")).unwrap();

    flows::devices::revoke(&account.client, &account.relay, &device_b_vk).await.unwrap();

    // Sealed under a generation B legitimately held, but B is revoked in A's log.
    let err = account.client.lock().await.receive_sync(&forged.blob).unwrap_err();
    assert!(err.to_string().contains("revoked"), "{err}");
}

#[tokio::test]
async fn a_device_the_log_does_not_list_is_refused_until_it_does() {
    let relay_url = common::start_relay().await;
    let alice = create_account(&relay_url, "alice").await;
    let carol = create_account(&relay_url, "carol").await;
    let server_id = create_server(&alice, "club").await;
    let invite = flows::invite::create(&alice.client, &alice.relay, &server_id, None).await.unwrap();
    flows::invite::join(&carol.client, &carol.relay, &carol.relay, &invite.token, &invite.key, 2000).await.unwrap();
    let (_client_b, _relay_b, device_b_vk) = pair_second_device(&relay_url, &alice).await;
    let channel_id = ghost_core::wire::derive_default_channel_id(&server_id);
    let mailbox_id = alice.client.lock().await.mailbox_id_for_server(&server_id).unwrap();

    // Carol's cached log for Alice predates device B, so B's join commit is refused
    // before it merges, and processed once she has fetched Alice's log again.
    let (reader, mut events) = RelayClient::new(&relay_url);
    reader.copy_auth_from(&carol.relay);
    let since = carol.client.lock().await.store().get_last_seen_seq(&mailbox_id).unwrap_or(0);
    reader.subscribe(mailbox_id, since);
    let mut refused = false;
    tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(event) = events.recv().await {
            let RelayEvent::Blob(blob) = event else { continue };
            let first = carol.client.lock().await.receive_any(&channel_id, &blob.payload, Some(blob.received_at));
            if let Err(GhostError::UnknownDevice { account_fp }) = first {
                assert_eq!(account_fp, alice.fp);
                refused = true;
                flows::idlog::fetch_and_verify(&carol.client, &carol.relay, &account_fp).await.unwrap();
                carol.client.lock().await.receive_any(&channel_id, &blob.payload, Some(blob.received_at)).unwrap();
            }
            if !carol.client.lock().await.find_device_leaves(&channel_id, &device_b_vk).is_empty() {
                return;
            }
        }
    })
    .await
    .expect("Carol never took device B in");
    assert!(refused, "device B was accepted before Carol's log listed it");
}

/// A device added without a covering generation (its rekey still to come) cannot replace
/// the recovery key: the generation it would make could not link back to the current one.
/// Once a device holding the current generation covers it, it can.
#[tokio::test]
async fn a_device_outside_the_current_generation_waits_to_replace_the_recovery_key() {
    let relay_url = common::start_relay().await;
    let a = create_account(&relay_url, "desktop").await;

    // Device B lands in the log with its key published but no generation sealed to it.
    let device_b = SigningKey::generate(&mut rand::rngs::OsRng);
    let encryption_b = DeviceEncryptionKey::generate();
    let state = flows::idlog::fetch_and_verify(&a.client, &a.relay, &a.fp).await.unwrap();
    let signer = a.client.lock().await.signing_key_clone();
    let add = create_add_device(&state, &signer, &device_b, "phone");
    let mut batch = BatchBuilder::new(state);
    batch.push(add.clone()).unwrap();
    batch.push(create_device_key(batch.state(), &signer, &device_b, encryption_b.key_pair().unwrap().public())).unwrap();
    a.relay.post_idlog_batch(&a.fp, &batch.finish()).await.unwrap();
    let identity_b = Identity::from_device(a.fp, device_b.clone(), encryption_b, Addition::of(&add));
    let client_b = Arc::new(Mutex::new(GhostClient::open_in_memory(identity_b, [0x55; 32]).unwrap()));
    let (relay_b, _) = RelayClient::new(&relay_url);
    relay_b.set_auth(a.fp, device_b.verifying_key().to_bytes(), device_b);
    let relay_b = Arc::new(relay_b);
    let state = flows::idlog::fetch_and_verify(&client_b, &relay_b, &a.fp).await.unwrap();
    assert!(state.rekey_needed());

    let replacement = RecoveryKey::generate();
    let err = flows::account::replace_recovery_key(&client_b, &relay_b, &a.recovery_key, &replacement).await.unwrap_err();
    assert!(matches!(err, GhostError::AccountKeyUnavailable(_)), "{err}");

    // A, holding the current generation, covers B; then B replaces the key, and A opens
    // the generation that came with it.
    assert!(flows::account_keys::repair(&a.client, &a.relay).await.unwrap());
    flows::account_keys::refresh(&client_b, &relay_b).await.unwrap();
    flows::account::replace_recovery_key(&client_b, &relay_b, &a.recovery_key, &replacement).await.unwrap();
    // A checks before anything told it of the replacement: the check reads the home.
    let check = flows::account::check_recovery_key(&a.client, &a.relay, &replacement).await.unwrap();
    assert!(check.matches && check.current, "{check:?}");
    flows::account_keys::refresh(&a.client, &a.relay).await.unwrap();
    assert_eq!(client_b.lock().await.sealing_seed().unwrap().bytes(), a.client.lock().await.sealing_seed().unwrap().bytes());
}

#[tokio::test]
async fn a_device_that_opens_a_bad_copy_names_the_writer() {
    let relay_url = common::start_relay().await;
    let account = create_account(&relay_url, "desktop").await;
    let (client_b, relay_b, device_b_vk) = pair_second_device(&relay_url, &account).await;

    // A writes generation 3 but seals B's copy from a different seed.
    let state = flows::idlog::fetch_and_verify(&account.client, &account.relay, &account.fp).await.unwrap();
    let (published, other) = (AccountSeed::generate(3), AccountSeed::generate(3));
    let previous = account.client.lock().await.account_seed(2).unwrap();
    let mut set = seal_key_set(&account.fp, &published, &holders(&state).unwrap(), previous.as_ref()).unwrap();
    let bad = seal_key_set(&account.fp, &other, &holders(&state).unwrap(), None).unwrap();
    let b = Recipient::device(device_b_vk);
    let index = set.copies.iter().position(|c| c.recipient == b).unwrap();
    set.copies[index] = bad.copy_for(&b).unwrap().clone();
    let writer = account.client.lock().await.signing_key_clone();
    let entry = create_account_key(&state, &writer, &published.signing_key().unwrap(), published.encryption_key().unwrap().public(), &set);
    let batch = LogBatch { entries: vec![entry], key_sets: vec![set] };
    account.relay.post_idlog_batch(&account.fp, &batch).await.unwrap();

    let err = flows::account_keys::refresh(&client_b, &relay_b).await.unwrap_err();
    assert!(matches!(err, GhostError::BadAccountKeyCopy { generation: 3 }), "{err:?}");
    let c = client_b.lock().await;
    let key = c.own_log().unwrap().account_keys.iter().find(|k| k.generation == 3).unwrap().clone();
    assert_eq!(key.writer, account.device_vk, "the alert can name who wrote it");
    assert!(c.account_seed(3).unwrap().is_none(), "the bad copy was not kept");
}

#[tokio::test]
async fn replacing_the_recovery_key_needs_the_current_one() {
    let relay_url = common::start_relay().await;
    let account = create_account(&relay_url, "desktop").await;
    let new_key = RecoveryKey::generate();

    let wrong = flows::account::replace_recovery_key(&account.client, &account.relay, &RecoveryKey::generate(), &new_key).await;
    assert!(matches!(wrong, Err(GhostError::AuthenticationFailed)), "{wrong:?}");
    let matches = async |key: &RecoveryKey| flows::account::check_recovery_key(&account.client, &account.relay, key).await.unwrap().matches;
    assert!(matches(&account.recovery_key).await);

    flows::account::replace_recovery_key(&account.client, &account.relay, &account.recovery_key, &new_key).await.unwrap();
    assert!(matches(&new_key).await);
    assert!(!matches(&account.recovery_key).await);

    let state = account.client.lock().await.own_log().unwrap().clone();
    let recovery_copy = Recipient::recovery(new_key.recovery_box().unwrap().public());
    assert!(state.account_key().unwrap().recipients.contains(&recovery_copy), "the new key holds the current generation");
    let (guest, _) = RelayClient::new(&relay_url);
    assert!(flows::recovery::find_account(&guest, &new_key).await.unwrap().is_some());
    assert!(flows::recovery::find_account(&guest, &account.recovery_key).await.unwrap().is_none());
}

/// Another device appending after this one read the log makes the home refuse this
/// device's batch as stale; the change is built again on the log as it is now, and both
/// land.
#[tokio::test]
async fn a_change_built_on_a_log_another_device_moved_is_built_again() {
    let relay_url = common::start_relay().await;
    let account = create_account(&relay_url, "desktop").await;
    let (client_b, relay_b, device_b_vk) = pair_second_device(&relay_url, &account).await;
    let rounds = std::sync::atomic::AtomicUsize::new(0);
    let (rounds_ref, client_a, laptop) = (&rounds, &account.client, (&client_b, &relay_b, &device_b_vk));
    let desktop_vk = &account.device_vk;
    flows::account::append_built(&account.client, &account.relay, |state| {
        Box::pin(async move {
            if rounds_ref.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                // The laptop renames itself after the desktop read the log.
                flows::devices::rename(laptop.0, laptop.1, laptop.2, "laptop").await.unwrap();
            }
            let c = client_a.lock().await;
            let mut batch = BatchBuilder::new(state);
            batch.push(create_rename_device(batch.state(), &c.signing_key_clone(), desktop_vk, "desktop at home"))?;
            Ok(Some((batch.finish(), ())))
        })
    })
    .await
    .unwrap();

    assert_eq!(rounds.load(std::sync::atomic::Ordering::SeqCst), 2, "built once more after the refusal");
    let (_, state) = flows::idlog::fetch_chain(&account.relay, &account.fp).await.unwrap();
    assert_eq!(state.devices[&account.device_vk].label, "desktop at home");
    assert_eq!(state.devices[&device_b_vk].label, "laptop");
}
