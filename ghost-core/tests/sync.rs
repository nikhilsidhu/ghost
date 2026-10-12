//! Device sync without a group between the devices: which relays carry it, what pauses
//! it, and how two devices' snapshots end up the same through the relays' conflict rule.

mod common;

use std::time::Duration;

use common::{create_account, pair_second_device};
use ghost_core::client::GhostClient;
use ghost_core::flows;
use ghost_core::identity::Identity;
use ghost_core::relay::{RelayClient, RelayEvent};
use ghost_core::storage::ServerKind;
use ghost_core::wire::{SyncMessageType, SyncReceiveResult, SYNC_KEY_DISPLAY_NAME};
use ghost_wire::relay_ref::RelayRef;

fn client_with_servers_on(home_vk: [u8; 32], relay_vks: &[[u8; 32]]) -> GhostClient {
    let mut client = GhostClient::open_in_memory(Identity::generate().unwrap(), [0x11; 32]).unwrap();
    client.set_relay_vk(home_vk);
    for (i, vk) in relay_vks.iter().enumerate() {
        let server_id = client.create_server(&format!("s{i}"), ServerKind::Server, 1000).unwrap();
        client.store().upsert_relay(&RelayRef::https(*vk, &format!("http://relay-{:02x}", vk[0])), 1000).unwrap();
        client.store().set_server_relay(&server_id, vk).unwrap();
    }
    client
}

#[test]
fn sync_relays_are_the_home_and_the_two_lowest_keyed_server_relays_whatever_the_join_order() {
    let home = [0x09; 32];
    let a = client_with_servers_on(home, &[[0x03; 32], [0x01; 32], home, [0x02; 32]]);
    let b = client_with_servers_on(home, &[[0x02; 32], home, [0x03; 32], [0x01; 32]]);
    let chosen_a = flows::sync::other_sync_relay_urls(&a, "http://home");
    let chosen_b = flows::sync::other_sync_relay_urls(&b, "http://home");
    assert_eq!(chosen_a, vec!["http://relay-01".to_string(), "http://relay-02".to_string()]);
    assert_eq!(chosen_a, chosen_b, "every device picks the same relays from the same servers");
    assert_eq!(flows::sync::SYNC_RELAY_COUNT, 3);

    // The home is never doubled, and a device in one server elsewhere uses just that relay.
    let one = client_with_servers_on(home, &[home, [0x07; 32]]);
    assert_eq!(flows::sync::other_sync_relay_urls(&one, "http://home"), vec!["http://relay-07".to_string()]);
}

#[tokio::test]
async fn nothing_is_written_while_a_removal_waits_for_the_home() {
    let relay_url = common::start_relay().await;
    let account = create_account(&relay_url, "desktop").await;
    let (_client_b, _relay_b, device_b_vk) = pair_second_device(&relay_url, &account).await;
    flows::sync::set_and_push(&account.client, &account.relay, "pref:a", b"before").await;
    flows::sync::push_snapshot(&account.client, &account.relay).await;
    let before = account.relay.get_sync_state(&account.fp).await.unwrap().map(|(g, _)| g);
    assert!(before.is_some());

    // The removal cannot reach the home: the removed device still holds the current key.
    account.client.lock().await.store().add_pending_revocation(&device_b_vk, 1).unwrap();
    assert!(flows::sync::paused(&*account.client.lock().await));
    flows::sync::set_and_push(&account.client, &account.relay, "pref:a", b"during").await;
    // The session takes the push it was asked for; the pause hands it back.
    assert!(account.client.lock().await.take_snapshot_push(Duration::ZERO));
    flows::sync::push_snapshot(&account.client, &account.relay).await;
    let during = account.relay.get_sync_state(&account.fp).await.unwrap().map(|(g, _)| g);
    assert_eq!(during, before, "no snapshot while the removal waits");
    assert!(!flows::sync::snapshot_writable(&*account.client.lock().await));
    assert!(account.client.lock().await.take_snapshot_push(Duration::ZERO), "the push waits for the pause to lift");

    // It landed: writes resume, carrying what changed meanwhile.
    account.client.lock().await.store().remove_pending_revocation(&device_b_vk).unwrap();
    flows::sync::set_and_push(&account.client, &account.relay, "pref:b", b"after").await;
    flows::sync::push_snapshot(&account.client, &account.relay).await;
    let (after, body) = account.relay.get_sync_state(&account.fp).await.unwrap().unwrap();
    assert!(after > before.unwrap());
    let dump = flows::sync::open_snapshot(&*account.client.lock().await, &body).unwrap();
    let value = |key: &str| dump.entries.iter().find(|(k, _, _)| k == key).and_then(|(_, v, _)| v.clone());
    assert_eq!(value("pref:a"), Some(b"during".to_vec()));
    assert_eq!(value("pref:b"), Some(b"after".to_vec()));
}

/// A removal still waiting for the home is said again, so the other devices hear the
/// pause however the first one fared.
#[tokio::test]
async fn a_removal_waiting_for_the_home_is_said_again() {
    let relay_url = common::start_relay().await;
    let account = create_account(&relay_url, "desktop").await;
    let (client_b, relay_b, _device_b_vk) = pair_second_device(&relay_url, &account).await;
    let removed = [0x5A; 32];
    account.client.lock().await.store().add_pending_revocation(&removed, 1).unwrap();

    let mailbox = account.client.lock().await.account_sync_mailbox();
    let (reader, mut events) = RelayClient::new(&relay_url);
    reader.copy_auth_from(&relay_b);
    reader.subscribe(mailbox, client_b.lock().await.store().get_last_seen_seq(&mailbox).unwrap_or(0));
    flows::sync::ensure_sync_relays(&account.client, &account.relay).await;
    flows::sync::repeat_pauses(&account.client, &account.relay).await;

    let heard = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(event) = events.recv().await {
            let RelayEvent::Blob(blob) = event else { continue };
            if let Ok(SyncReceiveResult::Application { plaintext, .. }) = client_b.lock().await.receive_sync(&blob.payload) {
                if plaintext.first() == Some(&(SyncMessageType::SyncPause as u8)) {
                    return plaintext[1..].to_vec();
                }
            }
        }
        panic!("event stream ended");
    })
    .await
    .expect("the pause was not said again");
    assert_eq!(heard, removed.to_vec());
}

/// The pref entries a client holds, sorted, for comparing two devices' states.
fn prefs_of(c: &GhostClient) -> Vec<(String, Option<Vec<u8>>)> {
    let mut entries: Vec<(String, Option<Vec<u8>>)> =
        c.sync_dump().unwrap().entries.into_iter().filter(|(k, _, _)| k.starts_with("pref:")).map(|(k, v, _)| (k, v)).collect();
    entries.sort();
    entries
}

#[tokio::test]
async fn a_device_whose_clock_lags_writes_past_the_generation_the_relay_holds() {
    let relay_url = common::start_relay().await;
    let account = create_account(&relay_url, "desktop").await;
    let (client_b, relay_b, _device_b_vk) = pair_second_device(&relay_url, &account).await;

    // B's snapshot sits on the relay under a generation an hour past A's clock, as it
    // would if B's clock ran ahead.
    flows::sync::set_and_push(&client_b, &relay_b, "pref:b", b"from b").await;
    flows::sync::push_snapshot(&client_b, &relay_b).await;
    let (written_by_b, body) = relay_b.get_sync_state(&account.fp).await.unwrap().unwrap();
    let ahead = written_by_b + 3_600_000;
    relay_b.put_sync_state(&account.fp, ahead, body).await.unwrap();

    // A's clock cannot reach that generation; the refusal tells it what to pass.
    flows::sync::set_and_push(&account.client, &account.relay, "pref:a", b"from a").await;
    flows::sync::push_snapshot(&account.client, &account.relay).await;
    let (after, body) = account.relay.get_sync_state(&account.fp).await.unwrap().unwrap();
    assert!(after > ahead, "A wrote past the generation the relay held");
    let dump = flows::sync::open_snapshot(&*account.client.lock().await, &body).unwrap();
    let value = |key: &str| dump.entries.iter().find(|(k, _, _)| k == key).and_then(|(_, v, _)| v.clone());
    assert_eq!(value("pref:a"), Some(b"from a".to_vec()));
    assert_eq!(value("pref:b"), Some(b"from b".to_vec()), "the merge took B's entry in first");
}

#[tokio::test]
async fn a_snapshot_a_relay_missed_is_written_once_it_is_back() {
    let home = common::start_switched_relay().await;
    let account = create_account(&home.url(), "desktop").await;
    flows::sync::set_and_push(&account.client, &account.relay, "pref:a", b"before").await;
    flows::sync::push_snapshot(&account.client, &account.relay).await;

    home.go_down();
    flows::sync::set_and_push(&account.client, &account.relay, "pref:b", b"while down").await;
    flows::sync::push_snapshot(&account.client, &account.relay).await;
    home.come_back();
    let (_, body) = account.relay.get_sync_state(&account.fp).await.unwrap().unwrap();
    let dump = flows::sync::open_snapshot(&*account.client.lock().await, &body).unwrap();
    assert!(!dump.entries.iter().any(|(k, _, _)| k == "pref:b"), "the relay was down for that write");

    // Nothing changed since, and the relay still gets the state it missed.
    flows::sync::push_snapshot(&account.client, &account.relay).await;
    let (_, body) = account.relay.get_sync_state(&account.fp).await.unwrap().unwrap();
    let dump = flows::sync::open_snapshot(&*account.client.lock().await, &body).unwrap();
    assert!(dump.entries.iter().any(|(k, v, _)| k == "pref:b" && v.as_deref() == Some(b"while down".as_slice())));
}

#[tokio::test]
async fn two_devices_snapshots_converge_through_the_relays_conflict_rule() {
    let relay_url = common::start_relay().await;
    let account = create_account(&relay_url, "desktop").await;
    let (client_b, relay_b, _device_b_vk) = pair_second_device(&relay_url, &account).await;
    // Both devices have read the relay's copy once, so neither reads it before writing.
    flows::sync::merge_snapshots(&client_b, &relay_b).await.unwrap();

    // Each device changes something the other has not seen and writes its own snapshot;
    // the relay keeps whichever came last.
    flows::sync::set_and_push(&account.client, &account.relay, "pref:a", b"from a").await;
    flows::sync::push_snapshot(&account.client, &account.relay).await;
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    flows::sync::set_and_push(&client_b, &relay_b, "pref:b", b"from b").await;
    flows::sync::push_snapshot(&client_b, &relay_b).await;

    // Merging reads the relay's copy, takes in what is new, and writes back what it added;
    // the other device then merges that. Nothing either wrote is lost.
    let merged_a = flows::sync::merge_snapshots(&account.client, &account.relay).await.unwrap();
    assert!(merged_a.is_some(), "A took in B's change");
    flows::sync::merge_snapshots(&client_b, &relay_b).await.unwrap();

    let expected = vec![("pref:a".to_string(), Some(b"from a".to_vec())), ("pref:b".to_string(), Some(b"from b".to_vec()))];
    assert_eq!(prefs_of(&*account.client.lock().await), expected);
    assert_eq!(prefs_of(&*client_b.lock().await), expected);

    // The relay's copy holds both too, and another merge changes nothing anywhere.
    let (_, body) = account.relay.get_sync_state(&account.fp).await.unwrap().unwrap();
    let dump = flows::sync::open_snapshot(&*account.client.lock().await, &body).unwrap();
    assert_eq!(dump.entries.iter().filter(|(k, _, _)| k.starts_with("pref:")).count(), 2);
    assert!(flows::sync::merge_snapshots(&client_b, &relay_b).await.unwrap().is_none());
}

/// A device that never read a relay's snapshot (one just linked or recovered) takes it in
/// before its first write there, so it never puts its own state in place of the
/// account's, and the settings it took in come back for applying.
#[tokio::test]
async fn a_device_reads_a_relays_snapshot_before_first_writing_over_it() {
    let relay_url = common::start_relay().await;
    let account = create_account(&relay_url, "desktop").await;
    let (client_b, relay_b, _device_b_vk) = pair_second_device(&relay_url, &account).await;

    // The desktop's change reaches only the relay's copy, as one made while the laptop
    // missed the message would.
    {
        let c = account.client.lock().await;
        let ts = c.sync_tick().unwrap();
        c.sync_set(SYNC_KEY_DISPLAY_NAME, b"Alice", ts).unwrap();
    }
    flows::sync::push_snapshot(&account.client, &account.relay).await;

    let changed = flows::sync::push_snapshot(&client_b, &relay_b).await;
    assert_eq!(changed.and_then(|s| s.display_name).as_deref(), Some("Alice"), "the laptop took the relay's copy in first");
    let (_, body) = account.relay.get_sync_state(&account.fp).await.unwrap().unwrap();
    let dump = flows::sync::open_snapshot(&*account.client.lock().await, &body).unwrap();
    assert!(
        dump.entries.iter().any(|(k, v, _)| k == SYNC_KEY_DISPLAY_NAME && v.as_deref() == Some(b"Alice".as_slice())),
        "the laptop's write kept what the relay held"
    );
}
