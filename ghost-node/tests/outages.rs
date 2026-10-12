//! A home relay going down and coming back, with real devices running their sessions:
//! what waited for it lands, and what was missed catches up.

mod support;

use std::time::Duration;

use ghost_core::flows;
use ghost_core::flows::devices::RevokeOutcome;
use ghost_core::session::{AccountAlert, ClientEvent};
use ghost_node::Device;
use support::{caught_up, eventually, invite_into, message_text, server_changed, start_relay, start_relay_with, start_switched_relay, test_config, Peer, EVENT_WAIT};

/// Time for a device to notice the home is back: its connections retry with backoff.
const RECONNECT_WAIT: Duration = Duration::from_secs(30);

#[tokio::test(flavor = "multi_thread")]
async fn a_removal_made_while_the_home_is_down_lands_when_it_comes_back() {
    let home = start_switched_relay().await;
    let laptop = Peer::new(&home.url(), "laptop").await;
    let phone_dir = tempfile::tempdir().unwrap();
    let mut phone = laptop.device.link_device(phone_dir.path(), &home.url(), "phone").await.unwrap();
    phone.start();
    let phone_vk = phone.verifying_key().await;
    let mark = phone.mark();

    home.go_down();
    assert_eq!(laptop.device.revoke(&phone_vk).await.unwrap(), RevokeOutcome::LogPending);
    home.come_back();

    // The laptop's session appends the removal once it reconnects, and the relay's
    // refusal tells the phone.
    let removed = phone
        .wait_for(mark, RECONNECT_WAIT, |e| matches!(e, ClientEvent::Account(AccountAlert::ThisDeviceRemoved { .. })).then_some(()))
        .await;
    assert!(removed.is_some(), "the phone never heard it was removed: {:#?}", phone.events_since(mark));
    assert!(!laptop.device.devices().await.unwrap().state.is_active_device(&phone_vk));
}

/// A pause sealed under an account key generation the phone has not fetched, with the
/// home down: the relay hosting the account's server mirrors the log and key sets, so
/// the phone's check fetches the generation there and the pause is not lost.
#[tokio::test(flavor = "multi_thread")]
async fn a_pause_sealed_under_a_key_the_phone_lacks_lands_while_the_home_is_down() {
    let home = start_switched_relay().await;
    let shared = start_relay().await;
    let bob = Peer::new(&shared.url(), "bob").await;
    let server_id = bob.device.create_server("club").await.unwrap();
    let laptop = Peer::new(&home.url(), "laptop").await;
    let (token, key) = bob.device.invite(&server_id).await.unwrap();
    laptop.device.join_at(&shared.url(), &token, &key).await.unwrap();
    let mut devices = Vec::new();
    for label in ["phone", "tablet", "watch"] {
        let dir = tempfile::tempdir().unwrap();
        let device = laptop.device.link_device(dir.path(), &home.url(), label).await.unwrap();
        devices.push((device, dir));
    }
    let tablet_vk = devices[1].0.verifying_key().await;
    let watch_vk = devices[2].0.verifying_key().await;

    // The phone is off while the laptop removes the tablet, which makes a generation the
    // phone holds a copy of but has not fetched, and then the home goes down.
    assert_eq!(laptop.device.revoke(&tablet_vk).await.unwrap(), RevokeOutcome::Complete);
    home.go_down();
    // Removing the watch waits for the home and says the pause, under that generation.
    assert_eq!(laptop.device.revoke(&watch_vk).await.unwrap(), RevokeOutcome::LogPending);

    let phone = &mut devices[0].0;
    phone.start();
    eventually(RECONNECT_WAIT, "the phone to take in the pause", async || flows::sync::paused(&*phone.client.lock().await)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_server_joined_while_the_home_is_down_reaches_the_other_device_when_it_comes_back() {
    let home = start_switched_relay().await;
    let elsewhere = start_relay().await;
    let bob = Peer::new(&elsewhere.url(), "bob").await;
    let server_id = bob.device.create_server("club").await.unwrap();
    let laptop = Peer::new(&home.url(), "laptop").await;
    let phone_dir = tempfile::tempdir().unwrap();
    let mut phone = laptop.device.link_device(phone_dir.path(), &home.url(), "phone").await.unwrap();
    phone.start();
    let mark = phone.mark();

    // Joining a server on another relay needs nothing from the home.
    home.go_down();
    let bob_mark = bob.device.mark();
    let (token, key) = bob.device.invite(&server_id).await.unwrap();
    laptop.device.join_at(&elsewhere.url(), &token, &key).await.unwrap();
    bob.expect(bob_mark, "the join", server_changed(server_id)).await;
    home.come_back();

    let deadline = tokio::time::Instant::now() + RECONNECT_WAIT;
    while phone.client.lock().await.store().get_server(&server_id).is_err() {
        assert!(tokio::time::Instant::now() < deadline, "the phone never joined the server: {:#?}", phone.events_since(mark));
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn unread_in(device: &Device, server_id: &[u8; 32]) -> u32 {
    device.client.lock().await.store().get_unread_counts(server_id).unwrap_or_default().iter().map(|(_, n)| n).sum()
}

#[tokio::test(flavor = "multi_thread")]
async fn sync_between_devices_carries_on_while_the_home_is_down() {
    let home = start_switched_relay().await;
    let elsewhere = start_relay().await;
    let bob = Peer::new(&elsewhere.url(), "bob").await;
    let server_id = bob.device.create_server("club").await.unwrap();
    let laptop = Peer::new(&home.url(), "laptop").await;
    // A server on another relay makes that relay one of the account's sync relays.
    let bob_mark = bob.device.mark();
    let (token, key) = bob.device.invite(&server_id).await.unwrap();
    laptop.device.join_at(&elsewhere.url(), &token, &key).await.unwrap();
    bob.expect(bob_mark, "the join", server_changed(server_id)).await;
    let phone_dir = tempfile::tempdir().unwrap();
    let mut phone = laptop.device.link_device(phone_dir.path(), &home.url(), "phone").await.unwrap();
    phone.start();
    // A message sealed before Bob has the phone in the group is one the phone cannot read.
    caught_up(&bob.device, &phone, &server_id).await;

    home.go_down();
    let laptop_mark = laptop.device.mark();
    let phone_mark = phone.mark();
    bob.device.say(&server_id, &ghost_core::wire::derive_default_channel_id(&server_id), "hi both").await.unwrap();
    laptop.expect(laptop_mark, "bob's message", message_text("hi both")).await;
    phone.wait_for(phone_mark, EVENT_WAIT, message_text("hi both")).await.expect("the phone got bob's message");
    assert_eq!(unread_in(&phone, &server_id).await, 1);

    // Read on the laptop: the marker reaches the phone through the other relay.
    laptop.device.mark_all_read().await.unwrap();
    eventually(EVENT_WAIT, "the phone to see the laptop's read marker with the home down", async || unread_in(&phone, &server_id).await == 0).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_kick_while_a_device_is_offline_reaches_it_from_sync_with_who_removed_it() {
    let relay = start_relay().await;
    let alice = Peer::new(&relay.url(), "alice").await;
    let bob = Peer::new(&relay.url(), "bob").await;
    let server_id = alice.device.create_server("club").await.unwrap();
    invite_into(&alice, &bob, &server_id).await;
    let phone_dir = tempfile::tempdir().unwrap();
    let mut phone = bob.device.link_device(phone_dir.path(), &relay.url(), "phone").await.unwrap();
    phone.start();
    eventually(EVENT_WAIT, "the phone to join the server", async || phone.client.lock().await.store().get_server(&server_id).is_ok()).await;
    // A kick from behind the phone's join is refused as stale.
    caught_up(&alice.device, &phone, &server_id).await;
    phone.stop().await;

    let bob_mark = bob.device.mark();
    let bob_fp = bob.device.fingerprint().await;
    alice.device.kick(&server_id, &bob_fp).await.unwrap();
    bob.expect(bob_mark, "the kick", support::kicked_from(server_id)).await;

    // Back online, the phone learns from the account's state who removed it.
    phone.start();
    let alice_fp = alice.device.fingerprint().await;
    eventually(EVENT_WAIT, "the phone to learn of the removal", async || {
        phone.client.lock().await.store().server_removal(&server_id).ok().flatten().is_some_and(|r| r.by == Some(alice_fp))
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sync_carries_on_across_a_home_move_and_the_other_device_follows() {
    let old_home = start_relay().await;
    let shared = start_relay().await;
    // The new home advertises an address, as a relay others must reach does.
    let new_home = start_switched_relay().await;
    let bob = Peer::new(&shared.url(), "bob").await;
    let server_id = bob.device.create_server("club").await.unwrap();
    let laptop = Peer::new(&old_home.url(), "laptop").await;
    let bob_mark = bob.device.mark();
    let (token, key) = bob.device.invite(&server_id).await.unwrap();
    laptop.device.join_at(&shared.url(), &token, &key).await.unwrap();
    bob.expect(bob_mark, "the join", server_changed(server_id)).await;
    let phone_dir = tempfile::tempdir().unwrap();
    let mut phone = laptop.device.link_device(phone_dir.path(), &old_home.url(), "phone").await.unwrap();
    phone.start();
    let followed_mark = phone.mark();

    laptop.device.move_home(&new_home.url(), &laptop.recovery_key).await.unwrap();
    assert_eq!(laptop.device.home_url().trim_end_matches('/'), new_home.url().trim_end_matches('/'));

    // The old home refuses the phone now; it reads the log from the shared relay and moves,
    // saying where its home now is, for whoever keeps the address to connect at next time.
    eventually(RECONNECT_WAIT, "the phone to follow the move", async || phone.home_url().trim_end_matches('/') == new_home.url().trim_end_matches('/')).await;
    let followed = phone.wait_for(followed_mark, EVENT_WAIT, |e| match e {
        ClientEvent::HomeFollowed { url } => Some(url.clone()),
        _ => None,
    });
    assert_eq!(followed.await.expect("the phone reported following the move").trim_end_matches('/'), new_home.url().trim_end_matches('/'));

    let phone_mark = phone.mark();
    bob.device.say(&server_id, &ghost_core::wire::derive_default_channel_id(&server_id), "after the move").await.unwrap();
    phone.wait_for(phone_mark, EVENT_WAIT, message_text("after the move")).await.expect("the phone got bob's message");
    laptop.device.mark_all_read().await.unwrap();
    eventually(EVENT_WAIT, "the read marker to reach the phone after the move", async || unread_in(&phone, &server_id).await == 0).await;
}

/// An account in no servers anywhere: no other relay holds its log, so the device that
/// missed the move reads it at the old home, which serves the account's own devices
/// after the move, and follows.
#[tokio::test(flavor = "multi_thread")]
async fn a_device_in_no_servers_follows_a_move_it_missed_through_the_old_home() {
    let old_home = start_relay().await;
    let new_home = start_switched_relay().await;
    let laptop = Peer::new(&old_home.url(), "laptop").await;
    let phone_dir = tempfile::tempdir().unwrap();
    let mut phone = laptop.device.link_device(phone_dir.path(), &old_home.url(), "phone").await.unwrap();

    // The phone is off while the laptop moves the account.
    laptop.device.move_home(&new_home.url(), &laptop.recovery_key).await.unwrap();
    let mark = phone.mark();
    phone.start();
    let followed = phone.wait_for(mark, RECONNECT_WAIT, |e| match e {
        ClientEvent::HomeFollowed { url } => Some(url.clone()),
        _ => None,
    });
    let followed = followed.await.unwrap_or_else(|| panic!("the phone never followed: {:#?}", phone.events_since(mark)));
    assert_eq!(followed.trim_end_matches('/'), new_home.url().trim_end_matches('/'));
}

/// A device the old home still admits, as a member of a server there, gets no refusal
/// to go on: the moving device's announcement sends it after the move at once.
#[tokio::test(flavor = "multi_thread")]
async fn a_device_the_old_home_still_admits_follows_the_move_when_told() {
    let old_home = start_relay().await;
    let new_home = start_switched_relay().await;
    let laptop = Peer::new(&old_home.url(), "laptop").await;
    let server_id = laptop.device.create_server("club").await.unwrap();
    let phone_dir = tempfile::tempdir().unwrap();
    let mut phone = laptop.device.link_device(phone_dir.path(), &old_home.url(), "phone").await.unwrap();
    phone.start();
    // Joined, the phone's start-up account check is long done; the next is minutes away.
    caught_up(&phone, &laptop.device, &server_id).await;
    let followed_mark = phone.mark();

    laptop.device.move_home(&new_home.url(), &laptop.recovery_key).await.unwrap();

    let followed = phone.wait_for(followed_mark, EVENT_WAIT, |e| match e {
        ClientEvent::HomeFollowed { url } => Some(url.clone()),
        _ => None,
    });
    assert_eq!(followed.await.expect("the phone followed the move").trim_end_matches('/'), new_home.url().trim_end_matches('/'));
}

/// A relay that refuses one device as revoked, whatever the log says, and the handle
/// to say which.
async fn start_relay_refusing_devices() -> (ghost_relay::server::RunningRelay, std::sync::Arc<std::sync::RwLock<std::collections::HashSet<[u8; 32]>>>) {
    let config = test_config();
    let refused = config.revoked_devices_for_tests.clone();
    (start_relay_with(config).await, refused)
}

/// `member` joins a server `owner` makes on `owner`'s relay.
async fn join_a_server_at(owner: &Peer, member: &Peer, relay_url: &str) -> [u8; 32] {
    let server_id = owner.device.create_server("club").await.unwrap();
    let (token, key) = owner.device.invite(&server_id).await.unwrap();
    member.device.join_at(relay_url, &token, &key).await.unwrap();
    caught_up(&member.device, &owner.device, &server_id).await;
    server_id
}

fn this_device_removed(e: &ClientEvent) -> Option<()> {
    matches!(e, ClientEvent::Account(AccountAlert::ThisDeviceRemoved { .. })).then_some(())
}

fn relay_refuses_device(url: String) -> impl Fn(&ClientEvent) -> Option<()> {
    move |e| matches!(e, ClientEvent::Account(AccountAlert::RelayRefusesDevice { relay_url }) if *relay_url == url).then_some(())
}

/// One relay's word that this device is revoked is a claim, not the account's verdict:
/// the home denies it, the relay is named, and the device goes on.
#[tokio::test(flavor = "multi_thread")]
async fn a_relay_alone_cannot_make_a_device_give_itself_up() {
    let home = start_relay().await;
    let (elsewhere, refused) = start_relay_refusing_devices().await;
    let mut alice = Peer::new(&home.url(), "alice").await;
    let bob = Peer::new(&elsewhere.url(), "bob").await;
    join_a_server_at(&bob, &alice, &elsewhere.url()).await;

    refused.write().unwrap().insert(alice.device.verifying_key().await);
    alice.device.stop().await;
    let mark = alice.device.mark();
    alice.device.start();
    alice.expect(mark, "the disputed relay", relay_refuses_device(elsewhere.url())).await;
    assert!(alice.device.events_since(mark).iter().all(|e| this_device_removed(e).is_none()), "the device gave itself up on one relay's word");
}

/// While the home is out of reach, two of the servers' relays agreeing count as the
/// account's word; one alone does not, and the home settles it when it is back.
#[tokio::test(flavor = "multi_thread")]
async fn relays_agreeing_while_the_home_is_down_count_as_the_accounts_word() {
    let home = start_switched_relay().await;
    let (first, first_refused) = start_relay_refusing_devices().await;
    let (second, second_refused) = start_relay_refusing_devices().await;
    let mut alice = Peer::new(&home.url(), "alice").await;
    let bob = Peer::new(&first.url(), "bob").await;
    let carol = Peer::new(&second.url(), "carol").await;
    join_a_server_at(&bob, &alice, &first.url()).await;
    join_a_server_at(&carol, &alice, &second.url()).await;
    let alice_vk = alice.device.verifying_key().await;

    // One relay refusing, the home down: nothing is settled, so nothing is shown.
    first_refused.write().unwrap().insert(alice_vk);
    home.go_down();
    alice.device.stop().await;
    let mark = alice.device.mark();
    alice.device.start();
    tokio::time::sleep(EVENT_WAIT).await;
    assert!(alice.device.events_since(mark).iter().all(|e| this_device_removed(e).is_none()), "one relay's word, with the home down, was taken");

    // The home comes back and denies the claim.
    home.come_back();
    assert!(alice.device.wait_for(mark, RECONNECT_WAIT, relay_refuses_device(first.url())).await.is_some(), "the home's denial was not reported");

    // Both relays refusing while the home is down again: the device takes it.
    second_refused.write().unwrap().insert(alice_vk);
    home.go_down();
    alice.device.stop().await;
    let mark = alice.device.mark();
    alice.device.start();
    alice.expect(mark, "the removal", this_device_removed).await;
}
