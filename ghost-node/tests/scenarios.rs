//! Scenarios run through the client's real event loop (`ghost_core::session`), the same
//! loop the desktop app runs: devices are started, stopped and restarted against an
//! in-process relay, and the tests watch the events each device reports.

mod support;

use std::time::Duration;

use ghost_core::flows;
use ghost_core::storage::ChannelKind;
use ghost_core::wire::derive_default_channel_id;
use ghost_wire::policy::Role;
use support::{invite_into, kicked_from, message_text, server_changed, start_relay, Peer, EVENT_WAIT};

#[tokio::test]
async fn messages_reach_a_running_device() {
    let relay = start_relay().await;
    let alice = Peer::new(&relay.url(), "alice").await;
    let bob = Peer::new(&relay.url(), "bob").await;
    let server_id = alice.device.create_server("club").await.unwrap();
    invite_into(&alice, &bob, &server_id).await;
    let general = derive_default_channel_id(&server_id);

    let mark = alice.device.mark();
    bob.device.say(&server_id, &general, "hello alice").await.unwrap();
    alice.expect(mark, "Bob's message", message_text("hello alice")).await;
}

#[tokio::test]
async fn kicked_devices_learn_it_online_and_after_coming_back() {
    let relay = start_relay().await;
    let alice = Peer::new(&relay.url(), "alice").await;
    let bob = Peer::new(&relay.url(), "bob").await;
    let mut carol = Peer::new(&relay.url(), "carol").await;
    let server_id = alice.device.create_server("club").await.unwrap();
    invite_into(&alice, &bob, &server_id).await;
    invite_into(&alice, &carol, &server_id).await;

    // Bob is online when he is kicked.
    let mark = bob.device.mark();
    assert!(alice.device.kick(&server_id, &bob.device.fingerprint().await).await.unwrap());
    bob.expect(mark, "being kicked", kicked_from(server_id)).await;

    // Carol is offline when she is kicked and learns it on reconnecting: the relay lets
    // her read up to the commit that removed her.
    carol.device.stop().await;
    assert!(alice.device.kick(&server_id, &carol.device.fingerprint().await).await.unwrap());
    let mark = carol.device.mark();
    carol.device.start();
    carol.expect(mark, "being kicked while offline", kicked_from(server_id)).await;
}

#[tokio::test]
async fn a_device_rejoins_after_missing_more_than_the_relay_kept() {
    let relay = start_relay().await;
    let alice = Peer::new(&relay.url(), "alice").await;
    let mut bob = Peer::new(&relay.url(), "bob").await;
    let server_id = alice.device.create_server("club").await.unwrap();
    invite_into(&alice, &bob, &server_id).await;
    let general = derive_default_channel_id(&server_id);

    // While Bob is away, the group moves on and the relay drops everything he missed.
    bob.device.stop().await;
    let carol = Peer::new(&relay.url(), "carol").await;
    invite_into(&alice, &carol, &server_id).await;
    alice.device.say(&server_id, &general, "while bob was away").await.unwrap();
    let swept = relay.state.storage.sweep_log(flows::now_millis() + 3_600_000, 0).unwrap();
    assert!(swept > 0, "the relay kept everything");

    // Bob comes back past the gap, rejoins the group, and takes part again.
    let mark = alice.device.mark();
    bob.device.start();
    alice.expect(mark, "Bob's rejoin", server_changed(server_id)).await;
    let mark = alice.device.mark();
    bob.device.say(&server_id, &general, "bob is back").await.unwrap();
    alice.expect(mark, "Bob's message after rejoining", message_text("bob is back")).await;
    let mark = bob.device.mark();
    alice.device.say(&server_id, &general, "welcome back").await.unwrap();
    bob.expect(mark, "Alice's message after rejoining", message_text("welcome back")).await;
}

/// Wait until `check` holds, polling device state the loop updates.
async fn eventually(what: &str, mut check: impl AsyncFnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + EVENT_WAIT;
    while !check().await {
        assert!(tokio::time::Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn private_channels_are_joined_named_and_left_by_the_running_loops() {
    let relay = start_relay().await;
    let alice = Peer::new(&relay.url(), "alice").await;
    let bob = Peer::new(&relay.url(), "bob").await;
    let carol = Peer::new(&relay.url(), "carol").await;
    let server_id = alice.device.create_server("club").await.unwrap();
    invite_into(&alice, &bob, &server_id).await;
    invite_into(&alice, &carol, &server_id).await;
    let (a, b) = (&alice.device, &bob.device);
    let bob_fp = b.fingerprint().await;

    // A "staff" channel for a role only Bob holds.
    let mut policy = a.client.lock().await.server_policy(&server_id).unwrap();
    policy.roles.push(Role { id: 1, permissions: 0 });
    policy.assignments.push((bob_fp, vec![1]));
    flows::roles::set_server_policy(&a.client, &a.relay, &server_id, &policy).await.unwrap();
    let channel_id = flows::channels::create_private(&a.client, &a.relay, &a.relay, &server_id, "staff", ChannelKind::Text, vec![1], vec![])
        .await
        .unwrap();

    // Bob's loop joins it when the relay signals him, and learns its name from Alice's loop.
    eventually("Bob to learn the channel's name", async || {
        b.client.lock().await.store().get_channel(&channel_id).is_ok_and(|c| c.name == "staff")
    })
    .await;
    // Carol, without the role, never learns of it.
    assert!(carol.device.client.lock().await.store().get_channel(&channel_id).is_err());

    let mark = b.mark();
    a.say(&server_id, &channel_id, "staff only").await.unwrap();
    bob.expect(mark, "the channel message", message_text("staff only")).await;

    // Bob loses the role: the relay proposes his removal, Alice's loop commits it, and
    // Bob's device forgets the channel.
    policy.assignments.retain(|(account, _)| *account != bob_fp);
    flows::roles::set_server_policy(&a.client, &a.relay, &server_id, &policy).await.unwrap();
    eventually("Bob to lose the channel", async || b.client.lock().await.store().get_channel(&channel_id).is_err()).await;
}
