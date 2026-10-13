//! Scenarios run through the client's real event loop (`ghost_core::session`), the same
//! loop the desktop app runs: devices are started, stopped and restarted against an
//! in-process relay, and the tests watch the events each device reports.

mod support;

use std::time::Duration;

use ghost_core::account_keys::RecoveryKey;
use ghost_core::mls::presence::OnlineStatus;
use ghost_core::error::GhostError;
use ghost_core::flows;
use ghost_core::flows::devices::RevokeOutcome;
use ghost_core::flows::recovery::SnapshotRestore;
use ghost_wire::RevocationCause;
use ghost_core::storage::ChannelKind;
use ghost_core::wire::derive_default_channel_id;
use ghost_wire::policy::{Role, MANAGE_CHANNELS};
use ghost_core::session::{AccountAlert, ClientEvent};
use ghost_core::voice::VoiceEvent;
use ghost_node::Device;
use support::{caught_up, epoch_of, eventually, invite_into, kicked_from, message_text, server_changed, start_relay, start_relay_that_skips_policy_checks, start_relay_with, test_config, Peer, EVENT_WAIT};

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
async fn a_dm_is_named_after_the_other_person_on_each_side() {
    let relay = start_relay().await;
    let alice = Peer::new(&relay.url(), "alice").await;
    let bob = Peer::new(&relay.url(), "bob").await;
    // The DM's own name is what its creator typed, which both sides share.
    let dm = alice.device.create_dm("bobby").await.unwrap();
    invite_into(&alice, &bob, &dm).await;
    let named = |peer: &Peer| {
        let client = peer.device.client.clone();
        async move {
            let client = client.lock().await;
            client.server_display_name(&client.store().get_server(&dm).unwrap())
        }
    };
    assert_eq!(named(&bob).await, "alice");
    let deadline = tokio::time::Instant::now() + EVENT_WAIT;
    while named(&alice).await != "bob" {
        assert!(tokio::time::Instant::now() < deadline, "alice's DM never took bob's name");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
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
    alice.device.kick(&server_id, &bob.device.fingerprint().await).await.unwrap();
    bob.expect(mark, "being kicked", kicked_from(server_id)).await;

    // Carol is offline when she is kicked and learns it on reconnecting: the relay lets
    // her read up to the commit that removed her.
    carol.device.stop().await;
    alice.device.kick(&server_id, &carol.device.fingerprint().await).await.unwrap();
    let mark = carol.device.mark();
    carol.device.start();
    carol.expect(mark, "being kicked while offline", kicked_from(server_id)).await;

    // Both keep the server, read-only, knowing who removed them.
    let alice_fp = alice.device.fingerprint().await;
    for peer in [&bob, &carol] {
        let removal = peer.device.client.lock().await.removed_from(&server_id).unwrap();
        assert_eq!(removal.map(|r| r.by), Some(Some(alice_fp)), "{} sees who removed them", peer.name);
    }
}

/// A device kicked while it was away for longer than the relay keeps history never sees
/// the removing commit; the relay's refusal tells it instead, and the server stays,
/// read-only, with nothing more read from it.
#[tokio::test]
async fn a_device_kicked_while_away_past_retention_learns_it_on_coming_back() {
    let relay = start_relay().await;
    let alice = Peer::new(&relay.url(), "alice").await;
    let mut bob = Peer::new(&relay.url(), "bob").await;
    let server_id = alice.device.create_server("club").await.unwrap();
    invite_into(&alice, &bob, &server_id).await;
    let general = derive_default_channel_id(&server_id);

    bob.device.stop().await;
    let bob_fp = bob.device.fingerprint().await;
    alice.device.kick(&server_id, &bob_fp).await.unwrap();
    alice.device.say(&server_id, &general, "after the kick").await.unwrap();
    let swept = relay.state.storage.sweep_log(flows::now_millis() + 3_600_000, 0).await.unwrap();
    assert!(swept > 0, "the relay kept everything");

    let mark = bob.device.mark();
    bob.device.start();
    bob.expect(mark, "being kicked past retention", kicked_from(server_id)).await;
    let c = bob.device.client.lock().await;
    let removal = c.removed_from(&server_id).unwrap().expect("the server is marked removed");
    assert_eq!(removal.by, None, "nobody is named: the removing commit was gone");
    let mailbox = c.mailbox_id_for_server(&server_id).unwrap();
    assert!(!bob.device.relay.is_subscribed_at(&relay.url(), &mailbox), "the removed server is still read");
}

#[tokio::test]
async fn a_kicked_account_stays_out_until_someone_lets_it_back() {
    let relay = start_relay().await;
    let alice = Peer::new(&relay.url(), "alice").await;
    let bob = Peer::new(&relay.url(), "bob").await;
    let server_id = alice.device.create_server("club").await.unwrap();
    invite_into(&alice, &bob, &server_id).await;
    let bob_fp = bob.device.fingerprint().await;

    let mark = bob.device.mark();
    alice.device.kick(&server_id, &bob_fp).await.unwrap();
    bob.expect(mark, "being kicked", kicked_from(server_id)).await;

    // A fresh, valid invite does not bring him back, and his read-only copy stays.
    let (token, key) = alice.device.invite(&server_id).await.unwrap();
    assert!(matches!(bob.device.join(&token, &key).await, Err(GhostError::RemovedFromServer)));
    assert!(bob.device.client.lock().await.removed_from(&server_id).unwrap().is_some());

    // Once let back in, an invite works again and the server is his to use.
    alice.device.let_back_in(&server_id, &bob_fp).await.unwrap();
    invite_into(&alice, &bob, &server_id).await;
    assert!(bob.device.client.lock().await.removed_from(&server_id).unwrap().is_none());
    let general = derive_default_channel_id(&server_id);
    let mark = alice.device.mark();
    bob.device.say(&server_id, &general, "back again").await.unwrap();
    alice.expect(mark, "Bob's message after rejoining", message_text("back again")).await;
}

#[tokio::test]
async fn a_kick_takes_the_members_roles_with_them() {
    let relay = start_relay().await;
    let alice = Peer::new(&relay.url(), "alice").await;
    let bob = Peer::new(&relay.url(), "bob").await;
    let server_id = alice.device.create_server("club").await.unwrap();
    invite_into(&alice, &bob, &server_id).await;
    let bob_fp = bob.device.fingerprint().await;
    alice.device.add_role(&server_id, "moderator", ghost_wire::policy::KICK, &[bob_fp]).await.unwrap();

    alice.device.kick(&server_id, &bob_fp).await.unwrap();
    let policy = alice.device.client.lock().await.server_policy(&server_id).unwrap();
    assert!(policy.roles_of(&bob_fp).is_empty(), "a returning member never quietly regains a role");
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
    let swept = relay.state.storage.sweep_log(flows::now_millis() + 3_600_000, 0).await.unwrap();
    assert!(swept > 0, "the relay kept everything");

    // Bob comes back past the gap, rejoins the group, and takes part again. His history
    // marks where it skips what the relay no longer kept.
    let before = epoch_of(&bob.device, &server_id).await;
    bob.device.start();
    eventually(EVENT_WAIT, "Bob's rejoin", async || epoch_of(&bob.device, &server_id).await > before).await;
    caught_up(&alice.device, &bob.device, &server_id).await;
    let gaps = bob
        .device
        .client
        .lock()
        .await
        .store()
        .get_messages(&general, None, 100)
        .unwrap()
        .into_iter()
        .filter(|m| m.message_type == ghost_core::crypto::MessageType::HistoryGap as u8)
        .count();
    assert_eq!(gaps, 1, "the gap is marked once in Bob's history");
    let mark = alice.device.mark();
    bob.device.say(&server_id, &general, "bob is back").await.unwrap();
    alice.expect(mark, "Bob's message after rejoining", message_text("bob is back")).await;
    let mark = bob.device.mark();
    alice.device.say(&server_id, &general, "welcome back").await.unwrap();
    bob.expect(mark, "Alice's message after rejoining", message_text("welcome back")).await;
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
    eventually(EVENT_WAIT, "Bob to learn the channel's name", async || {
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
    eventually(EVENT_WAIT, "Bob to lose the channel", async || b.client.lock().await.store().get_channel(&channel_id).is_err()).await;
}

/// Members a new channel admits are told of it together, so all their joins but the
/// first lose to an earlier one; each is told again once any member's GroupInfo makes
/// the channel joinable at the epoch the winner made. The server's owner is away, so
/// nothing waits on her device.
#[tokio::test]
async fn members_a_new_channel_admits_together_all_get_in_with_the_owner_away() {
    let relay = start_relay().await;
    let mut alice = Peer::new(&relay.url(), "alice").await;
    let bob = Peer::new(&relay.url(), "bob").await;
    let carol = Peer::new(&relay.url(), "carol").await;
    let dave = Peer::new(&relay.url(), "dave").await;
    let server_id = alice.device.create_server("club").await.unwrap();
    for member in [&bob, &carol, &dave] {
        invite_into(&alice, member, &server_id).await;
    }
    let (b, c, d) = (&bob.device, &carol.device, &dave.device);

    // Bob manages channels; Carol and Dave hold the role his channel is for.
    let a = &alice.device;
    let mut policy = a.client.lock().await.server_policy(&server_id).unwrap();
    policy.roles.push(Role { id: 1, permissions: MANAGE_CHANNELS });
    policy.roles.push(Role { id: 2, permissions: 0 });
    policy.assignments.push((b.fingerprint().await, vec![1]));
    policy.assignments.push((c.fingerprint().await, vec![2]));
    policy.assignments.push((d.fingerprint().await, vec![2]));
    flows::roles::set_server_policy(&a.client, &a.relay, &server_id, &policy).await.unwrap();
    for member in [b, c, d] {
        caught_up(member, a, &server_id).await;
    }
    alice.device.stop().await;

    let channel_id = flows::channels::create_private(&b.client, &b.relay, &b.relay, &server_id, "staff", ChannelKind::Text, vec![2], vec![])
        .await
        .unwrap();
    eventually(EVENT_WAIT, "Carol and Dave to enter the channel", async || {
        c.client.lock().await.store().get_channel(&channel_id).is_ok() && d.client.lock().await.store().get_channel(&channel_id).is_ok()
    })
    .await;
}

/// The relay tells only live connections that a channel can be joined; a device whose
/// connection was down then looks again once it is back.
#[tokio::test(flavor = "multi_thread")]
async fn a_channel_made_while_a_member_was_disconnected_is_joined_once_it_is_back() {
    let relay = support::start_switched_relay().await;
    let alice = Peer::new(&relay.url(), "alice").await;
    let bob = Peer::new(&relay.url(), "bob").await;
    let server_id = alice.device.create_server("club").await.unwrap();
    invite_into(&alice, &bob, &server_id).await;
    let (a, b) = (&alice.device, &bob.device);
    let mut policy = a.client.lock().await.server_policy(&server_id).unwrap();
    policy.roles.push(Role { id: 1, permissions: 0 });
    policy.assignments.push((b.fingerprint().await, vec![1]));
    flows::roles::set_server_policy(&a.client, &a.relay, &server_id, &policy).await.unwrap();
    caught_up(b, a, &server_id).await;

    // The channel reaches the relay while every connection is down, so nobody hears of it.
    relay.go_down();
    let created = a.client.lock().await.create_private_channel(&server_id, "staff", ChannelKind::Text, 1, vec![1], vec![]).unwrap();
    assert!(relay.relay.state.init_public_group(created.mailbox_id, created.group_info, a.fingerprint().await).await.unwrap());
    relay.come_back();
    eventually(EVENT_WAIT, "Bob to enter the channel", async || b.client.lock().await.store().get_channel(&created.channel_id).is_ok()).await;
}

async fn channel_name(device: &Device, channel_id: &[u8; 32]) -> Option<String> {
    device.client.lock().await.store().get_channel(channel_id).ok().map(|c| c.name)
}

/// A manager's channel changes reach another member's running loop, and exist on the
/// manager's device once the relay took them.
#[tokio::test]
async fn channel_changes_reach_a_member_through_the_running_loops() {
    let relay = start_relay().await;
    let alice = Peer::new(&relay.url(), "alice").await;
    let bob = Peer::new(&relay.url(), "bob").await;
    let server_id = alice.device.create_server("club").await.unwrap();
    invite_into(&alice, &bob, &server_id).await;
    let (a, b) = (&alice.device, &bob.device);

    let news = a.create_channel(&server_id, "news", ChannelKind::Text).await.unwrap();
    assert_eq!(channel_name(a, &news).await.as_deref(), Some("news"));
    eventually(EVENT_WAIT, "Bob to see the new channel", async || channel_name(b, &news).await.as_deref() == Some("news")).await;

    flows::channels::rename(&a.client, &a.relay, &news, "updates").await.unwrap();
    eventually(EVENT_WAIT, "Bob to see the rename", async || channel_name(b, &news).await.as_deref() == Some("updates")).await;

    flows::channels::delete(&a.client, &a.relay, &news).await.unwrap();
    assert_eq!(channel_name(a, &news).await, None);
    eventually(EVENT_WAIT, "Bob to lose the channel", async || channel_name(b, &news).await.is_none()).await;
}

/// Metadata of a kind this app does not know, as a newer app might send, is marked seen
/// when read: a restart does not read it again, where it could only stand in.
#[tokio::test]
async fn metadata_this_app_does_not_know_is_marked_seen_and_never_stands_in() {
    let relay = start_relay().await;
    let alice = Peer::new(&relay.url(), "alice").await;
    let mut bob = Peer::new(&relay.url(), "bob").await;
    let server_id = alice.device.create_server("club").await.unwrap();
    invite_into(&alice, &bob, &server_id).await;
    let general = derive_default_channel_id(&server_id);
    caught_up(&bob.device, &alice.device, &server_id).await;

    let unknown = alice.device.client.lock().await.send_control(&server_id, vec![0xEE, 1, 2]).unwrap();
    let posted = alice.device.relay.post_blob(&unknown.mailbox_id, unknown.blob).await.unwrap();
    eventually(EVENT_WAIT, "Bob to mark the unknown metadata seen", async || {
        bob.device.client.lock().await.store().get_last_seen_seq(&unknown.mailbox_id).unwrap_or(0) >= posted.seq
    })
    .await;

    bob.device.stop().await;
    bob.device.start();
    let mark = bob.device.mark();
    alice.device.say(&server_id, &general, "after the restart").await.unwrap();
    bob.expect(mark, "the message after the restart", message_text("after the restart")).await;
    let stand_ins = bob
        .device
        .client
        .lock()
        .await
        .store()
        .get_messages(&general, None, 100)
        .unwrap()
        .into_iter()
        .filter(|m| m.message_type == ghost_core::crypto::MessageType::Undecryptable as u8)
        .count();
    assert_eq!(stand_ins, 0, "the unknown metadata was read again and stood in");
}

async fn member_name(device: &Device, server_id: &[u8; 32], fingerprint: &[u8; 32]) -> Option<String> {
    let members = device.client.lock().await.store().list_members(server_id).ok()?;
    members.into_iter().find(|m| m.fingerprint == *fingerprint).map(|m| m.display_name)
}

/// A joiner through an invite made before the server changed gets the server as it is:
/// a channel made and one renamed since, a role named since, and a member who joined
/// since, named, from the owner's running loop.
#[tokio::test]
async fn a_joiner_gets_the_server_as_it_is_not_as_the_invite_had_it() {
    let relay = start_relay().await;
    let alice = Peer::new(&relay.url(), "alice").await;
    let bob = Peer::new(&relay.url(), "bob").await;
    let carol = Peer::new(&relay.url(), "carol").await;
    let server_id = alice.device.create_server("club").await.unwrap();
    let general = derive_default_channel_id(&server_id);
    let (token, key) = alice.device.invite(&server_id).await.unwrap();

    let news = alice.device.create_channel(&server_id, "news", ChannelKind::Text).await.unwrap();
    flows::channels::rename(&alice.device.client, &alice.device.relay, &general, "lobby").await.unwrap();
    let staff = alice.device.add_role(&server_id, "staff", 0, &[]).await.unwrap();
    invite_into(&alice, &bob, &server_id).await;
    let bob_fp = bob.device.fingerprint().await;
    eventually(EVENT_WAIT, "Alice to learn Bob's name", async || member_name(&alice.device, &server_id, &bob_fp).await.as_deref() == Some("bob")).await;

    carol.device.join(&token, &key).await.unwrap();
    let c = &carol.device;
    eventually(EVENT_WAIT, "Carol to get the server as it is", async || {
        channel_name(c, &news).await.as_deref() == Some("news")
            && channel_name(c, &general).await.as_deref() == Some("lobby")
            && c.client.lock().await.store().list_role_names(&server_id).unwrap_or_default().contains(&(staff, "staff".to_string()))
            && member_name(c, &server_id, &bob_fp).await.as_deref() == Some("bob")
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_device_at_home_on_another_relay_joins_a_server_and_its_call() {
    let (hosting, other) = (start_relay().await, start_relay().await);
    let alice = Peer::new(&hosting.url(), "alice").await;
    let bob = Peer::new(&other.url(), "bob").await;
    let server = alice.device.create_server("club").await.unwrap();
    let mark = alice.device.mark();
    let (token, key) = alice.device.invite(&server).await.unwrap();
    bob.device.join_at(&hosting.url(), &token, &key).await.unwrap();
    alice.expect(mark, "the join", server_changed(server)).await;

    let general = derive_default_channel_id(&server);
    let bob_mark = bob.device.mark();
    alice.device.say(&server, &general, "over here").await.unwrap();
    bob.expect(bob_mark, "alice's message", message_text("over here")).await;

    // The call runs on the hosting relay, whichever relay each caller calls home.
    let in_call = |fingerprint: [u8; 32]| {
        move |e: &ClientEvent| match e {
            ClientEvent::Voice(VoiceEvent::Participants(everyone)) if everyone.contains(&fingerprint) => Some(()),
            _ => None,
        }
    };
    let (alice_mark, bob_mark) = (alice.device.mark(), bob.device.mark());
    alice.device.voice().join(server, general, false, false).await.unwrap();
    bob.device.voice().join(server, general, false, false).await.unwrap();
    alice.expect(alice_mark, "bob in the call", in_call(bob.device.fingerprint().await)).await;
    bob.expect(bob_mark, "alice in the call", in_call(alice.device.fingerprint().await)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_linked_device_in_its_own_folder_is_the_same_account_in_the_same_servers() {
    let relay = start_relay().await;
    let alice = Peer::new(&relay.url(), "alice").await;
    let server = alice.device.create_server("club").await.unwrap();
    let folder = tempfile::tempdir().unwrap();
    let laptop = alice.device.link_device(folder.path(), &relay.url(), "laptop").await.unwrap();
    assert_eq!(laptop.fingerprint().await, alice.device.fingerprint().await);
    assert!(laptop.client.lock().await.store().get_server(&server).is_ok(), "the provision brought the server");

    drop(laptop);
    let reopened = Device::open(folder.path(), &relay.url()).unwrap();
    assert!(reopened.client.lock().await.store().get_server(&server).is_ok(), "kept in its folder");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_running_device_hears_when_another_device_of_its_account_links_one() {
    let relay = start_relay().await;
    let alice = Peer::new(&relay.url(), "alice").await;
    let phone_dir = tempfile::tempdir().unwrap();
    let mut phone = alice.device.link_device(phone_dir.path(), &relay.url(), "phone").await.unwrap();
    phone.start();

    // Alice's first device links a laptop; the phone did not, so it is told.
    let mark = phone.mark();
    let laptop_dir = tempfile::tempdir().unwrap();
    let _laptop = alice.device.link_device(laptop_dir.path(), &relay.url(), "laptop").await.unwrap();
    let linked = phone
        .wait_for(mark, EVENT_WAIT, |e| match e {
            ClientEvent::Account(AccountAlert::DeviceLinked { label }) => Some(label.clone()),
            _ => None,
        })
        .await;
    assert_eq!(linked.as_deref(), Some("laptop"), "the phone reported: {:#?}", phone.events_since(mark));
}

fn this_device_removed(e: &ClientEvent) -> Option<Option<RevocationCause>> {
    match e {
        ClientEvent::Account(AccountAlert::ThisDeviceRemoved { cause }) => Some(cause.clone()),
        _ => None,
    }
}

/// One device removing another: the removed device hears which device did it, a third
/// hears which device went and who removed it, and the one that did it is not told.
#[tokio::test(flavor = "multi_thread")]
async fn a_removal_names_who_did_it_to_the_removed_device_and_the_others() {
    let relay = start_relay().await;
    let alice = Peer::new(&relay.url(), "alice").await;
    let phone_dir = tempfile::tempdir().unwrap();
    let mut phone = alice.device.link_device(phone_dir.path(), &relay.url(), "phone").await.unwrap();
    phone.start();
    let laptop_dir = tempfile::tempdir().unwrap();
    let mut laptop = alice.device.link_device(laptop_dir.path(), &relay.url(), "laptop").await.unwrap();
    laptop.start();
    let phone_vk = phone.verifying_key().await;

    let (alice_mark, phone_mark, laptop_mark) = (alice.device.mark(), phone.mark(), laptop.mark());
    assert_eq!(alice.device.revoke(&phone_vk).await.unwrap(), RevokeOutcome::Complete);

    let cause = phone.wait_for(phone_mark, EVENT_WAIT, this_device_removed).await;
    assert_eq!(cause, Some(Some(RevocationCause::Device("alice".into()))), "the phone reported: {:#?}", phone.events_since(phone_mark));
    let told = laptop
        .wait_for(laptop_mark, EVENT_WAIT, |e| match e {
            ClientEvent::Account(AccountAlert::DeviceRemoved { label, by }) => Some((label.clone(), by.clone())),
            _ => None,
        })
        .await;
    assert_eq!(told, Some(("phone".to_string(), RevocationCause::Device("alice".into()))), "the laptop reported: {:#?}", laptop.events_since(laptop_mark));
    assert!(
        !alice.device.events_since(alice_mark).iter().any(|e| matches!(e, ClientEvent::Account(AccountAlert::DeviceRemoved { .. }))),
        "the device that removed it was told"
    );
}

/// A recovery on a new device: a running old device hears the account was recovered,
/// not that another device removed it, and the recovered device has the account's
/// servers back.
#[tokio::test(flavor = "multi_thread")]
async fn an_old_device_hears_the_account_was_recovered_elsewhere() {
    let relay = start_relay().await;
    let alice = Peer::new(&relay.url(), "alice").await;
    let bob = Peer::new(&relay.url(), "bob").await;
    let server_id = bob.device.create_server("club").await.unwrap();
    invite_into(&bob, &alice, &server_id).await;
    flows::sync::push_snapshot(&alice.device.client, &alice.device.relay).await;

    let mark = alice.device.mark();
    let new_dir = tempfile::tempdir().unwrap();
    let (recovered, restore) = Device::recover(new_dir.path(), &relay.url(), &alice.recovery_key, &RecoveryKey::generate(), "new laptop").await.unwrap();
    assert_eq!(restore, SnapshotRestore::Restored);
    assert!(recovered.client.lock().await.store().get_server(&server_id).is_ok(), "the recovered device rejoined the server");

    let cause = alice.expect(mark, "its removal", this_device_removed).await;
    assert_eq!(cause, Some(RevocationCause::Recovery));
}

/// Who a device reports online in the server, by account, once it names everyone in `who`.
fn everyone_online(server_id: [u8; 32], who: Vec<[u8; 32]>) -> impl Fn(&ClientEvent) -> Option<()> {
    move |e| match e {
        ClientEvent::OnlinePresence { server_id: sid, members } if *sid == server_id => who
            .iter()
            .all(|fp| members.iter().any(|m| m.fingerprint == *fp && m.status == OnlineStatus::Online))
            .then_some(()),
        _ => None,
    }
}

#[tokio::test]
async fn members_show_online_while_running_and_again_after_everyone_restarts() {
    let relay = start_relay().await;
    let mut alice = Peer::new(&relay.url(), "alice").await;
    let mut bob = Peer::new(&relay.url(), "bob").await;
    let mut carol = Peer::new(&relay.url(), "carol").await;
    let server_id = alice.device.create_server("club").await.unwrap();
    let mark = alice.device.mark();
    invite_into(&alice, &bob, &server_id).await;
    invite_into(&alice, &carol, &server_id).await;
    let (bob_fp, carol_fp) = (bob.device.fingerprint().await, carol.device.fingerprint().await);
    let alice_fp = alice.device.fingerprint().await;

    // Joining members announce themselves; the owner sees both online.
    alice.expect(mark, "bob and carol online", everyone_online(server_id, vec![bob_fp, carol_fp])).await;
    caught_up(&bob.device, &alice.device, &server_id).await;
    caught_up(&carol.device, &alice.device, &server_id).await;

    // Everyone goes away and comes back, as a seeded world's apps open on their folders.
    for peer in [&mut alice, &mut bob, &mut carol] {
        peer.device.stop().await;
    }
    let marks = [alice.device.mark(), bob.device.mark(), carol.device.mark()];
    for peer in [&mut alice, &mut bob, &mut carol] {
        peer.device.start();
    }
    alice.expect(marks[0], "bob and carol online again", everyone_online(server_id, vec![bob_fp, carol_fp])).await;
    bob.expect(marks[1], "alice and carol online again", everyone_online(server_id, vec![alice_fp, carol_fp])).await;
    carol.expect(marks[2], "alice and bob online again", everyone_online(server_id, vec![alice_fp, bob_fp])).await;
}

/// An online presence report for the server without `who` in it.
fn gone_offline(server_id: [u8; 32], who: [u8; 32]) -> impl Fn(&ClientEvent) -> Option<()> {
    move |e| match e {
        ClientEvent::OnlinePresence { server_id: sid, members } if *sid == server_id => {
            (!members.iter().any(|m| m.fingerprint == who)).then_some(())
        }
        _ => None,
    }
}

#[tokio::test]
async fn a_short_drop_shows_no_one_offline_but_a_long_one_does() {
    let relay = start_relay().await;
    let alice = Peer::new(&relay.url(), "alice").await;
    let mut bob = Peer::new(&relay.url(), "bob").await;
    let server_id = alice.device.create_server("club").await.unwrap();
    let mark = alice.device.mark();
    invite_into(&alice, &bob, &server_id).await;
    let bob_fp = bob.device.fingerprint().await;
    alice.expect(mark, "bob online", everyone_online(server_id, vec![bob_fp])).await;

    // Connections answer the relay's pings (one a second here): nothing drops.
    let mark = alice.device.mark();
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(alice.device.events_since(mark).iter().all(|e| gone_offline(server_id, bob_fp)(e).is_none()), "bob stayed online");

    // Bob drops without a word and is back within the grace: nobody saw him go.
    let mark = alice.device.mark();
    bob.device.cut_off().await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    bob.device.start();
    alice.expect(mark, "bob announcing himself again", everyone_online(server_id, vec![bob_fp])).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(alice.device.events_since(mark).iter().all(|e| gone_offline(server_id, bob_fp)(e).is_none()), "bob never showed offline");

    // Gone for longer than the grace, he shows offline.
    let mark = alice.device.mark();
    bob.device.cut_off().await;
    alice.expect(mark, "bob offline", gone_offline(server_id, bob_fp)).await;
}

/// Going offline on purpose closes the connections: the relay shows the device offline
/// at once, without waiting out the grace it gives a dropped connection.
#[tokio::test]
async fn going_offline_on_purpose_shows_offline_at_once() {
    let relay = start_relay_with(ghost_relay::config::Config { presence_grace_secs: 60, ..test_config() }).await;
    let alice = Peer::new(&relay.url(), "alice").await;
    let mut bob = Peer::new(&relay.url(), "bob").await;
    let server_id = alice.device.create_server("club").await.unwrap();
    let mark = alice.device.mark();
    invite_into(&alice, &bob, &server_id).await;
    let bob_fp = bob.device.fingerprint().await;
    alice.expect(mark, "bob online", everyone_online(server_id, vec![bob_fp])).await;

    let mark = alice.device.mark();
    bob.device.stop().await;
    alice.expect(mark, "bob offline well within the grace", gone_offline(server_id, bob_fp)).await;
}

/// A member whose rules refuse a change the relay accepted keeps its copy, read-only,
/// until it accepts the relay's version or the server moves.
#[tokio::test]
async fn a_change_the_rules_forbid_halts_the_server_until_the_person_decides() {
    let relay = start_relay_that_skips_policy_checks().await;
    let alice = Peer::new(&relay.url(), "alice").await;
    let bob = Peer::new(&relay.url(), "bob").await;
    let carol = Peer::new(&relay.url(), "carol").await;
    let server_id = alice.device.create_server("club").await.unwrap();
    invite_into(&alice, &bob, &server_id).await;
    invite_into(&alice, &carol, &server_id).await;
    caught_up(&bob.device, &alice.device, &server_id).await;
    caught_up(&carol.device, &alice.device, &server_id).await;

    // Bob may not kick, but the relay takes his forged removal of Carol anyway.
    let carol_vk = carol.device.verifying_key().await;
    let carol_fp = carol.device.fingerprint().await;
    let mark = alice.device.mark();
    let forged = {
        let mut c = bob.device.client.lock().await;
        let channel = derive_default_channel_id(&server_id);
        let leaves = c.find_device_leaves(&channel, &carol_vk);
        c.remove_channel_members(&channel, &leaves).unwrap()
    };
    let mailbox = alice.device.client.lock().await.mailbox_id_for_server(&server_id).unwrap();
    bob.device.relay.post_blob(&mailbox, forged).await.unwrap();
    bob.device.client.lock().await.merge_pending_commit_for_channel(&derive_default_channel_id(&server_id)).unwrap();
    flows::publish_server_info(&bob.device.client, &bob.device.relay, &mailbox).await;

    // Alice's device refuses it: the server halts, Carol stays a member here, nothing is sent.
    alice.expect(mark, "the halt", |e| matches!(e, ClientEvent::ServerHalted { server_id: id, .. } if *id == server_id).then_some(())).await;
    {
        let c = alice.device.client.lock().await;
        assert!(c.halt(&server_id).unwrap().is_some());
        assert!(c.store().list_members(&server_id).unwrap().iter().any(|m| m.fingerprint == carol_fp), "Carol was dropped");
    }
    let general = derive_default_channel_id(&server_id);
    let refused = alice.device.say(&server_id, &general, "still here?").await;
    assert!(matches!(refused, Err(GhostError::PolicyRefused(_))), "{refused:?}");

    // Alice accepts the relay's version: the server follows the relay again, Carol is gone.
    alice.device.accept_relay_state(&server_id).await.unwrap();
    {
        let c = alice.device.client.lock().await;
        assert!(c.halt(&server_id).unwrap().is_none());
        assert!(!c.mls_member_fingerprints(&server_id).unwrap().contains(&carol_fp), "Carol is still in the group");
    }
    alice.device.say(&server_id, &general, "back").await.unwrap();
}

/// A name change a server's relay missed is owed to the server and told the moment its
/// mailbox connects again.
#[tokio::test(flavor = "multi_thread")]
async fn a_name_change_a_server_missed_reaches_it_once_it_is_back() {
    let relay = support::start_switched_relay().await;
    let alice = Peer::new(&relay.url(), "alice").await;
    let bob = Peer::new(&relay.url(), "bob").await;
    let server_id = alice.device.create_server("club").await.unwrap();
    invite_into(&alice, &bob, &server_id).await;
    let alice_fp = alice.device.fingerprint().await;

    relay.go_down();
    let reach = alice.device.set_name("Alicia").await.unwrap();
    assert_eq!((reach.reached, reach.servers), (0, 1), "the server's relay was down");
    relay.come_back();
    eventually(EVENT_WAIT, "bob to see alice's new name", async || {
        bob.device.client.lock().await.store().get_member(&server_id, &alice_fp).is_ok_and(|m| m.display_name == "Alicia")
    })
    .await;
    // Told first, then marked told: the mark may come a moment after Bob has it.
    eventually(EVENT_WAIT, "alice's name no longer owed", async || alice.device.client.lock().await.store().profile_owed(&server_id).unwrap().is_empty()).await;
}

/// The avatar's key rides in presence, so a member who joins after the avatar was
/// announced can open it.
#[tokio::test(flavor = "multi_thread")]
async fn a_member_who_joins_later_sees_an_avatar_set_before() {
    let relay = start_relay().await;
    let alice = Peer::new(&relay.url(), "alice").await;
    let carol = Peer::new(&relay.url(), "carol").await;
    let server_id = alice.device.create_server("club").await.unwrap();
    let image = b"not really a png, but bytes all the same".to_vec();
    let reach = alice.device.set_avatar(&image).await.unwrap();
    assert!(reach.complete());
    let alice_fp = alice.device.fingerprint().await;

    let mark = carol.device.mark();
    invite_into(&alice, &carol, &server_id).await;
    carol.expect(mark, "alice's avatar", |e| matches!(e, ClientEvent::AvatarUpdated(fp) if *fp == alice_fp).then_some(())).await;
    let cached = std::fs::read(ghost_core::session::avatars::cache_path(carol.device.data_dir(), &alice_fp)).unwrap();
    assert_eq!(cached, image);
}

/// Another device of the account that changes the avatar has this one announce it too,
/// rather than the avatar it had.
#[tokio::test(flavor = "multi_thread")]
async fn a_device_announces_the_avatar_another_device_of_its_account_set() {
    let relay = start_relay().await;
    let alice = Peer::new(&relay.url(), "alice").await;
    let bob = Peer::new(&relay.url(), "bob").await;
    let server_id = alice.device.create_server("club").await.unwrap();
    invite_into(&alice, &bob, &server_id).await;
    let folder = tempfile::tempdir().unwrap();
    let mut laptop = alice.device.link_device(folder.path(), &relay.url(), "laptop").await.unwrap();
    laptop.start();
    let alice_fp = alice.device.fingerprint().await;

    laptop.set_avatar(b"a new face").await.unwrap();
    let hash = eventually_avatar(&alice, &server_id, &alice_fp).await;

    // The phone announces again (its mailbox reconnects); Bob, who shows the account as
    // its latest announcing device, sees the new avatar from it.
    let mailbox_id = alice.device.client.lock().await.mailbox_id_for_server(&server_id).unwrap();
    let last_seen = alice.device.client.lock().await.store().get_last_seen_seq(&mailbox_id).unwrap();
    alice.device.relay.unsubscribe(&mailbox_id);
    let mark = bob.device.mark();
    alice.device.relay.subscribe(mailbox_id, last_seen);
    bob.expect(mark, "alice announcing the new avatar", move |e| match e {
        ClientEvent::OnlinePresence { members, .. } => members.iter().any(|m| m.fingerprint == alice_fp && m.avatar_hash == Some(hash)).then_some(()),
        _ => None,
    })
    .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let last = bob.device.events_since(mark).into_iter().rev().find_map(|e| match e {
        ClientEvent::OnlinePresence { members, .. } => members.into_iter().find(|m| m.fingerprint == alice_fp),
        _ => None,
    });
    assert_eq!(last.and_then(|m| m.avatar_hash), Some(hash), "the phone announced the avatar it had");
}

/// The avatar the device's member record of its own account names, once the
/// announcement from its other device arrived.
async fn eventually_avatar(peer: &Peer, server_id: &[u8; 32], account: &[u8; 32]) -> [u8; 32] {
    let mut hash = None;
    eventually(EVENT_WAIT, "the other device's avatar announcement", async || {
        hash = peer.device.client.lock().await.store().get_member(server_id, account).ok().and_then(|m| m.avatar_hash);
        hash.is_some()
    })
    .await;
    hash.unwrap()
}

/// An avatar a server's relay missed is put there, as the same sealed bytes, once its
/// mailbox connects again, and the members fetch it.
#[tokio::test(flavor = "multi_thread")]
async fn an_avatar_a_relay_missed_is_put_once_it_is_back() {
    let relay = support::start_switched_relay().await;
    let alice = Peer::new(&relay.url(), "alice").await;
    let bob = Peer::new(&relay.url(), "bob").await;
    let server_id = alice.device.create_server("club").await.unwrap();
    invite_into(&alice, &bob, &server_id).await;
    let alice_fp = alice.device.fingerprint().await;
    let image = b"a face for the relay that was away".to_vec();

    relay.go_down();
    let reach = alice.device.set_avatar(&image).await.unwrap();
    assert_eq!((reach.reached, reach.servers), (0, 1));
    let mark = bob.device.mark();
    relay.come_back();
    bob.expect(mark, "alice's avatar", |e| matches!(e, ClientEvent::AvatarUpdated(fp) if *fp == alice_fp).then_some(())).await;
    let cached = std::fs::read(ghost_core::session::avatars::cache_path(bob.device.data_dir(), &alice_fp)).unwrap();
    assert_eq!(cached, image);
    // Told first, then marked told: the mark may come a moment after Bob has it.
    eventually(EVENT_WAIT, "alice's avatar no longer owed", async || alice.device.client.lock().await.store().profile_owed(&server_id).unwrap().is_empty()).await;
}

/// A device coming back reports that it is catching up on what it missed, then that it
/// is done, so the app can tell a replay from a quiet connection.
#[tokio::test(flavor = "multi_thread")]
async fn a_device_says_when_it_has_caught_up() {
    let relay = start_relay().await;
    let alice = Peer::new(&relay.url(), "alice").await;
    let mut bob = Peer::new(&relay.url(), "bob").await;
    let server_id = alice.device.create_server("club").await.unwrap();
    invite_into(&alice, &bob, &server_id).await;
    bob.device.stop().await;
    let general = derive_default_channel_id(&server_id);
    for text in ["one", "two", "three"] {
        alice.device.say(&server_id, &general, text).await.unwrap();
    }

    let mark = bob.device.mark();
    bob.device.start();
    let catching_up = |wanted: bool| move |e: &ClientEvent| match e {
        ClientEvent::RelayConnectivity(c) if c.any && c.catching_up == wanted => Some(()),
        _ => None,
    };
    bob.expect(mark, "catching up", catching_up(true)).await;
    bob.expect(mark, "having caught up", catching_up(false)).await;
    bob.expect(mark, "the last message missed", message_text("three")).await;
}
