//! Scenarios run through the client's real event loop (`ghost_core::session`), the same
//! loop the desktop app runs: devices are started, stopped and restarted against
//! in-process relays, and the tests watch the events each device reports.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{create_account, create_server, Account};
use ghost_core::flows;
use ghost_core::flows::presence::PresenceInfo;
use ghost_core::relay::RelayClient;
use ghost_core::session::{ClientEvent, EventSink, ServerScope, Session};
use tokio::sync::{Mutex, Notify};
use tokio::task::JoinHandle;

/// How long a scenario waits for an expected event before failing.
const EVENT_WAIT: Duration = Duration::from_secs(10);

/// Every event one device reported, in order.
#[derive(Default)]
struct EventLog {
    events: std::sync::Mutex<Vec<ClientEvent>>,
    arrived: Notify,
}

impl EventSink for EventLog {
    fn emit(&self, event: ClientEvent) {
        self.events.lock().unwrap().push(event);
        self.arrived.notify_waiters();
    }
}

/// A device running the session loop.
struct Node {
    name: &'static str,
    account: Account,
    log: Arc<EventLog>,
    task: Option<JoinHandle<()>>,
    data_dir: tempfile::TempDir,
}

impl Node {
    fn new(name: &'static str, account: Account) -> Self {
        Self { name, account, log: Arc::default(), task: None, data_dir: tempfile::tempdir().unwrap() }
    }

    /// Start (or restart) the loop on the account's current relay client.
    fn start(&mut self) {
        let events = self.account.events.lock().unwrap().take().expect("relay events already consumed");
        let session = Session {
            client: self.account.client.clone(),
            relay: self.account.relay.clone(),
            presence: Arc::new(Mutex::new(PresenceInfo::default())),
            sink: self.log.clone(),
            data_dir: self.data_dir.path().to_path_buf(),
            discovery: Arc::default(),
        };
        self.task = Some(tokio::spawn(session.run(events)));
    }

    /// Go offline: stop the loop and close every relay connection. A fresh relay client
    /// with the same credentials is kept ready for `start`.
    async fn stop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
        let mut relay = self.account.relay.lock().await;
        let (mut fresh, events) = RelayClient::new(relay.base_url());
        fresh.copy_auth_from(&relay);
        // Dropping the old client's subscriptions closes their connections.
        *relay = fresh;
        *self.account.events.lock().unwrap() = Some(events);
    }

    /// How many events have arrived so far, to wait only for later ones.
    fn mark(&self) -> usize {
        self.log.events.lock().unwrap().len()
    }

    /// Wait for an event after `since` that `pick` accepts, and return what it picked.
    async fn wait_for<T>(&self, since: usize, what: &str, pick: impl Fn(&ClientEvent) -> Option<T>) -> T {
        let deadline = tokio::time::Instant::now() + EVENT_WAIT;
        loop {
            let arrived = self.log.arrived.notified();
            if let Some(found) = self.log.events.lock().unwrap().iter().skip(since).find_map(&pick) {
                return found;
            }
            if tokio::time::timeout_at(deadline, arrived).await.is_err() {
                let seen: Vec<String> = self.log.events.lock().unwrap().iter().skip(since).map(|e| format!("{e:?}")).collect();
                panic!("{} never reported {what}; it reported: {seen:#?}", self.name);
            }
        }
    }

    /// Create a server and subscribe to it, as the app does.
    async fn create_server(&self) -> [u8; 32] {
        let server_id = create_server(&self.account, "club").await;
        let mailbox_id = self.account.client.lock().await.mailbox_id_for_server(&server_id).unwrap();
        self.account.relay.lock().await.subscribe(mailbox_id, 0);
        server_id
    }

    /// Send a chat message to a channel.
    async fn say(&self, server_id: &[u8; 32], channel_id: &[u8; 32], text: &str) {
        let outbound = {
            let mut c = self.account.client.lock().await;
            c.send_message(server_id, channel_id, text.as_bytes().to_vec(), vec![], flows::now_millis()).unwrap().0
        };
        self.account.relay.lock().await.post_blob(&outbound.mailbox_id, outbound.blob).await.unwrap();
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

fn message_text(text: &'static str) -> impl Fn(&ClientEvent) -> Option<()> {
    move |e| match e {
        ClientEvent::Message { message, .. } if message.content == text.as_bytes() => Some(()),
        _ => None,
    }
}

fn kicked_from(server_id: [u8; 32]) -> impl Fn(&ClientEvent) -> Option<()> {
    move |e| matches!(e, ClientEvent::Kicked(id) if *id == server_id).then_some(())
}

fn server_changed(server_id: [u8; 32]) -> impl Fn(&ClientEvent) -> Option<()> {
    move |e| matches!(e, ClientEvent::ServerChanged(ServerScope::One(id)) if *id == server_id).then_some(())
}

/// Join `member` to the server by an invite from `owner`, whose running loop must take
/// in the join before the next invite, so each invite carries current group state.
async fn invite_into(owner: &Node, member: &Node, server_id: &[u8; 32]) {
    let mark = owner.mark();
    let invite = flows::invite::create(&owner.account.client, &owner.account.relay, server_id, u64::MAX).await.unwrap();
    let (client, relay) = (&member.account.client, &member.account.relay);
    flows::invite::join(client, relay, relay, &invite.token, &invite.key, flows::now_millis()).await.unwrap();
    owner.wait_for(mark, "the join", server_changed(*server_id)).await;
}

/// Started nodes for new accounts on one relay.
async fn nodes(relay_url: &str, names: &[&'static str]) -> Vec<Node> {
    let mut nodes = Vec::new();
    for name in names {
        let mut node = Node::new(name, create_account(relay_url, name).await);
        node.start();
        nodes.push(node);
    }
    nodes
}

#[tokio::test]
async fn messages_reach_a_running_device() {
    let relay_url = common::start_relay().await;
    let [alice, bob]: [Node; 2] = nodes(&relay_url, &["alice", "bob"]).await.try_into().ok().unwrap();
    let server_id = alice.create_server().await;
    invite_into(&alice, &bob, &server_id).await;
    let general = ghost_core::wire::derive_default_channel_id(&server_id);

    let mark = alice.mark();
    bob.say(&server_id, &general, "hello alice").await;
    alice.wait_for(mark, "Bob's message", message_text("hello alice")).await;
}

#[tokio::test]
async fn kicked_devices_learn_it_online_and_after_coming_back() {
    let relay_url = common::start_relay().await;
    let [alice, bob, mut carol]: [Node; 3] = nodes(&relay_url, &["alice", "bob", "carol"]).await.try_into().ok().unwrap();
    let server_id = alice.create_server().await;
    invite_into(&alice, &bob, &server_id).await;
    invite_into(&alice, &carol, &server_id).await;

    // Bob is online when he is kicked.
    let bob_mark = bob.mark();
    assert!(flows::members::kick(&alice.account.client, &alice.account.relay, &server_id, &bob.account.fp).await.unwrap());
    bob.wait_for(bob_mark, "being kicked", kicked_from(server_id)).await;

    // Carol is offline when she is kicked and learns it on reconnecting: the relay lets
    // her read up to the commit that removed her.
    carol.stop().await;
    assert!(flows::members::kick(&alice.account.client, &alice.account.relay, &server_id, &carol.account.fp).await.unwrap());
    let carol_mark = carol.mark();
    carol.start();
    carol.wait_for(carol_mark, "being kicked while offline", kicked_from(server_id)).await;
}

#[tokio::test]
async fn a_device_rejoins_after_missing_more_than_the_relay_kept() {
    let relay = common::start_relay_with_handle().await;
    let relay_url = relay.url();
    let [alice, mut bob]: [Node; 2] = nodes(&relay_url, &["alice", "bob"]).await.try_into().ok().unwrap();
    let server_id = alice.create_server().await;
    invite_into(&alice, &bob, &server_id).await;
    let general = ghost_core::wire::derive_default_channel_id(&server_id);

    // While Bob is away, the group moves on and the relay drops everything he missed.
    bob.stop().await;
    let mut carol = Node::new("carol", create_account(&relay_url, "carol").await);
    carol.start();
    invite_into(&alice, &carol, &server_id).await;
    alice.say(&server_id, &general, "while bob was away").await;
    relay.state.storage.sweep_log(u64::MAX, 0).unwrap();

    // Bob comes back past the gap, rejoins the group, and takes part again.
    bob.start();
    tokio::time::sleep(Duration::from_secs(2)).await;
    let mark = alice.mark();
    bob.say(&server_id, &general, "bob is back").await;
    alice.wait_for(mark, "Bob's message after rejoining", message_text("bob is back")).await;
    let mark = bob.mark();
    alice.say(&server_id, &general, "welcome back").await;
    bob.wait_for(mark, "Alice's message after rejoining", message_text("welcome back")).await;
}

#[tokio::test]
async fn private_channels_are_joined_named_and_left_by_the_running_loops() {
    use ghost_core::storage::ChannelKind;
    use ghost_wire::policy::Role;

    let relay_url = common::start_relay().await;
    let [alice, bob, carol]: [Node; 3] = nodes(&relay_url, &["alice", "bob", "carol"]).await.try_into().ok().unwrap();
    let server_id = alice.create_server().await;
    invite_into(&alice, &bob, &server_id).await;
    invite_into(&alice, &carol, &server_id).await;

    // A "staff" channel for a role only Bob holds.
    let mut policy = alice.account.client.lock().await.server_policy(&server_id).unwrap();
    policy.roles.push(Role { id: 1, permissions: 0 });
    policy.assignments.push((bob.account.fp, vec![1]));
    let bob_mark = bob.mark();
    flows::roles::set_server_policy(&alice.account.client, &alice.account.relay, &server_id, &policy).await.unwrap();
    let channel_id = flows::channels::create_private(
        &alice.account.client, &alice.account.relay, &alice.account.relay, &server_id, "staff", ChannelKind::Text, vec![1], vec![],
    )
    .await
    .unwrap();

    // Bob's loop joins it after the role change and learns its name from Alice's loop.
    let named = |e: &ClientEvent| matches!(e, ClientEvent::ServerChanged(ServerScope::One(id)) if *id == server_id).then_some(());
    let deadline = tokio::time::Instant::now() + EVENT_WAIT;
    loop {
        bob.wait_for(bob_mark, "a server change", named).await;
        let name = bob.account.client.lock().await.store().get_channel(&channel_id).ok().map(|c| c.name);
        if name.as_deref() == Some("staff") {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "Bob never learned the channel's name (has {name:?})");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // Carol, without the role, never learns of it.
    assert!(carol.account.client.lock().await.store().get_channel(&channel_id).is_err());

    // Messages flow in the channel.
    let mark = bob.mark();
    alice.say(&server_id, &channel_id, "staff only").await;
    bob.wait_for(mark, "the channel message", message_text("staff only")).await;

    // Bob loses the role: the relay proposes his removal, Alice's loop commits it, and
    // Bob's device forgets the channel.
    policy.assignments.retain(|(account, _)| *account != bob.account.fp);
    flows::roles::set_server_policy(&alice.account.client, &alice.account.relay, &server_id, &policy).await.unwrap();
    let deadline = tokio::time::Instant::now() + EVENT_WAIT;
    while bob.account.client.lock().await.store().get_channel(&channel_id).is_ok() {
        assert!(tokio::time::Instant::now() < deadline, "Bob still holds the channel after losing access");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
