//! Helpers shared by the ghost-node test suites.

#![allow(dead_code)]

use std::sync::Once;
use std::time::Duration;

use ghost_core::account_keys::RecoveryKey;
use ghost_core::session::{ClientEvent, ServerScope};
use ghost_node::Device;
use ghost_relay::config::Config;
use ghost_relay::outage::SwitchedRelay;
use ghost_relay::server::RunningRelay;
use ghost_relay::storage::Storage;

/// How long a test waits for an expected event before failing.
pub const EVENT_WAIT: Duration = Duration::from_secs(10);

/// Log to stderr as the binaries do, so `GHOST_LOG=debug cargo test -- --nocapture`
/// shows what the relays and devices did. Once per test process.
pub fn logging() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| std::mem::forget(ghost_log::init(None)));
}

/// A relay configuration for tests: ephemeral ports, fast mirror pulls.
pub fn test_config() -> Config {
    Config {
        port: 0,
        max_blob_size: 10 * 1024 * 1024,
        voice_port: 0,
        voice_public_port: None,
        max_voice_participants: 25,
        db_path: None,
        log_retention_hours: 72,
        log_min_entries: 100,
        public_url: None,
        mirror_refresh_secs: 1,
        ws_ping_secs: 1,
        presence_grace_secs: 2,
        skip_policy_checks_for_tests: false,
        revoked_devices_for_tests: Default::default(),
        trusted_proxies: Vec::new(),
    }
}

/// An in-process relay started exactly as the binary starts it.
pub async fn start_relay() -> RunningRelay {
    start_relay_with(test_config()).await
}

/// An in-process relay with the given configuration.
pub async fn start_relay_with(config: Config) -> RunningRelay {
    logging();
    ghost_relay::server::start(config, Storage::open_ephemeral().unwrap(), ([127, 0, 0, 1], 0).into()).await.unwrap()
}

/// A relay that stores commits without judging them under the rules, as a dishonest or
/// broken relay would.
pub async fn start_relay_that_skips_policy_checks() -> RunningRelay {
    let mut config = test_config();
    config.skip_policy_checks_for_tests = true;
    start_relay_with(config).await
}

/// A relay a test can take down and bring back: down, devices and other relays alike
/// lose it; back, it serves everything it held.
pub async fn start_switched_relay() -> SwitchedRelay {
    logging();
    SwitchedRelay::start(test_config(), Storage::open_ephemeral().unwrap()).await.unwrap()
}

/// A relay whose voice traffic passes through `forwarder`: it tells clients to send
/// voice to the forwarder's port, and the forwarder relays to the real one.
pub async fn start_relay_behind(forwarder: &ghost_media::netem::Forwarder) -> RunningRelay {
    let config = Config { voice_public_port: Some(forwarder.port()), ..test_config() };
    let relay = start_relay_with(config).await;
    forwarder.forward_to(([127, 0, 0, 1], relay.voice_port).into());
    relay
}

/// A named device with its own data directory, running its session loop, and the
/// recovery key its user saved when the account was made.
pub struct Peer {
    pub name: &'static str,
    pub device: Device,
    pub recovery_key: RecoveryKey,
    _dir: tempfile::TempDir,
}

impl Peer {
    pub async fn new(relay_url: &str, name: &'static str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let recovery_key = RecoveryKey::generate();
        let mut device = Device::create(dir.path(), relay_url, name, &recovery_key).await.unwrap();
        device.start();
        Self { name, device, recovery_key, _dir: dir }
    }

    /// Wait for an event after `since` that `pick` accepts; fail the test otherwise.
    pub async fn expect<T>(&self, since: usize, what: &str, pick: impl Fn(&ClientEvent) -> Option<T>) -> T {
        match self.device.wait_for(since, EVENT_WAIT, pick).await {
            Some(found) => found,
            None => panic!("{} never reported {what}; it reported: {:#?}", self.name, self.device.events_since(since)),
        }
    }
}

pub fn message_text(text: &'static str) -> impl Fn(&ClientEvent) -> Option<()> {
    move |e| match e {
        ClientEvent::Message { message, .. } if message.content == text.as_bytes() => Some(()),
        _ => None,
    }
}

pub fn kicked_from(server_id: [u8; 32]) -> impl Fn(&ClientEvent) -> Option<()> {
    move |e| matches!(e, ClientEvent::Kicked(id) if *id == server_id).then_some(())
}

pub fn server_changed(server_id: [u8; 32]) -> impl Fn(&ClientEvent) -> Option<()> {
    move |e| matches!(e, ClientEvent::ServerChanged(ServerScope::One(id)) if *id == server_id).then_some(())
}

/// Poll `check` until it holds, failing with `what` after `wait`.
pub async fn eventually(wait: Duration, what: &str, mut check: impl AsyncFnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + wait;
    while !check().await {
        assert!(tokio::time::Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The epoch of a device's copy of the server's group; 0 before it has one.
pub async fn epoch_of(device: &Device, server_id: &[u8; 32]) -> u64 {
    let channel = ghost_core::wire::derive_default_channel_id(server_id);
    device.client.lock().await.channel_epoch(&channel).unwrap_or(0)
}

/// Wait until `follower` has applied every commit `leader` has in the server's group.
pub async fn caught_up(follower: &Device, leader: &Device, server_id: &[u8; 32]) {
    eventually(EVENT_WAIT, "a device to catch up with the server group", async || {
        epoch_of(follower, server_id).await >= epoch_of(leader, server_id).await
    })
    .await;
}

/// Join `member` to the server by an invite from `owner`, whose running loop must take
/// in the join before the next invite, so each invite carries current group state.
pub async fn invite_into(owner: &Peer, member: &Peer, server_id: &[u8; 32]) {
    let mark = owner.device.mark();
    let (token, key) = owner.device.invite(server_id).await.unwrap();
    member.device.join(&token, &key).await.unwrap();
    owner.expect(mark, "the join", server_changed(*server_id)).await;
}
