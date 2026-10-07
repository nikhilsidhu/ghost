//! Helpers shared by the ghost-node test suites.

#![allow(dead_code)]

use std::time::Duration;

use ghost_core::session::{ClientEvent, ServerScope};
use ghost_node::Device;
use ghost_relay::config::Config;
use ghost_relay::server::RunningRelay;
use ghost_relay::storage::Storage;

/// How long a test waits for an expected event before failing.
pub const EVENT_WAIT: Duration = Duration::from_secs(10);

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
    }
}

/// An in-process relay started exactly as the binary starts it.
pub async fn start_relay() -> RunningRelay {
    ghost_relay::server::start(test_config(), Storage::open_in_memory().unwrap(), ([127, 0, 0, 1], 0).into()).await.unwrap()
}

/// A relay whose voice traffic passes through `forwarder`: it tells clients to send
/// voice to the forwarder's port, and the forwarder relays to the real one.
pub async fn start_relay_behind(forwarder: &ghost_media::netem::Forwarder) -> RunningRelay {
    let config = Config { voice_public_port: Some(forwarder.port()), ..test_config() };
    let relay = ghost_relay::server::start(config, Storage::open_in_memory().unwrap(), ([127, 0, 0, 1], 0).into()).await.unwrap();
    forwarder.forward_to(([127, 0, 0, 1], relay.voice_port).into());
    relay
}

/// A named device with its own data directory, running its session loop.
pub struct Peer {
    pub name: &'static str,
    pub device: Device,
    _dir: tempfile::TempDir,
}

impl Peer {
    pub async fn new(relay_url: &str, name: &'static str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut device = Device::create(dir.path(), relay_url, name).await.unwrap();
        device.start();
        Self { name, device, _dir: dir }
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

/// Join `member` to the server by an invite from `owner`, whose running loop must take
/// in the join before the next invite, so each invite carries current group state.
pub async fn invite_into(owner: &Peer, member: &Peer, server_id: &[u8; 32]) {
    let mark = owner.device.mark();
    let (token, key) = owner.device.invite(server_id).await.unwrap();
    member.device.join(&token, &key).await.unwrap();
    owner.expect(mark, "the join", server_changed(*server_id)).await;
}
