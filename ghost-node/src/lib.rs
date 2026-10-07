//! A headless Ghost device: an account kept in a data directory, the client's session
//! and voice loops (`ghost_core::session` and `ghost_core::voice`, the same loops the
//! desktop app runs), a record of the events they report, and the actions a user would
//! take. Its voice calls run on synthetic devices: a tone for a microphone and a
//! recorder for speakers. Tests use it in-process, and the `ghost-node` binary drives
//! it over stdin and stdout so tests can also run devices as separate processes and
//! kill them.
//!
//! The device key sits in a plain file in the data directory: this is a test tool, not
//! something to keep a real account in.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ghost_audio::fake::ToneDevices;
use ghost_audio::{NoiseSuppressionMode, VoiceAudio};
use ghost_core::client::GhostClient;
use ghost_core::error::{GhostError, Result};
use ghost_core::flows::presence::PresenceInfo;
use ghost_core::flows::{self, SharedClient, SharedRelay};
use ghost_core::identity::keyring_store::StoredDevice;
use ghost_core::identity::Identity;
use ghost_core::relay::{RelayClient, RelayEvent};
use ghost_core::session::{ClientEvent, EventSink, Session, GENESIS_PENDING_FILE};
use ghost_core::storage::ServerKind;
use ghost_core::voice::Voice;
use tokio::sync::{mpsc, Mutex, Notify};
use tokio::task::JoinHandle;

/// File in the data directory holding the device record.
pub const DEVICE_FILE: &str = "device.key";
/// File in the data directory holding the client database (SQLCipher).
pub const DATABASE_FILE: &str = "ghost.db";

/// Every event the device reported, in order.
#[derive(Default)]
pub struct EventLog {
    events: std::sync::Mutex<Vec<ClientEvent>>,
    arrived: Notify,
    /// Also forward each event, for the binary to print.
    forward: std::sync::Mutex<Option<mpsc::UnboundedSender<ClientEvent>>>,
}

impl EventSink for EventLog {
    fn emit(&self, event: ClientEvent) {
        if let Some(forward) = self.forward.lock().unwrap().as_ref() {
            let _ = forward.send(event.clone());
        }
        self.events.lock().unwrap().push(event);
        self.arrived.notify_waiters();
    }
}

/// A headless device.
pub struct Device {
    pub client: Arc<SharedClient>,
    pub relay: Arc<SharedRelay>,
    pub log: Arc<EventLog>,
    /// The microphone and speakers of its calls.
    pub tone: Arc<ToneDevices>,
    pub audio: Arc<VoiceAudio>,
    data_dir: PathBuf,
    events: Option<mpsc::Receiver<RelayEvent>>,
    /// The session and voice loops, while started.
    tasks: Vec<JoinHandle<()>>,
    voice: Option<Voice>,
}

fn relay_client(relay_url: &str, device: &StoredDevice) -> (RelayClient, mpsc::Receiver<RelayEvent>) {
    let (mut relay, events) = RelayClient::new(relay_url);
    relay.set_auth(device.fingerprint, device.signing_key.verifying_key().to_bytes(), device.signing_key.clone());
    (relay, events)
}

impl Device {
    /// Create a new account in `data_dir` (which must not hold one) homed on `relay_url`.
    pub async fn create(data_dir: &Path, relay_url: &str, label: &str) -> Result<Self> {
        std::fs::create_dir_all(data_dir)?;
        let creation = Identity::create_account(label)?;
        let device = StoredDevice {
            fingerprint: creation.identity.fingerprint,
            signing_key: creation.identity.signing_key.clone(),
            db_key: creation.db_key,
            mls_db_key: creation.mls_db_key,
            idlog_seq: 1,
            master_vk: creation.identity.master_vk,
            master_sk: creation.identity.master_sk.clone(),
            delegation_sig: creation.identity.delegation_sig,
        };
        let genesis = creation.genesis_entry.to_bytes();
        std::fs::write(data_dir.join(DEVICE_FILE), device.to_bytes())?;
        std::fs::write(data_dir.join(GENESIS_PENDING_FILE), &genesis)?;

        let (relay, events) = relay_client(relay_url, &device);
        relay.put_idlog_entry(&device.fingerprint, genesis).await?;
        let mut client = GhostClient::open(device.identity(), device.db_key, device.mls_db_key, &data_dir.join(DATABASE_FILE))?;
        client.set_relay_vk(relay.get_relay_info().await?.relay_vk);
        let mut sync_key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut sync_key);
        client.set_sync_key(sync_key)?;

        let this = Self::assemble(data_dir, client, relay, events);
        flows::account::ensure_home_relay(&this.client, &this.relay).await?;
        Ok(this)
    }

    /// Open the account kept in `data_dir`, reaching its relays through `relay_url`.
    pub fn open(data_dir: &Path, relay_url: &str) -> Result<Self> {
        let device = StoredDevice::from_bytes(&std::fs::read(data_dir.join(DEVICE_FILE))?)?;
        let (relay, events) = relay_client(relay_url, &device);
        let client = GhostClient::open(device.identity(), device.db_key, device.mls_db_key, &data_dir.join(DATABASE_FILE))?;
        Ok(Self::assemble(data_dir, client, relay, events))
    }

    fn assemble(data_dir: &Path, client: GhostClient, relay: RelayClient, events: mpsc::Receiver<RelayEvent>) -> Self {
        let tone = ToneDevices::new();
        let audio = Arc::new(VoiceAudio::new(tone.clone()));
        // A pure tone is not speech, and noise suppression would silence it; loudness
        // decides what is sent instead.
        audio.set_noise_suppression(NoiseSuppressionMode::Off);
        Self {
            client: Arc::new(Mutex::new(client)),
            relay: Arc::new(Mutex::new(relay)),
            log: Arc::default(),
            tone,
            audio,
            data_dir: data_dir.to_path_buf(),
            events: Some(events),
            tasks: Vec::new(),
            voice: None,
        }
    }

    pub async fn fingerprint(&self) -> [u8; 32] {
        *self.client.lock().await.fingerprint()
    }

    /// Start the session and voice loops. After `stop`, starts them again on a fresh
    /// relay client.
    pub fn start(&mut self) {
        let events = self.events.take().expect("session already running");
        let session = Session {
            client: self.client.clone(),
            relay: self.relay.clone(),
            presence: Arc::new(Mutex::new(PresenceInfo::default())),
            sink: self.log.clone(),
            data_dir: self.data_dir.clone(),
            discovery: Arc::default(),
        };
        let (voice, voice_loop) = Voice::new(self.client.clone(), self.relay.clone(), self.audio.clone());
        self.tasks = vec![tokio::spawn(session.run(events)), tokio::spawn(voice_loop.run(self.log.clone()))];
        self.voice = Some(voice);
    }

    /// Go offline: stop the loops (ending any call) and close every relay connection.
    pub async fn stop(&mut self) {
        self.voice = None;
        for task in self.tasks.drain(..) {
            task.abort();
            let _ = task.await;
        }
        let mut relay = self.relay.lock().await;
        let (mut fresh, events) = RelayClient::new(relay.base_url());
        fresh.copy_auth_from(&relay);
        // Dropping the old client's subscriptions closes their connections.
        *relay = fresh;
        self.events = Some(events);
    }

    /// Forward every later event to `tx` as well.
    pub fn forward_events(&self, tx: mpsc::UnboundedSender<ClientEvent>) {
        *self.log.forward.lock().unwrap() = Some(tx);
    }

    /// How many events have arrived so far, to wait only for later ones.
    pub fn mark(&self) -> usize {
        self.log.events.lock().unwrap().len()
    }

    /// Wait up to `timeout` for an event after `since` that `pick` accepts.
    pub async fn wait_for<T>(&self, since: usize, timeout: Duration, pick: impl Fn(&ClientEvent) -> Option<T>) -> Option<T> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let arrived = self.log.arrived.notified();
            if let Some(found) = self.log.events.lock().unwrap().iter().skip(since).find_map(&pick) {
                return Some(found);
            }
            if tokio::time::timeout_at(deadline, arrived).await.is_err() {
                return None;
            }
        }
    }

    /// Every event after `since`, for failure messages.
    pub fn events_since(&self, since: usize) -> Vec<ClientEvent> {
        self.log.events.lock().unwrap().iter().skip(since).cloned().collect()
    }

    /// Create a server, publish its group state and subscribe to it, as the app does.
    pub async fn create_server(&self, name: &str) -> Result<[u8; 32]> {
        let (server_id, mailbox_id, group_info) = {
            let mut c = self.client.lock().await;
            let server_id = c.create_server(name, ServerKind::Server, flows::now_millis())?;
            let mailbox_id = c.mailbox_id_for_server(&server_id).ok_or_else(|| GhostError::ServerNotLoaded(name.into()))?;
            (server_id, mailbox_id, c.export_server_info(&server_id)?)
        };
        let mut relay = self.relay.lock().await;
        relay.put_server_info(&mailbox_id, group_info).await?;
        relay.subscribe(mailbox_id, 0);
        Ok(server_id)
    }

    /// Create an invite to a server. Returns (token, key).
    pub async fn invite(&self, server_id: &[u8; 32]) -> Result<(String, [u8; 32])> {
        let invite = flows::invite::create(&self.client, &self.relay, server_id, u64::MAX).await?;
        Ok((invite.token, invite.key))
    }

    /// Join a server through an invite on this device's relay.
    pub async fn join(&self, token: &str, key: &[u8; 32]) -> Result<[u8; 32]> {
        flows::invite::join(&self.client, &self.relay, &self.relay, token, key, flows::now_millis()).await
    }

    /// Send a chat message.
    pub async fn say(&self, server_id: &[u8; 32], channel_id: &[u8; 32], text: &str) -> Result<()> {
        flows::channels::remove_excluded(&self.client, &self.relay, channel_id).await?;
        let outbound = {
            let mut c = self.client.lock().await;
            c.send_message(server_id, channel_id, text.as_bytes().to_vec(), vec![], flows::now_millis())?.0
        };
        self.relay.lock().await.post_blob(&outbound.mailbox_id, outbound.blob).await?;
        Ok(())
    }

    /// Kick a member from a server.
    pub async fn kick(&self, server_id: &[u8; 32], member: &[u8; 32]) -> Result<bool> {
        flows::members::kick(&self.client, &self.relay, server_id, member).await
    }

    /// This device's voice calls; it must be started.
    pub fn voice(&self) -> &Voice {
        self.voice.as_ref().expect("device not started")
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        for task in self.tasks.drain(..) {
            task.abort();
        }
    }
}
