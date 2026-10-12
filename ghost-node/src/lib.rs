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
use ghost_core::account_keys::{DeviceEncryptionKey, RecoveryKey};
use ghost_core::client::GhostClient;
use ghost_core::error::{GhostError, Result};
use ghost_core::flows::presence::PresenceInfo;
use ghost_core::flows::{self, SharedClient};
use ghost_core::flows::pairing::{PairingCode, PairingOffer};
use ghost_core::flows::devices::RevokeOutcome;
use ghost_core::identity::keyring_store::StoredDevice;
use ghost_core::identity::Identity;
use ghost_core::relay::{RelayClient, RelayEvent};
use ghost_core::session::{ClientEvent, EventSink, Session};
use ghost_core::storage::{ChannelKind, ServerKind};
use ghost_core::voice::Voice;
use ghost_wire::policy::Role;
use tokio::sync::{mpsc, Mutex, Notify};
use tokio::task::JoinHandle;

/// File in the data directory holding the device record.
pub const DEVICE_FILE: &str = "device.key";
/// File in the data directory holding the client database (SQLCipher).
pub const DATABASE_FILE: &str = "ghost.db";
/// File in the data directory holding the display name, which the client keeps only in
/// memory (the app keeps it in its config).
pub const DISPLAY_NAME_FILE: &str = "display_name";
/// How often, and how long, either side of a pairing waits on the other.
const PAIRING_POLLS: usize = 50;
const PAIRING_POLL_INTERVAL: Duration = Duration::from_millis(200);

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
    pub relay: Arc<RelayClient>,
    pub log: Arc<EventLog>,
    /// The microphone and speakers of its calls.
    pub tone: Arc<ToneDevices>,
    pub audio: Arc<VoiceAudio>,
    /// What this device announces of its user; kept across `stop` and `start`.
    presence: Arc<Mutex<PresenceInfo>>,
    data_dir: PathBuf,
    events: Option<mpsc::Receiver<RelayEvent>>,
    /// The session and voice loops, while started.
    tasks: Vec<JoinHandle<()>>,
    voice: Option<Voice>,
}

fn relay_client(relay_url: &str, device: &StoredDevice) -> (RelayClient, mpsc::Receiver<RelayEvent>) {
    let (relay, events) = RelayClient::new(relay_url);
    relay.set_auth(device.fingerprint, device.signing_key.verifying_key().to_bytes(), device.signing_key.clone());
    (relay, events)
}

impl Device {
    /// Create a new account in `data_dir` (which must not hold one) homed on `relay_url`,
    /// with `label` as both its device label and its display name, and `recovery_key`
    /// as its root, which the caller keeps: the device does not.
    pub async fn create(data_dir: &Path, relay_url: &str, label: &str, recovery_key: &RecoveryKey) -> Result<Self> {
        std::fs::create_dir_all(data_dir)?;
        let (guest, _) = RelayClient::new(relay_url);
        let home = guest.get_relay_info().await?;
        let new = Identity::create_account(&home.relay_ref, label, recovery_key)?;
        let device = StoredDevice {
            fingerprint: new.identity.fingerprint,
            signing_key: new.identity.signing_key.clone(),
            encryption_key: new.identity.encryption_key.clone(),
            db_key: new.db_key,
            mls_db_key: new.mls_db_key,
            added_at: new.identity.added_at,
        };

        // Published before anything is written here, so a failed start leaves no
        // device for an account that does not exist.
        let (relay, events) = relay_client(relay_url, &device);
        relay.post_idlog_batch(&device.fingerprint, &new.batch).await?;
        std::fs::write(data_dir.join(DEVICE_FILE), device.to_bytes())?;
        std::fs::write(data_dir.join(DISPLAY_NAME_FILE), label)?;

        let mut client = GhostClient::open(device.identity(), device.db_key, device.mls_db_key, &data_dir.join(DATABASE_FILE))?;
        client.set_display_name(label.to_string());
        client.set_relay_vk(home.relay_vk);
        client.store_account_seed(&new.account_seed)?;

        let this = Self::assemble(data_dir, client, relay, events);
        flows::idlog::fetch_and_verify(&this.client, &this.relay, &device.fingerprint).await?;
        Ok(this)
    }

    /// Recover the account `recovery_key` is the root of into `data_dir` (which must not
    /// hold one) as a new device labelled `label`, through its home at `relay_url`, as the
    /// app does: every other device is removed, `new_key` replaces the recovery key, and
    /// the account's servers and settings come back from its snapshot.
    pub async fn recover(
        data_dir: &Path,
        relay_url: &str,
        recovery_key: &RecoveryKey,
        new_key: &RecoveryKey,
        label: &str,
    ) -> Result<(Self, flows::recovery::SnapshotRestore)> {
        std::fs::create_dir_all(data_dir)?;
        let (guest, _) = RelayClient::new(relay_url);
        let located = flows::recovery::locate(&guest, recovery_key).await?.ok_or(GhostError::AuthenticationFailed)?;
        let material = flows::recovery::begin(&guest, located.account_fp, recovery_key, new_key, label).await?;

        // Active in the log from here: the record comes before anything that can fail.
        let mut keys = [[0u8; 32]; 2];
        for key in &mut keys {
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, key);
        }
        let stored = StoredDevice {
            fingerprint: material.account_fp,
            signing_key: material.device_key.clone(),
            encryption_key: material.encryption_key.clone(),
            db_key: keys[0],
            mls_db_key: keys[1],
            added_at: material.added_at,
        };
        std::fs::write(data_dir.join(DEVICE_FILE), stored.to_bytes())?;
        let mut client = GhostClient::open(material.identity(), stored.db_key, stored.mls_db_key, &data_dir.join(DATABASE_FILE))?;
        client.set_relay_vk(guest.get_relay_info().await?.relay_vk);
        let (relay, events) = relay_client(relay_url, &stored);
        let device = Self::assemble(data_dir, client, relay, events);
        let finished = flows::recovery::finish(&device.client, &device.relay, &material).await?;
        if let Some(name) = &finished.settings.display_name {
            device.client.lock().await.set_display_name(name.clone());
            std::fs::write(data_dir.join(DISPLAY_NAME_FILE), name)?;
        }
        Ok((device, finished.snapshot))
    }

    /// Open the account kept in `data_dir`, reaching its relays through `relay_url`.
    pub fn open(data_dir: &Path, relay_url: &str) -> Result<Self> {
        let device = StoredDevice::from_bytes(&std::fs::read(data_dir.join(DEVICE_FILE))?)?;
        let (relay, events) = relay_client(relay_url, &device);
        let mut client = GhostClient::open(device.identity(), device.db_key, device.mls_db_key, &data_dir.join(DATABASE_FILE))?;
        if let Ok(name) = std::fs::read_to_string(data_dir.join(DISPLAY_NAME_FILE)) {
            client.set_display_name(name);
        }
        Ok(Self::assemble(data_dir, client, relay, events))
    }

    fn assemble(data_dir: &Path, client: GhostClient, relay: RelayClient, events: mpsc::Receiver<RelayEvent>) -> Self {
        let tone = ToneDevices::new();
        let audio = Arc::new(VoiceAudio::new(tone.clone()));
        // A pure tone is not speech, and noise suppression would silence it; loudness
        // decides what is sent instead.
        audio.set_noise_suppression(NoiseSuppressionMode::Off);
        // Synthetic devices have no room for playback to echo in.
        audio.set_echo_cancellation(false);
        let presence = PresenceInfo { avatar: flows::presence::own_avatar(&client), ..PresenceInfo::default() };
        Self {
            client: Arc::new(Mutex::new(client)),
            relay: Arc::new(relay),
            log: Arc::default(),
            tone,
            audio,
            presence: Arc::new(Mutex::new(presence)),
            data_dir: data_dir.to_path_buf(),
            events: Some(events),
            tasks: Vec::new(),
            voice: None,
        }
    }

    pub async fn fingerprint(&self) -> [u8; 32] {
        *self.client.lock().await.fingerprint()
    }

    /// Where this device keeps its data, the avatar cache included.
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Take a new display name, kept here and announced in every server.
    pub async fn set_name(&self, name: &str) -> Result<flows::profile::Reach> {
        std::fs::write(self.data_dir.join(DISPLAY_NAME_FILE), name)?;
        flows::profile::set_display_name(&self.client, &self.relay, &self.data_dir, name).await
    }

    /// Give the account a new avatar from `image`, announced in this device's presence
    /// too.
    pub async fn set_avatar(&self, image: &[u8]) -> Result<flows::profile::Reach> {
        let (avatar, reach) = flows::profile::set_avatar(&self.client, &self.relay, &self.data_dir, image).await?;
        let info = {
            let mut p = self.presence.lock().await;
            p.avatar = Some(avatar);
            p.clone()
        };
        flows::presence::broadcast(&self.client, &self.relay, &info).await;
        Ok(reach)
    }

    /// Start the session and voice loops; after `stop`, starts them again.
    pub fn start(&mut self) {
        let events = self.events.take().expect("session already running");
        let session = Session {
            client: self.client.clone(),
            relay: self.relay.clone(),
            presence: self.presence.clone(),
            sink: self.log.clone(),
            data_dir: self.data_dir.clone(),
            discovery: Arc::default(),
            split_views: Arc::default(),
        };
        let (voice, voice_loop) = Voice::new(self.client.clone(), self.relay.clone(), self.audio.clone());
        self.tasks = vec![tokio::spawn(session.run(events)), tokio::spawn(voice_loop.run(self.log.clone()))];
        self.voice = Some(voice);
    }

    /// Go offline: stop the loops (ending any call) and close every relay connection,
    /// so relays show this device offline at once.
    pub async fn stop(&mut self) {
        self.stop_loops().await;
        self.events = Some(self.relay.restart());
    }

    /// Lose every relay connection at once, without closing them, as when the network
    /// goes: relays keep this device present for their grace period. `start` comes back.
    pub async fn cut_off(&mut self) {
        self.stop_loops().await;
        self.events = Some(self.relay.restart_cut_off());
    }

    async fn stop_loops(&mut self) {
        self.voice = None;
        for task in self.tasks.drain(..) {
            task.abort();
            let _ = task.await;
        }
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

    /// Create a server, as the app does.
    pub async fn create_server(&self, name: &str) -> Result<[u8; 32]> {
        flows::server::create(&self.client, &self.relay, name, ServerKind::Server, flows::now_millis()).await
    }

    /// Start a direct conversation, which others join by invite like a server.
    pub async fn create_dm(&self, name: &str) -> Result<[u8; 32]> {
        flows::server::create(&self.client, &self.relay, name, ServerKind::Dm, flows::now_millis()).await
    }

    /// Mark every channel this device has read, servers and DMs alike, as someone who has
    /// caught up on everything would.
    pub async fn mark_all_read(&self) -> Result<()> {
        let channels: Vec<[u8; 32]> = {
            let client = self.client.lock().await;
            let store = client.store();
            let mut channels = Vec::new();
            for server in store.list_servers()? {
                channels.extend(store.list_channels(&server.server_id)?.into_iter().map(|channel| channel.channel_id));
            }
            channels
        };
        for channel in channels {
            flows::channels::mark_read(&self.client, &self.relay, &channel, flows::now_millis()).await?;
        }
        Ok(())
    }

    /// Add a channel every member of the server sees.
    pub async fn create_channel(&self, server_id: &[u8; 32], name: &str, kind: ChannelKind) -> Result<[u8; 32]> {
        flows::channels::create(&self.client, &self.relay, server_id, name, kind).await
    }

    /// Add a channel only holders of `roles`, and `accounts`, may enter, on a server this
    /// device's home relay hosts.
    pub async fn create_private_channel(
        &self,
        server_id: &[u8; 32],
        name: &str,
        roles: Vec<u8>,
        accounts: Vec<[u8; 32]>,
    ) -> Result<[u8; 32]> {
        flows::channels::create_private(&self.client, &self.relay, &self.relay, server_id, name, ChannelKind::Text, roles, accounts).await
    }

    /// Add a role named `name` with `permissions`, given to `holders`. Returns its id.
    pub async fn add_role(&self, server_id: &[u8; 32], name: &str, permissions: u32, holders: &[[u8; 32]]) -> Result<u8> {
        let mut policy = self.client.lock().await.server_policy(server_id)?;
        let id = policy.roles.iter().map(|role| role.id).max().map_or(1, |highest| highest + 1);
        policy.roles.push(Role { id, permissions });
        for holder in holders {
            match policy.assignments.iter_mut().find(|(account, _)| account == holder) {
                Some((_, roles)) => roles.push(id),
                None => policy.assignments.push((*holder, vec![id])),
            }
        }
        flows::roles::set_server_policy(&self.client, &self.relay, server_id, &policy).await?;
        flows::roles::name_roles(&self.client, &self.relay, server_id, &[(id, name.to_string())]).await?;
        Ok(id)
    }

    /// Link a new device to this account, kept in `data_dir` and reaching relays through
    /// `relay_url`: the whole pairing exchange, both sides, as the app runs it. Its user
    /// compares the codes both screens show, which this does by checking they match.
    pub async fn link_device(&self, data_dir: &Path, relay_url: &str, label: &str) -> Result<Device> {
        let display_name = self.client.lock().await.identity().display_name.clone();
        let offer = PairingOffer { relay_url: relay_url.to_string(), display_name: display_name.clone(), avatar_hash: None, avatar_key: None };
        let code = PairingCode::parse(&flows::pairing::start(&self.client, &self.relay, &offer).await?.encode())?;

        // The new device has no identity yet, so its relay client is unauthenticated.
        let (guest, _events) = RelayClient::new(&code.relay_url);
        let device_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let encryption_key = DeviceEncryptionKey::generate();
        let shown_on_new = flows::pairing::respond(&guest, &code, &device_key, &encryption_key, label).await?;

        let mut pending = None;
        for _ in 0..PAIRING_POLLS {
            pending = flows::pairing::await_response(&self.relay, &code).await?;
            if pending.is_some() {
                break;
            }
            tokio::time::sleep(PAIRING_POLL_INTERVAL).await;
        }
        let pending = pending.ok_or_else(|| GhostError::Network("the new device never answered".into()))?;
        if pending.code != shown_on_new {
            return Err(GhostError::AuthenticationFailed);
        }
        let mut draft = flows::pairing::post_draft(&self.client, &self.relay, &self.relay, &code, &pending).await?;

        // The new device counter-signs while it waits; this device completes the link.
        let existing = async {
            for _ in 0..PAIRING_POLLS {
                if let Some(label) = flows::pairing::complete(&self.client, &self.relay, &self.relay, &code, &pending, &mut draft).await? {
                    return Ok(label);
                }
                tokio::time::sleep(PAIRING_POLL_INTERVAL).await;
            }
            Err(GhostError::Network("the new device never signed the addition".into()))
        };
        let new = flows::pairing::wait_for_device(&guest, &code, &device_key, label, PAIRING_POLLS, PAIRING_POLL_INTERVAL);
        let (linked, added) = tokio::join!(existing, new);
        linked?;
        let (_log_state, added_at) = added?;

        // Active in the log from here: the record comes before anything that can fail.
        std::fs::create_dir_all(data_dir)?;
        let mut keys = [[0u8; 32]; 2];
        for key in &mut keys {
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, key);
        }
        let stored = StoredDevice {
            fingerprint: code.account_fp,
            signing_key: device_key.clone(),
            encryption_key: encryption_key.clone(),
            db_key: keys[0],
            mls_db_key: keys[1],
            added_at,
        };
        std::fs::write(data_dir.join(DEVICE_FILE), stored.to_bytes())?;
        std::fs::write(data_dir.join(DISPLAY_NAME_FILE), &display_name)?;
        let identity = flows::pairing::linked_identity(code.account_fp, device_key, encryption_key, added_at);
        let mut client = GhostClient::open(identity, stored.db_key, stored.mls_db_key, &data_dir.join(DATABASE_FILE))?;
        client.set_display_name(display_name);
        client.set_relay_vk(guest.get_relay_info().await?.relay_vk);
        let (relay, events) = relay_client(relay_url, &stored);
        let device = Self::assemble(data_dir, client, relay, events);
        let blob = flows::pairing::fetch_provision(&guest, &code, PAIRING_POLLS, PAIRING_POLL_INTERVAL).await?;
        flows::provision::consume(&device.client, &device.relay, &blob, flows::now_millis()).await?;
        Ok(device)
    }

    /// Create an invite to a server. Returns (token, key).
    pub async fn invite(&self, server_id: &[u8; 32]) -> Result<(String, [u8; 32])> {
        let invite = flows::invite::create(&self.client, &self.relay, server_id, None).await?;
        Ok((invite.token, invite.key))
    }

    /// Join a server through an invite on this device's relay.
    pub async fn join(&self, token: &str, key: &[u8; 32]) -> Result<[u8; 32]> {
        flows::invite::join(&self.client, &self.relay, &self.relay, token, key, flows::now_millis()).await
    }

    /// Join a server hosted on the relay at `relay_url` through an invite there, staying
    /// at home on this device's relay.
    pub async fn join_at(&self, relay_url: &str, token: &str, key: &[u8; 32]) -> Result<[u8; 32]> {
        let hosting = self.relay.at(relay_url);
        flows::invite::join(&self.client, &self.relay, &hosting, token, key, flows::now_millis()).await
    }

    /// Send a chat message and wait for where it stands: delivered, or queued when its
    /// connection ended first. A refusal is the error.
    pub async fn say(&self, server_id: &[u8; 32], channel_id: &[u8; 32], text: &str) -> Result<flows::messages::Landed> {
        let sent = flows::messages::send_text(&self.client, &self.relay, server_id, channel_id, text.as_bytes().to_vec()).await?;
        flows::messages::delivered(sent.outcome).await
    }

    /// Kick a member from a server, which keeps them from rejoining when the server and
    /// its relay can enforce it.
    pub async fn kick(&self, server_id: &[u8; 32], member: &[u8; 32]) -> Result<()> {
        flows::members::kick(&self.client, &self.relay, server_id, member).await
    }

    /// Take the relay's version of a halted server after all.
    pub async fn accept_relay_state(&self, server_id: &[u8; 32]) -> Result<()> {
        flows::server::accept_relay_state(&self.client, &self.relay, server_id).await
    }

    /// Let an account the server keeps out back in, so it may rejoin with an invite.
    pub async fn let_back_in(&self, server_id: &[u8; 32], account: &[u8; 32]) -> Result<()> {
        flows::members::let_back_in(&self.client, &self.relay, server_id, account).await
    }

    /// The account's devices, verified against the home's log, or as last verified while
    /// the home is out of reach.
    pub async fn devices(&self) -> Result<flows::devices::DeviceList> {
        flows::devices::list(&self.client, &self.relay).await
    }

    /// Remove another device of this account. While the home is unreachable the removal
    /// waits on this device and lands once the home is back.
    pub async fn revoke(&self, device_vk: &[u8; 32]) -> Result<RevokeOutcome> {
        flows::devices::revoke(&self.client, &self.relay, device_vk).await
    }

    pub async fn verifying_key(&self) -> [u8; 32] {
        self.client.lock().await.verifying_key_bytes()
    }

    /// Move the account's home to the relay at `relay_url`, which the recovery key
    /// authorises, and connect there. The account's other devices follow when their home
    /// connection is refused or at their next account check.
    pub async fn move_home(&self, relay_url: &str, recovery_key: &RecoveryKey) -> Result<()> {
        let new_home = self.relay.at(relay_url);
        flows::account::rehome(&self.client, &new_home, Some(&self.relay), recovery_key).await?;
        flows::account::follow_home(&self.client, &self.relay).await?;
        Ok(())
    }

    /// Where this device's home connection points.
    pub fn home_url(&self) -> String {
        self.relay.base_url()
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
