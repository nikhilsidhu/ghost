use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, RwLock};

use crate::relay_task::LiveState;

use ghost_core::account_keys::RecoveryKey;
use ghost_core::client::GhostClient;
use ghost_core::flows::pairing::{PairingCode, PendingDevice};
use ghost_core::flows::recovery::Located;
use ghost_core::identity::log::LogEntry;
use ghost_core::identity::NewAccount;
use ghost_core::relay::RelayClient;
use tokio::sync::Mutex;

use crate::audio::CpalDevices;
use crate::config::GhostConfig;
use ghost_audio::VoiceAudio;
use ghost_core::flows::presence::PresenceInfo;
use ghost_core::voice::Voice;

/// Device credentials used to authenticate relay clients. Kept outside GhostClient so a
/// relay client can be rebuilt without taking the heavy client mutex.
pub struct AuthMaterial {
    pub account_fp: [u8; 32],
    pub device_vk: [u8; 32],
    pub signing_key: ed25519_dalek::SigningKey,
}

/// Where this device stands with its account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountPhase {
    /// No account yet: the client runs a provisional identity until one is made, linked
    /// or recovered.
    None,
    Ready,
}

/// An account made but not published: nothing leaves this device until its user has
/// typed the recovery key back.
pub struct PendingCreation {
    pub account: NewAccount,
    pub recovery_key: RecoveryKey,
    pub display_name: String,
    pub relay_url: String,
}

/// A pairing this device opened, as far as it has got.
pub struct PendingPairing {
    pub code: PairingCode,
    /// The new device's answer, once it arrives; the user compares codes before going on.
    pub device: Option<PendingDevice>,
    /// The addition drafted after the user confirmed, awaiting the new device's signature.
    pub draft: Option<LogEntry>,
}

/// A recovery begun but not run: the new key is shown and typed back first.
pub struct PendingRecovery {
    pub relay_url: String,
    pub located: Located,
    /// The key the user recovers with.
    pub recovery_key: RecoveryKey,
    pub new_key: RecoveryKey,
    /// What the recovered device will be called in the account's device list.
    pub device_label: String,
}

/// A replacement of the recovery key begun but not made: the new key is shown and typed
/// back first; the current one authorizes the change.
pub struct PendingNewKey {
    pub current: RecoveryKey,
    pub new_key: RecoveryKey,
}

/// What the session, idle and voice loops run on, cloned out of the app state.
#[derive(Clone)]
pub struct SessionHandles {
    pub client: Arc<Mutex<GhostClient>>,
    pub relay: Arc<RelayClient>,
    pub presence: Arc<Mutex<PresenceInfo>>,
    pub voice: Voice,
    pub audio: Arc<VoiceAudio>,
    pub config: Arc<Mutex<GhostConfig>>,
    pub config_path: PathBuf,
    /// Holds the avatar cache.
    pub data_dir: PathBuf,
    pub live: Arc<std::sync::Mutex<LiveState>>,
    /// Whether the call's mute is the one going idle applied, which the return from idle
    /// lifts; a mute or deafen the user chooses takes it over.
    pub idle_mute: Arc<AtomicBool>,
}

pub struct AppState {
    pub client: Arc<Mutex<GhostClient>>,
    /// This device's one relay client, for the life of the process: pointing the app at
    /// another relay or another identity changes it in place and restarts its event stream.
    pub relay: Arc<RelayClient>,
    pub config_path: PathBuf,
    pub config: Arc<Mutex<GhostConfig>>,
    pub voice: Voice,
    /// The voice calls' audio, whose settings commands change directly.
    pub audio: Arc<VoiceAudio>,
    /// The devices calls use, chosen again at each join.
    pub devices: Arc<CpalDevices>,
    pub presence: Arc<Mutex<PresenceInfo>>,
    pub phase: Arc<Mutex<AccountPhase>>,
    pub pending_creation: Arc<Mutex<Option<PendingCreation>>>,
    pub pending_pairing: Arc<Mutex<Option<PendingPairing>>>,
    pub pending_recovery: Arc<Mutex<Option<PendingRecovery>>>,
    pub pending_new_key: Arc<Mutex<Option<PendingNewKey>>>,
    /// The running session loop, awaited when the relay client is replaced.
    pub relay_task_handle: Arc<Mutex<Option<tauri::async_runtime::JoinHandle<()>>>>,
    /// Device auth material for building relay clients during hot-swaps.
    pub auth: Arc<RwLock<AuthMaterial>>,
    /// The latest event-only state, for a front end that starts after it was reported.
    pub live: Arc<std::sync::Mutex<LiveState>>,
    /// Whether the call's mute is the one going idle applied (see `SessionHandles`).
    pub idle_mute: Arc<AtomicBool>,
}

impl AppState {
    pub fn handles(&self) -> SessionHandles {
        SessionHandles {
            client: self.client.clone(),
            relay: self.relay.clone(),
            presence: self.presence.clone(),
            voice: self.voice.clone(),
            audio: self.audio.clone(),
            config: self.config.clone(),
            config_path: self.config_path.clone(),
            data_dir: self.data_dir(),
            live: self.live.clone(),
            idle_mute: self.idle_mute.clone(),
        }
    }

    /// The directory holding the device's databases, config and caches.
    pub fn data_dir(&self) -> PathBuf {
        self.config_path.parent().expect("the config file is inside the data directory").to_path_buf()
    }

    /// The URL of the relay this device connects to.
    pub fn relay_url(&self) -> String {
        self.relay.base_url()
    }
}
