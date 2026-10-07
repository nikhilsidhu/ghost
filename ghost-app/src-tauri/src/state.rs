use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use ghost_core::client::GhostClient;
use ghost_core::relay::RelayClient;
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::config::GhostConfig;
use ghost_core::flows::presence::PresenceInfo;
use crate::voice_task::VoiceHandle;

/// Device credentials used to authenticate relay clients. Kept outside GhostClient so a
/// relay client can be rebuilt without taking the heavy client mutex.
pub struct AuthMaterial {
    pub account_fp: [u8; 32],
    pub device_vk: [u8; 32],
    pub signing_key: ed25519_dalek::SigningKey,
}

pub struct AppState {
    pub client: Arc<Mutex<GhostClient>>,
    pub relay: Arc<Mutex<RelayClient>>,
    pub relay_url: Arc<Mutex<String>>,
    pub config_path: PathBuf,
    pub config: Arc<Mutex<GhostConfig>>,
    pub voice: VoiceHandle,
    pub presence: Arc<Mutex<PresenceInfo>>,
    /// The code of the pairing session this device opened; its secret is wiped on drop.
    pub pairing_code: Arc<Mutex<Option<ghost_core::flows::pairing::PairingCode>>>,
    /// Holds the account seed between creation and recovery passphrase setup (or skip).
    pub recovery_seed: Arc<Mutex<Option<Zeroizing<[u8; 32]>>>>,
    /// Handle for the running relay task — used to abort it before hot-swap.
    pub relay_task_handle: Arc<Mutex<Option<tauri::async_runtime::JoinHandle<()>>>>,
    /// Device auth material for building relay clients during hot-swaps.
    pub auth: Arc<RwLock<AuthMaterial>>,
}

pub fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
