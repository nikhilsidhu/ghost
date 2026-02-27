use std::path::PathBuf;
use std::sync::Arc;

use ghost_core::client::GhostClient;
use ghost_core::relay::RelayClient;
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::config::GhostConfig;
use crate::presence::PresenceInfo;
use crate::voice_task::VoiceHandle;

pub struct AppState {
    pub client: Arc<Mutex<GhostClient>>,
    pub relay: Arc<Mutex<RelayClient>>,
    pub relay_url: Arc<Mutex<String>>,
    pub http: reqwest::Client,
    pub config_path: PathBuf,
    pub config: Arc<Mutex<GhostConfig>>,
    pub voice: VoiceHandle,
    pub presence: Arc<Mutex<PresenceInfo>>,
    pub pairing_secret: Arc<Mutex<Option<Zeroizing<[u8; 32]>>>>,
    /// Holds the account seed between creation and recovery passphrase setup (or skip).
    pub recovery_seed: Arc<Mutex<Option<Zeroizing<[u8; 32]>>>>,
    /// Handle for the running relay task — used to abort it before hot-swap.
    pub relay_task_handle: Arc<Mutex<Option<tauri::async_runtime::JoinHandle<()>>>>,
}

pub fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
