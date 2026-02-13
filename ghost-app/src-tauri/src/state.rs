use std::path::PathBuf;
use std::sync::Arc;

use ghost_core::client::GhostClient;
use ghost_core::relay::RelayClient;
use tokio::sync::Mutex;

pub struct AppState {
    pub client: Arc<Mutex<GhostClient>>,
    pub relay: Arc<Mutex<RelayClient>>,
    pub relay_url: String,
    pub http: reqwest::Client,
    pub config_path: PathBuf,
}
