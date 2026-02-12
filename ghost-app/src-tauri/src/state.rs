use std::sync::Mutex;

use ghost_core::client::GhostClient;

pub struct AppState {
    pub client: Mutex<GhostClient>,
    pub relay_url: String,
    pub http: reqwest::Client,
}
