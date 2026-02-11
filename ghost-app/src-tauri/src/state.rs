use std::sync::Mutex;

use ghost_core::client::GhostClient;

pub struct AppState {
    pub client: Mutex<GhostClient>,
}
