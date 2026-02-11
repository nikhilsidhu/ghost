use axum::extract::State;
use axum::Json;
use serde::Serialize;
use std::sync::atomic::Ordering;

use crate::state::AppState;

#[derive(Serialize)]
pub struct HealthResponse {
    pub version: &'static str,
    pub uptime_secs: u64,
    pub active_mailboxes: usize,
    pub blob_count: usize,
    pub memory_bytes: usize,
}

pub async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    let map = state.mailboxes.read().await;
    let active_mailboxes = map.len();
    let blob_count: usize = map.values().map(|m| m.blobs.len()).sum();
    drop(map);

    Json(HealthResponse {
        version: env!("CARGO_PKG_VERSION"),
        uptime_secs: state.start_time.elapsed().as_secs(),
        active_mailboxes,
        blob_count,
        memory_bytes: state.memory_used.load(Ordering::Relaxed),
    })
}
