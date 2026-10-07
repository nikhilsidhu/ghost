use axum::extract::State;
use axum::Json;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ghost_wire::relay_ref::RelayRef;
use serde::Serialize;

use crate::error::Result;
use crate::state::AppState;

/// Protocol generation this relay speaks; 2 adds anchored logs and multi-relay accounts.
pub const PROTOCOL_VERSION: u32 = 2;

#[derive(Serialize)]
pub struct RelayInfo {
    pub relay_vk: String,
    pub protocol: u32,
    /// base64url `RelayRef`; key-only when no public URL is configured.
    pub r#ref: String,
    /// base64 of the latest KT checkpoint, absent before the first entry.
    pub kt_head: Option<String>,
}

/// GET /relay — identity and reachability of this relay.
pub async fn get(State(state): State<AppState>) -> Result<Json<RelayInfo>> {
    let relay_ref = match &state.config.public_url {
        Some(url) => RelayRef::https(state.relay_vk, url),
        None => RelayRef::key_only(state.relay_vk),
    };
    let kt_head = state.storage.kt_load_checkpoint()?.map(|cp| B64.encode(cp));
    Ok(Json(RelayInfo {
        relay_vk: hex::encode(state.relay_vk),
        protocol: PROTOCOL_VERSION,
        r#ref: relay_ref.encode(),
        kt_head,
    }))
}
