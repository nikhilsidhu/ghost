mod avatar;
mod blob;
mod idlog;
pub(crate) mod pair;
mod recovery;
mod relay_key;
mod server_info;
mod sync_state;
mod health;
mod invite;
mod voice;
mod ws;

use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post, put};
use axum::Router;

use crate::error::{RelayError, Result};
use crate::state::AppState;

pub(crate) fn decode_account_fp(hex: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex)
        .map_err(|_| RelayError::BadRequest("invalid hex account fingerprint".into()))?;
    bytes
        .try_into()
        .map_err(|_| RelayError::BadRequest("account fingerprint must be 32 bytes".into()))
}

pub fn router(state: AppState) -> Router {
    let max_body = state.config.max_blob_size;
    Router::new()
        .route("/health", get(health::health))
        .route("/relay_key", get(relay_key::get))
        .route("/box/{mailbox_id}", post(blob::post_blob).get(blob::get_blobs))
        .route("/box/{mailbox_id}/server_info", put(server_info::put).get(server_info::get))
        .route("/box/{mailbox_id}/avatar/{fingerprint}", put(avatar::put).get(avatar::get).delete(avatar::delete))
        .route("/idlog/{account_fp}", put(idlog::put).get(idlog::get))
        .route("/pair/{account_fp}", post(pair::post_offer).get(pair::get_offer))
        .route("/pair/{account_fp}/respond", post(pair::post_respond))
        .route("/pair/{account_fp}/response", get(pair::get_response))
        .route("/pair/{account_fp}/provision", put(pair::put_provision).get(pair::get_provision))
        .route("/recovery/{account_fp}", put(recovery::put).get(recovery::get))
        .route("/sync_state/{account_fp}", put(sync_state::put).get(sync_state::get))
        .route("/ws/{mailbox_id}", get(ws::ws_upgrade))
        .route("/voice/{channel_id}", get(voice::ws_upgrade))
        .route("/invite", post(invite::register))
        .route(
            "/invite/{token}/join",
            post(invite::join).get(invite::get_join),
        )
        .route(
            "/invite/{token}/accept",
            post(invite::post_accept).get(invite::get_accept),
        )
        .layer(DefaultBodyLimit::max(max_body))
        .with_state(state)
}
