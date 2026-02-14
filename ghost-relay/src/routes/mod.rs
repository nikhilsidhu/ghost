mod blob;
mod health;
mod invite;
mod voice;
mod ws;

use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use axum::Router;

use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    let max_body = state.config.max_blob_size;
    Router::new()
        .route("/health", get(health::health))
        .route("/box/{mailbox_id}", post(blob::post_blob).get(blob::get_blobs))
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
