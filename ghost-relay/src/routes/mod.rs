mod blob;
mod health;
mod ws;

use axum::routing::{delete, get, post};
use axum::Router;

use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health::health))
        .route("/box/{mailbox_id}", post(blob::post_blob).get(blob::get_blobs))
        .route(
            "/box/{mailbox_id}/{blob_id}",
            delete(blob::delete_blob),
        )
        .route("/ws/{mailbox_id}", get(ws::ws_upgrade))
        .with_state(state)
}
