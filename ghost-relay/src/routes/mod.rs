mod accounts;
mod avatar;
mod blob;
mod channels;
mod idlog;
mod kt;
pub(crate) mod pair;
mod relay;
mod server_info;
mod sync_state;
mod health;
mod invite;
mod voice;
mod ws;

use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post, put};
use axum::Router;

use crate::constants::MAX_KEY_SETS_BODY;
use crate::error::{RelayError, Result};
use crate::state::AppState;

pub(crate) fn decode_account_fp(hex: &str) -> Result<[u8; 32]> {
    decode_id32(hex, "account fingerprint")
}

/// Decode a hex path segment holding a 32-byte id; `what` names it in errors.
pub(crate) fn decode_id32(hex: &str, what: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex).map_err(|_| RelayError::BadRequest(format!("invalid hex {what}")))?;
    bytes
        .try_into()
        .map_err(|_| RelayError::BadRequest(format!("{what} must be 32 bytes")))
}

pub fn router(state: AppState) -> Router {
    let max_body = state.config.max_blob_size;
    Router::new()
        .route("/health", get(health::health))
        .route("/relay", get(relay::get))
        .route("/accounts/by_root", get(accounts::by_root))
        .route("/accounts/{account_fp}", get(accounts::get))
        .route("/accounts/{account_fp}/import", post(accounts::import))
        .route(
            "/accounts/{account_fp}/key_sets",
            get(accounts::get_key_sets)
                .put(accounts::put_key_sets)
                .layer(DefaultBodyLimit::max(MAX_KEY_SETS_BODY)),
        )
        .route("/accounts/{account_fp}/mirrors", put(accounts::put_mirrors))
        .route(
            "/accounts/{account_fp}/servers/{server_id}/location",
            put(accounts::put_server_location).get(accounts::get_server_location),
        )
        .route("/box/{mailbox_id}", post(blob::post_blob).delete(blob::delete_mailbox))
        .route("/box/{mailbox_id}/server_info", put(server_info::put).get(server_info::get))
        .route("/servers/{server_mailbox}/channels", get(channels::list))
        .route("/box/{mailbox_id}/avatar/{fingerprint}", put(avatar::put).get(avatar::get).delete(avatar::delete))
        .route("/idlog/{account_fp}", put(idlog::put).get(idlog::get))
        .route("/idlog/{account_fp}/anchored", put(idlog::put_anchored))
        .route(
            "/idlog/{account_fp}/batch",
            post(idlog::post_batch).layer(DefaultBodyLimit::max(ghost_wire::batch::MAX_BATCH_BYTES)),
        )
        .route("/kt/head", get(kt::head))
        .route("/kt/consistency-proof", get(kt::consistency_proof))
        .route("/pair/{account_fp}", post(pair::post_offer))
        .route("/pair/{account_fp}/{token}", get(pair::get_offer).delete(pair::delete_session))
        .route("/pair/{account_fp}/{token}/respond", post(pair::post_respond))
        .route("/pair/{account_fp}/{token}/response", get(pair::get_response))
        .route("/pair/{account_fp}/{token}/draft", put(pair::put_draft).get(pair::get_draft))
        .route("/pair/{account_fp}/{token}/signatures", post(pair::post_signatures).get(pair::get_signatures))
        .route("/pair/{account_fp}/{token}/provision", put(pair::put_provision).get(pair::get_provision))
        .route("/sync_state/{account_fp}", put(sync_state::put).get(sync_state::get))
        .route("/ws/{mailbox_id}", get(ws::ws_upgrade))
        .route("/voice/{mailbox_id}/{channel_id}", get(voice::ws_upgrade))
        .route("/invite", post(invite::register))
        .route("/invite/{token}/join", post(invite::join).get(invite::get_join))
        .layer(DefaultBodyLimit::max(max_body))
        // Outermost: every request's device signature is checked before any handler runs.
        .layer(axum::middleware::from_fn_with_state(state.clone(), crate::auth::verify_signatures))
        .with_state(state)
}
