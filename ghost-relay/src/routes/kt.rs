use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use ghost_wire::merkle::consistency_proof_from_store;
use serde::Deserialize;

use crate::error::{RelayError, Result};
use crate::state::AppState;

/// GET /kt/head — latest signed checkpoint (raw bytes).
pub async fn head(State(state): State<AppState>) -> Result<impl IntoResponse> {
    match state.storage.kt_load_checkpoint()? {
        Some(cp) => Ok((StatusCode::OK, cp)),
        None => Err(RelayError::NotFound),
    }
}

#[derive(Deserialize)]
pub struct ConsistencyQuery {
    pub from: u64,
    pub to: u64,
}

/// GET /kt/consistency-proof?from=N&to=M — consistency proof between tree sizes.
pub async fn consistency_proof(
    State(state): State<AppState>,
    Query(q): Query<ConsistencyQuery>,
) -> Result<impl IntoResponse> {
    if q.from == 0 || q.from > q.to {
        return Err(RelayError::BadRequest("invalid range".into()));
    }

    let tree = state.kt_tree.read().await;
    let tree_size = tree.size();
    drop(tree);

    if q.to > tree_size {
        return Err(RelayError::BadRequest(format!(
            "to ({}) exceeds tree size ({tree_size})",
            q.to,
        )));
    }

    let storage = &state.storage;
    let load = |start: u64, count: u64| -> Option<[u8; 32]> {
        storage.kt_load_hash(start, count).ok().flatten()
    };
    let proof = consistency_proof_from_store(q.from, q.to, &load);
    Ok((StatusCode::OK, proof.to_bytes()))
}
