use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Deserialize;

use crate::error::{RelayError, Result};
use crate::state::AppState;

/// GET /kt/head — latest signed checkpoint (raw bytes).
pub async fn head(State(state): State<AppState>) -> Result<impl IntoResponse> {
    match state.storage.kt_load_checkpoint().await? {
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
    Ok((StatusCode::OK, state.consistency_proof(q.from, q.to).await?))
}
