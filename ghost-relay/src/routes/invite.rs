use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::Deserialize;
use std::time::Duration;
use tokio::sync::broadcast;

use crate::constants::{DEFAULT_LONG_POLL_MS, MAX_LONG_POLL_MS, NOTIFY_CAPACITY};
use crate::error::{RelayError, Result};
use crate::state::{AppState, Invite};
use crate::util::now_millis;

#[derive(Deserialize)]
pub struct RegisterInvite {
    pub token: String,
    pub expires_at: u64,
}

pub async fn register(
    State(state): State<AppState>,
    Json(body): Json<RegisterInvite>,
) -> Result<StatusCode> {
    let (join_notify, _) = broadcast::channel(NOTIFY_CAPACITY);
    let (accept_notify, _) = broadcast::channel(NOTIFY_CAPACITY);

    let mut invites = state.invites.write().await;
    if invites.contains_key(&body.token) {
        return Err(RelayError::BadRequest("token already registered".into()));
    }
    invites.insert(
        body.token,
        Invite {
            expires_at: body.expires_at,
            join: None,
            accept: None,
            join_notify,
            accept_notify,
        },
    );

    Ok(StatusCode::CREATED)
}

pub async fn join(
    State(state): State<AppState>,
    Path(token): Path<String>,
    body: Bytes,
) -> Result<StatusCode> {
    let now = now_millis();
    let payload = body.to_vec();

    if !state.try_reserve(payload.len()) {
        return Err(RelayError::StorageFull);
    }

    let mut invites = state.invites.write().await;
    let invite = match invites.get_mut(&token) {
        Some(inv) => inv,
        None => {
            state.release(payload.len());
            return Err(RelayError::NotFound);
        }
    };

    if invite.expires_at <= now {
        state.release(payload.len());
        return Err(RelayError::Gone("invite expired".into()));
    }

    if invite.join.is_some() {
        state.release(payload.len());
        return Err(RelayError::BadRequest("already joined".into()));
    }

    invite.join = Some(payload);
    let _ = invite.join_notify.send(());

    Ok(StatusCode::ACCEPTED)
}

pub async fn get_join(
    State(state): State<AppState>,
    Path(token): Path<String>,
    headers: HeaderMap,
) -> Result<(StatusCode, Vec<u8>)> {
    let timeout_ms: u64 = headers
        .get("X-Ghost-Long-Poll")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_LONG_POLL_MS)
        .min(MAX_LONG_POLL_MS);

    // Check + subscribe under one lock to avoid race
    let mut rx = {
        let invites = state.invites.read().await;
        let invite = invites.get(&token).ok_or(RelayError::NotFound)?;
        if let Some(ref join) = invite.join {
            return Ok((StatusCode::OK, join.clone()));
        }
        invite.join_notify.subscribe()
    };

    let timeout = Duration::from_millis(timeout_ms);
    let _ = tokio::time::timeout(timeout, rx.recv()).await;

    let invites = state.invites.read().await;
    let invite = invites.get(&token).ok_or(RelayError::NotFound)?;
    match &invite.join {
        Some(join) => Ok((StatusCode::OK, join.clone())),
        None => Ok((StatusCode::NO_CONTENT, Vec::new())),
    }
}

pub async fn post_accept(
    State(state): State<AppState>,
    Path(token): Path<String>,
    body: Bytes,
) -> Result<StatusCode> {
    let payload = body.to_vec();

    if !state.try_reserve(payload.len()) {
        return Err(RelayError::StorageFull);
    }

    let mut invites = state.invites.write().await;
    let invite = match invites.get_mut(&token) {
        Some(inv) => inv,
        None => {
            state.release(payload.len());
            return Err(RelayError::NotFound);
        }
    };

    if invite.accept.is_some() {
        state.release(payload.len());
        return Err(RelayError::BadRequest("accept already posted".into()));
    }

    invite.accept = Some(payload);
    let _ = invite.accept_notify.send(());

    Ok(StatusCode::NO_CONTENT)
}

pub async fn get_accept(
    State(state): State<AppState>,
    Path(token): Path<String>,
    headers: HeaderMap,
) -> Result<(StatusCode, Vec<u8>)> {
    let timeout_ms: u64 = headers
        .get("X-Ghost-Long-Poll")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_LONG_POLL_MS)
        .min(MAX_LONG_POLL_MS);

    // Check + subscribe under one lock to avoid race
    let mut rx = {
        let invites = state.invites.read().await;
        let invite = invites.get(&token).ok_or(RelayError::NotFound)?;
        if let Some(ref accept) = invite.accept {
            return Ok((StatusCode::OK, accept.clone()));
        }
        invite.accept_notify.subscribe()
    };

    let timeout = Duration::from_millis(timeout_ms);
    let _ = tokio::time::timeout(timeout, rx.recv()).await;

    let invites = state.invites.read().await;
    let invite = invites.get(&token).ok_or(RelayError::NotFound)?;
    match &invite.accept {
        Some(accept) => Ok((StatusCode::OK, accept.clone())),
        None => Ok((StatusCode::NO_CONTENT, Vec::new())),
    }
}
