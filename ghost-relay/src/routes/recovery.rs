use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use ghost_wire::recovery_bundle::{RecoveryBundle, RECOVERY_BUNDLE_MAX_BYTES};

use crate::auth::DeviceAuth;
use crate::error::{RelayError, Result};
use crate::state::AppState;

use super::decode_account_fp;

/// PUT /recovery/{account_fp_hex} — store the account's RecoveryBundle.
/// 409 when the stored bundle's generation is equal or newer.
pub async fn put(
    auth: DeviceAuth,
    State(state): State<AppState>,
    Path(account_fp_hex): Path<String>,
    body: Bytes,
) -> Result<StatusCode> {
    let account_fp = decode_account_fp(&account_fp_hex)?;
    if auth.account_fp != account_fp {
        return Err(RelayError::Unauthorized("account mismatch".into()));
    }
    if body.len() > RECOVERY_BUNDLE_MAX_BYTES {
        return Err(RelayError::PayloadTooLarge);
    }
    let bundle = RecoveryBundle::from_bytes(&body).map_err(|e| RelayError::BadRequest(e.to_string()))?;
    state.storage.put_recovery_bundle(&account_fp, bundle.generation, &body)?;
    Ok(StatusCode::NO_CONTENT)
}

/// GET /recovery/{account_fp_hex} — fetch the RecoveryBundle (rate-limited, no auth:
/// the recovering device has no key yet).
pub async fn get(
    State(state): State<AppState>,
    Path(account_fp_hex): Path<String>,
) -> Result<impl IntoResponse> {
    let account_fp = decode_account_fp(&account_fp_hex)?;
    if !state.recovery_limiter.check(&account_fp) {
        return Err(RelayError::RateLimited);
    }
    match state.storage.get_recovery_bundle(&account_fp)? {
        // Rows from before bundles existed hold the bare blob; serve it as generation 0.
        Some((0, blob)) if RecoveryBundle::from_bytes(&blob).is_err() => {
            let bundle = RecoveryBundle { generation: 0, recovery_blob: blob, master_blob: Vec::new() };
            Ok((StatusCode::OK, bundle.to_bytes()))
        }
        Some((_, bundle)) => Ok((StatusCode::OK, bundle)),
        None => Err(RelayError::NotFound),
    }
}
