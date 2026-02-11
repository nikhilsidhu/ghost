use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("not found")]
    NotFound,

    #[error("gone: {0}")]
    Gone(String),

    #[error("payload too large")]
    PayloadTooLarge,

    #[error("storage full")]
    StorageFull,
}

impl IntoResponse for RelayError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            Self::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            Self::NotFound => (StatusCode::NOT_FOUND, "not found".into()),
            Self::Gone(msg) => (StatusCode::GONE, msg.clone()),
            Self::PayloadTooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "payload too large".into()),
            Self::StorageFull => (StatusCode::INSUFFICIENT_STORAGE, "storage full".into()),
        };
        (status, body).into_response()
    }
}

pub type Result<T> = std::result::Result<T, RelayError>;
