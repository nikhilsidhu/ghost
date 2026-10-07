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

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("conflict")]
    Conflict,

    /// This relay does not sequence the account's log; the body names the home.
    #[error("wrong home: {0}")]
    WrongHome(String),

    /// Well-formed but fails a cryptographic check (anchor, chain, generation).
    #[error("unprocessable: {0}")]
    Unprocessable(String),

    #[error("rate limited")]
    RateLimited,

    #[error("storage error: {0}")]
    Storage(String),
}

impl IntoResponse for RelayError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            Self::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            Self::NotFound => (StatusCode::NOT_FOUND, "not found".into()),
            Self::Gone(msg) => (StatusCode::GONE, msg.clone()),
            Self::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg.clone()),
            Self::Forbidden(msg) => (StatusCode::FORBIDDEN, msg.clone()),
            Self::PayloadTooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "payload too large".into()),
            Self::Conflict => (StatusCode::CONFLICT, "conflict".into()),
            Self::WrongHome(msg) => (StatusCode::CONFLICT, msg.clone()),
            Self::Unprocessable(msg) => (StatusCode::UNPROCESSABLE_ENTITY, msg.clone()),
            Self::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate limited".into()),
            Self::Storage(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
        };
        (status, body).into_response()
    }
}

pub type Result<T> = std::result::Result<T, RelayError>;
