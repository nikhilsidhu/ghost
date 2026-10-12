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

    /// The account was removed from the server and has not been let back in.
    #[error("removed from this server")]
    Removed,

    /// The account's log revokes the device that signed the request; what revoked it,
    /// when the log says, which only that device is told.
    #[error("this device was removed from its account")]
    DeviceRevoked(Option<ghost_wire::RevocationCause>),

    #[error("conflict")]
    Conflict,

    /// This relay does not sequence the account's log; the body names the home.
    #[error("wrong home: {0}")]
    WrongHome(String),

    /// Well-formed but fails a cryptographic check (anchor, chain, generation).
    #[error("unprocessable: {0}")]
    Unprocessable(String),

    /// Past an allowance; a request is let through again after the wait given.
    #[error("rate limited")]
    RateLimited(std::time::Duration),

    #[error("storage error: {0}")]
    Storage(String),
}

impl From<rusqlite::Error> for RelayError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Storage(e.to_string())
    }
}

impl RelayError {
    /// The HTTP status this error answers with; a WebSocket refusal carries the same.
    pub fn status(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Gone(_) => StatusCode::GONE,
            Self::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::Unauthorized(_) | Self::DeviceRevoked(_) => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) | Self::Removed => StatusCode::FORBIDDEN,
            Self::Conflict => StatusCode::CONFLICT,
            // The request belongs at another relay: the account's home.
            Self::WrongHome(_) => StatusCode::MISDIRECTED_REQUEST,
            Self::Unprocessable(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::RateLimited(_) => StatusCode::TOO_MANY_REQUESTS,
            Self::Storage(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for RelayError {
    fn into_response(self) -> Response {
        let body = match &self {
            Self::BadRequest(msg) | Self::Gone(msg) | Self::Unauthorized(msg) | Self::Forbidden(msg) => msg.clone(),
            Self::WrongHome(msg) | Self::Unprocessable(msg) | Self::Storage(msg) => msg.clone(),
            Self::Removed => {
                let headers = [(ghost_wire::REFUSAL_HEADER, ghost_wire::REFUSAL_REMOVED)];
                return (self.status(), headers, self.to_string()).into_response();
            }
            Self::DeviceRevoked(cause) => {
                let mut response = (self.status(), [(ghost_wire::REFUSAL_HEADER, ghost_wire::REFUSAL_DEVICE_REVOKED)], self.to_string()).into_response();
                if let Some(value) = cause.as_ref().and_then(|c| axum::http::HeaderValue::from_str(&c.encode()).ok()) {
                    response.headers_mut().insert(ghost_wire::REVOKED_BY_HEADER, value);
                }
                return response;
            }
            Self::RateLimited(wait) => {
                // Whole seconds, rounded up, as HTTP's Retry-After takes them.
                let seconds = wait.as_secs() + u64::from(wait.subsec_nanos() > 0);
                let headers = [(axum::http::header::RETRY_AFTER, seconds.to_string())];
                return (self.status(), headers, self.to_string()).into_response();
            }
            Self::NotFound | Self::PayloadTooLarge | Self::Conflict => self.to_string(),
        };
        (self.status(), body).into_response()
    }
}

pub type Result<T> = std::result::Result<T, RelayError>;
