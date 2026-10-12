//! What a command reports when it fails: a code the front end branches on and a message
//! for the user. Core errors map to codes here, once, so the front end never matches on
//! message text.

use ghost_core::error::GhostError;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "ErrorCode"))]
pub enum ErrorCode {
    /// A relay could not be reached, failed, or the connection dropped.
    Network,
    /// What was asked for is not there: an expired pairing code, an unknown account.
    NotFound,
    /// The relay refused because its state moved on; trying again may work.
    Conflict,
    /// A relay refused the request for another reason.
    RelayRefused,
    /// The relay reached is not the one the request was for.
    WrongRelay,
    /// This account may not do that in the server.
    PermissionDenied,
    /// A key, code or passphrase that does not fit.
    WrongKey,
    /// Input the command cannot use.
    BadInput,
    /// The command does not apply to where the account or device stands.
    WrongState,
    /// Waiting on another party ran out.
    TimedOut,
    /// A relay refuses more attempts for now; the message says when to try again.
    RateLimited,
    /// This account was removed from the server.
    Removed,
    /// This device was revoked from the account.
    Revoked,
    /// Anything else; the message says what.
    Internal,
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "CommandError"))]
pub struct CommandError {
    pub code: ErrorCode,
    pub message: String,
}

pub type CommandResult<T> = Result<T, CommandError>;

impl CommandError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }

    pub fn input(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::BadInput, message)
    }

    pub fn state(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::WrongState, message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Internal, message)
    }

    /// Say what was being done when it failed.
    pub fn context(mut self, what: &str) -> Self {
        self.message = format!("{what}: {}", self.message);
        self
    }
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl From<GhostError> for CommandError {
    fn from(e: GhostError) -> Self {
        let code = match &e {
            GhostError::Network(_) => ErrorCode::Network,
            GhostError::RelayStatus { status: 404, .. } => ErrorCode::NotFound,
            GhostError::RelayStatus { status: 409, .. } | GhostError::GroupMoved => ErrorCode::Conflict,
            GhostError::RelayStatus { status: 500..=599, .. } => ErrorCode::Network,
            GhostError::RelayStatus { .. } => ErrorCode::RelayRefused,
            GhostError::PermissionDenied(_) => ErrorCode::PermissionDenied,
            // A sealed blob that does not open, or a key that does not verify: the
            // key, code or passphrase given does not fit.
            GhostError::RecoveryKeyTypo | GhostError::AuthenticationFailed | GhostError::InvalidKey(_) | GhostError::Crypto(_) => {
                ErrorCode::WrongKey
            }
            // Codes, links and keys the user typed are parsed before anything is sent.
            GhostError::Format(_) => ErrorCode::BadInput,
            GhostError::TimedOut(_) => ErrorCode::TimedOut,
            GhostError::RateLimited(_) => ErrorCode::RateLimited,
            GhostError::RemovedFromServer => ErrorCode::Removed,
            GhostError::DeviceRevoked(_) => ErrorCode::Revoked,
            _ => ErrorCode::Internal,
        };
        Self { code, message: e.to_string() }
    }
}

impl From<std::io::Error> for CommandError {
    fn from(e: std::io::Error) -> Self {
        Self::internal(e.to_string())
    }
}
