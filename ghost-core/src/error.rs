use ghost_wire::short_id;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum GhostError {
    #[error("crypto: {0}")]
    Crypto(String),

    #[error("keyring: {0}")]
    Keyring(#[from] keyring::Error),

    #[error("invalid key material: {0}")]
    InvalidKey(String),

    #[error("export/import: {0}")]
    Export(String),

    #[error("authentication failed")]
    AuthenticationFailed,

    #[error("invalid format: {0}")]
    Format(String),

    #[error("MLS: {0}")]
    Mls(String),

    #[error("database: {0}")]
    Database(String),

    #[error("server not loaded: {0}")]
    ServerNotLoaded(String),

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// A commit the relay accepted but the group's rules, as this device holds them,
    /// forbid. The device keeps its copy from before it until the person decides.
    #[error("the server's rules forbid this change: {0}")]
    PolicyRefused(String),

    /// The relay refused a commit built on an epoch the group has left: catch up and retry.
    #[error("the group changed meanwhile; catch up and try again")]
    GroupMoved,

    #[error("received own message (relay echo)")]
    SelfMessage,

    /// A private channel commit was authorized at a server group epoch this client
    /// has not reached; hold the blob until the server group catches up.
    #[error("server group must reach epoch {epoch} first")]
    PolicyBehind { server_mailbox: [u8; 32], epoch: u64 },

    #[error("identity log: {0}")]
    IdentityLog(String),

    /// The sender's device is one its account's log revokes, or its credential names an
    /// entry that log contradicts: refused by design, not something this device failed
    /// to read.
    #[error("sender refused: {0}")]
    SenderRefused(String),

    /// The receiver's log for this account does not list the device yet. Fetch the
    /// account's log and try again; refuse if the device is still not there.
    #[error("a device of account {} is not in its identity log", short_id(account_fp))]
    UnknownDevice { account_fp: [u8; 32] },

    /// A recovery key that does not decode or fails its checksum.
    #[error("that recovery key has a typo")]
    RecoveryKeyTypo,

    /// The account key needed is not held: the account has none yet, its current
    /// generation must be fetched, or it no longer covers the account's devices.
    #[error("account key: {0}")]
    AccountKeyUnavailable(String),

    /// A copy of an account key opened to a seed other than the one its entry
    /// published: the device that wrote the generation made a bad copy.
    #[error("the copy of account key generation {generation} does not match its entry")]
    BadAccountKeyCopy { generation: u32 },

    #[error("network: {0}")]
    Network(String),

    /// Waiting on another party ran out: the user's other device, a relay's answer.
    #[error("timed out: {0}")]
    TimedOut(String),

    /// The relay answered with a non-success HTTP status. Callers branch on
    /// `status` (404, 409, ...) instead of matching on error strings; `message`
    /// is the relay's explanation, for logs.
    #[error("relay: {context}: HTTP {status}: {message}")]
    RelayStatus { status: u16, context: String, message: String },

    /// This account was removed from the server and has not been let back in, so it may
    /// neither take part nor rejoin.
    #[error("you were removed from this server; someone who can kick has to let you back in")]
    RemovedFromServer,

    /// The relay refused more attempts for now; how long until it takes one again,
    /// when it said.
    #[error("the relay is refusing more attempts for now; try again {}", retry_phrase(.0))]
    RateLimited(Option<std::time::Duration>),

    /// A relay refused this device because the account's log revokes it; what revoked
    /// it, when the relay said.
    #[error("this device was removed from its account")]
    DeviceRevoked(Option<ghost_wire::RevocationCause>),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// When to try again, as a person reads it.
fn retry_phrase(wait: &Option<std::time::Duration>) -> String {
    const MINUTE: u64 = 60;
    const HOUR: u64 = 60 * MINUTE;
    match wait.map(|w| w.as_secs()) {
        None => "later".into(),
        Some(s) if s <= MINUTE => "in a minute".into(),
        Some(s) if s < HOUR => format!("in {} minutes", s.div_ceil(MINUTE)),
        Some(s) if s <= HOUR => "in an hour".into(),
        Some(s) => format!("in {} hours", s.div_ceil(HOUR)),
    }
}

impl From<ghost_wire::bytes::ReadError> for GhostError {
    fn from(e: ghost_wire::bytes::ReadError) -> Self {
        GhostError::Format(e.to_string())
    }
}

impl From<ghost_wire::idlog::IdlogError> for GhostError {
    fn from(e: ghost_wire::idlog::IdlogError) -> Self {
        match e {
            ghost_wire::idlog::IdlogError::Format(msg) => GhostError::Format(msg),
            ghost_wire::idlog::IdlogError::InvalidKey(msg) => GhostError::InvalidKey(msg),
            ghost_wire::idlog::IdlogError::AuthenticationFailed => GhostError::AuthenticationFailed,
        }
    }
}

pub type Result<T> = std::result::Result<T, GhostError>;

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn a_rate_limit_says_when_to_try_again() {
        let says = |wait: Option<u64>| GhostError::RateLimited(wait.map(Duration::from_secs)).to_string();
        assert!(says(None).ends_with("try again later"));
        assert!(says(Some(20)).ends_with("in a minute"));
        assert!(says(Some(61)).ends_with("in 2 minutes"));
        assert!(says(Some(3600)).ends_with("in an hour"));
        assert!(says(Some(23 * 3600 + 1)).ends_with("in 24 hours"));
    }
}
