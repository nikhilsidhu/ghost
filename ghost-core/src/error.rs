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

    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, GhostError>;
