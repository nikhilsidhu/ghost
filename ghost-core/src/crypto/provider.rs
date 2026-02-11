use openmls_rust_crypto::RustCrypto;
use openmls_sqlite_storage::{Codec, SqliteStorageProvider};
use openmls_traits::OpenMlsProvider;
use rusqlite::Connection;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::error::{GhostError, Result};

#[derive(Default)]
pub struct JsonCodec;

impl Codec for JsonCodec {
    type Error = serde_json::Error;

    fn to_vec<T: Serialize>(value: &T) -> std::result::Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    fn from_slice<T: DeserializeOwned>(slice: &[u8]) -> std::result::Result<T, Self::Error> {
        serde_json::from_slice(slice)
    }
}

type Storage = SqliteStorageProvider<JsonCodec, Connection>;

/// Holds the OpenMLS crypto backend and persistent SQLite storage.
pub struct GhostProvider {
    crypto: RustCrypto,
    storage: Storage,
}

impl GhostProvider {
    /// Create a provider backed by a persistent SQLite connection (already opened/encrypted).
    pub fn new(conn: Connection) -> Result<Self> {
        let mut storage = SqliteStorageProvider::new(conn);
        storage
            .run_migrations()
            .map_err(|e| GhostError::Database(format!("mls migrations: {e}")))?;
        Ok(Self {
            crypto: RustCrypto::default(),
            storage,
        })
    }

    /// Create a provider backed by an in-memory SQLite database (for testing).
    pub fn new_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()
            .map_err(|e| GhostError::Database(format!("mls in-memory: {e}")))?;
        Self::new(conn)
    }
}

impl OpenMlsProvider for GhostProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = Storage;

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }
}
