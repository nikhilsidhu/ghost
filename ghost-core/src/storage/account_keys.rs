//! Seeds of the account key generations this device has opened. A fork can replace a
//! generation, so a stored seed is trusted only after checking it against the log.

use super::db;
use rusqlite::OptionalExtension;

use crate::account_keys::AccountSeed;
use crate::error::{GhostError, Result};

use super::GhostStore;

impl GhostStore {
    /// Keep a generation's seed, replacing one stored for the same generation.
    pub fn store_account_seed(&self, seed: &AccountSeed) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO account_key_seeds (generation, seed) VALUES (?1, ?2)
                 ON CONFLICT (generation) DO UPDATE SET seed = ?2",
                rusqlite::params![seed.generation() as i64, seed.bytes().as_slice()],
            )
            .map_err(db("store account key seed"))?;
        Ok(())
    }

    pub fn account_seed(&self, generation: u32) -> Result<Option<AccountSeed>> {
        let bytes: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT seed FROM account_key_seeds WHERE generation = ?1",
                [generation as i64],
                |row| row.get(0),
            )
            .optional()
            .map_err(db("read account key seed"))?;
        bytes
            .map(|b| {
                let seed: [u8; 32] = b
                    .try_into()
                    .map_err(|_| GhostError::Database("account key seed is not 32 bytes".into()))?;
                Ok(AccountSeed::from_bytes(generation, seed))
            })
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeds_roundtrip_and_a_generation_can_be_replaced() {
        let store = GhostStore::open_in_memory(&[0xAB; 32]).unwrap();
        assert!(store.account_seed(1).unwrap().is_none());
        let first = AccountSeed::generate(1);
        store.store_account_seed(&first).unwrap();
        assert_eq!(store.account_seed(1).unwrap().unwrap().bytes(), first.bytes());
        let replacement = AccountSeed::generate(1);
        store.store_account_seed(&replacement).unwrap();
        assert_eq!(store.account_seed(1).unwrap().unwrap().bytes(), replacement.bytes());
    }
}
