//! Building identity log batches: entries appended together, each checked against
//! the state the ones before it produced, with the key sets they commit to.

use ed25519_dalek::SigningKey;
use ghost_wire::account_key::AccountKeySet;
use ghost_wire::batch::LogBatch;
use ghost_wire::idlog::{validate_entry, LogEntry, LogState};

use crate::account_keys::{holders, seal_key_set, AccountSeed};
use crate::error::Result;
use crate::identity::log::create_account_key;

pub struct BatchBuilder {
    state: LogState,
    entries: Vec<LogEntry>,
    key_sets: Vec<AccountKeySet>,
}

impl BatchBuilder {
    /// Start a batch that extends `state`.
    pub fn new(state: LogState) -> Self {
        Self { state, entries: Vec::new(), key_sets: Vec::new() }
    }

    /// The state after the entries added so far.
    pub fn state(&self) -> &LogState {
        &self.state
    }

    pub fn push(&mut self, entry: LogEntry) -> Result<()> {
        validate_entry(&mut self.state, &entry)?;
        self.entries.push(entry);
        Ok(())
    }

    /// Add the next account key generation, sealed to everyone the batch's state must
    /// cover and linking back to `previous`, written by `authorizer`. Returns the seed.
    pub fn push_rekey(&mut self, authorizer: &SigningKey, previous: Option<&AccountSeed>) -> Result<AccountSeed> {
        let generation = self.state.account_key().map_or(1, |k| k.generation + 1);
        let seed = AccountSeed::generate(generation);
        let set = seal_key_set(&self.state.account_fp, &seed, &holders(&self.state)?, previous)?;
        let entry = create_account_key(&self.state, authorizer, &seed.signing_key()?, seed.encryption_key()?.public(), &set);
        self.push(entry)?;
        self.key_sets.push(set);
        Ok(seed)
    }

    pub fn finish(self) -> LogBatch {
        LogBatch { entries: self.entries, key_sets: self.key_sets }
    }
}
