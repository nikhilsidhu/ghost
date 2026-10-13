//! Other accounts' identity logs as this device has checked them, and the relay's
//! key-transparency heads it accepted: what credentials and claimed heads are judged
//! against. The logic lives with the cache in `idlog_cache`; these hand it the store.

use crate::error::Result;
use crate::idlog_cache::{self, HeadClaim};

use super::GhostClient;

impl GhostClient {
    /// The head of an account's identity log as cached: its sequence and hash.
    pub fn cached_head(&self, account_fp: &[u8; 32]) -> Option<(u64, [u8; 32])> {
        self.idlog_cache.get(account_fp).map(|state| (state.head_seq, state.head_hash))
    }

    /// The home relay an account's cached log names, if the log is cached and names one.
    pub fn cached_home_relay(&self, account_fp: &[u8; 32]) -> Option<[u8; 32]> {
        self.idlog_cache.get(account_fp).and_then(|state| state.home_relay_vk)
    }

    /// Validate an anchored identity log (chain plus every home anchor), merge it into
    /// the local cache, and return the account's state.
    pub fn cache_anchored_log(&mut self, account_fp: &[u8; 32], log: &crate::relay::AnchoredLog) -> Result<ghost_wire::idlog::LogState> {
        self.idlog_cache.cache_anchored_log(self.provider.store(), &self.identity.fingerprint, account_fp, log)
    }

    /// Last KT head accepted from this relay, if any.
    pub fn kt_head(&self, relay_vk: &[u8; 32]) -> Result<Option<ghost_wire::merkle::Checkpoint>> {
        idlog_cache::kt_head(self.provider.store(), relay_vk)
    }

    /// Accept a new KT head from `relay_vk`: it must be signed by that relay and extend
    /// the last head accepted from it (`proof` covers the growth).
    pub fn accept_kt_head(
        &self,
        relay_vk: &[u8; 32],
        head: &ghost_wire::merkle::Checkpoint,
        proof: Option<&ghost_wire::merkle::ConsistencyProof>,
    ) -> Result<()> {
        idlog_cache::accept_kt_head(self.provider.store(), relay_vk, head, proof)
    }

    /// The cached identity log state for an account, loading it from the local
    /// database when it is not in memory yet. `None` if this device never cached it.
    pub fn cached_identity_log(&mut self, account_fp: &[u8; 32]) -> Result<Option<ghost_wire::idlog::LogState>> {
        Ok(self.idlog_cache.get_or_load(self.provider.store(), account_fp)?.cloned())
    }

    /// Validate a chain held locally and cache it, as when a device has just written
    /// entries itself.
    pub fn cache_identity_chain(&mut self, entries: &[ghost_wire::idlog::LogEntry]) -> Result<()> {
        self.idlog_cache.insert_chain(entries)
    }

    /// This device's own account, as its cached log has it.
    pub fn own_log(&self) -> Option<&ghost_wire::idlog::LogState> {
        self.idlog_cache.get(&self.identity.fingerprint)
    }

    /// Judge the head a message's sender claims for its own identity log against the
    /// cached copy of that log.
    pub fn judge_head(&self, account_fp: &[u8; 32], claimed: &[u8; 32]) -> HeadClaim {
        self.idlog_cache.judge_head(account_fp, claimed)
    }
}
