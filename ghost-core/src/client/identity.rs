//! This device's own account: its identity, keys, display name, the account seeds held,
//! and the home relay's key.

use crate::account_keys::AccountSeed;
use crate::error::{GhostError, Result};
use crate::identity::Identity;
use crate::storage::GhostStore;

use super::GhostClient;

impl GhostClient {
    /// Set the relay's verifying key for ExternalSendersExtension in new groups.
    pub fn set_relay_vk(&mut self, vk: [u8; 32]) {
        self.relay_vk = Some(vk);
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub fn fingerprint(&self) -> &[u8; 32] {
        &self.identity.fingerprint
    }

    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.identity.verifying_key.to_bytes()
    }

    pub fn signing_key_clone(&self) -> ed25519_dalek::SigningKey {
        self.identity.signing_key.clone()
    }

    pub fn store(&self) -> &GhostStore {
        self.provider.store()
    }

    /// Verifying key of the relay this client is connected to, once fetched.
    pub fn relay_vk(&self) -> Option<[u8; 32]> {
        self.relay_vk
    }

    /// Update own display name in identity and all server member records.
    pub fn set_display_name(&mut self, name: String) {
        let fp = self.identity.fingerprint;
        let server_ids = self.groups.servers();
        for server_id in &server_ids {
            let _ = self.provider.store().update_member_name(server_id, &fp, &name);
        }
        self.identity.display_name = name;
    }

    pub fn store_account_seed(&self, seed: &AccountSeed) -> Result<()> {
        self.provider.store().store_account_seed(seed)
    }

    /// A generation's seed, if held and it is the one the account's log published.
    pub fn account_seed(&self, generation: u32) -> Result<Option<AccountSeed>> {
        let Some(key) = self.own_log().and_then(|log| log.account_keys.iter().find(|k| k.generation == generation)) else {
            return Ok(None);
        };
        match self.provider.store().account_seed(generation)? {
            Some(seed) if seed.matches(key)? => Ok(Some(seed)),
            _ => Ok(None),
        }
    }

    /// The seed new data is sealed under: the account's current generation, and only
    /// while it covers exactly the account's devices, so nothing new is ever sealed to
    /// a key a revoked device holds.
    pub fn sealing_seed(&self) -> Result<AccountSeed> {
        let log = self.own_log().ok_or_else(|| GhostError::IdentityLog("own identity log is not cached".into()))?;
        let key = log
            .account_key()
            .ok_or_else(|| GhostError::AccountKeyUnavailable("the account has no account key yet".into()))?;
        if log.rekey_needed() {
            return Err(GhostError::AccountKeyUnavailable(format!("generation {} no longer covers the account", key.generation)));
        }
        let generation = key.generation;
        self.account_seed(generation)?
            .ok_or_else(|| GhostError::AccountKeyUnavailable(format!("generation {generation} is not held yet")))
    }
}
