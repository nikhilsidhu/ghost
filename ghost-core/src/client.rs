use std::collections::HashMap;
use std::path::Path;

use openmls::prelude::KeyPackage;

use crate::crypto::GhostProvider;
use crate::error::Result;
use crate::identity::Identity;
use crate::mls::credential::generate_key_package;
use crate::mls::group::GhostGroup;
use crate::storage::{
    Channel, ChannelKind, GhostStore, Group, Member, MemberRole,
};
use crate::wire::derive_default_channel_id;

/// Session-level orchestration: holds identity, MLS state, and local storage.
pub struct GhostClient {
    identity: Identity,
    provider: GhostProvider,
    store: GhostStore,
    groups: HashMap<[u8; 32], GhostGroup>,
}

impl GhostClient {
    pub fn open(seed: [u8; 32], db_path: &Path) -> Result<Self> {
        let identity = Identity::from_seed(seed)?;
        let provider = GhostProvider::new();
        let store = GhostStore::open(&seed, db_path)?;
        Ok(Self {
            identity,
            provider,
            store,
            groups: HashMap::new(),
        })
    }

    pub fn open_in_memory(seed: [u8; 32]) -> Result<Self> {
        let identity = Identity::from_seed(seed)?;
        let provider = GhostProvider::new();
        let store = GhostStore::open_in_memory(&seed)?;
        Ok(Self {
            identity,
            provider,
            store,
            groups: HashMap::new(),
        })
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub fn fingerprint(&self) -> &[u8; 32] {
        &self.identity.fingerprint
    }

    pub fn store(&self) -> &GhostStore {
        &self.store
    }

    pub fn generate_key_package(&self) -> Result<KeyPackage> {
        generate_key_package(&self.provider, &self.identity)
    }

    pub fn create_group(&mut self, name: &str, timestamp: u64) -> Result<[u8; 32]> {
        let mut group_id = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut group_id);

        let ghost_group =
            GhostGroup::create_with_id(&self.provider, &self.identity, &group_id)?;

        self.store.insert_group(&Group {
            group_id,
            name: name.to_string(),
            creator_fp: self.identity.fingerprint,
            created_at: timestamp,
        })?;

        let channel_id = derive_default_channel_id(&group_id);
        self.store.insert_channel(&Channel {
            channel_id,
            group_id,
            name: "general".to_string(),
            kind: ChannelKind::Text,
            position: 0,
        })?;

        self.store.insert_member(&Member {
            group_id,
            fingerprint: self.identity.fingerprint,
            display_name: self.identity.display_name.clone(),
            role: MemberRole::Creator,
            joined_at: timestamp,
        })?;

        self.groups.insert(group_id, ghost_group);
        Ok(group_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_in_memory_succeeds() {
        let client = GhostClient::open_in_memory([0x01; 32]).unwrap();
        assert_eq!(client.fingerprint().len(), 32);
    }

    #[test]
    fn different_seeds_different_fingerprints() {
        let a = GhostClient::open_in_memory([0x01; 32]).unwrap();
        let b = GhostClient::open_in_memory([0x02; 32]).unwrap();
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn create_group_stores_records() {
        let mut client = GhostClient::open_in_memory([0x01; 32]).unwrap();
        let group_id = client.create_group("test-group", 1000).unwrap();

        let group = client.store().get_group(&group_id).unwrap();
        assert_eq!(group.name, "test-group");
        assert_eq!(group.creator_fp, *client.fingerprint());
        assert_eq!(group.created_at, 1000);

        let channels = client.store().list_channels(&group_id).unwrap();
        assert_eq!(channels.len(), 1);
        assert_eq!(channels[0].name, "general");
        assert_eq!(channels[0].kind, ChannelKind::Text);
        assert_eq!(channels[0].channel_id, derive_default_channel_id(&group_id));

        let members = client.store().list_members(&group_id).unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].fingerprint, *client.fingerprint());
        assert_eq!(members[0].role, MemberRole::Creator);
    }
}
