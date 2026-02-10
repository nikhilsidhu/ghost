use std::collections::HashMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use openmls::prelude::KeyPackage;

use crate::crypto::{GhostProvider, MessageType};
use crate::error::{GhostError, Result};
use crate::identity::Identity;
use crate::mls::credential::generate_key_package;
use crate::mls::group::GhostGroup;
use crate::storage::{
    Channel, ChannelKind, GhostStore, Group, Member, MemberRole, StoredMessage,
};
use crate::wire::{
    derive_default_channel_id, group_mailbox_id, open, seal, ApplicationMessage, Outbound,
};

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

    pub fn send_message(
        &mut self,
        group_id: &[u8; 32],
        channel_id: &[u8; 32],
        content: Vec<u8>,
        references: Vec<[u8; 32]>,
        timestamp: u64,
    ) -> Result<(Outbound, [u8; 32])> {
        let group = self.groups.get_mut(group_id).ok_or_else(|| {
            GhostError::GroupNotLoaded(hex::encode(&group_id[..8]))
        })?;

        let msg = ApplicationMessage::new(
            MessageType::Text,
            *channel_id,
            self.identity.fingerprint,
            timestamp,
            references,
            content,
        )?;

        let blob = seal(group, &self.provider, &msg)?;
        let mailbox_id = group_mailbox_id(group.group_id());
        let message_id = msg.message_id;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        self.store.insert_message(&StoredMessage {
            message_id: msg.message_id,
            channel_id: msg.channel_id,
            sender_fp: msg.sender_fp,
            message_type: msg.message_type as u8,
            timestamp: msg.timestamp,
            received_at: now,
            content: msg.content,
            expires_at: None,
            references: msg.references,
        })?;

        Ok((Outbound { mailbox_id, blob }, message_id))
    }

    /// Decrypt a blob and store the message. `received_at` is the relay-stamped arrival
    /// time (ms since epoch) used for ordering; pass 0 to fall back to local clock.
    pub fn receive_blob(
        &mut self,
        group_id: &[u8; 32],
        blob: &[u8],
        received_at: u64,
    ) -> Result<ApplicationMessage> {
        let group = self.groups.get_mut(group_id).ok_or_else(|| {
            GhostError::GroupNotLoaded(hex::encode(&group_id[..8]))
        })?;

        let msg = open(group, &self.provider, blob)?;

        let recv_ts = if received_at > 0 {
            received_at
        } else {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64
        };

        self.store.insert_message(&StoredMessage {
            message_id: msg.message_id,
            channel_id: msg.channel_id,
            sender_fp: msg.sender_fp,
            message_type: msg.message_type as u8,
            timestamp: msg.timestamp,
            received_at: recv_ts,
            content: msg.content.clone(),
            expires_at: None,
            references: msg.references.clone(),
        })?;

        Ok(msg)
    }

    pub fn invite_member(
        &mut self,
        group_id: &[u8; 32],
        key_package: KeyPackage,
        invitee_fp: [u8; 32],
        invitee_name: &str,
        timestamp: u64,
    ) -> Result<(Outbound, Vec<u8>)> {
        let group = self.groups.get_mut(group_id).ok_or_else(|| {
            GhostError::GroupNotLoaded(hex::encode(&group_id[..8]))
        })?;

        let (commit, welcome) = group.add_member(&self.provider, key_package)?;

        let commit_blob = commit
            .to_bytes()
            .map_err(|e| GhostError::Mls(format!("serialize commit: {e}")))?;
        let welcome_bytes = welcome
            .to_bytes()
            .map_err(|e| GhostError::Mls(format!("serialize welcome: {e}")))?;

        let mailbox_id = group_mailbox_id(group.group_id());

        self.store.insert_member(&Member {
            group_id: *group_id,
            fingerprint: invitee_fp,
            display_name: invitee_name.to_string(),
            role: MemberRole::Member,
            joined_at: timestamp,
        })?;

        Ok((Outbound { mailbox_id, blob: commit_blob }, welcome_bytes))
    }

    pub fn join_group(
        &mut self,
        group_id: &[u8; 32],
        welcome_bytes: &[u8],
        group_name: &str,
        timestamp: u64,
    ) -> Result<()> {
        let ghost_group =
            GhostGroup::join(&self.provider, &self.identity, welcome_bytes)?;

        self.store.insert_group(&Group {
            group_id: *group_id,
            name: group_name.to_string(),
            creator_fp: [0u8; 32],
            created_at: timestamp,
        })?;

        let channel_id = derive_default_channel_id(group_id);
        self.store.insert_channel(&Channel {
            channel_id,
            group_id: *group_id,
            name: "general".to_string(),
            kind: ChannelKind::Text,
            position: 0,
        })?;

        self.store.insert_member(&Member {
            group_id: *group_id,
            fingerprint: self.identity.fingerprint,
            display_name: self.identity.display_name.clone(),
            role: MemberRole::Member,
            joined_at: timestamp,
        })?;

        self.groups.insert(*group_id, ghost_group);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns (creator, joiner, group_id) with both clients in a shared MLS group.
    fn setup_two_clients() -> (GhostClient, GhostClient, [u8; 32]) {
        let mut c1 = GhostClient::open_in_memory([0x01; 32]).unwrap();
        let mut c2 = GhostClient::open_in_memory([0x02; 32]).unwrap();

        let group_id = c1.create_group("test", 1000).unwrap();

        let kp = c2.generate_key_package().unwrap();
        let fp = *c2.fingerprint();
        let name = c2.identity().display_name.clone();
        let (_outbound, welcome_bytes) =
            c1.invite_member(&group_id, kp, fp, &name, 1000).unwrap();

        c2.join_group(&group_id, &welcome_bytes, "test", 1000).unwrap();

        (c1, c2, group_id)
    }

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

    #[test]
    fn send_to_unknown_group_fails() {
        let mut client = GhostClient::open_in_memory([0x01; 32]).unwrap();
        let result = client.send_message(&[0xFF; 32], &[0xAA; 32], b"hi".to_vec(), vec![], 1000);
        assert!(matches!(result, Err(GhostError::GroupNotLoaded(_))));
    }

    #[test]
    fn receive_from_unknown_group_fails() {
        let mut client = GhostClient::open_in_memory([0x01; 32]).unwrap();
        let result = client.receive_blob(&[0xFF; 32], &[0x00; 64], 0);
        assert!(matches!(result, Err(GhostError::GroupNotLoaded(_))));
    }

    #[test]
    fn send_message_stores_in_db() {
        let (mut c1, _c2, group_id) = setup_two_clients();
        let channel_id = derive_default_channel_id(&group_id);

        let (_outbound, msg_id) = c1
            .send_message(&group_id, &channel_id, b"hello".to_vec(), vec![], 2000)
            .unwrap();

        let stored = c1.store().get_message(&msg_id).unwrap();
        assert_eq!(stored.content, b"hello");
        assert_eq!(stored.sender_fp, *c1.fingerprint());
        assert_eq!(stored.timestamp, 2000);
    }

    #[test]
    fn send_receive_roundtrip() {
        let (mut c1, mut c2, group_id) = setup_two_clients();
        let channel_id = derive_default_channel_id(&group_id);

        let (outbound, msg_id) = c1
            .send_message(&group_id, &channel_id, b"hello".to_vec(), vec![], 2000)
            .unwrap();

        let received = c2.receive_blob(&group_id, &outbound.blob, 0).unwrap();
        assert_eq!(received.content, b"hello");
        assert_eq!(received.sender_fp, *c1.fingerprint());
        assert_eq!(received.message_id, msg_id);

        let stored = c2.store().get_message(&msg_id).unwrap();
        assert_eq!(stored.content, b"hello");
    }

    #[test]
    fn two_client_full_flow() {
        let mut c1 = GhostClient::open_in_memory([0x01; 32]).unwrap();
        let mut c2 = GhostClient::open_in_memory([0x02; 32]).unwrap();

        let group_id = c1.create_group("full-flow", 1000).unwrap();
        let channel_id = derive_default_channel_id(&group_id);

        // c1 invites c2
        let kp = c2.generate_key_package().unwrap();
        let fp = *c2.fingerprint();
        let name = c2.identity().display_name.clone();
        let (_outbound, welcome) =
            c1.invite_member(&group_id, kp, fp, &name, 1000).unwrap();

        // c2 joins
        c2.join_group(&group_id, &welcome, "full-flow", 1000).unwrap();

        // c1 sends, c2 receives
        let (out1, id1) = c1
            .send_message(&group_id, &channel_id, b"from c1".to_vec(), vec![], 2000)
            .unwrap();
        let recv1 = c2.receive_blob(&group_id, &out1.blob, 0).unwrap();
        assert_eq!(recv1.content, b"from c1");
        assert_eq!(recv1.sender_fp, *c1.fingerprint());

        // c2 sends, c1 receives
        let (out2, id2) = c2
            .send_message(&group_id, &channel_id, b"from c2".to_vec(), vec![], 3000)
            .unwrap();
        let recv2 = c1.receive_blob(&group_id, &out2.blob, 0).unwrap();
        assert_eq!(recv2.content, b"from c2");
        assert_eq!(recv2.sender_fp, *c2.fingerprint());

        // Both stores have both messages
        assert_eq!(c1.store().get_message(&id1).unwrap().content, b"from c1");
        assert_eq!(c1.store().get_message(&id2).unwrap().content, b"from c2");
        assert_eq!(c2.store().get_message(&id1).unwrap().content, b"from c1");
        assert_eq!(c2.store().get_message(&id2).unwrap().content, b"from c2");
    }
}
