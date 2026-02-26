use std::collections::HashMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use openmls::prelude::KeyPackage;
use rusqlite::Connection;

use crate::crypto::{GhostProvider, MessageType};
use crate::error::{GhostError, Result};
use crate::identity::Identity;
use crate::mls::credential::generate_key_package;
use crate::mls::group::GhostGroup;
use crate::storage::{
    Channel, ChannelKind, GhostStore, Server, ServerKind, Member, MemberRole, StoredMessage,
};
use crate::wire::{
    derive_default_channel_id, mls_group_mailbox_id, open, open_any, seal, ApplicationMessage,
    InboundMessage, InviteChannel, InviteMember, InvitePayload, Outbound, ProvisionPayload,
};

/// Open an encrypted SQLite connection for MLS state, separate from the app DB.
fn open_mls_connection(mls_db_key: &[u8; 32], app_db_path: &Path) -> Result<Connection> {
    let mls_path = app_db_path.with_extension("mls.db");

    let conn = Connection::open(&mls_path)
        .map_err(|e| GhostError::Database(format!("open mls db: {e}")))?;

    conn.pragma_update(None, "key", format!("x'{}'", hex::encode(mls_db_key)))
        .map_err(|e| GhostError::Database(format!("set mls key: {e}")))?;

    conn.pragma_update(None, "journal_mode", "WAL")
        .map_err(|e| GhostError::Database(format!("set mls WAL: {e}")))?;

    Ok(conn)
}

pub enum ReceiveResult {
    Message(ApplicationMessage),
    CommitProcessed,
    /// This client was removed from the group by a commit.
    Kicked,
    /// A commit removed these members (fingerprints) from the group.
    MembersRemoved(Vec<[u8; 32]>),
    Skipped,
}

/// Session-level orchestration: holds identity, MLS state, and local storage.
pub struct GhostClient {
    identity: Identity,
    provider: GhostProvider,
    store: GhostStore,
    servers: HashMap<[u8; 32], GhostGroup>,
    /// mailbox_id → server_id for O(1) reverse lookup
    mailbox_map: HashMap<[u8; 32], [u8; 32]>,
}

impl GhostClient {
    pub fn open(identity: Identity, db_key: [u8; 32], mls_db_key: [u8; 32], db_path: &Path) -> Result<Self> {
        let store = GhostStore::open(&db_key, db_path)?;

        let mls_conn = open_mls_connection(&mls_db_key, db_path)?;
        let provider = GhostProvider::new(mls_conn)?;

        // Reload MLS groups that were persisted from previous sessions
        let mut servers = HashMap::new();
        if let Ok(stored_servers) = store.list_servers() {
            for s in &stored_servers {
                if let Ok(Some(ghost_group)) =
                    GhostGroup::load(&provider, &identity, &s.server_id)
                {
                    servers.insert(s.server_id, ghost_group);
                }
            }
        }

        let mailbox_map = servers
            .iter()
            .map(|(sid, g)| (mls_group_mailbox_id(g.group_id()), *sid))
            .collect();

        Ok(Self {
            identity,
            provider,
            store,
            servers,
            mailbox_map,
        })
    }

    pub fn open_in_memory(identity: Identity, db_key: [u8; 32]) -> Result<Self> {
        let provider = GhostProvider::new_in_memory()?;
        let store = GhostStore::open_in_memory(&db_key)?;
        Ok(Self {
            identity,
            provider,
            store,
            servers: HashMap::new(),
            mailbox_map: HashMap::new(),
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

    pub fn set_display_name(&mut self, name: String) {
        self.identity.display_name = name;
    }

    pub fn sync_key(&self) -> Option<[u8; 32]> {
        self.store
            .get_config_blob("sync_key")
            .ok()
            .flatten()
            .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
    }

    pub fn set_sync_key(&self, key: [u8; 32]) -> Result<()> {
        self.store.set_config_blob("sync_key", &key)
    }

    /// Export server metadata for provisioning a sibling device (no role check).
    pub fn export_provision_payload(&self, server_id: &[u8; 32]) -> Result<ProvisionPayload> {
        let group = self.servers.get(server_id).ok_or_else(|| {
            GhostError::ServerNotLoaded(hex::encode(&server_id[..8]))
        })?;
        let meta = self.store.get_server(server_id)?;
        let members = self.store.list_members(server_id)?;
        let channels = self.store.list_channels(server_id)?;
        let mailbox_id = mls_group_mailbox_id(group.group_id());

        Ok(ProvisionPayload {
            server_id: *server_id,
            server_name: meta.name,
            kind: meta.kind,
            members: members
                .iter()
                .map(|m| InviteMember {
                    fingerprint: m.fingerprint,
                    display_name: m.display_name.clone(),
                    role: m.role,
                })
                .collect(),
            channels: channels
                .iter()
                .map(|c| InviteChannel {
                    channel_id: c.channel_id,
                    name: c.name.clone(),
                    kind: c.kind,
                    position: c.position,
                })
                .collect(),
            mailbox_id,
        })
    }

    /// Join a server from a provision payload + fresh GroupInfo (handles duplicates).
    /// Returns (commit_bytes_to_broadcast, mailbox_id).
    pub fn join_from_provision(
        &mut self,
        payload: &ProvisionPayload,
        group_info_bytes: &[u8],
        timestamp: u64,
    ) -> Result<(Vec<u8>, [u8; 32])> {
        let (ghost_group, commit_bytes) = GhostGroup::join_by_external_commit(
            &self.provider,
            &self.identity,
            group_info_bytes,
        )?;

        let creator_fp = payload
            .members
            .iter()
            .find(|m| m.role == MemberRole::Creator)
            .map(|m| m.fingerprint)
            .unwrap_or([0u8; 32]);

        self.store.insert_server_if_not_exists(&Server {
            server_id: payload.server_id,
            name: payload.server_name.clone(),
            kind: payload.kind,
            creator_fp,
            created_at: timestamp,
        })?;

        for ch in &payload.channels {
            self.store.insert_channel_if_not_exists(&Channel {
                channel_id: ch.channel_id,
                server_id: payload.server_id,
                name: ch.name.clone(),
                kind: ch.kind,
                position: ch.position,
            })?;
        }

        for m in &payload.members {
            self.store.insert_member_if_not_exists(&Member {
                server_id: payload.server_id,
                fingerprint: m.fingerprint,
                display_name: m.display_name.clone(),
                role: m.role,
                joined_at: timestamp,
                avatar_hash: None,
                avatar_key: None,
            })?;
        }

        // Insert self as member
        self.store.insert_member_if_not_exists(&Member {
            server_id: payload.server_id,
            fingerprint: self.identity.fingerprint,
            display_name: self.identity.display_name.clone(),
            role: MemberRole::Member,
            joined_at: timestamp,
            avatar_hash: None,
            avatar_key: None,
        })?;

        let mailbox_id = mls_group_mailbox_id(ghost_group.group_id());
        self.servers.insert(payload.server_id, ghost_group);
        self.mailbox_map.insert(mailbox_id, payload.server_id);

        Ok((commit_bytes, mailbox_id))
    }

    pub fn generate_key_package(&self) -> Result<KeyPackage> {
        generate_key_package(&self.provider, &self.identity)
    }

    pub fn create_server(&mut self, name: &str, kind: ServerKind, timestamp: u64) -> Result<[u8; 32]> {
        let mut server_id = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut server_id);

        let ghost_group =
            GhostGroup::create_with_id(&self.provider, &self.identity, &server_id)?;

        self.store.insert_server(&Server {
            server_id,
            name: name.to_string(),
            kind,
            creator_fp: self.identity.fingerprint,
            created_at: timestamp,
        })?;

        let channel_name = match kind {
            ServerKind::Dm | ServerKind::Group => "messages",
            ServerKind::Server => "general",
        };
        let channel_id = derive_default_channel_id(&server_id);
        self.store.insert_channel(&Channel {
            channel_id,
            server_id,
            name: channel_name.to_string(),
            kind: ChannelKind::Text,
            position: 0,
        })?;

        self.store.insert_member(&Member {
            server_id,
            fingerprint: self.identity.fingerprint,
            display_name: self.identity.display_name.clone(),
            role: MemberRole::Creator,
            joined_at: timestamp,
            avatar_hash: None,
            avatar_key: None,
        })?;

        let mailbox_id = mls_group_mailbox_id(ghost_group.group_id());
        self.servers.insert(server_id, ghost_group);
        self.mailbox_map.insert(mailbox_id, server_id);
        Ok(server_id)
    }

    pub fn send_message(
        &mut self,
        server_id: &[u8; 32],
        channel_id: &[u8; 32],
        content: Vec<u8>,
        references: Vec<[u8; 32]>,
        timestamp: u64,
    ) -> Result<(Outbound, [u8; 32])> {
        let group = self.servers.get_mut(server_id).ok_or_else(|| {
            GhostError::ServerNotLoaded(hex::encode(&server_id[..8]))
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
        let mailbox_id = mls_group_mailbox_id(group.group_id());
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

    /// Send a control message (e.g. channel ops). MLS-encrypted but not stored locally.
    pub fn send_control(
        &mut self,
        server_id: &[u8; 32],
        content: Vec<u8>,
    ) -> Result<Outbound> {
        let group = self.servers.get_mut(server_id).ok_or_else(|| {
            GhostError::ServerNotLoaded(hex::encode(&server_id[..8]))
        })?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let msg = ApplicationMessage::new(
            MessageType::Metadata,
            [0u8; 32],
            self.identity.fingerprint,
            now,
            vec![],
            content,
        )?;

        let blob = seal(group, &self.provider, &msg)?;
        let mailbox_id = mls_group_mailbox_id(group.group_id());
        Ok(Outbound { mailbox_id, blob })
    }

    /// Decrypt a blob and store the message. Uses relay-stamped arrival time if
    /// provided, otherwise falls back to local clock.
    pub fn receive_blob(
        &mut self,
        server_id: &[u8; 32],
        blob: &[u8],
        received_at: Option<u64>,
    ) -> Result<ApplicationMessage> {
        let group = self.servers.get_mut(server_id).ok_or_else(|| {
            GhostError::ServerNotLoaded(hex::encode(&server_id[..8]))
        })?;

        let msg = open(group, &self.provider, blob)?;

        let recv_ts = received_at.unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64
        });

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
        server_id: &[u8; 32],
        key_package: KeyPackage,
        invitee_fp: [u8; 32],
        invitee_name: &str,
        timestamp: u64,
    ) -> Result<(Outbound, Vec<u8>)> {
        let group = self.servers.get_mut(server_id).ok_or_else(|| {
            GhostError::ServerNotLoaded(hex::encode(&server_id[..8]))
        })?;

        let (commit_blob, welcome) = group.add_member(&self.provider, key_package)?;
        let welcome_bytes = welcome
            .to_bytes()
            .map_err(|e| GhostError::Mls(format!("serialize welcome: {e}")))?;

        let mailbox_id = mls_group_mailbox_id(group.group_id());

        self.store.insert_member(&Member {
            server_id: *server_id,
            fingerprint: invitee_fp,
            display_name: invitee_name.to_string(),
            role: MemberRole::Member,
            joined_at: timestamp,
            avatar_hash: None,
            avatar_key: None,
        })?;

        Ok((Outbound { mailbox_id, blob: commit_blob }, welcome_bytes))
    }

    pub fn join_server(
        &mut self,
        server_id: &[u8; 32],
        welcome_bytes: &[u8],
        server_name: &str,
        kind: ServerKind,
        timestamp: u64,
    ) -> Result<()> {
        let ghost_group =
            GhostGroup::join(&self.provider, &self.identity, welcome_bytes)?;

        self.store.insert_server(&Server {
            server_id: *server_id,
            name: server_name.to_string(),
            kind,
            creator_fp: [0u8; 32],
            created_at: timestamp,
        })?;

        let channel_name = match kind {
            ServerKind::Dm | ServerKind::Group => "messages",
            ServerKind::Server => "general",
        };
        let channel_id = derive_default_channel_id(server_id);
        self.store.insert_channel(&Channel {
            channel_id,
            server_id: *server_id,
            name: channel_name.to_string(),
            kind: ChannelKind::Text,
            position: 0,
        })?;

        self.store.insert_member(&Member {
            server_id: *server_id,
            fingerprint: self.identity.fingerprint,
            display_name: self.identity.display_name.clone(),
            role: MemberRole::Member,
            joined_at: timestamp,
            avatar_hash: None,
            avatar_key: None,
        })?;

        let mailbox_id = mls_group_mailbox_id(ghost_group.group_id());
        self.servers.insert(*server_id, ghost_group);
        self.mailbox_map.insert(mailbox_id, *server_id);
        Ok(())
    }

    fn build_invite_payload(
        server_id: &[u8; 32],
        server_name: &str,
        kind: ServerKind,
        members: &[Member],
        channels: &[Channel],
        group_info_bytes: Vec<u8>,
    ) -> InvitePayload {
        InvitePayload {
            server_id: *server_id,
            server_name: server_name.to_string(),
            kind,
            members: members
                .iter()
                .map(|m| InviteMember {
                    fingerprint: m.fingerprint,
                    display_name: m.display_name.clone(),
                    role: m.role,
                })
                .collect(),
            channels: channels
                .iter()
                .map(|c| InviteChannel {
                    channel_id: c.channel_id,
                    name: c.name.clone(),
                    kind: c.kind,
                    position: c.position,
                })
                .collect(),
            group_info_bytes,
        }
    }

    /// Creator exports an invite payload containing GroupInfo + server metadata.
    /// Returns (random_token, serialized_payload).
    pub fn create_invite(&self, server_id: &[u8; 32]) -> Result<(String, Vec<u8>)> {
        let member = self.store.get_member(server_id, &self.identity.fingerprint)?;
        if member.role != MemberRole::Creator {
            return Err(GhostError::PermissionDenied(
                "only the creator can create invites".into(),
            ));
        }

        let group = self.servers.get(server_id).ok_or_else(|| {
            GhostError::ServerNotLoaded(hex::encode(&server_id[..8]))
        })?;

        let group_info_bytes = group.export_group_info(&self.provider)?;
        let meta = self.store.get_server(server_id)?;
        let members = self.store.list_members(server_id)?;
        let channels = self.store.list_channels(server_id)?;

        let payload = Self::build_invite_payload(server_id, &meta.name, meta.kind, &members, &channels, group_info_bytes);

        let mut token_bytes = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut token_bytes);
        let token = hex::encode(token_bytes);

        Ok((token, payload.to_bytes()))
    }

    /// Join a server via an invite payload (external commit).
    /// Returns (server_id, commit_bytes_to_broadcast, mailbox_id).
    pub fn join_by_invite(
        &mut self,
        payload_bytes: &[u8],
        timestamp: u64,
    ) -> Result<([u8; 32], Vec<u8>, [u8; 32])> {
        let payload = InvitePayload::from_bytes(payload_bytes)?;

        let (ghost_group, commit_bytes) = GhostGroup::join_by_external_commit(
            &self.provider,
            &self.identity,
            &payload.group_info_bytes,
        )?;

        let creator_fp = payload
            .members
            .iter()
            .find(|m| m.role == MemberRole::Creator)
            .map(|m| m.fingerprint)
            .unwrap_or([0u8; 32]);

        self.store.insert_server(&Server {
            server_id: payload.server_id,
            name: payload.server_name,
            kind: payload.kind,
            creator_fp,
            created_at: timestamp,
        })?;

        for ch in &payload.channels {
            self.store.insert_channel(&Channel {
                channel_id: ch.channel_id,
                server_id: payload.server_id,
                name: ch.name.clone(),
                kind: ch.kind,
                position: ch.position,
            })?;
        }

        for m in &payload.members {
            self.store.insert_member(&Member {
                server_id: payload.server_id,
                fingerprint: m.fingerprint,
                display_name: m.display_name.clone(),
                role: m.role.clone(),
                joined_at: timestamp,
                avatar_hash: None,
                avatar_key: None,
            })?;
        }

        self.store.insert_member(&Member {
            server_id: payload.server_id,
            fingerprint: self.identity.fingerprint,
            display_name: self.identity.display_name.clone(),
            role: MemberRole::Member,
            joined_at: timestamp,
            avatar_hash: None,
            avatar_key: None,
        })?;

        let mailbox_id = mls_group_mailbox_id(ghost_group.group_id());
        self.servers.insert(payload.server_id, ghost_group);
        self.mailbox_map.insert(mailbox_id, payload.server_id);

        Ok((payload.server_id, commit_bytes, mailbox_id))
    }

    /// Re-export an invite payload with fresh GroupInfo (after joining via external commit).
    pub fn refresh_invite_payload(&self, server_id: &[u8; 32]) -> Result<Vec<u8>> {
        let group = self.servers.get(server_id).ok_or_else(|| {
            GhostError::ServerNotLoaded(hex::encode(&server_id[..8]))
        })?;

        let group_info_bytes = group.export_group_info(&self.provider)?;
        let meta = self.store.get_server(server_id)?;
        let members = self.store.list_members(server_id)?;
        let channels = self.store.list_channels(server_id)?;

        let payload = Self::build_invite_payload(server_id, &meta.name, meta.kind, &members, &channels, group_info_bytes);
        Ok(payload.to_bytes())
    }

    /// Export GroupInfo for a server so other clients can recover via external commit.
    pub fn export_server_info(&self, server_id: &[u8; 32]) -> Result<Vec<u8>> {
        let group = self.servers.get(server_id).ok_or_else(|| {
            GhostError::ServerNotLoaded(hex::encode(&server_id[..8]))
        })?;
        group.export_group_info(&self.provider)
    }

    /// Rejoin a server via external commit after falling too far behind.
    /// Deletes old MLS state and creates a fresh session from GroupInfo.
    /// Returns (commit_bytes_to_broadcast, mailbox_id).
    pub fn recover_via_external_commit(
        &mut self,
        server_id: &[u8; 32],
        group_info_bytes: &[u8],
    ) -> Result<(Vec<u8>, [u8; 32])> {
        if let Some(old_group) = self.servers.remove(server_id) {
            let _ = old_group.delete(&self.provider);
        }

        let (ghost_group, commit_bytes) = GhostGroup::join_by_external_commit(
            &self.provider,
            &self.identity,
            group_info_bytes,
        )?;

        let mailbox_id = mls_group_mailbox_id(ghost_group.group_id());
        self.servers.insert(*server_id, ghost_group);
        self.mailbox_map.insert(mailbox_id, *server_id);

        Ok((commit_bytes, mailbox_id))
    }

    /// Creator-only: remove a member from the MLS group and broadcast the commit.
    pub fn kick_member(
        &mut self,
        server_id: &[u8; 32],
        target_fp: &[u8; 32],
    ) -> Result<Outbound> {
        if target_fp == &self.identity.fingerprint {
            return Err(GhostError::PermissionDenied("cannot kick yourself".into()));
        }

        let member = self.store.get_member(server_id, &self.identity.fingerprint)?;
        if member.role != MemberRole::Creator {
            return Err(GhostError::PermissionDenied(
                "only the creator can kick members".into(),
            ));
        }

        let group = self.servers.get_mut(server_id).ok_or_else(|| {
            GhostError::ServerNotLoaded(hex::encode(&server_id[..8]))
        })?;

        // Collect ALL leaves matching target — a user may have multiple devices
        let leaf_indices: Vec<_> = group
            .members()
            .filter(|m| {
                openmls::prelude::BasicCredential::try_from(m.credential.clone())
                    .ok()
                    .map(|bc| bc.identity() == target_fp.as_slice())
                    .unwrap_or(false)
            })
            .map(|m| m.index)
            .collect();

        if leaf_indices.is_empty() {
            return Err(GhostError::Mls("member not found in MLS group".into()));
        }

        let commit_blob = group.remove_members(&self.provider, &leaf_indices)?;
        let mailbox_id = mls_group_mailbox_id(group.group_id());

        self.store.remove_member(server_id, target_fp)?;

        Ok(Outbound { mailbox_id, blob: commit_blob })
    }

    /// Remove a specific device's leaf from all MLS groups by its verifying key.
    /// Returns a list of (mailbox_id, commit_blob) to broadcast.
    pub fn revoke_device_leaves(&mut self, device_vk: &[u8; 32]) -> Vec<Outbound> {
        let server_ids: Vec<[u8; 32]> = self.servers.keys().copied().collect();
        let mut outbound = Vec::new();
        for sid in server_ids {
            let group = match self.servers.get_mut(&sid) {
                Some(g) => g,
                None => continue,
            };
            let leaf_indices: Vec<_> = group
                .members()
                .filter(|m| m.signature_key.as_slice() == device_vk.as_slice())
                .map(|m| m.index)
                .collect();
            if leaf_indices.is_empty() {
                continue;
            }
            match group.remove_members(&self.provider, &leaf_indices) {
                Ok(commit_blob) => {
                    let mailbox_id = mls_group_mailbox_id(group.group_id());
                    outbound.push(Outbound { mailbox_id, blob: commit_blob });
                }
                Err(e) => eprintln!("revoke: remove from {}: {e}", hex::encode(&sid[..8])),
            }
        }
        outbound
    }

    /// Derive a per-sender encryption key for voice in this server+channel.
    pub fn derive_voice_key(
        &self,
        server_id: &[u8; 32],
        channel_id: &[u8; 32],
        sender_fp: &[u8; 32],
        device_vk: &[u8; 32],
    ) -> Result<[u8; 32]> {
        let group = self.servers.get(server_id).ok_or_else(|| {
            GhostError::ServerNotLoaded(hex::encode(&server_id[..8]))
        })?;
        crate::mls::voice::derive_voice_key(group, &self.provider, channel_id, sender_fp, device_vk)
    }

    /// Derive a per-sender presence encryption key for a voice channel.
    pub fn derive_presence_key(
        &self,
        server_id: &[u8; 32],
        channel_id: &[u8; 32],
        sender_fp: &[u8; 32],
    ) -> Result<[u8; 32]> {
        let group = self.servers.get(server_id).ok_or_else(|| {
            GhostError::ServerNotLoaded(hex::encode(&server_id[..8]))
        })?;
        crate::mls::voice::derive_presence_key(group, &self.provider, channel_id, sender_fp)
    }

    /// Seal an encrypted presence blob for the current identity.
    pub fn seal_presence_blob(
        &self,
        server_id: &[u8; 32],
        channel_id: &[u8; 32],
        muted: bool,
        deafened: bool,
    ) -> Result<Vec<u8>> {
        let key = self.derive_presence_key(server_id, channel_id, &self.identity.fingerprint)?;
        let state = crate::mls::voice::PresenceState {
            fingerprint: self.identity.fingerprint,
            muted,
            deafened,
            device_vk: *self.identity.verifying_key.as_bytes(),
        };
        crate::mls::voice::seal_presence(&key, &state)
    }

    /// Decrypt a presence blob by trial-decrypting with all server members' keys.
    pub fn open_presence_blob(
        &self,
        server_id: &[u8; 32],
        channel_id: &[u8; 32],
        blob: &[u8],
    ) -> Result<crate::mls::voice::PresenceState> {
        let group = self.servers.get(server_id).ok_or_else(|| {
            GhostError::ServerNotLoaded(hex::encode(&server_id[..8]))
        })?;
        let member_fps = self.mls_member_fingerprints(server_id)?;
        crate::mls::voice::try_open_presence(&member_fps, group, &self.provider, channel_id, blob)
    }

    /// Seal an encrypted online presence blob for the current identity.
    pub fn seal_online_presence_blob(
        &self,
        server_id: &[u8; 32],
        status: crate::mls::presence::OnlineStatus,
        status_message: Option<String>,
        status_expiry: Option<u64>,
        avatar_hash: Option<[u8; 32]>,
    ) -> Result<Vec<u8>> {
        let group = self.servers.get(server_id).ok_or_else(|| {
            GhostError::ServerNotLoaded(hex::encode(&server_id[..8]))
        })?;
        let key = crate::mls::presence::derive_online_presence_key(
            group, &self.provider, &self.identity.fingerprint,
        )?;
        let state = crate::mls::presence::OnlinePresence {
            fingerprint: self.identity.fingerprint,
            status,
            status_message,
            status_expiry,
            avatar_hash,
        };
        crate::mls::presence::seal_online_presence(&key, &state)
    }

    /// Decrypt an online presence blob by trial-decrypting with all server members' keys.
    pub fn open_online_presence_blob(
        &self,
        server_id: &[u8; 32],
        blob: &[u8],
    ) -> Result<crate::mls::presence::OnlinePresence> {
        let group = self.servers.get(server_id).ok_or_else(|| {
            GhostError::ServerNotLoaded(hex::encode(&server_id[..8]))
        })?;
        let member_fps = self.mls_member_fingerprints(server_id)?;
        crate::mls::presence::try_open_online_presence(&member_fps, group, &self.provider, blob)
    }

    /// Returns (server_id, mailbox_id) for every loaded server.
    pub fn server_mailboxes(&self) -> Vec<([u8; 32], [u8; 32])> {
        self.servers
            .iter()
            .map(|(sid, g)| (*sid, mls_group_mailbox_id(g.group_id())))
            .collect()
    }

    /// Direct lookup: get mailbox_id for a server.
    pub fn mailbox_id_for_server(&self, server_id: &[u8; 32]) -> Option<[u8; 32]> {
        self.servers
            .get(server_id)
            .map(|g| mls_group_mailbox_id(g.group_id()))
    }

    /// Reverse lookup: find server_id for a given mailbox_id.
    pub fn server_id_for_mailbox(&self, mailbox_id: &[u8; 32]) -> Option<[u8; 32]> {
        self.mailbox_map.get(mailbox_id).copied()
    }

    /// Extract fingerprints of all MLS group members (from credentials).
    pub fn mls_member_fingerprints(&self, server_id: &[u8; 32]) -> Result<Vec<[u8; 32]>> {
        let group = self.servers.get(server_id).ok_or_else(|| {
            GhostError::ServerNotLoaded(hex::encode(&server_id[..8]))
        })?;
        let mut fps = Vec::new();
        for member in group.members() {
            if let Ok(bc) = openmls::prelude::BasicCredential::try_from(member.credential) {
                if let Ok(fp) = <[u8; 32]>::try_from(bc.identity().as_ref()) {
                    fps.push(fp);
                }
            }
        }
        Ok(fps)
    }

    /// Process an inbound blob — could be an app message, a commit, or a self-message.
    pub fn receive_any(
        &mut self,
        server_id: &[u8; 32],
        blob: &[u8],
        received_at: Option<u64>,
    ) -> Result<ReceiveResult> {
        let group = self.servers.get_mut(server_id).ok_or_else(|| {
            GhostError::ServerNotLoaded(hex::encode(&server_id[..8]))
        })?;

        let inbound = match open_any(group, &self.provider, blob) {
            Err(GhostError::SelfMessage) => return Ok(ReceiveResult::Skipped),
            other => other?,
        };

        match inbound {
            InboundMessage::Application(msg) => {
                // Control messages (Metadata) aren't chat — don't persist them
                if msg.message_type != MessageType::Metadata {
                    let recv_ts = received_at.unwrap_or_else(|| {
                        SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_millis() as u64
                    });

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
                }

                Ok(ReceiveResult::Message(msg))
            }
            InboundMessage::Commit { removed } => {
                if removed.contains(&self.identity.fingerprint) {
                    // With multi-device, removing one leaf isn't a kick if other leaves remain
                    let own_fp = self.identity.fingerprint;
                    let group = self.servers.get(server_id).ok_or_else(|| {
                        GhostError::ServerNotLoaded(hex::encode(&server_id[..8]))
                    })?;
                    let still_in = group.members().any(|m| {
                        openmls::prelude::BasicCredential::try_from(m.credential)
                            .ok()
                            .map(|bc| bc.identity() == own_fp.as_slice())
                            .unwrap_or(false)
                    });
                    if !still_in {
                        return Ok(ReceiveResult::Kicked);
                    }
                }
                if removed.is_empty() {
                    Ok(ReceiveResult::CommitProcessed)
                } else {
                    Ok(ReceiveResult::MembersRemoved(removed))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_client(seed: [u8; 32]) -> GhostClient {
        let identity = Identity::from_seed(seed).unwrap();
        GhostClient::open_in_memory(identity, seed).unwrap()
    }

    /// Returns (creator, joiner, server_id) with both clients in a shared MLS group.
    fn setup_two_clients() -> (GhostClient, GhostClient, [u8; 32]) {
        let mut c1 = test_client([0x01; 32]);
        let mut c2 = test_client([0x02; 32]);

        let server_id = c1.create_server("test", ServerKind::Server, 1000).unwrap();

        let kp = c2.generate_key_package().unwrap();
        let fp = *c2.fingerprint();
        let name = c2.identity().display_name.clone();
        let (_outbound, welcome_bytes) =
            c1.invite_member(&server_id, kp, fp, &name, 1000).unwrap();

        c2.join_server(&server_id, &welcome_bytes, "test", ServerKind::Server, 1000).unwrap();

        (c1, c2, server_id)
    }

    #[test]
    fn open_in_memory_succeeds() {
        let client = test_client([0x01; 32]);
        assert_eq!(client.fingerprint().len(), 32);
    }

    #[test]
    fn different_seeds_different_fingerprints() {
        let a = test_client([0x01; 32]);
        let b = test_client([0x02; 32]);
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn create_server_stores_records() {
        let mut client = test_client([0x01; 32]);
        let server_id = client.create_server("test-server", ServerKind::Server, 1000).unwrap();

        let server = client.store().get_server(&server_id).unwrap();
        assert_eq!(server.name, "test-server");
        assert_eq!(server.creator_fp, *client.fingerprint());
        assert_eq!(server.created_at, 1000);

        let channels = client.store().list_channels(&server_id).unwrap();
        assert_eq!(channels.len(), 1);
        assert_eq!(channels[0].name, "general");
        assert_eq!(channels[0].kind, ChannelKind::Text);
        assert_eq!(channels[0].channel_id, derive_default_channel_id(&server_id));

        let members = client.store().list_members(&server_id).unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].fingerprint, *client.fingerprint());
        assert_eq!(members[0].role, MemberRole::Creator);
    }

    #[test]
    fn send_to_unknown_server_fails() {
        let mut client = test_client([0x01; 32]);
        let result = client.send_message(&[0xFF; 32], &[0xAA; 32], b"hi".to_vec(), vec![], 1000);
        assert!(matches!(result, Err(GhostError::ServerNotLoaded(_))));
    }

    #[test]
    fn receive_from_unknown_server_fails() {
        let mut client = test_client([0x01; 32]);
        let result = client.receive_blob(&[0xFF; 32], &[0x00; 64], None);
        assert!(matches!(result, Err(GhostError::ServerNotLoaded(_))));
    }

    #[test]
    fn send_message_stores_in_db() {
        let (mut c1, _c2, server_id) = setup_two_clients();
        let channel_id = derive_default_channel_id(&server_id);

        let (_outbound, msg_id) = c1
            .send_message(&server_id, &channel_id, b"hello".to_vec(), vec![], 2000)
            .unwrap();

        let stored = c1.store().get_message(&msg_id).unwrap();
        assert_eq!(stored.content, b"hello");
        assert_eq!(stored.sender_fp, *c1.fingerprint());
        assert_eq!(stored.timestamp, 2000);
    }

    #[test]
    fn send_receive_roundtrip() {
        let (mut c1, mut c2, server_id) = setup_two_clients();
        let channel_id = derive_default_channel_id(&server_id);

        let (outbound, msg_id) = c1
            .send_message(&server_id, &channel_id, b"hello".to_vec(), vec![], 2000)
            .unwrap();

        let received = c2.receive_blob(&server_id, &outbound.blob, None).unwrap();
        assert_eq!(received.content, b"hello");
        assert_eq!(received.sender_fp, *c1.fingerprint());
        assert_eq!(received.message_id, msg_id);

        let stored = c2.store().get_message(&msg_id).unwrap();
        assert_eq!(stored.content, b"hello");
    }

    #[test]
    fn two_client_full_flow() {
        let mut c1 = test_client([0x01; 32]);
        let mut c2 = test_client([0x02; 32]);

        let server_id = c1.create_server("full-flow", ServerKind::Server, 1000).unwrap();
        let channel_id = derive_default_channel_id(&server_id);

        // c1 invites c2
        let kp = c2.generate_key_package().unwrap();
        let fp = *c2.fingerprint();
        let name = c2.identity().display_name.clone();
        let (_outbound, welcome) =
            c1.invite_member(&server_id, kp, fp, &name, 1000).unwrap();

        // c2 joins
        c2.join_server(&server_id, &welcome, "full-flow", ServerKind::Server, 1000).unwrap();

        // c1 sends, c2 receives
        let (out1, id1) = c1
            .send_message(&server_id, &channel_id, b"from c1".to_vec(), vec![], 2000)
            .unwrap();
        let recv1 = c2.receive_blob(&server_id, &out1.blob, None).unwrap();
        assert_eq!(recv1.content, b"from c1");
        assert_eq!(recv1.sender_fp, *c1.fingerprint());

        // c2 sends, c1 receives
        let (out2, id2) = c2
            .send_message(&server_id, &channel_id, b"from c2".to_vec(), vec![], 3000)
            .unwrap();
        let recv2 = c1.receive_blob(&server_id, &out2.blob, None).unwrap();
        assert_eq!(recv2.content, b"from c2");
        assert_eq!(recv2.sender_fp, *c2.fingerprint());

        // Both stores have both messages
        assert_eq!(c1.store().get_message(&id1).unwrap().content, b"from c1");
        assert_eq!(c1.store().get_message(&id2).unwrap().content, b"from c2");
        assert_eq!(c2.store().get_message(&id1).unwrap().content, b"from c1");
        assert_eq!(c2.store().get_message(&id2).unwrap().content, b"from c2");
    }

    #[test]
    fn create_invite_requires_creator() {
        let (c1, c2, server_id) = setup_two_clients();

        // c1 (creator) can create invite
        let result = c1.create_invite(&server_id);
        assert!(result.is_ok());

        // c2 (member) cannot
        let result = c2.create_invite(&server_id);
        assert!(matches!(result, Err(GhostError::PermissionDenied(_))));
    }

    #[test]
    fn invite_full_roundtrip() {
        let mut c1 = test_client([0x01; 32]);
        let mut c2 = test_client([0x02; 32]);

        let server_id = c1.create_server("test", ServerKind::Server, 1000).unwrap();

        let (_token, payload_bytes) = c1.create_invite(&server_id).unwrap();

        let (joined_server_id, commit_bytes, _mailbox_id) =
            c2.join_by_invite(&payload_bytes, 2000).unwrap();
        assert_eq!(joined_server_id, server_id);

        // c2 should have the server, channel, and members in their store
        let server = c2.store().get_server(&server_id).unwrap();
        assert_eq!(server.name, "test");
        let channels = c2.store().list_channels(&server_id).unwrap();
        assert_eq!(channels.len(), 1);
        assert_eq!(channels[0].name, "general");
        let members = c2.store().list_members(&server_id).unwrap();
        assert_eq!(members.len(), 2); // c1 + c2

        // c1 processes the external commit
        let result = c1.receive_any(&server_id, &commit_bytes, Some(2000)).unwrap();
        assert!(matches!(result, ReceiveResult::CommitProcessed));

        // After merging, c1's MLS group should include c2
        let mls_fps = c1.mls_member_fingerprints(&server_id).unwrap();
        assert_eq!(mls_fps.len(), 2, "MLS group should have both members after external commit");
        assert!(mls_fps.contains(c1.fingerprint()));
        assert!(mls_fps.contains(c2.fingerprint()));
    }

    #[test]
    fn refresh_invite_payload_has_new_member() {
        let mut c1 = test_client([0x01; 32]);
        let mut c2 = test_client([0x02; 32]);

        let server_id = c1.create_server("test", ServerKind::Server, 1000).unwrap();
        let (_, payload_bytes) = c1.create_invite(&server_id).unwrap();

        c2.join_by_invite(&payload_bytes, 2000).unwrap();

        let refreshed = c2.refresh_invite_payload(&server_id).unwrap();
        let payload = InvitePayload::from_bytes(&refreshed).unwrap();

        // Should include c1 + c2
        assert_eq!(payload.members.len(), 2);
        assert_eq!(payload.server_name, "test");
        assert!(!payload.group_info_bytes.is_empty());
    }
}
