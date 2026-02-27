use openmls::prelude::*;
use openmls::prelude::tls_codec::Deserialize;
use openmls::versions::ProtocolVersion;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;

use crate::crypto::constants::GHOST_MEMBERSHIP_EXTENSION_TYPE;
use crate::crypto::GhostProvider;
use crate::error::{GhostError, Result};
use crate::identity::Identity;
use crate::mls::membership::{GroupMembership, MemberBinding};
use crate::wire::derive_mls_group_id;

pub(crate) fn leaf_node_capabilities() -> Capabilities {
    Capabilities::new(
        None, None,
        Some(&[ExtensionType::Unknown(GHOST_MEMBERSHIP_EXTENSION_TYPE)]),
        None, None,
    )
}

use super::credential::{credential_from_identity, signer_from_identity};

fn wrap_commit(mls_bytes: &[u8], epoch: u64) -> Vec<u8> {
    let header = ghost_wire::encode_envelope(ghost_wire::EnvelopeType::Commit, epoch);
    let mut out = Vec::with_capacity(ghost_wire::ENVELOPE_HEADER_SIZE + mls_bytes.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(mls_bytes);
    out
}

// Serialize an outbound MLS message and re-parse it as an inbound message.
// Needed because OpenMLS uses separate types for sent vs received messages.
fn outbound_to_inbound(msg: &MlsMessageOut) -> std::result::Result<MlsMessageIn, GhostError> {
    let bytes = msg
        .to_bytes()
        .map_err(|e| GhostError::Mls(format!("serialize: {e}")))?;
    MlsMessageIn::tls_deserialize_exact(&bytes)
        .map_err(|e| GhostError::Mls(format!("deserialize: {e}")))
}

/// An encrypted MLS group — used for both multi-member groups and 2-person DMs.
pub struct GhostGroup {
    mls_group: MlsGroup,
    signer: SignatureKeyPair,
}

impl GhostGroup {
    /// Start a new group where this identity is the first (and only) member.
    pub fn create(
        provider: &GhostProvider,
        identity: &Identity,
        own_binding: MemberBinding,
    ) -> Result<Self> {
        let signer = signer_from_identity(identity);
        let credential = credential_from_identity(identity);

        let mut membership = GroupMembership::new();
        membership.add(own_binding);

        let config = MlsGroupCreateConfig::builder()
            .use_ratchet_tree_extension(true)
            .max_past_epochs(1)
            .capabilities(leaf_node_capabilities())
            .with_group_context_extensions(membership.to_group_context_extensions()?)
            .build();

        let mls_group = MlsGroup::new(
            provider,
            &signer,
            &config,
            credential,
        )
        .map_err(|e| GhostError::Mls(format!("create group: {e}")))?;

        Ok(Self { mls_group, signer })
    }

    /// Start a new group with a deterministic MLS group ID derived from the application group_id.
    pub fn create_with_id(
        provider: &GhostProvider,
        identity: &Identity,
        server_id: &[u8; 32],
        own_binding: MemberBinding,
    ) -> Result<Self> {
        let signer = signer_from_identity(identity);
        let credential = credential_from_identity(identity);

        let mut membership = GroupMembership::new();
        membership.add(own_binding);

        let config = MlsGroupCreateConfig::builder()
            .use_ratchet_tree_extension(true)
            .max_past_epochs(1)
            .capabilities(leaf_node_capabilities())
            .with_group_context_extensions(membership.to_group_context_extensions()?)
            .build();

        let mls_group_id = derive_mls_group_id(server_id);
        let mls_group = MlsGroup::new_with_group_id(
            provider,
            &signer,
            &config,
            GroupId::from_slice(&mls_group_id),
            credential,
        )
        .map_err(|e| GhostError::Mls(format!("create group: {e}")))?;

        Ok(Self { mls_group, signer })
    }

    /// Reload a group from persistent storage.
    pub fn load(
        provider: &GhostProvider,
        identity: &Identity,
        server_id: &[u8; 32],
    ) -> Result<Option<Self>> {
        let mls_group_id = derive_mls_group_id(server_id);
        let mls_group = MlsGroup::load(
            provider.storage(),
            &GroupId::from_slice(&mls_group_id),
        )
        .map_err(|e| GhostError::Mls(format!("load group: {e}")))?;

        Ok(mls_group.map(|g| Self {
            mls_group: g,
            signer: signer_from_identity(identity),
        }))
    }

    /// Add someone to this group. Returns envelope-wrapped commit bytes
    /// (broadcast to existing members) and a welcome (sent to the new member).
    pub fn add_member(
        &mut self,
        provider: &GhostProvider,
        key_package: KeyPackage,
        new_binding: MemberBinding,
    ) -> Result<(Vec<u8>, MlsMessageOut)> {
        let mut membership = self.read_membership()?;
        membership.add(new_binding);

        let epoch = self.epoch();
        let bundle = self.mls_group.commit_builder()
            .propose_adds([key_package])
            .propose_group_context_extensions(membership.to_group_context_extensions()?)
            .map_err(|e| GhostError::Mls(format!("propose extensions: {e}")))?
            .load_psks(provider.storage())
            .map_err(|e| GhostError::Mls(format!("load psks: {e}")))?
            .build(provider.rand(), provider.crypto(), &self.signer, |_| true)
            .map_err(|e| GhostError::Mls(format!("build add commit: {e}")))?
            .stage_commit(provider)
            .map_err(|e| GhostError::Mls(format!("stage add commit: {e}")))?;

        let commit_bytes = bundle.commit()
            .to_bytes()
            .map_err(|e| GhostError::Mls(format!("serialize commit: {e}")))?;
        let welcome_msg = bundle.welcome().cloned()
            .ok_or_else(|| GhostError::Mls("add commit produced no welcome".into()))?;

        self.mls_group
            .merge_pending_commit(provider)
            .map_err(|e| GhostError::Mls(format!("merge add commit: {e}")))?;

        // Serialize welcome as MlsMessageOut for the caller
        let welcome_out = MlsMessageOut::from_welcome(welcome_msg, ProtocolVersion::Mls10);
        Ok((wrap_commit(&commit_bytes, epoch), welcome_out))
    }

    /// Kick one or more leaves from the group. Returns envelope-wrapped commit bytes.
    pub fn remove_members(
        &mut self,
        provider: &GhostProvider,
        members: &[LeafNodeIndex],
        removed_device_keys: &[[u8; 32]],
    ) -> Result<Vec<u8>> {
        let mut membership = self.read_membership()?;
        for dk in removed_device_keys {
            membership.remove_device(dk);
        }

        let epoch = self.epoch();
        let bundle = self.mls_group.commit_builder()
            .propose_removals(members.iter().copied())
            .propose_group_context_extensions(membership.to_group_context_extensions()?)
            .map_err(|e| GhostError::Mls(format!("propose extensions: {e}")))?
            .load_psks(provider.storage())
            .map_err(|e| GhostError::Mls(format!("load psks: {e}")))?
            .build(provider.rand(), provider.crypto(), &self.signer, |_| true)
            .map_err(|e| GhostError::Mls(format!("build remove commit: {e}")))?
            .stage_commit(provider)
            .map_err(|e| GhostError::Mls(format!("stage remove commit: {e}")))?;

        let commit_bytes = bundle.into_commit()
            .to_bytes()
            .map_err(|e| GhostError::Mls(format!("serialize commit: {e}")))?;

        self.mls_group
            .merge_pending_commit(provider)
            .map_err(|e| GhostError::Mls(format!("merge remove commit: {e}")))?;

        Ok(wrap_commit(&commit_bytes, epoch))
    }

    /// Encrypt a plaintext message so only group members can read it.
    pub fn encrypt(
        &mut self,
        provider: &GhostProvider,
        plaintext: &[u8],
    ) -> Result<MlsMessageOut> {
        self.mls_group
            .create_message(provider, &self.signer, plaintext)
            .map_err(|e| GhostError::Mls(format!("encrypt: {e}")))
    }

    /// Decrypt and validate an inbound MLS message (could be a commit or an app message).
    pub fn process_message(
        &mut self,
        provider: &GhostProvider,
        message: &MlsMessageOut,
    ) -> Result<ProcessedMessage> {
        let inbound = outbound_to_inbound(message)?;
        let protocol_message = inbound
            .try_into_protocol_message()
            .map_err(|_| GhostError::Mls("not a protocol message".into()))?;
        self.mls_group
            .process_message(provider, protocol_message)
            .map_err(|e| GhostError::Mls(format!("process message: {e}")))
    }

    /// Process an inbound MLS message from raw bytes (as received from relay).
    pub fn process_message_bytes(
        &mut self,
        provider: &GhostProvider,
        bytes: &[u8],
    ) -> Result<ProcessedMessage> {
        let inbound = MlsMessageIn::tls_deserialize_exact(bytes)
            .map_err(|e| GhostError::Mls(format!("deserialize: {e}")))?;
        let protocol_message = inbound
            .try_into_protocol_message()
            .map_err(|_| GhostError::Mls("not a protocol message".into()))?;
        self.mls_group
            .process_message(provider, protocol_message)
            .map_err(|e| match e {
                ProcessMessageError::ValidationError(
                    ValidationError::CannotDecryptOwnMessage,
                ) => GhostError::SelfMessage,
                _ => GhostError::Mls(format!("process message: {e}")),
            })
    }

    /// Apply a commit that we received and already validated via process_message.
    pub fn merge_staged_commit(
        &mut self,
        provider: &GhostProvider,
        commit: StagedCommit,
    ) -> Result<()> {
        self.mls_group
            .merge_staged_commit(provider, commit)
            .map_err(|e| GhostError::Mls(format!("merge staged commit: {e}")))
    }

    /// Join an existing group using a serialized Welcome message.
    pub fn join(
        provider: &GhostProvider,
        identity: &Identity,
        bytes: &[u8],
    ) -> Result<Self> {
        let signer = signer_from_identity(identity);
        let msg_in = MlsMessageIn::tls_deserialize_exact(bytes)
            .map_err(|e| GhostError::Mls(format!("deserialize welcome: {e}")))?;
        let welcome_msg = match msg_in.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => return Err(GhostError::Mls("not a welcome message".into())),
        };
        let join_config = MlsGroupJoinConfig::builder()
            .max_past_epochs(1)
            .build();
        let mls_group =
            StagedWelcome::new_from_welcome(provider, &join_config, welcome_msg, None)
                .map_err(|e| GhostError::Mls(format!("staged welcome: {e}")))?
                .into_group(provider)
                .map_err(|e| GhostError::Mls(format!("join group: {e}")))?;
        Ok(Self { mls_group, signer })
    }

    /// Derive a secret from the current MLS epoch. Used for voice encryption keys.
    pub fn export_secret(
        &self,
        provider: &GhostProvider,
        label: &str,
        context: &[u8],
        length: usize,
    ) -> Result<Vec<u8>> {
        self.mls_group
            .export_secret(provider.crypto(), label, context, length)
            .map_err(|e| GhostError::Mls(format!("export secret: {e}")))
    }

    /// Remove all MLS state for this group from persistent storage.
    pub fn delete(mut self, provider: &GhostProvider) -> Result<()> {
        self.mls_group
            .delete(provider.storage())
            .map_err(|e| GhostError::Mls(format!("delete group: {e}")))
    }

    /// Read the current GroupMembership from the group context extension.
    pub fn read_membership(&self) -> Result<GroupMembership> {
        GroupMembership::from_group(&self.mls_group)
    }

    /// Issue a commit that updates the GroupMembership extension.
    /// Used after external commits to add the joiner's binding.
    pub fn update_membership(
        &mut self,
        provider: &GhostProvider,
        membership: GroupMembership,
    ) -> Result<Vec<u8>> {
        let epoch = self.epoch();
        let bundle = self.mls_group.commit_builder()
            .propose_group_context_extensions(membership.to_group_context_extensions()?)
            .map_err(|e| GhostError::Mls(format!("propose extensions: {e}")))?
            .load_psks(provider.storage())
            .map_err(|e| GhostError::Mls(format!("load psks: {e}")))?
            .build(provider.rand(), provider.crypto(), &self.signer, |_| true)
            .map_err(|e| GhostError::Mls(format!("build membership commit: {e}")))?
            .stage_commit(provider)
            .map_err(|e| GhostError::Mls(format!("stage membership commit: {e}")))?;

        let commit_bytes = bundle.into_commit()
            .to_bytes()
            .map_err(|e| GhostError::Mls(format!("serialize commit: {e}")))?;

        self.mls_group
            .merge_pending_commit(provider)
            .map_err(|e| GhostError::Mls(format!("merge membership commit: {e}")))?;

        Ok(wrap_commit(&commit_bytes, epoch))
    }

    pub fn group_id(&self) -> &[u8] {
        self.mls_group.group_id().as_slice()
    }

    pub fn epoch(&self) -> u64 {
        self.mls_group.epoch().as_u64()
    }

    pub fn members(&self) -> impl Iterator<Item = Member> + '_ {
        self.mls_group.members()
    }

    /// Export the group's current state so someone can join via external commit.
    pub fn export_group_info(&self, provider: &GhostProvider) -> Result<Vec<u8>> {
        let msg = self
            .mls_group
            .export_group_info(provider.crypto(), &self.signer, true)
            .map_err(|e| GhostError::Mls(format!("export group info: {e}")))?;
        msg.to_bytes()
            .map_err(|e| GhostError::Mls(format!("serialize group info: {e}")))
    }

    /// Join an existing group using exported GroupInfo (external commit).
    /// Returns the new group and the serialized commit to broadcast to existing members.
    pub fn join_by_external_commit(
        provider: &GhostProvider,
        identity: &Identity,
        group_info_bytes: &[u8],
    ) -> Result<(Self, Vec<u8>)> {
        let signer = signer_from_identity(identity);
        let credential = credential_from_identity(identity);

        let msg_in = MlsMessageIn::tls_deserialize_exact(group_info_bytes)
            .map_err(|e| GhostError::Mls(format!("deserialize group info: {e}")))?;
        let vgi = match msg_in.extract() {
            MlsMessageBodyIn::GroupInfo(vgi) => vgi,
            _ => return Err(GhostError::Mls("expected GroupInfo message".into())),
        };

        let ext_join_config = MlsGroupJoinConfig::builder()
            .max_past_epochs(1)
            .build();
        let leaf_params = LeafNodeParameters::builder()
            .with_capabilities(leaf_node_capabilities())
            .build();
        let (mls_group, commit_bundle) = MlsGroup::external_commit_builder()
            .with_config(ext_join_config)
            .build_group(provider, vgi, credential)
            .map_err(|e| GhostError::Mls(format!("build external commit: {e}")))?
            .leaf_node_parameters(leaf_params)
            .load_psks(provider.storage())
            .map_err(|e| GhostError::Mls(format!("load psks: {e}")))?
            .build(provider.rand(), provider.crypto(), &signer, |_| true)
            .map_err(|e| GhostError::Mls(format!("build commit: {e}")))?
            .finalize(provider)
            .map_err(|e| GhostError::Mls(format!("finalize external commit: {e}")))?;

        let commit_bytes = commit_bundle
            .into_commit()
            .to_bytes()
            .map_err(|e| GhostError::Mls(format!("serialize commit: {e}")))?;

        let group = Self { mls_group, signer };
        let commit_epoch = group.epoch().saturating_sub(1);
        Ok((group, wrap_commit(&commit_bytes, commit_epoch)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mls::credential::generate_key_package;

    fn test_binding(id: &Identity, seq: u64) -> MemberBinding {
        MemberBinding {
            account_fp: id.fingerprint,
            idlog_seq: seq,
            device_key: id.verifying_key.to_bytes(),
        }
    }

    #[test]
    fn create_group() {
        let provider = GhostProvider::new_in_memory().unwrap();
        let id = Identity::from_seed([0x01u8; 32]).unwrap();
        let group = GhostGroup::create(&provider, &id, test_binding(&id, 1)).unwrap();
        assert!(!group.group_id().is_empty());
    }

    #[test]
    fn add_member_and_join() {
        let provider_a = GhostProvider::new_in_memory().unwrap();
        let provider_b = GhostProvider::new_in_memory().unwrap();

        let id_a = Identity::from_seed([0x01u8; 32]).unwrap();
        let id_b = Identity::from_seed([0x02u8; 32]).unwrap();

        let mut group_a = GhostGroup::create(&provider_a, &id_a, test_binding(&id_a, 1)).unwrap();
        let kp_b = generate_key_package(&provider_b, &id_b).unwrap();

        let (_commit, welcome) = group_a
            .add_member(&provider_a, kp_b, test_binding(&id_b, 1))
            .unwrap();

        let group_b =
            GhostGroup::join(&provider_b, &id_b, &welcome.to_bytes().unwrap()).unwrap();

        assert_eq!(group_a.group_id(), group_b.group_id());
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let provider_a = GhostProvider::new_in_memory().unwrap();
        let provider_b = GhostProvider::new_in_memory().unwrap();

        let id_a = Identity::from_seed([0x01u8; 32]).unwrap();
        let id_b = Identity::from_seed([0x02u8; 32]).unwrap();

        let mut group_a = GhostGroup::create(&provider_a, &id_a, test_binding(&id_a, 1)).unwrap();
        let kp_b = generate_key_package(&provider_b, &id_b).unwrap();
        let (_commit, welcome) = group_a
            .add_member(&provider_a, kp_b, test_binding(&id_b, 1))
            .unwrap();
        let mut group_b =
            GhostGroup::join(&provider_b, &id_b, &welcome.to_bytes().unwrap()).unwrap();

        let msg = b"hello from sender";
        let ciphertext = group_a.encrypt(&provider_a, msg).unwrap();
        let processed = group_b.process_message(&provider_b, &ciphertext).unwrap();

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app_msg) => {
                assert_eq!(app_msg.into_bytes(), msg);
            }
            other => panic!("expected ApplicationMessage, got {:?}", other),
        }
    }

    #[test]
    fn export_secret_returns_32_bytes() {
        let provider = GhostProvider::new_in_memory().unwrap();
        let id = Identity::from_seed([0x01u8; 32]).unwrap();
        let group = GhostGroup::create(&provider, &id, test_binding(&id, 1)).unwrap();

        let secret = group
            .export_secret(&provider, "ghost-voice", b"test-context", 32)
            .unwrap();
        assert_eq!(secret.len(), 32);
    }

    #[test]
    fn export_and_external_commit() {
        let provider_a = GhostProvider::new_in_memory().unwrap();
        let provider_b = GhostProvider::new_in_memory().unwrap();

        let id_a = Identity::from_seed([0x01u8; 32]).unwrap();
        let id_b = Identity::from_seed([0x02u8; 32]).unwrap();

        let group_a = GhostGroup::create(&provider_a, &id_a, test_binding(&id_a, 1)).unwrap();
        let group_info_bytes = group_a.export_group_info(&provider_a).unwrap();

        let (group_b, commit_bytes) =
            GhostGroup::join_by_external_commit(&provider_b, &id_b, &group_info_bytes).unwrap();

        assert_eq!(group_a.group_id(), group_b.group_id());
        assert!(!commit_bytes.is_empty());
    }

    #[test]
    fn load_persisted_group() {
        let provider = GhostProvider::new_in_memory().unwrap();
        let id = Identity::from_seed([0x01u8; 32]).unwrap();
        let server_id = [0x42u8; 32];

        let original = GhostGroup::create_with_id(
            &provider, &id, &server_id, test_binding(&id, 1),
        ).unwrap();
        let original_mls_id = original.group_id().to_vec();

        let loaded = GhostGroup::load(&provider, &id, &server_id)
            .unwrap()
            .expect("group should be loadable");
        assert_eq!(loaded.group_id(), original_mls_id.as_slice());
    }

    #[test]
    fn membership_survives_create_and_join() {
        let provider_a = GhostProvider::new_in_memory().unwrap();
        let provider_b = GhostProvider::new_in_memory().unwrap();

        let id_a = Identity::from_seed([0x01u8; 32]).unwrap();
        let id_b = Identity::from_seed([0x02u8; 32]).unwrap();
        let server_id = [0x42u8; 32];

        let mut group_a = GhostGroup::create_with_id(
            &provider_a, &id_a, &server_id, test_binding(&id_a, 1),
        ).unwrap();

        let kp_b = generate_key_package(&provider_b, &id_b).unwrap();
        let (_commit, welcome) = group_a
            .add_member(&provider_a, kp_b, test_binding(&id_b, 1))
            .unwrap();

        // Creator sees both bindings
        let m_a = group_a.read_membership().unwrap();
        assert_eq!(m_a.bindings.len(), 2);

        // Joiner sees both bindings via Welcome
        let group_b = GhostGroup::join(&provider_b, &id_b, &welcome.to_bytes().unwrap()).unwrap();
        let m_b = group_b.read_membership().unwrap();
        assert_eq!(m_b.bindings.len(), 2);
        assert_eq!(m_a.bindings, m_b.bindings);
    }

    #[test]
    fn membership_bindings_contain_correct_data() {
        let provider = GhostProvider::new_in_memory().unwrap();
        let id = Identity::from_seed([0x01u8; 32]).unwrap();
        let server_id = [0x42u8; 32];

        let binding = test_binding(&id, 5);
        let group = GhostGroup::create_with_id(
            &provider, &id, &server_id, binding.clone(),
        ).unwrap();

        let membership = group.read_membership().unwrap();
        assert_eq!(membership.bindings.len(), 1);
        let b = &membership.bindings[0];
        assert_eq!(b.account_fp, id.fingerprint);
        assert_eq!(b.device_key, id.verifying_key.to_bytes());
        assert_eq!(b.idlog_seq, 5);
    }

    #[test]
    fn remove_member_updates_membership() {
        let provider_a = GhostProvider::new_in_memory().unwrap();
        let provider_b = GhostProvider::new_in_memory().unwrap();

        let id_a = Identity::from_seed([0x01u8; 32]).unwrap();
        let id_b = Identity::from_seed([0x02u8; 32]).unwrap();
        let server_id = [0x42u8; 32];

        let mut group_a = GhostGroup::create_with_id(
            &provider_a, &id_a, &server_id, test_binding(&id_a, 1),
        ).unwrap();

        let kp_b = generate_key_package(&provider_b, &id_b).unwrap();
        let (_commit, _welcome) = group_a
            .add_member(&provider_a, kp_b, test_binding(&id_b, 1))
            .unwrap();

        // Find b's leaf index
        let b_leaf: Vec<_> = group_a.members()
            .filter(|m| m.credential.serialized_content() == id_b.fingerprint.as_slice())
            .map(|m| m.index)
            .collect();
        assert_eq!(b_leaf.len(), 1);

        // Remove b
        let _remove_commit = group_a.remove_members(
            &provider_a,
            &b_leaf,
            &[id_b.verifying_key.to_bytes()],
        ).unwrap();

        // Membership should only have a's binding now
        let m = group_a.read_membership().unwrap();
        assert_eq!(m.bindings.len(), 1);
        assert_eq!(m.bindings[0].account_fp, id_a.fingerprint);
    }

    #[test]
    fn update_membership_after_external_commit() {
        let provider_a = GhostProvider::new_in_memory().unwrap();
        let provider_b = GhostProvider::new_in_memory().unwrap();

        let id_a = Identity::from_seed([0x01u8; 32]).unwrap();
        let id_b = Identity::from_seed([0x02u8; 32]).unwrap();
        let server_id = [0x42u8; 32];

        let group_a = GhostGroup::create_with_id(
            &provider_a, &id_a, &server_id, test_binding(&id_a, 1),
        ).unwrap();
        let group_info_bytes = group_a.export_group_info(&provider_a).unwrap();

        // b joins via external commit — initially no binding for b in membership
        let (mut group_b, _commit) =
            GhostGroup::join_by_external_commit(&provider_b, &id_b, &group_info_bytes).unwrap();
        let m_before = group_b.read_membership().unwrap();
        assert_eq!(m_before.bindings.len(), 1); // only a's binding

        // b updates membership with own binding
        let mut membership = group_b.read_membership().unwrap();
        membership.add(test_binding(&id_b, 2));
        let _update_commit = group_b.update_membership(&provider_b, membership).unwrap();

        // Now both bindings are present
        let m_after = group_b.read_membership().unwrap();
        assert_eq!(m_after.bindings.len(), 2);
        let fps: Vec<_> = m_after.bindings.iter().map(|b| b.account_fp).collect();
        assert!(fps.contains(&id_a.fingerprint));
        assert!(fps.contains(&id_b.fingerprint));
    }
}
