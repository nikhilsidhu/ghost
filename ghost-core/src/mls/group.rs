use openmls::prelude::*;
use openmls::prelude::tls_codec::Deserialize;
use openmls::versions::ProtocolVersion;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;

use crate::crypto::GhostProvider;
use crate::error::{GhostError, Result};
use crate::identity::Identity;
use crate::wire::derive_mls_group_id;

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

/// Validate pending proposals when building commits.
/// Accepts member proposals (relay already validated) and relay external proposals
/// (remove + group context extensions). Rejects unexpected sender types.
fn validate_pending_proposal(proposal: &QueuedProposal) -> bool {
    match proposal.sender() {
        Sender::Member(_) => true,
        Sender::External(_) => matches!(
            proposal.proposal(),
            Proposal::Remove(_) | Proposal::GroupContextExtensions(_)
        ),
        // External commit: ExternalInit is required, Remove/PSK are allowed
        Sender::NewMemberCommit => matches!(
            proposal.proposal(),
            Proposal::ExternalInit(_) | Proposal::Remove(_) | Proposal::PreSharedKey(_)
        ),
        _ => false,
    }
}

/// An encrypted MLS group — used for both multi-member groups and 2-person DMs.
pub struct GhostGroup {
    mls_group: MlsGroup,
    signer: SignatureKeyPair,
}

impl GhostGroup {
    /// Build an MlsGroupCreateConfig, optionally adding ExternalSendersExtension.
    fn build_create_config(relay_vk: Option<&[u8; 32]>) -> Result<MlsGroupCreateConfig> {
        let mut builder = MlsGroupCreateConfig::builder()
            .use_ratchet_tree_extension(true)
            .max_past_epochs(1)
            .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY);

        if let Some(vk) = relay_vk {
            let external_sender = ExternalSender::new(
                SignaturePublicKey::from(vk.to_vec()),
                Credential::new(CredentialType::Basic, b"ghost-relay".to_vec()),
            );
            let ext = Extension::ExternalSenders(vec![external_sender]);
            let extensions = Extensions::single(ext)
                .map_err(|e| GhostError::Mls(format!("external senders extension: {e}")))?;
            builder = builder.with_group_context_extensions(extensions);
        }

        Ok(builder.build())
    }

    /// Start a new group where this identity is the first (and only) member.
    pub fn create(
        provider: &GhostProvider,
        identity: &Identity,
        relay_vk: Option<&[u8; 32]>,
    ) -> Result<Self> {
        let signer = signer_from_identity(identity);
        let credential = credential_from_identity(identity);
        let config = Self::build_create_config(relay_vk)?;

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
        relay_vk: Option<&[u8; 32]>,
    ) -> Result<Self> {
        let signer = signer_from_identity(identity);
        let credential = credential_from_identity(identity);
        let config = Self::build_create_config(relay_vk)?;

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
    ) -> Result<(Vec<u8>, MlsMessageOut)> {
        let epoch = self.epoch();
        let bundle = self.mls_group.commit_builder()
            .propose_adds([key_package])
            .load_psks(provider.storage())
            .map_err(|e| GhostError::Mls(format!("load psks: {e}")))?
            .build(provider.rand(), provider.crypto(), &self.signer, validate_pending_proposal)
            .map_err(|e| GhostError::Mls(format!("build add commit: {e}")))?
            .stage_commit(provider)
            .map_err(|e| GhostError::Mls(format!("stage add commit: {e}")))?;

        let commit_bytes = bundle.commit()
            .to_bytes()
            .map_err(|e| GhostError::Mls(format!("serialize commit: {e}")))?;
        let welcome_msg = bundle.welcome().cloned()
            .ok_or_else(|| GhostError::Mls("add commit produced no welcome".into()))?;

        // Commit is staged but NOT merged — caller must post to relay first,
        // then call merge_pending_commit() on success or clear_pending_commit() on failure.

        // Serialize welcome as MlsMessageOut for the caller
        let welcome_out = MlsMessageOut::from_welcome(welcome_msg, ProtocolVersion::Mls10);
        Ok((wrap_commit(&commit_bytes, epoch), welcome_out))
    }

    /// Kick one or more leaves from the group. Returns envelope-wrapped commit bytes.
    pub fn remove_members(
        &mut self,
        provider: &GhostProvider,
        members: &[LeafNodeIndex],
    ) -> Result<Vec<u8>> {
        let epoch = self.epoch();
        let bundle = self.mls_group.commit_builder()
            .propose_removals(members.iter().copied())
            .load_psks(provider.storage())
            .map_err(|e| GhostError::Mls(format!("load psks: {e}")))?
            .build(provider.rand(), provider.crypto(), &self.signer, validate_pending_proposal)
            .map_err(|e| GhostError::Mls(format!("build remove commit: {e}")))?
            .stage_commit(provider)
            .map_err(|e| GhostError::Mls(format!("stage remove commit: {e}")))?;

        let commit_bytes = bundle.into_commit()
            .to_bytes()
            .map_err(|e| GhostError::Mls(format!("serialize commit: {e}")))?;

        // Commit is staged but NOT merged — caller must post to relay first,
        // then call merge_pending_commit() on success or clear_pending_commit() on failure.

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

    /// Merge a commit we created after the relay has accepted it.
    pub fn merge_pending_commit(&mut self, provider: &GhostProvider) -> Result<()> {
        self.mls_group
            .merge_pending_commit(provider)
            .map_err(|e| GhostError::Mls(format!("merge pending commit: {e}")))
    }

    /// Discard a pending commit after the relay rejected it.
    /// Returns Ok(()) even if there is no pending commit.
    pub fn clear_pending_commit(&mut self, provider: &GhostProvider) -> Result<()> {
        let _ = self.mls_group.clear_pending_commit(provider.storage());
        Ok(())
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
            .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true)
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

    /// Check if this group already has ExternalSendersExtension.
    pub fn has_external_senders(&self) -> bool {
        self.mls_group.extensions().external_senders().is_some()
    }

    /// Add ExternalSendersExtension for the relay key to a group that was
    /// created before relay MLS enforcement. Returns envelope-wrapped commit.
    pub fn add_external_sender_extension(
        &mut self,
        provider: &GhostProvider,
        relay_vk: &[u8; 32],
    ) -> Result<Vec<u8>> {
        let external_sender = ExternalSender::new(
            SignaturePublicKey::from(relay_vk.to_vec()),
            Credential::new(CredentialType::Basic, b"ghost-relay".to_vec()),
        );

        // Build new extensions: keep existing ones, add ExternalSenders
        let mut ext_vec: Vec<Extension> = Vec::new();
        for e in self.mls_group.extensions().iter() {
            ext_vec.push(e.clone());
        }
        ext_vec.push(Extension::ExternalSenders(vec![external_sender]));

        let extensions = Extensions::from_vec(ext_vec)
            .map_err(|e| GhostError::Mls(format!("build extensions: {e}")))?;

        let epoch = self.epoch();
        let bundle = self.mls_group.commit_builder()
            .propose_group_context_extensions(extensions)
            .map_err(|e| GhostError::Mls(format!("propose extensions: {e}")))?
            .load_psks(provider.storage())
            .map_err(|e| GhostError::Mls(format!("load psks: {e}")))?
            .build(provider.rand(), provider.crypto(), &self.signer, validate_pending_proposal)
            .map_err(|e| GhostError::Mls(format!("build extension commit: {e}")))?
            .stage_commit(provider)
            .map_err(|e| GhostError::Mls(format!("stage extension commit: {e}")))?;

        let commit_bytes = bundle.into_commit()
            .to_bytes()
            .map_err(|e| GhostError::Mls(format!("serialize extension commit: {e}")))?;

        // Commit is staged but NOT merged — caller must post to relay first,
        // then call merge_pending_commit() on success or clear_pending_commit() on failure.

        Ok(wrap_commit(&commit_bytes, epoch))
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
            .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true)
            .build();
        let (mls_group, commit_bundle) = MlsGroup::external_commit_builder()
            .with_config(ext_join_config)
            .build_group(provider, vgi, credential)
            .map_err(|e| GhostError::Mls(format!("build external commit: {e}")))?
            .load_psks(provider.storage())
            .map_err(|e| GhostError::Mls(format!("load psks: {e}")))?
            .build(provider.rand(), provider.crypto(), &signer, validate_pending_proposal)
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

    #[test]
    fn create_group_has_single_member() {
        let provider = GhostProvider::new_in_memory().unwrap();
        let id = Identity::from_seed([0x01u8; 32]).unwrap();
        let group = GhostGroup::create(&provider, &id, None).unwrap();
        assert!(!group.group_id().is_empty());
        assert_eq!(group.members().count(), 1);
        assert!(!group.has_external_senders());
    }

    #[test]
    fn create_with_relay_vk_enables_external_senders() {
        let provider = GhostProvider::new_in_memory().unwrap();
        let id = Identity::from_seed([0x01u8; 32]).unwrap();
        let relay_vk = [0xFFu8; 32];
        let group = GhostGroup::create(&provider, &id, Some(&relay_vk)).unwrap();
        assert!(group.has_external_senders());
    }

    #[test]
    fn add_member_and_join() {
        let provider_a = GhostProvider::new_in_memory().unwrap();
        let provider_b = GhostProvider::new_in_memory().unwrap();

        let id_a = Identity::from_seed([0x01u8; 32]).unwrap();
        let id_b = Identity::from_seed([0x02u8; 32]).unwrap();

        let mut group_a = GhostGroup::create(&provider_a, &id_a, None).unwrap();
        let kp_b = generate_key_package(&provider_b, &id_b).unwrap();

        let (_commit, welcome) = group_a
            .add_member(&provider_a, kp_b)
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

        let mut group_a = GhostGroup::create(&provider_a, &id_a, None).unwrap();
        let kp_b = generate_key_package(&provider_b, &id_b).unwrap();
        let (_commit, welcome) = group_a
            .add_member(&provider_a, kp_b)
            .unwrap();
        group_a.merge_pending_commit(&provider_a).unwrap();
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
    fn export_secret_differs_by_label_and_is_deterministic() {
        let provider = GhostProvider::new_in_memory().unwrap();
        let id = Identity::from_seed([0x01u8; 32]).unwrap();
        let group = GhostGroup::create(&provider, &id, None).unwrap();

        let s1 = group.export_secret(&provider, "label-a", b"ctx", 32).unwrap();
        let s2 = group.export_secret(&provider, "label-b", b"ctx", 32).unwrap();
        let s3 = group.export_secret(&provider, "label-a", b"other-ctx", 32).unwrap();
        assert_ne!(s1, s2, "different labels must produce different secrets");
        assert_ne!(s1, s3, "different contexts must produce different secrets");

        // Same inputs must be deterministic
        let s1_again = group.export_secret(&provider, "label-a", b"ctx", 32).unwrap();
        assert_eq!(s1, s1_again);
    }

    #[test]
    fn export_and_external_commit() {
        let provider_a = GhostProvider::new_in_memory().unwrap();
        let provider_b = GhostProvider::new_in_memory().unwrap();

        let id_a = Identity::from_seed([0x01u8; 32]).unwrap();
        let id_b = Identity::from_seed([0x02u8; 32]).unwrap();

        let group_a = GhostGroup::create(&provider_a, &id_a, None).unwrap();
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
            &provider, &id, &server_id, None,
        ).unwrap();
        let original_mls_id = original.group_id().to_vec();

        let loaded = GhostGroup::load(&provider, &id, &server_id)
            .unwrap()
            .expect("group should be loadable");
        assert_eq!(loaded.group_id(), original_mls_id.as_slice());
    }

    #[test]
    fn remove_member() {
        let provider_a = GhostProvider::new_in_memory().unwrap();
        let provider_b = GhostProvider::new_in_memory().unwrap();

        let id_a = Identity::from_seed([0x01u8; 32]).unwrap();
        let id_b = Identity::from_seed([0x02u8; 32]).unwrap();

        let mut group_a = GhostGroup::create(&provider_a, &id_a, None).unwrap();

        let kp_b = generate_key_package(&provider_b, &id_b).unwrap();
        let (_commit, _welcome) = group_a
            .add_member(&provider_a, kp_b)
            .unwrap();
        group_a.merge_pending_commit(&provider_a).unwrap();

        let b_leaf: Vec<_> = group_a.members()
            .filter(|m| m.credential.serialized_content() == id_b.fingerprint.as_slice())
            .map(|m| m.index)
            .collect();
        assert_eq!(b_leaf.len(), 1);

        let _remove_commit = group_a.remove_members(
            &provider_a,
            &b_leaf,
        ).unwrap();
        group_a.merge_pending_commit(&provider_a).unwrap();

        // Only creator's leaf should remain
        let member_count = group_a.members().count();
        assert_eq!(member_count, 1);
    }

    #[test]
    fn add_external_sender_extension_to_existing_group() {
        let provider = GhostProvider::new_in_memory().unwrap();
        let id = Identity::from_seed([0x01u8; 32]).unwrap();
        let mut group = GhostGroup::create(&provider, &id, None).unwrap();
        assert!(!group.has_external_senders());

        let relay_vk = [0xFFu8; 32];
        let commit = group.add_external_sender_extension(&provider, &relay_vk).unwrap();
        group.merge_pending_commit(&provider).unwrap();
        assert!(!commit.is_empty());
        assert!(group.has_external_senders());
    }

    #[test]
    fn delete_then_load_returns_none() {
        let provider = GhostProvider::new_in_memory().unwrap();
        let id = Identity::from_seed([0x01u8; 32]).unwrap();
        let server_id = [0x42u8; 32];

        let group = GhostGroup::create_with_id(&provider, &id, &server_id, None).unwrap();
        assert!(GhostGroup::load(&provider, &id, &server_id).unwrap().is_some());
        group.delete(&provider).unwrap();
        assert!(GhostGroup::load(&provider, &id, &server_id).unwrap().is_none());
    }

    #[test]
    fn load_nonexistent_returns_none() {
        let provider = GhostProvider::new_in_memory().unwrap();
        let id = Identity::from_seed([0x01u8; 32]).unwrap();
        assert!(GhostGroup::load(&provider, &id, &[0x99u8; 32]).unwrap().is_none());
    }

    #[test]
    fn wrap_commit_produces_valid_envelope() {
        let mls_bytes = b"fake-commit-payload";
        let epoch = 42u64;
        let wrapped = wrap_commit(mls_bytes, epoch);

        let (envelope_type, decoded_epoch) = ghost_wire::decode_envelope(&wrapped).unwrap();
        assert_eq!(envelope_type, ghost_wire::EnvelopeType::Commit);
        assert_eq!(decoded_epoch, epoch);
        assert_eq!(ghost_wire::envelope_payload(&wrapped), mls_bytes);
    }

    #[test]
    fn process_message_bytes_rejects_garbage() {
        let provider = GhostProvider::new_in_memory().unwrap();
        let id = Identity::from_seed([0x01u8; 32]).unwrap();
        let mut group = GhostGroup::create(&provider, &id, None).unwrap();
        assert!(group.process_message_bytes(&provider, b"not-valid-mls").is_err());
    }
}
