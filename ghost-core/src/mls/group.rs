use openmls::prelude::*;
use openmls::prelude::tls_codec::Deserialize;
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

/// An encrypted MLS group — used for both multi-member groups and 2-person DMs.
pub struct GhostGroup {
    mls_group: MlsGroup,
    signer: SignatureKeyPair,
}

impl GhostGroup {
    /// Start a new group where this identity is the first (and only) member.
    pub fn create(provider: &GhostProvider, identity: &Identity) -> Result<Self> {
        let signer = signer_from_identity(identity);
        let credential = credential_from_identity(identity);

        let config = MlsGroupCreateConfig::builder()
            .use_ratchet_tree_extension(true)
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
        group_id: &[u8; 32],
    ) -> Result<Self> {
        let signer = signer_from_identity(identity);
        let credential = credential_from_identity(identity);

        let config = MlsGroupCreateConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();

        let mls_group_id = derive_mls_group_id(group_id);
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
        group_id: &[u8; 32],
    ) -> Result<Option<Self>> {
        let mls_group_id = derive_mls_group_id(group_id);
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
        let (commit, welcome, _group_info) = self
            .mls_group
            .add_members(provider, &self.signer, &[key_package])
            .map_err(|e| GhostError::Mls(format!("add member: {e}")))?;

        let epoch = self.epoch();
        let commit_bytes = commit
            .to_bytes()
            .map_err(|e| GhostError::Mls(format!("serialize commit: {e}")))?;

        self.mls_group
            .merge_pending_commit(provider)
            .map_err(|e| GhostError::Mls(format!("merge add commit: {e}")))?;

        Ok((wrap_commit(&commit_bytes, epoch), welcome))
    }

    /// Kick a member from the group. Returns envelope-wrapped commit bytes.
    pub fn remove_member(
        &mut self,
        provider: &GhostProvider,
        member: LeafNodeIndex,
    ) -> Result<Vec<u8>> {
        let (commit, _welcome, _group_info) = self
            .mls_group
            .remove_members(provider, &self.signer, &[member])
            .map_err(|e| GhostError::Mls(format!("remove member: {e}")))?;

        let epoch = self.epoch();
        let commit_bytes = commit
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
        let join_config = MlsGroupJoinConfig::default();
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

        let (mls_group, commit_bundle) = MlsGroup::external_commit_builder()
            .build_group(provider, vgi, credential)
            .map_err(|e| GhostError::Mls(format!("build external commit: {e}")))?
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

        // epoch() is post-merge; the commit targeted epoch - 1
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
    fn create_group() {
        let provider = GhostProvider::new_in_memory().unwrap();
        let id = Identity::from_seed([0x01u8; 32]).unwrap();
        let group = GhostGroup::create(&provider, &id).unwrap();
        assert!(!group.group_id().is_empty());
    }

    #[test]
    fn add_member_and_join() {
        let provider_a = GhostProvider::new_in_memory().unwrap();
        let provider_b = GhostProvider::new_in_memory().unwrap();

        let id_a = Identity::from_seed([0x01u8; 32]).unwrap();
        let id_b = Identity::from_seed([0x02u8; 32]).unwrap();

        let mut group_a = GhostGroup::create(&provider_a, &id_a).unwrap();
        let kp_b = generate_key_package(&provider_b, &id_b).unwrap();

        let (_commit, welcome) = group_a.add_member(&provider_a, kp_b).unwrap();

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

        let mut group_a = GhostGroup::create(&provider_a, &id_a).unwrap();
        let kp_b = generate_key_package(&provider_b, &id_b).unwrap();
        let (_commit, welcome) = group_a.add_member(&provider_a, kp_b).unwrap();
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
        let group = GhostGroup::create(&provider, &id).unwrap();

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

        let group_a = GhostGroup::create(&provider_a, &id_a).unwrap();
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
        let group_id = [0x42u8; 32];

        let original = GhostGroup::create_with_id(&provider, &id, &group_id).unwrap();
        let original_mls_id = original.group_id().to_vec();

        // Load from the same provider — state was written automatically
        let loaded = GhostGroup::load(&provider, &id, &group_id)
            .unwrap()
            .expect("group should be loadable");
        assert_eq!(loaded.group_id(), original_mls_id.as_slice());
    }
}
