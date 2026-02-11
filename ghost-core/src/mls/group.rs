use openmls::prelude::*;
use openmls::prelude::tls_codec::Deserialize;
use openmls_basic_credential::SignatureKeyPair;

use crate::crypto::GhostProvider;
use crate::error::{GhostError, Result};
use crate::identity::Identity;
use crate::wire::derive_mls_group_id;

use super::credential::{credential_from_identity, signer_from_identity};

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
            provider.inner(),
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
            provider.inner(),
            &signer,
            &config,
            GroupId::from_slice(&mls_group_id),
            credential,
        )
        .map_err(|e| GhostError::Mls(format!("create group: {e}")))?;

        Ok(Self { mls_group, signer })
    }

    /// Add someone to this group. Returns a commit (broadcast to existing members)
    /// and a welcome (sent to the new member so they can join).
    pub fn add_member(
        &mut self,
        provider: &GhostProvider,
        key_package: KeyPackage,
    ) -> Result<(MlsMessageOut, MlsMessageOut)> {
        let (commit, welcome, _group_info) = self
            .mls_group
            .add_members(provider.inner(), &self.signer, &[key_package])
            .map_err(|e| GhostError::Mls(format!("add member: {e}")))?;

        self.mls_group
            .merge_pending_commit(provider.inner())
            .map_err(|e| GhostError::Mls(format!("merge add commit: {e}")))?;

        Ok((commit, welcome))
    }

    /// Kick a member from the group by their leaf position in the MLS tree.
    pub fn remove_member(
        &mut self,
        provider: &GhostProvider,
        member: LeafNodeIndex,
    ) -> Result<MlsMessageOut> {
        let (commit, _welcome, _group_info) = self
            .mls_group
            .remove_members(provider.inner(), &self.signer, &[member])
            .map_err(|e| GhostError::Mls(format!("remove member: {e}")))?;

        self.mls_group
            .merge_pending_commit(provider.inner())
            .map_err(|e| GhostError::Mls(format!("merge remove commit: {e}")))?;

        Ok(commit)
    }

    /// Encrypt a plaintext message so only group members can read it.
    pub fn encrypt(
        &mut self,
        provider: &GhostProvider,
        plaintext: &[u8],
    ) -> Result<MlsMessageOut> {
        self.mls_group
            .create_message(provider.inner(), &self.signer, plaintext)
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
            .process_message(provider.inner(), protocol_message)
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
            .process_message(provider.inner(), protocol_message)
            .map_err(|e| GhostError::Mls(format!("process message: {e}")))
    }

    /// Apply a commit that we received and already validated via process_message.
    pub fn merge_staged_commit(
        &mut self,
        provider: &GhostProvider,
        commit: StagedCommit,
    ) -> Result<()> {
        self.mls_group
            .merge_staged_commit(provider.inner(), commit)
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
            StagedWelcome::new_from_welcome(provider.inner(), &join_config, welcome_msg, None)
                .map_err(|e| GhostError::Mls(format!("staged welcome: {e}")))?
                .into_group(provider.inner())
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
            .export_secret(provider.inner().crypto(), label, context, length)
            .map_err(|e| GhostError::Mls(format!("export secret: {e}")))
    }

    pub fn group_id(&self) -> &[u8] {
        self.mls_group.group_id().as_slice()
    }

    pub fn members(&self) -> impl Iterator<Item = Member> + '_ {
        self.mls_group.members()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mls::credential::generate_key_package;

    #[test]
    fn create_group() {
        let provider = GhostProvider::new();
        let alice = Identity::from_seed([0x01u8; 32]).unwrap();
        let group = GhostGroup::create(&provider, &alice).unwrap();
        assert!(!group.group_id().is_empty());
    }

    #[test]
    fn add_member_and_join() {
        let alice_provider = GhostProvider::new();
        let bob_provider = GhostProvider::new();

        let alice = Identity::from_seed([0x01u8; 32]).unwrap();
        let bob = Identity::from_seed([0x02u8; 32]).unwrap();

        let mut alice_group = GhostGroup::create(&alice_provider, &alice).unwrap();
        let bob_kp = generate_key_package(&bob_provider, &bob).unwrap();

        let (_commit, welcome) = alice_group.add_member(&alice_provider, bob_kp).unwrap();

        let bob_group =
            GhostGroup::join(&bob_provider, &bob, &welcome.to_bytes().unwrap()).unwrap();

        assert_eq!(alice_group.group_id(), bob_group.group_id());
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let alice_provider = GhostProvider::new();
        let bob_provider = GhostProvider::new();

        let alice = Identity::from_seed([0x01u8; 32]).unwrap();
        let bob = Identity::from_seed([0x02u8; 32]).unwrap();

        let mut alice_group = GhostGroup::create(&alice_provider, &alice).unwrap();
        let bob_kp = generate_key_package(&bob_provider, &bob).unwrap();
        let (_commit, welcome) = alice_group.add_member(&alice_provider, bob_kp).unwrap();
        let mut bob_group =
            GhostGroup::join(&bob_provider, &bob, &welcome.to_bytes().unwrap()).unwrap();

        let msg = b"hello from alice";
        let ciphertext = alice_group.encrypt(&alice_provider, msg).unwrap();
        let processed = bob_group.process_message(&bob_provider, &ciphertext).unwrap();

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app_msg) => {
                assert_eq!(app_msg.into_bytes(), msg);
            }
            other => panic!("expected ApplicationMessage, got {:?}", other),
        }
    }

    #[test]
    fn dm_two_person_group() {
        let alice_provider = GhostProvider::new();
        let bob_provider = GhostProvider::new();

        let alice = Identity::from_seed([0x10u8; 32]).unwrap();
        let bob = Identity::from_seed([0x20u8; 32]).unwrap();

        let mut alice_group = GhostGroup::create(&alice_provider, &alice).unwrap();
        let bob_kp = generate_key_package(&bob_provider, &bob).unwrap();
        let (_commit, welcome) = alice_group.add_member(&alice_provider, bob_kp).unwrap();
        let mut bob_group =
            GhostGroup::join(&bob_provider, &bob, &welcome.to_bytes().unwrap()).unwrap();

        // Bob sends a DM to Alice
        let msg = b"hey alice, this is a DM";
        let ciphertext = bob_group.encrypt(&bob_provider, msg).unwrap();
        let processed = alice_group.process_message(&alice_provider, &ciphertext).unwrap();

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app_msg) => {
                assert_eq!(app_msg.into_bytes(), msg);
            }
            other => panic!("expected ApplicationMessage, got {:?}", other),
        }
    }

    #[test]
    fn export_secret_returns_32_bytes() {
        let provider = GhostProvider::new();
        let alice = Identity::from_seed([0x01u8; 32]).unwrap();
        let group = GhostGroup::create(&provider, &alice).unwrap();

        let secret = group
            .export_secret(&provider, "ghost-voice", b"test-context", 32)
            .unwrap();
        assert_eq!(secret.len(), 32);
    }
}
