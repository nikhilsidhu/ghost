use openmls::prelude::*;
use openmls::prelude::tls_codec::Deserialize;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;

use crate::crypto::GhostProvider;
use crate::error::{GhostError, Result};
use crate::idlog_cache::IdLogCache;
use crate::identity::Identity;
use crate::wire::derive_mls_group_id;

use super::credential::{credential_from_identity, signer_from_identity};
use ghost_wire::policy::{
    ChannelPolicy, CommitAad, RemovedAccounts, ServerPolicy, CHANNEL_POLICY_EXTENSION, SERVER_POLICY_EXTENSION,
    SERVER_REMOVALS_EXTENSION,
};

/// Ghost's own GroupContext extension types. Every Ghost leaf advertises them all, and a
/// group may only carry an extension that all its members' leaves advertise.
const GHOST_EXTENSIONS: [u16; 3] = [SERVER_POLICY_EXTENSION, CHANNEL_POLICY_EXTENSION, SERVER_REMOVALS_EXTENSION];
/// The extensions roles and private channels rest on.
pub const POLICY_EXTENSIONS: [u16; 2] = [SERVER_POLICY_EXTENSION, CHANNEL_POLICY_EXTENSION];

/// Extension types every Ghost leaf supports beyond the MLS defaults.
pub fn ghost_capabilities() -> Capabilities {
    let types: Vec<ExtensionType> = GHOST_EXTENSIONS.iter().map(|ty| ExtensionType::Unknown(*ty)).collect();
    Capabilities::new(None, None, Some(&types), None, None)
}

/// One of the GroupContext extensions only Ghost reads.
pub enum GhostExtension {
    Server(ServerPolicy),
    Channel(ChannelPolicy),
    Removals(RemovedAccounts),
}

impl GhostExtension {
    fn extension_type(&self) -> u16 {
        match self {
            Self::Server(_) => SERVER_POLICY_EXTENSION,
            Self::Channel(_) => CHANNEL_POLICY_EXTENSION,
            Self::Removals(_) => SERVER_REMOVALS_EXTENSION,
        }
    }

    fn bytes(&self) -> Vec<u8> {
        match self {
            Self::Server(p) => p.to_bytes(),
            Self::Channel(p) => p.to_bytes(),
            Self::Removals(r) => r.to_bytes(),
        }
    }
}

/// `existing` context extensions with `updates` in place of any of the same type, plus a
/// required-capabilities entry naming every Ghost extension the result carries, so no
/// member may lack support for one.
fn with_ghost_extensions(existing: &Extensions<GroupContext>, updates: &[GhostExtension]) -> Result<Extensions<GroupContext>> {
    let replaced: Vec<ExtensionType> = updates.iter().map(|u| ExtensionType::Unknown(u.extension_type())).collect();
    let mut ext_vec: Vec<Extension> = existing
        .iter()
        .filter(|e| !matches!(e, Extension::RequiredCapabilities(_)) && !replaced.contains(&e.extension_type()))
        .cloned()
        .collect();
    ext_vec.extend(updates.iter().map(|u| Extension::Unknown(u.extension_type(), UnknownExtension(u.bytes()))));
    let required: Vec<ExtensionType> = GHOST_EXTENSIONS
        .iter()
        .map(|ty| ExtensionType::Unknown(*ty))
        .filter(|ty| ext_vec.iter().any(|e| e.extension_type() == *ty))
        .collect();
    if !required.is_empty() {
        ext_vec.push(Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(&required, &[], &[])));
    }
    Extensions::from_vec(ext_vec).map_err(|e| GhostError::Mls(format!("group context extensions: {e}")))
}

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

/// Validate pending proposals when building commits. Accepts member proposals (the
/// relay already validated them) and the relay's removals, the only external proposal
/// the shared commit check admits. Rejects unexpected sender types.
fn validate_pending_proposal(proposal: &QueuedProposal) -> bool {
    match proposal.sender() {
        Sender::Member(_) => true,
        Sender::External(_) => matches!(proposal.proposal(), Proposal::Remove(_)),
        // External commit: ExternalInit is required, Remove/PSK are allowed
        Sender::NewMemberCommit => matches!(
            proposal.proposal(),
            Proposal::ExternalInit(_) | Proposal::Remove(_) | Proposal::PreSharedKey(_)
        ),
        _ => false,
    }
}

/// The epoch a GroupInfo claims, read without verifying it: enough to tell whether the
/// group moved past this device's copy.
pub fn group_info_epoch(group_info_bytes: &[u8]) -> Result<u64> {
    let msg_in = MlsMessageIn::tls_deserialize_exact(group_info_bytes).map_err(|e| GhostError::Mls(format!("deserialize group info: {e}")))?;
    match msg_in.extract() {
        MlsMessageBodyIn::GroupInfo(vgi) => Ok(vgi.epoch().as_u64()),
        _ => Err(GhostError::Mls("expected GroupInfo message".into())),
    }
}

/// An encrypted MLS group — used for both multi-member groups and 2-person DMs.
pub struct GhostGroup {
    mls_group: MlsGroup,
    signer: SignatureKeyPair,
}

impl GhostGroup {
    /// Build an MlsGroupCreateConfig with Ghost's leaf capabilities, optionally adding
    /// the relay as external sender and an access policy.
    fn build_create_config(relay_vk: Option<&[u8; 32]>, policy: Option<GhostExtension>) -> Result<MlsGroupCreateConfig> {
        let mut builder = MlsGroupCreateConfig::builder()
            .use_ratchet_tree_extension(true)
            .max_past_epochs(1)
            .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
            .capabilities(ghost_capabilities());

        let mut ext_vec = Vec::new();
        if let Some(vk) = relay_vk {
            let external_sender = ExternalSender::new(
                SignaturePublicKey::from(vk.to_vec()),
                Credential::new(CredentialType::Basic, b"ghost-relay".to_vec()),
            );
            ext_vec.push(Extension::ExternalSenders(vec![external_sender]));
        }
        let base = Extensions::from_vec(ext_vec).map_err(|e| GhostError::Mls(format!("group context extensions: {e}")))?;
        let extensions = with_ghost_extensions(&base, policy.as_slice())?;
        if extensions.iter().next().is_some() {
            builder = builder.with_group_context_extensions(extensions);
        }

        Ok(builder.build())
    }

    /// Start a new group, its MLS group ID derived from the server and channel ids, with
    /// this identity as its first member.
    pub fn create(
        provider: &GhostProvider,
        identity: &Identity,
        server_id: &[u8; 32],
        channel_id: &[u8; 32],
        relay_vk: Option<&[u8; 32]>,
        policy: Option<GhostExtension>,
    ) -> Result<Self> {
        let signer = signer_from_identity(identity);
        let credential = credential_from_identity(identity);
        let config = Self::build_create_config(relay_vk, policy)?;

        let mls_group_id = derive_mls_group_id(server_id, channel_id);
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

    /// Reload a group from persistent storage by server_id + channel_id.
    pub fn load(
        provider: &GhostProvider,
        identity: &Identity,
        server_id: &[u8; 32],
        channel_id: &[u8; 32],
    ) -> Result<Option<Self>> {
        let mls_group_id = derive_mls_group_id(server_id, channel_id);
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

    /// Kick one or more leaves from the group. Returns envelope-wrapped commit bytes.
    pub fn remove_members(
        &mut self,
        provider: &GhostProvider,
        members: &[LeafNodeIndex],
        aad: &CommitAad,
    ) -> Result<Vec<u8>> {
        self.stage_change(provider, members, &[], aad)
    }

    /// Stage one commit removing `removed` leaves and putting `updates` in place of Ghost's
    /// context extensions of the same types, either or both, keeping every other
    /// extension. Returns the envelope-wrapped commit. It is staged, not merged: the caller
    /// posts it to the relay, then merges the pending commit or clears it.
    pub fn stage_change(
        &mut self,
        provider: &GhostProvider,
        removed: &[LeafNodeIndex],
        updates: &[GhostExtension],
        aad: &CommitAad,
    ) -> Result<Vec<u8>> {
        let extensions = if updates.is_empty() { None } else { Some(with_ghost_extensions(self.mls_group.extensions(), updates)?) };
        let epoch = self.epoch();
        self.mls_group.set_aad(aad.to_bytes());
        let mut builder = self.mls_group.commit_builder().propose_removals(removed.iter().copied());
        if let Some(extensions) = extensions {
            builder = builder.propose_group_context_extensions(extensions).map_err(|e| GhostError::Mls(format!("propose extensions: {e}")))?;
        }
        let bundle = builder
            .load_psks(provider.storage())
            .map_err(|e| GhostError::Mls(format!("load psks: {e}")))?
            .build(provider.rand(), provider.crypto(), &self.signer, validate_pending_proposal)
            .map_err(|e| GhostError::Mls(format!("build commit: {e}")))?
            .stage_commit(provider)
            .map_err(|e| GhostError::Mls(format!("stage commit: {e}")))?;
        let commit_bytes = bundle.into_commit()
            .to_bytes()
            .map_err(|e| GhostError::Mls(format!("serialize commit: {e}")))?;
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
                // Our own commit echoed back before we merged it.
                ProcessMessageError::InvalidCommit(StageCommitError::OwnCommit) => GhostError::SelfMessage,
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

    /// Commit the queued proposals this device may commit (e.g. relay-generated Remove
    /// proposals). External Remove proposals are only included if the target device is
    /// revoked in the identity log or its leaf is in `excluded` (a private channel's
    /// policy no longer admits it), so a compromised relay key cannot remove anyone
    /// else. A proposal removing this device is left for another member, since a member
    /// cannot commit its own removal. `None` when nothing is left to commit.
    pub fn commit_pending_proposals(
        &mut self,
        provider: &GhostProvider,
        idlog_cache: &IdLogCache,
        excluded: &[LeafNodeIndex],
        aad: &CommitAad,
    ) -> Result<Option<Vec<u8>>> {
        // Build leaf→(account_fp, device_vk) map for Remove target validation
        let member_map: std::collections::HashMap<u32, ([u8; 32], [u8; 32])> = self
            .members()
            .filter_map(|m| {
                let fp = super::credential::parse_credential(&m.credential).ok()?.account_fp;
                let vk: [u8; 32] = m.signature_key.as_slice().try_into().ok()?;
                Some((m.index.u32(), (fp, vk)))
            })
            .collect();
        let own_leaf = self.mls_group.own_leaf_index();
        let committable = |proposal: &QueuedProposal| {
            if !validate_pending_proposal(proposal) {
                return false;
            }
            if let Proposal::Remove(ref remove) = proposal.proposal() {
                if remove.removed() == own_leaf {
                    return false;
                }
                // External Remove proposals: only accept if target is revoked or excluded
                if matches!(proposal.sender(), Sender::External(_)) {
                    if excluded.contains(&remove.removed()) {
                        return true;
                    }
                    let leaf_idx = remove.removed().u32();
                    return match member_map.get(&leaf_idx) {
                        Some((account_fp, device_vk)) => matches!(idlog_cache.is_active_device(account_fp, device_vk), Ok(false)),
                        None => false, // unknown leaf → reject
                    };
                }
            }
            true
        };
        if !self.mls_group.pending_proposals().any(&committable) {
            return Ok(None);
        }

        let epoch = self.epoch();
        self.mls_group.set_aad(aad.to_bytes());
        let bundle = self.mls_group.commit_builder()
            .load_psks(provider.storage())
            .map_err(|e| GhostError::Mls(format!("load psks: {e}")))?
            .build(provider.rand(), provider.crypto(), &self.signer, committable)
            .map_err(|e| GhostError::Mls(format!("build pending commit: {e}")))?
            .stage_commit(provider)
            .map_err(|e| GhostError::Mls(format!("stage pending commit: {e}")))?;

        let commit_bytes = bundle.into_commit()
            .to_bytes()
            .map_err(|e| GhostError::Mls(format!("serialize pending commit: {e}")))?;
        Ok(Some(wrap_commit(&commit_bytes, epoch)))
    }

    /// Queue a received proposal so the next commit from this device can include it;
    /// OpenMLS hands processed proposals back without keeping them. One already queued
    /// (the same blob read again after a restart) is queued once.
    pub fn store_pending_proposal(&mut self, provider: &GhostProvider, proposal: QueuedProposal) -> Result<()> {
        let reference = proposal.proposal_reference_ref();
        if self.mls_group.pending_proposals().any(|queued| queued.proposal_reference_ref() == reference) {
            return Ok(());
        }
        self.mls_group
            .store_pending_proposal(provider.storage(), proposal)
            .map_err(|e| GhostError::Mls(format!("queue proposal: {e:?}")))
    }

    /// The accounts whose leaves queued Remove proposals name, each once.
    pub fn pending_removal_accounts(&self) -> Vec<[u8; 32]> {
        let targets: Vec<LeafNodeIndex> = self
            .mls_group
            .pending_proposals()
            .filter_map(|p| match p.proposal() {
                Proposal::Remove(remove) => Some(remove.removed()),
                _ => None,
            })
            .collect();
        let mut accounts: Vec<[u8; 32]> = Vec::new();
        for member in self.members().filter(|m| targets.contains(&m.index)) {
            if let Ok(parsed) = super::credential::parse_credential(&member.credential) {
                if !accounts.contains(&parsed.account_fp) {
                    accounts.push(parsed.account_fp);
                }
            }
        }
        accounts
    }

    /// Whether proposals are queued that another member's leaf, not this device's, is
    /// the subject of: once this device's view catches up it may be able to commit them.
    pub fn has_pending_proposals_for_others(&self) -> bool {
        let own_leaf = self.mls_group.own_leaf_index();
        self.mls_group.pending_proposals().any(|p| match p.proposal() {
            Proposal::Remove(remove) => remove.removed() != own_leaf,
            _ => true,
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

    /// The group's context extensions, where its access policy lives.
    pub fn context_extensions(&self) -> &Extensions<GroupContext> {
        self.mls_group.extensions()
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

    fn extension_bytes(&self, extension_type: u16) -> Option<&[u8]> {
        self.mls_group.extensions().unknown(extension_type).map(|ext| ext.0.as_slice())
    }

    /// The server policy this group carries, if any.
    pub fn server_policy(&self) -> Result<Option<ServerPolicy>> {
        self.extension_bytes(SERVER_POLICY_EXTENSION)
            .map(|b| ServerPolicy::from_bytes(b).map_err(|e| GhostError::Format(e.to_string())))
            .transpose()
    }

    /// The private channel policy this group carries, if any.
    pub fn channel_policy(&self) -> Result<Option<ChannelPolicy>> {
        self.extension_bytes(CHANNEL_POLICY_EXTENSION)
            .map(|b| ChannelPolicy::from_bytes(b).map_err(|e| GhostError::Format(e.to_string())))
            .transpose()
    }

    /// The removed list this server group carries, if any.
    pub fn removed_accounts(&self) -> Result<Option<RemovedAccounts>> {
        self.extension_bytes(SERVER_REMOVALS_EXTENSION)
            .map(|b| RemovedAccounts::from_bytes(b).map_err(|e| GhostError::Format(e.to_string())))
            .transpose()
    }

    /// Stage a commit setting the group's access policy, keeping every other extension.
    /// Returns the envelope-wrapped commit; the caller posts it and merges or clears it.
    pub fn stage_policy(&mut self, provider: &GhostProvider, policy: GhostExtension, aad: &CommitAad) -> Result<Vec<u8>> {
        self.stage_change(provider, &[], &[policy], aad)
    }

    /// Check if this group already has ExternalSendersExtension.
    pub fn has_external_senders(&self) -> bool {
        self.mls_group.extensions().external_senders().is_some()
    }

    /// Make `relay_vk` the group's only external sender, replacing any previous
    /// relay, so the relay now hosting the group may propose removals. Returns the
    /// envelope-wrapped commit, staged but not merged.
    pub fn set_external_sender(
        &mut self,
        provider: &GhostProvider,
        relay_vk: &[u8; 32],
        aad: &CommitAad,
    ) -> Result<Vec<u8>> {
        let external_sender = ExternalSender::new(
            SignaturePublicKey::from(relay_vk.to_vec()),
            Credential::new(CredentialType::Basic, b"ghost-relay".to_vec()),
        );

        // Keep every other extension; the external sender list is replaced.
        let mut ext_vec: Vec<Extension> = self
            .mls_group
            .extensions()
            .iter()
            .filter(|e| !matches!(e, Extension::ExternalSenders(_)))
            .cloned()
            .collect();
        ext_vec.push(Extension::ExternalSenders(vec![external_sender]));

        let extensions = Extensions::from_vec(ext_vec)
            .map_err(|e| GhostError::Mls(format!("build extensions: {e}")))?;

        let epoch = self.epoch();
        self.mls_group.set_aad(aad.to_bytes());
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
        aad: &CommitAad,
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
        // The joiner's leaf advertises Ghost's capabilities, so policy-carrying groups accept it.
        let leaf_parameters = LeafNodeParameters::builder()
            .with_credential_with_key(credential.clone())
            .with_capabilities(ghost_capabilities())
            .build();
        let (mls_group, commit_bundle) = MlsGroup::external_commit_builder()
            .with_config(ext_join_config)
            .with_aad(aad.to_bytes())
            .build_group(provider, vgi, credential)
            .map_err(|e| GhostError::Mls(format!("build external commit: {e}")))?
            .leaf_node_parameters(leaf_parameters)
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

/// A fresh server group of `identity`'s for tests, as the client makes one.
#[cfg(test)]
pub(crate) fn test_group(provider: &GhostProvider, identity: &Identity, relay_vk: Option<&[u8; 32]>) -> GhostGroup {
    let server_id = [0x42u8; 32];
    let channel_id = crate::wire::derive_default_channel_id(&server_id);
    GhostGroup::create(provider, identity, &server_id, &channel_id, relay_vk, None).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `group` takes in a commit another member made, as the client does over the wire.
    fn apply_commit(group: &mut GhostGroup, provider: &GhostProvider, wrapped_commit: &[u8]) {
        let processed = group.process_message_bytes(provider, &wrapped_commit[ghost_wire::ENVELOPE_HEADER_SIZE..]).unwrap();
        match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged) => group.merge_staged_commit(provider, *staged).unwrap(),
            other => panic!("expected a commit, got {other:?}"),
        }
    }

    #[test]
    fn create_group_has_single_member() {
        let provider = GhostProvider::new_in_memory().unwrap();
        let id = Identity::from_seed([0x01u8; 32]).unwrap();
        let group = test_group(&provider, &id, None);
        assert!(!group.group_id().is_empty());
        assert_eq!(group.members().count(), 1);
        assert!(!group.has_external_senders());
    }

    /// A relay's proposal read twice, as after a restart before the read was recorded,
    /// is queued once, so the next commit removes the leaf once.
    #[test]
    fn a_proposal_read_twice_is_queued_once() {
        use openmls::messages::external_proposals::ExternalProposal;
        let relay = openmls_basic_credential::SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
        let relay_vk: [u8; 32] = relay.public().try_into().unwrap();
        let (provider_a, provider_b) = (GhostProvider::new_in_memory().unwrap(), GhostProvider::new_in_memory().unwrap());
        let (id_a, id_b) = (Identity::from_seed([0x01u8; 32]).unwrap(), Identity::from_seed([0x02u8; 32]).unwrap());
        let mut group_a = test_group(&provider_a, &id_a, Some(&relay_vk));
        let group_info = group_a.export_group_info(&provider_a).unwrap();
        let (group_b, commit) = GhostGroup::join_by_external_commit(&provider_b, &id_b, &group_info, &CommitAad::default()).unwrap();
        apply_commit(&mut group_a, &provider_a, &commit);

        let proposal = ExternalProposal::new_remove::<openmls_rust_crypto::OpenMlsRustCrypto>(
            group_b.mls_group.own_leaf_index(),
            GroupId::from_slice(group_a.group_id()),
            GroupEpoch::from(group_a.epoch()),
            &relay,
            SenderExtensionIndex::new(0),
        )
        .unwrap()
        .to_bytes()
        .unwrap();
        for _ in 0..2 {
            match group_a.process_message_bytes(&provider_a, &proposal).unwrap().into_content() {
                ProcessedMessageContent::ProposalMessage(queued) => group_a.store_pending_proposal(&provider_a, *queued).unwrap(),
                other => panic!("expected a proposal, got {other:?}"),
            }
        }
        assert_eq!(group_a.mls_group.pending_proposals().count(), 1);
    }

    #[test]
    fn create_with_relay_vk_enables_external_senders() {
        let provider = GhostProvider::new_in_memory().unwrap();
        let id = Identity::from_seed([0x01u8; 32]).unwrap();
        let relay_vk = [0xFFu8; 32];
        let group = test_group(&provider, &id, Some(&relay_vk));
        assert!(group.has_external_senders());
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let provider_a = GhostProvider::new_in_memory().unwrap();
        let provider_b = GhostProvider::new_in_memory().unwrap();

        let id_a = Identity::from_seed([0x01u8; 32]).unwrap();
        let id_b = Identity::from_seed([0x02u8; 32]).unwrap();

        let mut group_a = test_group(&provider_a, &id_a, None);
        let group_info = group_a.export_group_info(&provider_a).unwrap();
        let (mut group_b, commit) =
            GhostGroup::join_by_external_commit(&provider_b, &id_b, &group_info, &CommitAad::default()).unwrap();
        apply_commit(&mut group_a, &provider_a, &commit);

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
        let group = test_group(&provider, &id, None);

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

        let group_a = test_group(&provider_a, &id_a, None);
        let group_info_bytes = group_a.export_group_info(&provider_a).unwrap();

        let (group_b, commit_bytes) =
            GhostGroup::join_by_external_commit(&provider_b, &id_b, &group_info_bytes, &CommitAad::default()).unwrap();

        assert_eq!(group_a.group_id(), group_b.group_id());
        assert!(!commit_bytes.is_empty());
    }

    #[test]
    fn load_persisted_group() {
        use crate::wire::derive_default_channel_id;
        let provider = GhostProvider::new_in_memory().unwrap();
        let id = Identity::from_seed([0x01u8; 32]).unwrap();
        let server_id = [0x42u8; 32];
        let channel_id = derive_default_channel_id(&server_id);

        let original = GhostGroup::create(&provider, &id, &server_id, &channel_id, None, None).unwrap();
        let original_mls_id = original.group_id().to_vec();

        let loaded = GhostGroup::load(&provider, &id, &server_id, &channel_id)
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

        let mut group_a = test_group(&provider_a, &id_a, None);
        let group_info = group_a.export_group_info(&provider_a).unwrap();
        let (_group_b, commit) =
            GhostGroup::join_by_external_commit(&provider_b, &id_b, &group_info, &CommitAad::default()).unwrap();
        apply_commit(&mut group_a, &provider_a, &commit);

        let b_leaf: Vec<_> = group_a.members()
            .filter(|m| {
                crate::mls::credential::parse_credential(&m.credential)
                    .ok()
                    .map(|pc| pc.account_fp == id_b.fingerprint)
                    .unwrap_or(false)
            })
            .map(|m| m.index)
            .collect();
        assert_eq!(b_leaf.len(), 1);

        let _remove_commit = group_a.remove_members(
            &provider_a,
            &b_leaf,
            &CommitAad::default(),
        ).unwrap();
        group_a.merge_pending_commit(&provider_a).unwrap();

        // Only creator's leaf should remain
        let member_count = group_a.members().count();
        assert_eq!(member_count, 1);
    }

    #[test]
    fn set_external_sender_on_existing_group() {
        let provider = GhostProvider::new_in_memory().unwrap();
        let id = Identity::from_seed([0x01u8; 32]).unwrap();
        let mut group = test_group(&provider, &id, None);
        assert!(!group.has_external_senders());

        let relay_vk = [0xFFu8; 32];
        let commit = group.set_external_sender(&provider, &relay_vk, &CommitAad::default()).unwrap();
        group.merge_pending_commit(&provider).unwrap();
        assert!(!commit.is_empty());
        assert!(group.has_external_senders());
    }

    #[test]
    fn delete_then_load_returns_none() {
        use crate::wire::derive_default_channel_id;
        let provider = GhostProvider::new_in_memory().unwrap();
        let id = Identity::from_seed([0x01u8; 32]).unwrap();
        let server_id = [0x42u8; 32];
        let channel_id = derive_default_channel_id(&server_id);

        let group = GhostGroup::create(&provider, &id, &server_id, &channel_id, None, None).unwrap();
        assert!(GhostGroup::load(&provider, &id, &server_id, &channel_id).unwrap().is_some());
        group.delete(&provider).unwrap();
        assert!(GhostGroup::load(&provider, &id, &server_id, &channel_id).unwrap().is_none());
    }

    #[test]
    fn load_nonexistent_returns_none() {
        use crate::wire::derive_default_channel_id;
        let provider = GhostProvider::new_in_memory().unwrap();
        let id = Identity::from_seed([0x01u8; 32]).unwrap();
        let fake_server = [0x99u8; 32];
        let fake_channel = derive_default_channel_id(&fake_server);
        assert!(GhostGroup::load(&provider, &id, &fake_server, &fake_channel).unwrap().is_none());
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
        let mut group = test_group(&provider, &id, None);
        assert!(group.process_message_bytes(&provider, b"not-valid-mls").is_err());
    }
}
