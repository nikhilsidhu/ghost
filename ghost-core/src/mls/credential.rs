use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;

use crate::crypto::{GhostProvider, MLS_CIPHERSUITE};
use crate::error::{GhostError, Result};
use crate::identity::Identity;

/// Self-validating credential: 136 bytes packed into BasicCredential identity.
pub const CREDENTIAL_SIZE: usize = 136;

/// Parsed fields from a self-validating credential.
pub struct ParsedCredential {
    pub account_fp: [u8; 32],
    pub master_vk: [u8; 32],
    pub idlog_seq: u64,
    pub delegation_sig: [u8; 64],
}

/// Wrap our Ed25519 signing key so OpenMLS can use it to sign MLS messages.
pub fn signer_from_identity(identity: &Identity) -> SignatureKeyPair {
    SignatureKeyPair::from_raw(
        MLS_CIPHERSUITE.signature_algorithm(),
        identity.signing_key.to_bytes().to_vec(),
        identity.verifying_key.as_bytes().to_vec(),
    )
}

/// Package identity into a self-validating 136-byte MLS credential.
pub fn credential_from_identity(identity: &Identity) -> CredentialWithKey {
    let mut id_bytes = Vec::with_capacity(CREDENTIAL_SIZE);
    id_bytes.extend_from_slice(&identity.fingerprint);
    id_bytes.extend_from_slice(&identity.master_vk);
    id_bytes.extend_from_slice(&identity.idlog_seq.to_be_bytes());
    id_bytes.extend_from_slice(&identity.delegation_sig);
    let basic = BasicCredential::new(id_bytes);
    CredentialWithKey {
        credential: basic.into(),
        signature_key: identity.verifying_key.as_bytes().to_vec().into(),
    }
}

/// Parse a 136-byte self-validating credential.
pub fn parse_credential(credential: &Credential) -> Result<ParsedCredential> {
    let basic = BasicCredential::try_from(credential.clone())
        .map_err(|_| GhostError::Mls("non-basic credential".into()))?;
    let id = basic.identity();
    if id.len() != CREDENTIAL_SIZE {
        return Err(GhostError::Format(format!(
            "credential identity is {} bytes, expected {}",
            id.len(), CREDENTIAL_SIZE,
        )));
    }
    let account_fp: [u8; 32] = id[..32].try_into().unwrap();
    let master_vk: [u8; 32] = id[32..64].try_into().unwrap();
    let idlog_seq = u64::from_be_bytes(id[64..72].try_into().unwrap());
    let delegation_sig: [u8; 64] = id[72..136].try_into().unwrap();
    Ok(ParsedCredential { account_fp, master_vk, idlog_seq, delegation_sig })
}

/// Create a one-time-use token that someone else needs to invite us into their group.
pub fn generate_key_package(
    provider: &GhostProvider,
    identity: &Identity,
) -> Result<KeyPackage> {
    let signer = signer_from_identity(identity);
    let credential = credential_from_identity(identity);

    let bundle = KeyPackage::builder()
        .build(MLS_CIPHERSUITE, provider, &signer, credential)
        .map_err(|e| GhostError::Mls(format!("key package: {e}")))?;
    Ok(bundle.key_package().clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_roundtrip() {
        let id = Identity::from_seed([0xAAu8; 32]).unwrap();
        let cred = credential_from_identity(&id);
        let parsed = parse_credential(&cred.credential).unwrap();
        assert_eq!(parsed.account_fp, id.fingerprint);
        assert_eq!(parsed.master_vk, id.master_vk);
        assert_eq!(parsed.idlog_seq, id.idlog_seq);
        assert_eq!(parsed.delegation_sig, id.delegation_sig);
        assert_eq!(parse_credential(&cred.credential).unwrap().account_fp, id.fingerprint);
    }

    #[test]
    fn signer_roundtrip() {
        let id = Identity::from_seed([0xBBu8; 32]).unwrap();
        let signer = signer_from_identity(&id);
        assert_eq!(signer.public(), id.verifying_key.as_bytes());
    }

    #[test]
    fn generate_key_package_succeeds() {
        let provider = GhostProvider::new_in_memory().unwrap();
        let id = Identity::from_seed([0xCCu8; 32]).unwrap();
        let kp = generate_key_package(&provider, &id).unwrap();
        assert_eq!(kp.ciphersuite(), MLS_CIPHERSUITE);
    }
}
