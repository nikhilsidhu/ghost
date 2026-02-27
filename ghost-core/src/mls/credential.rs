use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;

use crate::crypto::{GhostProvider, MLS_CIPHERSUITE};
use crate::error::{GhostError, Result};
use crate::identity::Identity;

/// Wrap our Ed25519 signing key so OpenMLS can use it to sign MLS messages.
pub fn signer_from_identity(identity: &Identity) -> SignatureKeyPair {
    SignatureKeyPair::from_raw(
        MLS_CIPHERSUITE.signature_algorithm(),
        identity.signing_key.to_bytes().to_vec(),
        identity.verifying_key.as_bytes().to_vec(),
    )
}

/// Package our fingerprint + public key so other MLS members can identify us.
pub fn credential_from_identity(identity: &Identity) -> CredentialWithKey {
    let basic = BasicCredential::new(identity.fingerprint.to_vec());
    CredentialWithKey {
        credential: basic.into(),
        signature_key: identity.verifying_key.as_bytes().to_vec().into(),
    }
}

/// Create a one-time-use token that someone else needs to invite us into their group.
pub fn generate_key_package(
    provider: &GhostProvider,
    identity: &Identity,
) -> Result<KeyPackage> {
    let signer = signer_from_identity(identity);
    let credential = credential_from_identity(identity);

    let bundle = KeyPackage::builder()
        .leaf_node_capabilities(super::group::leaf_node_capabilities())
        .build(MLS_CIPHERSUITE, provider, &signer, credential)
        .map_err(|e| GhostError::Mls(format!("key package: {e}")))?;
    Ok(bundle.key_package().clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_contains_fingerprint() {
        let id = Identity::from_seed([0xAAu8; 32]).unwrap();
        let cred = credential_from_identity(&id);
        let basic = BasicCredential::try_from(cred.credential).unwrap();
        assert_eq!(basic.identity(), &id.fingerprint);
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
