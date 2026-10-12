use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;

use crate::crypto::MLS_CIPHERSUITE;
use crate::error::{GhostError, Result};
use crate::identity::Identity;

/// A device's credential: `[account_fp:32][add_seq:8][add_entry_hash:32]` packed into
/// the BasicCredential identity. It proves nothing by itself; receivers check the
/// device against the account's identity log.
pub const CREDENTIAL_SIZE: usize = 72;

/// What a credential claims.
pub struct ParsedCredential {
    pub account_fp: [u8; 32],
    pub add_seq: u64,
    pub add_entry_hash: [u8; 32],
}

/// Wrap our Ed25519 signing key so OpenMLS can use it to sign MLS messages.
pub fn signer_from_identity(identity: &Identity) -> SignatureKeyPair {
    SignatureKeyPair::from_raw(
        MLS_CIPHERSUITE.signature_algorithm(),
        identity.signing_key.to_bytes().to_vec(),
        identity.verifying_key.as_bytes().to_vec(),
    )
}

/// This device's MLS credential, naming the identity log entry that added it.
pub fn credential_from_identity(identity: &Identity) -> CredentialWithKey {
    let mut id_bytes = Vec::with_capacity(CREDENTIAL_SIZE);
    id_bytes.extend_from_slice(&identity.fingerprint);
    id_bytes.extend_from_slice(&identity.added_at.seq.to_be_bytes());
    id_bytes.extend_from_slice(&identity.added_at.entry_hash);
    let basic = BasicCredential::new(id_bytes);
    CredentialWithKey {
        credential: basic.into(),
        signature_key: identity.verifying_key.as_bytes().to_vec().into(),
    }
}

pub fn parse_credential(credential: &Credential) -> Result<ParsedCredential> {
    let basic = BasicCredential::try_from(credential.clone())
        .map_err(|_| GhostError::Mls("non-basic credential".into()))?;
    let id = basic.identity();
    if id.len() != CREDENTIAL_SIZE {
        return Err(GhostError::Format(format!("credential identity is {} bytes, expected {CREDENTIAL_SIZE}", id.len())));
    }
    Ok(ParsedCredential {
        account_fp: id[..32].try_into().unwrap(),
        add_seq: u64::from_be_bytes(id[32..40].try_into().unwrap()),
        add_entry_hash: id[40..72].try_into().unwrap(),
    })
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
        assert_eq!(parsed.add_seq, id.added_at.seq);
        assert_eq!(parsed.add_entry_hash, id.added_at.entry_hash);
    }

    #[test]
    fn credentials_of_another_size_are_refused() {
        assert!(parse_credential(&BasicCredential::new(vec![0u8; 40]).into()).is_err());
        assert!(parse_credential(&BasicCredential::new(vec![0u8; 136]).into()).is_err());
    }

    #[test]
    fn signer_roundtrip() {
        let id = Identity::from_seed([0xBBu8; 32]).unwrap();
        let signer = signer_from_identity(&id);
        assert_eq!(signer.public(), id.verifying_key.as_bytes());
    }
}
