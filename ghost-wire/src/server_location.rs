//! Where a server lives, signed by a device of its creator. Members accept a
//! move only from a record they can verify against the creator's identity log,
//! so neither a relay nor another member can redirect a server.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use thiserror::Error;

use crate::relay_ref::RelayRef;

pub const SERVER_LOCATION_VERSION: u8 = 0x01;
const SIGN_PREFIX: &[u8] = b"ghost-server-location-v1:";
const SIGNATURE_LEN: usize = 64;

#[derive(Debug, Error)]
pub enum ServerLocationError {
    #[error("server location: {0}")]
    Format(String),
    #[error("server location signature is invalid")]
    BadSignature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerLocation {
    pub server_id: [u8; 32],
    /// Increases with every move; readers keep the highest they accepted.
    pub generation: u64,
    /// Device key of the server's creator that signed this record.
    pub signer_vk: [u8; 32],
    pub relay_ref: RelayRef,
    pub signature: [u8; 64],
}

impl ServerLocation {
    pub fn sign(server_id: [u8; 32], generation: u64, relay_ref: RelayRef, signer: &SigningKey) -> Self {
        let mut location = Self {
            server_id,
            generation,
            signer_vk: signer.verifying_key().to_bytes(),
            relay_ref,
            signature: [0u8; 64],
        };
        location.signature = signer.sign(&location.signed_message()).to_bytes();
        location
    }

    fn body(&self) -> Vec<u8> {
        let ref_bytes = self.relay_ref.to_bytes();
        let mut buf = Vec::with_capacity(1 + 32 + 8 + 32 + 2 + ref_bytes.len());
        buf.push(SERVER_LOCATION_VERSION);
        buf.extend_from_slice(&self.server_id);
        buf.extend_from_slice(&self.generation.to_be_bytes());
        buf.extend_from_slice(&self.signer_vk);
        buf.extend_from_slice(&(ref_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(&ref_bytes);
        buf
    }

    fn signed_message(&self) -> Vec<u8> {
        let mut msg = SIGN_PREFIX.to_vec();
        msg.extend_from_slice(&self.body());
        msg
    }

    /// Check the signature under `signer_vk`. Whether that key belongs to the
    /// server's creator is the caller's check, against the creator's log.
    pub fn verify_signature(&self) -> Result<(), ServerLocationError> {
        let vk = VerifyingKey::from_bytes(&self.signer_vk).map_err(|_| ServerLocationError::BadSignature)?;
        vk.verify_strict(&self.signed_message(), &Signature::from_bytes(&self.signature))
            .map_err(|_| ServerLocationError::BadSignature)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = self.body();
        buf.extend_from_slice(&self.signature);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, ServerLocationError> {
        let err = |msg: &str| ServerLocationError::Format(msg.into());
        if data.len() < 1 + 32 + 8 + 32 + 2 + SIGNATURE_LEN {
            return Err(err("too short"));
        }
        if data[0] != SERVER_LOCATION_VERSION {
            return Err(err("unknown version"));
        }
        let server_id: [u8; 32] = data[1..33].try_into().unwrap();
        let generation = u64::from_be_bytes(data[33..41].try_into().unwrap());
        let signer_vk: [u8; 32] = data[41..73].try_into().unwrap();
        let ref_len = u16::from_be_bytes(data[73..75].try_into().unwrap()) as usize;
        if data.len() != 75 + ref_len + SIGNATURE_LEN {
            return Err(err("length mismatch"));
        }
        let relay_ref = RelayRef::from_bytes(&data[75..75 + ref_len])
            .map_err(|e| ServerLocationError::Format(e.to_string()))?;
        let signature: [u8; 64] = data[75 + ref_len..].try_into().unwrap();
        Ok(Self { server_id, generation, signer_vk, relay_ref, signature })
    }

    /// Text form for a move link shared out of band.
    pub fn encode(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.to_bytes())
    }

    pub fn decode(text: &str) -> Result<Self, ServerLocationError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(text.trim())
            .map_err(|_| ServerLocationError::Format("invalid base64url".into()))?;
        Self::from_bytes(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> SigningKey {
        SigningKey::from_bytes(&[b; 32])
    }

    #[test]
    fn signed_roundtrip() {
        let loc = ServerLocation::sign([0x11; 32], 7, RelayRef::https([0x22; 32], "https://r.example"), &key(3));
        loc.verify_signature().unwrap();
        let decoded = ServerLocation::from_bytes(&loc.to_bytes()).unwrap();
        assert_eq!(decoded, loc);
        assert_eq!(ServerLocation::decode(&loc.encode()).unwrap(), loc);
    }

    #[test]
    fn tampering_breaks_the_signature() {
        let loc = ServerLocation::sign([0x11; 32], 7, RelayRef::https([0x22; 32], "https://r.example"), &key(3));
        let mut moved = loc.clone();
        moved.relay_ref = RelayRef::https([0x33; 32], "https://evil.example");
        assert!(moved.verify_signature().is_err());
        let mut bumped = loc.clone();
        bumped.generation += 1;
        assert!(bumped.verify_signature().is_err());
        let mut resigned = loc;
        resigned.signer_vk = key(4).verifying_key().to_bytes();
        assert!(resigned.verify_signature().is_err());
    }

    #[test]
    fn rejects_malformed() {
        let loc = ServerLocation::sign([0x11; 32], 1, RelayRef::key_only([0x22; 32]), &key(3));
        let mut bytes = loc.to_bytes();
        bytes.push(0);
        assert!(ServerLocation::from_bytes(&bytes).is_err());
        let bytes = loc.to_bytes();
        assert!(ServerLocation::from_bytes(&bytes[..bytes.len() - 1]).is_err());
    }
}
