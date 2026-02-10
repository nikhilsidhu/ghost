use keyring::Entry;

use super::Identity;
use crate::error::Result;

const SERVICE: &str = "ghost";

fn entry(fingerprint_short: &str) -> Result<Entry> {
    Ok(Entry::new(SERVICE, fingerprint_short)?)
}

/// Store identity seed in OS keyring (macOS Keychain, Windows DPAPI, Linux Secret Service).
pub fn store(identity: &Identity) -> Result<()> {
    let e = entry(&identity.fingerprint_short())?;
    e.set_password(&hex::encode(identity.seed()))?;
    Ok(())
}

/// Retrieve identity from OS keyring by fingerprint prefix.
pub fn retrieve(fingerprint_short: &str) -> Result<Identity> {
    let e = entry(fingerprint_short)?;
    let hex_seed = e.get_password()?;
    let bytes = hex::decode(&hex_seed)
        .map_err(|e| crate::error::GhostError::InvalidKey(format!("bad hex in keyring: {e}")))?;
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| crate::error::GhostError::InvalidKey("seed must be 32 bytes".into()))?;
    Identity::from_seed(seed)
}

/// Delete identity from OS keyring.
pub fn delete(fingerprint_short: &str) -> Result<()> {
    let e = entry(fingerprint_short)?;
    e.delete_credential()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_retrieve_roundtrip() {
        let id = Identity::from_seed([0x55u8; 32]).unwrap();
        let fp = id.fingerprint_short();

        store(&id).unwrap();
        let restored = retrieve(&fp).unwrap();

        assert_eq!(id.fingerprint, restored.fingerprint);
        assert_eq!(id.verifying_key, restored.verifying_key);
        assert_eq!(id.x25519_public.as_bytes(), restored.x25519_public.as_bytes());
        assert_eq!(id.display_name, restored.display_name);

        delete(&fp).unwrap();
    }

    #[test]
    fn delete_removes_from_keyring() {
        let id = Identity::from_seed([0x66u8; 32]).unwrap();
        let fp = id.fingerprint_short();

        store(&id).unwrap();
        delete(&fp).unwrap();

        assert!(retrieve(&fp).is_err());
    }

    #[test]
    fn retrieve_nonexistent_errors() {
        assert!(retrieve("0000000000000000").is_err());
    }
}
