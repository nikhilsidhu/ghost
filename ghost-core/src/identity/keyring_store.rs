use ed25519_dalek::SigningKey;
use keyring::Entry;

use crate::account_keys::DeviceEncryptionKey;
use crate::error::{GhostError, Result};
use crate::identity::{Addition, Identity};

const SERVICE: &str = "ghost";

const DEVICE_RECORD_VERSION: u8 = 3;
/// A record: version(1), fingerprint(32), signing_key(32), encryption_seed(32), db_key(32),
/// mls_db_key(32), add_seq(8) and add_entry_hash(32).
const DEVICE_RECORD_SIZE: usize = 1 + 32 + 32 + 32 + 32 + 32 + 8 + 32;

fn entry(fingerprint_short: &str) -> Result<Entry> {
    Ok(Entry::new(SERVICE, fingerprint_short)?)
}

/// Material needed to open a client session.
pub struct StoredDevice {
    pub fingerprint: [u8; 32],
    pub signing_key: SigningKey,
    pub encryption_key: DeviceEncryptionKey,
    pub db_key: [u8; 32],
    pub mls_db_key: [u8; 32],
    pub added_at: Addition,
}

impl StoredDevice {
    /// The record kept in the OS keyring (hex-encoded) or a device file.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut blob = Vec::with_capacity(DEVICE_RECORD_SIZE);
        blob.push(DEVICE_RECORD_VERSION);
        blob.extend_from_slice(&self.fingerprint);
        blob.extend_from_slice(&self.signing_key.to_bytes());
        blob.extend_from_slice(self.encryption_key.seed());
        blob.extend_from_slice(&self.db_key);
        blob.extend_from_slice(&self.mls_db_key);
        blob.extend_from_slice(&self.added_at.seq.to_be_bytes());
        blob.extend_from_slice(&self.added_at.entry_hash);
        blob
    }

    pub fn from_bytes(blob: &[u8]) -> Result<Self> {
        if blob.first() != Some(&DEVICE_RECORD_VERSION) || blob.len() != DEVICE_RECORD_SIZE {
            return Err(GhostError::InvalidKey(format!("unrecognised device record of {} bytes", blob.len())));
        }
        let key = |range: std::ops::Range<usize>| -> [u8; 32] { blob[range].try_into().unwrap() };
        Ok(Self {
            fingerprint: key(1..33),
            signing_key: SigningKey::from_bytes(&key(33..65)),
            encryption_key: DeviceEncryptionKey::from_seed(key(65..97)),
            db_key: key(97..129),
            mls_db_key: key(129..161),
            added_at: Addition { seq: u64::from_be_bytes(blob[161..169].try_into().unwrap()), entry_hash: key(169..201) },
        })
    }

    /// The identity this record opens.
    pub fn identity(&self) -> Identity {
        Identity::from_device(self.fingerprint, self.signing_key.clone(), self.encryption_key.clone(), self.added_at)
    }
}

/// Store device credentials in OS keyring.
pub fn store(fingerprint_short: &str, device: &StoredDevice) -> Result<()> {
    let e = entry(fingerprint_short)?;
    e.set_password(&hex::encode(device.to_bytes()))?;
    Ok(())
}

/// Retrieve device credentials from OS keyring by fingerprint prefix.
pub fn retrieve(fingerprint_short: &str) -> Result<StoredDevice> {
    let e = entry(fingerprint_short)?;
    let hex_blob = e.get_password()?;
    let blob = hex::decode(&hex_blob)
        .map_err(|e| GhostError::InvalidKey(format!("bad hex in keyring: {e}")))?;
    StoredDevice::from_bytes(&blob)
}

/// Delete device credentials from OS keyring.
pub fn delete(fingerprint_short: &str) -> Result<()> {
    let e = entry(fingerprint_short)?;
    e.delete_credential()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use ghost_wire::short_id;
    use super::*;
    use rand::rngs::OsRng;

    fn make_device() -> StoredDevice {
        StoredDevice {
            fingerprint: [0x11u8; 32],
            signing_key: SigningKey::generate(&mut OsRng),
            encryption_key: DeviceEncryptionKey::generate(),
            db_key: [0xAAu8; 32],
            mls_db_key: [0xBBu8; 32],
            added_at: Addition { seq: 4, entry_hash: [0xCC; 32] },
        }
    }

    fn assert_same(a: &StoredDevice, b: &StoredDevice) {
        assert_eq!(a.fingerprint, b.fingerprint);
        assert_eq!(a.signing_key.to_bytes(), b.signing_key.to_bytes());
        assert_eq!(a.encryption_key.seed(), b.encryption_key.seed());
        assert_eq!(a.db_key, b.db_key);
        assert_eq!(a.mls_db_key, b.mls_db_key);
        assert_eq!(a.added_at, b.added_at);
    }

    #[test]
    fn records_roundtrip() {
        let device = make_device();
        assert_same(&device, &StoredDevice::from_bytes(&device.to_bytes()).unwrap());
    }

    #[test]
    fn malformed_records_are_refused() {
        let mut blob = make_device().to_bytes();
        blob.push(0);
        assert!(StoredDevice::from_bytes(&blob).is_err());
        assert!(StoredDevice::from_bytes(&[0u8; 10]).is_err());
        let mut older = make_device().to_bytes();
        older[0] = 2;
        assert!(StoredDevice::from_bytes(&older).is_err(), "a record of another version was read");
    }

    #[test]
    #[ignore = "writes to the OS keyring"]
    fn store_retrieve_roundtrip() {
        let device = make_device();
        let fp_short = short_id(&device.fingerprint);

        store(&fp_short, &device).unwrap();
        assert_same(&device, &retrieve(&fp_short).unwrap());

        delete(&fp_short).unwrap();
    }

    #[test]
    #[ignore = "writes to the OS keyring"]
    fn delete_removes_from_keyring() {
        let device = make_device();
        let fp_short = "6666666666666666";

        store(fp_short, &device).unwrap();
        delete(fp_short).unwrap();

        assert!(retrieve(fp_short).is_err());
    }

    #[test]
    #[ignore = "writes to the OS keyring"]
    fn retrieve_nonexistent_errors() {
        assert!(retrieve("0000000000000000").is_err());
    }
}
