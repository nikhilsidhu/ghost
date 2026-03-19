use ed25519_dalek::SigningKey;
use keyring::Entry;

use crate::error::{GhostError, Result};

const SERVICE: &str = "ghost";
/// fingerprint(32) + signing_key(32) + db_key(32) + mls_db_key(32) + idlog_seq(8)
/// + master_vk(32) + master_sk(32) + delegation_sig(64) = 264 bytes.
pub const DEVICE_BLOB_SIZE: usize = 264;

fn entry(fingerprint_short: &str) -> Result<Entry> {
    Ok(Entry::new(SERVICE, fingerprint_short)?)
}

/// Material needed to open a client session.
pub struct StoredDevice {
    pub fingerprint: [u8; 32],
    pub signing_key: SigningKey,
    pub db_key: [u8; 32],
    pub mls_db_key: [u8; 32],
    pub idlog_seq: u64,
    pub master_vk: [u8; 32],
    pub master_sk: SigningKey,
    pub delegation_sig: [u8; 64],
}

/// Store device credentials in OS keyring.
pub fn store(fingerprint_short: &str, device: &StoredDevice) -> Result<()> {
    let mut blob = Vec::with_capacity(DEVICE_BLOB_SIZE);
    blob.extend_from_slice(&device.fingerprint);
    blob.extend_from_slice(&device.signing_key.to_bytes());
    blob.extend_from_slice(&device.db_key);
    blob.extend_from_slice(&device.mls_db_key);
    blob.extend_from_slice(&device.idlog_seq.to_be_bytes());
    blob.extend_from_slice(&device.master_vk);
    blob.extend_from_slice(&device.master_sk.to_bytes());
    blob.extend_from_slice(&device.delegation_sig);
    let e = entry(fingerprint_short)?;
    e.set_password(&hex::encode(&blob))?;
    Ok(())
}

/// Retrieve device credentials from OS keyring by fingerprint prefix.
pub fn retrieve(fingerprint_short: &str) -> Result<StoredDevice> {
    let e = entry(fingerprint_short)?;
    let hex_blob = e.get_password()?;
    let blob = hex::decode(&hex_blob)
        .map_err(|e| GhostError::InvalidKey(format!("bad hex in keyring: {e}")))?;
    if blob.len() != DEVICE_BLOB_SIZE {
        return Err(GhostError::InvalidKey(format!(
            "expected {} bytes, got {}",
            DEVICE_BLOB_SIZE,
            blob.len()
        )));
    }
    let fingerprint: [u8; 32] = blob[0..32].try_into().unwrap();
    let sk_bytes: [u8; 32] = blob[32..64].try_into().unwrap();
    let db_key: [u8; 32] = blob[64..96].try_into().unwrap();
    let mls_db_key: [u8; 32] = blob[96..128].try_into().unwrap();
    let idlog_seq = u64::from_be_bytes(blob[128..136].try_into().unwrap());
    let master_vk: [u8; 32] = blob[136..168].try_into().unwrap();
    let master_sk_bytes: [u8; 32] = blob[168..200].try_into().unwrap();
    let delegation_sig: [u8; 64] = blob[200..264].try_into().unwrap();
    Ok(StoredDevice {
        fingerprint,
        signing_key: SigningKey::from_bytes(&sk_bytes),
        db_key,
        mls_db_key,
        idlog_seq,
        master_vk,
        master_sk: SigningKey::from_bytes(&master_sk_bytes),
        delegation_sig,
    })
}

/// Delete device credentials from OS keyring.
pub fn delete(fingerprint_short: &str) -> Result<()> {
    let e = entry(fingerprint_short)?;
    e.delete_credential()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn make_device() -> StoredDevice {
        let master_sk = SigningKey::generate(&mut OsRng);
        let master_vk: [u8; 32] = master_sk.verifying_key().to_bytes();
        let fingerprint: [u8; 32] = blake3::hash(&master_vk).into();
        let device_sk = SigningKey::generate(&mut OsRng);
        let delegation_sig = crate::identity::compute_delegation_sig(
            &master_sk, device_sk.verifying_key().as_bytes(), &fingerprint, 1,
        );
        StoredDevice {
            fingerprint,
            signing_key: device_sk,
            db_key: [0xAAu8; 32],
            mls_db_key: [0xBBu8; 32],
            idlog_seq: 1,
            master_vk,
            master_sk,
            delegation_sig,
        }
    }

    #[test]
    fn store_retrieve_roundtrip() {
        let device = make_device();
        let fp_short = hex::encode(&device.fingerprint[..8]);

        store(&fp_short, &device).unwrap();
        let restored = retrieve(&fp_short).unwrap();

        assert_eq!(device.fingerprint, restored.fingerprint);
        assert_eq!(device.signing_key.to_bytes(), restored.signing_key.to_bytes());
        assert_eq!(device.db_key, restored.db_key);
        assert_eq!(device.mls_db_key, restored.mls_db_key);
        assert_eq!(device.idlog_seq, restored.idlog_seq);
        assert_eq!(device.master_vk, restored.master_vk);
        assert_eq!(device.master_sk.to_bytes(), restored.master_sk.to_bytes());
        assert_eq!(device.delegation_sig, restored.delegation_sig);

        delete(&fp_short).unwrap();
    }

    #[test]
    fn delete_removes_from_keyring() {
        let device = make_device();
        let fp_short = "6666666666666666";

        store(fp_short, &device).unwrap();
        delete(fp_short).unwrap();

        assert!(retrieve(fp_short).is_err());
    }

    #[test]
    fn retrieve_nonexistent_errors() {
        assert!(retrieve("0000000000000000").is_err());
    }
}
