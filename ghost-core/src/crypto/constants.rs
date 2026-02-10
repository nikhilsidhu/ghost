use openmls::prelude::Ciphersuite;

/// Which MLS ciphersuite all Ghost groups use.
pub const MLS_CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// Label used when deriving per-sender voice encryption keys from MLS epoch secrets.
pub const VOICE_EXPORT_LABEL: &str = "ghost-voice";

/// HKDF domain-separation label for deriving X25519 keys from identity seeds.
pub const X25519_DERIVE_LABEL: &[u8] = b"ghost-x25519";

/// How many bytes of a fingerprint to use for short display names (produces 2x hex chars).
pub const FINGERPRINT_SHORT_BYTES: usize = 8;

/// HKDF domain-separation label for deriving the SQLCipher database encryption key from the identity seed.
pub const DB_KEY_DERIVE_LABEL: &[u8] = b"ghost-db-key";

// Wire message types
pub const MSG_TYPE_TEXT: u8 = 1;
pub const MSG_TYPE_REPLY: u8 = 4;
pub const MSG_TYPE_DELETE: u8 = 6;
