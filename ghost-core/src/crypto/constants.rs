use openmls::prelude::Ciphersuite;

/// Which MLS ciphersuite all Ghost groups use.
pub const MLS_CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// Label used when deriving per-sender voice encryption keys from MLS epoch secrets.
pub const VOICE_EXPORT_LABEL: &str = "ghost-voice";
