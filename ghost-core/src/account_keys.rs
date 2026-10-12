//! Key material that is the account's rather than one device's: the recovery key the
//! user holds, which derives the account's root; each device's encryption key; and
//! the account key, a fresh seed per generation sealed to every holder with HPKE.

use ed25519_dalek::SigningKey;
use ghost_wire::account_key::{back_link_aad, copy_info, AccountKeySet, BackLink, SealedCopy, BACK_LINK_NONCE_LEN};
use ghost_wire::idlog::{AccountKeyState, LogState, Recipient, RecipientKind};
use openmls_rust_crypto::RustCrypto;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::{HpkeAeadType, HpkeCiphertext, HpkeConfig, HpkeKdfType, HpkeKemType};
use rand::RngCore;
use zeroize::Zeroizing;

use crate::crypto::aead;
use crate::crypto::constants::{
    ACCOUNT_KEY_BACKLINK_LABEL, ACCOUNT_KEY_ENCRYPTION_LABEL, ACCOUNT_KEY_SIGN_LABEL, ACCOUNT_KEY_SYNC_LABEL,
    RECOVERY_BOX_LABEL, RECOVERY_ROOT_LABEL,
};
use crate::crypto::keys::derive_key;
use crate::error::{GhostError, Result};

/// HPKE suite for account key copies: the one Ghost's MLS ciphersuite uses.
const HPKE: HpkeConfig = HpkeConfig(HpkeKemType::DhKem25519, HpkeKdfType::HkdfSha256, HpkeAeadType::AesGcm128);

// ── Recovery key ────────────────────────────────────────────────────

const RECOVERY_KEY_VERSION: u8 = 0x01;
const RECOVERY_KEY_CHECK_LABEL: &[u8] = b"ghost-recovery-key-check-v1";
/// Version, secret and a two-byte check: 35 bytes, exactly 56 base32 characters.
const RECOVERY_KEY_BYTES: usize = 1 + 32 + 2;
const RECOVERY_KEY_CHARS: usize = RECOVERY_KEY_BYTES * 8 / 5;
/// Characters per group in the written form.
const RECOVERY_KEY_GROUP: usize = 4;
/// Crockford's base32: no I, L, O or U, so it reads back unambiguously.
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// The secret the user keeps to recover the account. It derives the account's root
/// and the box key that opens the recovery copy of each account key; no device or
/// relay stores it.
pub struct RecoveryKey {
    secret: Zeroizing<[u8; 32]>,
}

impl RecoveryKey {
    pub fn generate() -> Self {
        let mut secret = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(secret.as_mut());
        Self { secret }
    }

    /// 56 characters in groups of four, such as `7K2M-QX9D-…`.
    pub fn encode(&self) -> String {
        let mut bytes = Zeroizing::new(Vec::with_capacity(RECOVERY_KEY_BYTES));
        bytes.push(RECOVERY_KEY_VERSION);
        bytes.extend_from_slice(self.secret.as_ref());
        bytes.extend_from_slice(&check(&self.secret));
        let chars = base32_encode(&bytes);
        chars
            .as_bytes()
            .chunks(RECOVERY_KEY_GROUP)
            .map(|group| std::str::from_utf8(group).expect("base32 is ASCII"))
            .collect::<Vec<_>>()
            .join("-")
    }

    /// Read a typed key back, ignoring case, spaces and dashes and reading I and L as
    /// 1 and O as 0. A wrong checksum is caught before anything is derived.
    pub fn parse(text: &str) -> Result<Self> {
        let bytes = Zeroizing::new(base32_decode(text).ok_or(GhostError::RecoveryKeyTypo)?);
        if bytes.len() != RECOVERY_KEY_BYTES || bytes[0] != RECOVERY_KEY_VERSION {
            return Err(GhostError::RecoveryKeyTypo);
        }
        let mut secret = Zeroizing::new([0u8; 32]);
        secret.copy_from_slice(&bytes[1..33]);
        if bytes[33..] != check(&secret) {
            return Err(GhostError::RecoveryKeyTypo);
        }
        Ok(Self { secret })
    }

    /// The account's root signing key.
    pub fn root(&self) -> Result<SigningKey> {
        let seed = Zeroizing::new(derive_key(self.secret.as_ref(), RECOVERY_ROOT_LABEL)?);
        Ok(SigningKey::from_bytes(&seed))
    }

    /// The key pair that opens the recovery copy of each account key.
    pub fn recovery_box(&self) -> Result<BoxKeyPair> {
        let ikm = Zeroizing::new(derive_key(self.secret.as_ref(), RECOVERY_BOX_LABEL)?);
        BoxKeyPair::derive(ikm.as_ref())
    }
}

fn check(secret: &[u8; 32]) -> [u8; 2] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(RECOVERY_KEY_CHECK_LABEL);
    hasher.update(&[RECOVERY_KEY_VERSION]);
    hasher.update(secret);
    let hash = hasher.finalize();
    [hash.as_bytes()[0], hash.as_bytes()[1]]
}

fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 8 / 5 + 1);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(CROCKFORD[((buffer >> bits) & 0x1F) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(CROCKFORD[((buffer << (5 - bits)) & 0x1F) as usize] as char);
    }
    out
}

fn base32_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(RECOVERY_KEY_BYTES);
    let (mut buffer, mut bits, mut chars) = (0u32, 0u32, 0usize);
    for c in text.chars() {
        let c = match c.to_ascii_uppercase() {
            '-' | ' ' => continue,
            'I' | 'L' => '1',
            'O' => '0',
            other => other,
        };
        let value = CROCKFORD.iter().position(|&a| a as char == c)? as u32;
        buffer = (buffer << 5) | value;
        bits += 5;
        chars += 1;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    (chars == RECOVERY_KEY_CHARS).then_some(out)
}

// ── Box keys ────────────────────────────────────────────────────────

/// An X25519 key pair that receives account key copies, derived with HPKE's
/// DeriveKeyPair from 32 bytes of input keying material.
pub struct BoxKeyPair {
    private: Zeroizing<Vec<u8>>,
    public: [u8; 32],
}

impl BoxKeyPair {
    pub fn derive(ikm: &[u8]) -> Result<Self> {
        let pair = RustCrypto::default()
            .derive_hpke_keypair(HPKE, ikm)
            .map_err(|e| GhostError::Crypto(format!("derive box key: {e:?}")))?;
        let public: [u8; 32] = pair
            .public
            .as_slice()
            .try_into()
            .map_err(|_| GhostError::Crypto("box public key is not 32 bytes".into()))?;
        Ok(Self { private: Zeroizing::new(pair.private.to_vec()), public })
    }

    pub fn public(&self) -> [u8; 32] {
        self.public
    }
}

/// A device's encryption key, kept as the 32 random bytes it is derived from.
pub struct DeviceEncryptionKey {
    seed: Zeroizing<[u8; 32]>,
}

impl DeviceEncryptionKey {
    pub fn generate() -> Self {
        let mut seed = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(seed.as_mut());
        Self { seed }
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self { seed: Zeroizing::new(seed) }
    }

    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    pub fn key_pair(&self) -> Result<BoxKeyPair> {
        BoxKeyPair::derive(self.seed.as_ref())
    }
}

impl Clone for DeviceEncryptionKey {
    fn clone(&self) -> Self {
        Self::from_seed(*self.seed)
    }
}

// ── Account key ─────────────────────────────────────────────────────

/// One generation of the account key.
pub struct AccountSeed {
    generation: u32,
    seed: Zeroizing<[u8; 32]>,
}

impl AccountSeed {
    pub fn generate(generation: u32) -> Self {
        let mut seed = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(seed.as_mut());
        Self { generation, seed }
    }

    pub fn from_bytes(generation: u32, seed: [u8; 32]) -> Self {
        Self { generation, seed: Zeroizing::new(seed) }
    }

    pub fn generation(&self) -> u32 {
        self.generation
    }

    pub fn bytes(&self) -> &[u8; 32] {
        &self.seed
    }

    /// Counter-signs the generation's entry, proving its writer holds the seed.
    pub fn signing_key(&self) -> Result<SigningKey> {
        let seed = Zeroizing::new(derive_key(self.seed.as_ref(), ACCOUNT_KEY_SIGN_LABEL)?);
        Ok(SigningKey::from_bytes(&seed))
    }

    /// What other accounts seal to this account.
    pub fn encryption_key(&self) -> Result<BoxKeyPair> {
        let ikm = Zeroizing::new(derive_key(self.seed.as_ref(), ACCOUNT_KEY_ENCRYPTION_LABEL)?);
        BoxKeyPair::derive(ikm.as_ref())
    }

    /// Seals the account's sync messages and snapshots under this generation.
    pub fn sync_key(&self) -> Result<Zeroizing<[u8; 32]>> {
        Ok(Zeroizing::new(derive_key(self.seed.as_ref(), ACCOUNT_KEY_SYNC_LABEL)?))
    }

    fn back_link_key(&self) -> Result<Zeroizing<[u8; 32]>> {
        Ok(Zeroizing::new(derive_key(self.seed.as_ref(), ACCOUNT_KEY_BACKLINK_LABEL)?))
    }

    /// Whether this is the seed `key` published, judged by the keys derived from it.
    pub fn matches(&self, key: &AccountKeyState) -> Result<bool> {
        Ok(self.generation == key.generation
            && self.signing_key()?.verifying_key().to_bytes() == key.verifying_key
            && self.encryption_key()?.public() == key.encryption_key)
    }
}

/// Everyone who must hold a copy of the next generation for `state`, with the public
/// key each copy is sealed to. Errors if a device in coverage lacks its key, which the
/// validator never allows.
pub fn holders(state: &LogState) -> Result<Vec<(Recipient, [u8; 32])>> {
    state
        .coverage()
        .into_iter()
        .map(|recipient| {
            let public = match recipient.kind {
                RecipientKind::Recovery => Some(recipient.id),
                RecipientKind::Device => state.devices.get(&recipient.id).and_then(|d| d.encryption_key),
            };
            public
                .map(|p| (recipient, p))
                .ok_or_else(|| GhostError::IdentityLog("a covered device has no encryption key".into()))
        })
        .collect()
}

/// Seal `seed` to every holder, in the order given, linking back to `previous`.
pub fn seal_key_set(
    account_fp: &[u8; 32],
    seed: &AccountSeed,
    holders: &[(Recipient, [u8; 32])],
    previous: Option<&AccountSeed>,
) -> Result<AccountKeySet> {
    let crypto = RustCrypto::default();
    let mut copies = Vec::with_capacity(holders.len());
    for (recipient, public) in holders {
        let info = copy_info(account_fp, seed.generation, recipient);
        let sealed = crypto
            .hpke_seal(HPKE, public, &info, &[], seed.bytes())
            .map_err(|e| GhostError::Crypto(format!("seal account key copy: {e:?}")))?;
        let encapsulated_key = sealed
            .kem_output
            .as_slice()
            .try_into()
            .map_err(|_| GhostError::Crypto("HPKE encapsulated key is not 32 bytes".into()))?;
        copies.push(SealedCopy { recipient: *recipient, encapsulated_key, ciphertext: sealed.ciphertext.as_slice().to_vec() });
    }
    let back_link = match previous {
        Some(prev) => {
            let aad = back_link_aad(account_fp, seed.generation, prev.generation);
            let (nonce, ciphertext) = aead::seal_detached(&*seed.back_link_key()?, prev.bytes(), &aad, "account key back-link")?;
            Some(BackLink { generation: prev.generation, nonce, ciphertext })
        }
        None => None,
    };
    Ok(AccountKeySet { account_fp: *account_fp, generation: seed.generation, copies, back_link })
}

/// Open `recipient`'s copy in `set` with its box key and check it is the seed `key`
/// published.
pub fn open_copy(set: &AccountKeySet, recipient: &Recipient, box_key: &BoxKeyPair, key: &AccountKeyState) -> Result<AccountSeed> {
    let copy = set
        .copy_for(recipient)
        .ok_or_else(|| GhostError::IdentityLog(format!("no copy of account key generation {} for this holder", set.generation)))?;
    let sealed = HpkeCiphertext { kem_output: copy.encapsulated_key.to_vec().into(), ciphertext: copy.ciphertext.clone().into() };
    let info = copy_info(&set.account_fp, set.generation, recipient);
    let opened = Zeroizing::new(
        RustCrypto::default()
            .hpke_open(HPKE, &sealed, &box_key.private, &info, &[])
            .map_err(|_| GhostError::BadAccountKeyCopy { generation: set.generation })?,
    );
    let bytes: [u8; 32] = opened
        .as_slice()
        .try_into()
        .map_err(|_| GhostError::BadAccountKeyCopy { generation: set.generation })?;
    verified(AccountSeed::from_bytes(set.generation, bytes), key)
}

/// Open the back-link in `set` with this generation's `seed` and check it is the seed
/// `previous` published. `previous` must be the generation the link names.
pub fn open_back_link(set: &AccountKeySet, seed: &AccountSeed, previous: &AccountKeyState) -> Result<AccountSeed> {
    let link = set
        .back_link
        .as_ref()
        .filter(|link| link.generation == previous.generation)
        .ok_or_else(|| GhostError::IdentityLog(format!("generation {} links to no generation {}", set.generation, previous.generation)))?;
    let nonce: &[u8; BACK_LINK_NONCE_LEN] = &link.nonce;
    let aad = back_link_aad(&set.account_fp, set.generation, link.generation);
    let opened = Zeroizing::new(
        aead::open_detached(&*seed.back_link_key()?, nonce, &link.ciphertext, &aad, "account key back-link")
            .map_err(|_| GhostError::BadAccountKeyCopy { generation: link.generation })?,
    );
    let bytes: [u8; 32] = opened
        .as_slice()
        .try_into()
        .map_err(|_| GhostError::BadAccountKeyCopy { generation: link.generation })?;
    verified(AccountSeed::from_bytes(link.generation, bytes), previous)
}

fn verified(seed: AccountSeed, key: &AccountKeyState) -> Result<AccountSeed> {
    if seed.matches(key)? {
        Ok(seed)
    } else {
        Err(GhostError::BadAccountKeyCopy { generation: key.generation })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn published(seed: &AccountSeed, set: &AccountKeySet) -> AccountKeyState {
        AccountKeyState {
            generation: seed.generation(),
            verifying_key: seed.signing_key().unwrap().verifying_key().to_bytes(),
            encryption_key: seed.encryption_key().unwrap().public(),
            set_digest: set.digest(),
            recipients: set.recipients(),
            writer: [0; 32],
            entry_hash: [0; 32],
        }
    }

    #[test]
    fn recovery_key_roundtrips_and_catches_typos() {
        let key = RecoveryKey::generate();
        let written = key.encode();
        assert_eq!(written.len(), 56 + 13, "14 groups of four with dashes");
        let read = RecoveryKey::parse(&written.to_lowercase().replace('-', " ")).unwrap();
        assert_eq!(read.root().unwrap().verifying_key(), key.root().unwrap().verifying_key());

        let mut typo: Vec<char> = written.chars().collect();
        typo[5] = if typo[5] == 'A' { 'B' } else { 'A' };
        assert!(matches!(RecoveryKey::parse(&typo.into_iter().collect::<String>()), Err(GhostError::RecoveryKeyTypo)));
        assert!(matches!(RecoveryKey::parse(&written[..written.len() - 1]), Err(GhostError::RecoveryKeyTypo)));
    }

    #[test]
    fn ambiguous_letters_read_as_digits() {
        let key = RecoveryKey::generate();
        let written = key.encode();
        let swapped = written.replace('1', "l").replace('0', "o");
        assert!(RecoveryKey::parse(&swapped).is_ok());
    }

    #[test]
    fn root_and_box_differ_and_differ_between_keys() {
        let a = RecoveryKey::generate();
        let b = RecoveryKey::generate();
        assert_ne!(a.root().unwrap().verifying_key().to_bytes(), a.recovery_box().unwrap().public());
        assert_ne!(a.root().unwrap().verifying_key(), b.root().unwrap().verifying_key());
    }

    #[test]
    fn copies_open_only_for_their_holder_and_match_the_entry() {
        let fp = [0x11; 32];
        let device = DeviceEncryptionKey::generate().key_pair().unwrap();
        let recovery = RecoveryKey::generate().recovery_box().unwrap();
        let device_r = Recipient::device([0x01; 32]);
        let recovery_r = Recipient::recovery(recovery.public());
        let mut holders = vec![(device_r, device.public()), (recovery_r, recovery.public())];
        holders.sort_by_key(|(r, _)| *r);

        let seed = AccountSeed::generate(1);
        let set = seal_key_set(&fp, &seed, &holders, None).unwrap();
        let key = published(&seed, &set);
        assert_eq!(open_copy(&set, &device_r, &device, &key).unwrap().bytes(), seed.bytes());
        assert_eq!(open_copy(&set, &recovery_r, &recovery, &key).unwrap().bytes(), seed.bytes());
        assert!(matches!(open_copy(&set, &device_r, &recovery, &key), Err(GhostError::BadAccountKeyCopy { .. })));
    }

    #[test]
    fn a_bad_copy_is_named_not_accepted() {
        let fp = [0x11; 32];
        let device = DeviceEncryptionKey::generate().key_pair().unwrap();
        let device_r = Recipient::device([0x01; 32]);
        let real = AccountSeed::generate(2);
        let other = AccountSeed::generate(2);
        // The writer published `real` but sealed `other`.
        let set = seal_key_set(&fp, &other, &[(device_r, device.public())], None).unwrap();
        let key = published(&real, &set);
        assert!(matches!(open_copy(&set, &device_r, &device, &key), Err(GhostError::BadAccountKeyCopy { generation: 2 })));
    }

    #[test]
    fn back_links_walk_to_earlier_generations() {
        let fp = [0x11; 32];
        let device = DeviceEncryptionKey::generate().key_pair().unwrap();
        let holders = [(Recipient::device([0x01; 32]), device.public())];
        let first = AccountSeed::generate(1);
        let first_set = seal_key_set(&fp, &first, &holders, None).unwrap();
        let second = AccountSeed::generate(2);
        let second_set = seal_key_set(&fp, &second, &holders, Some(&first)).unwrap();
        let first_key = published(&first, &first_set);
        assert_eq!(open_back_link(&second_set, &second, &first_key).unwrap().bytes(), first.bytes());
        let stranger = AccountSeed::generate(2);
        assert!(open_back_link(&second_set, &stranger, &first_key).is_err());
    }
}
