//! The copies of one account key generation: its seed sealed to every recipient the
//! generation's `AccountKey` entry names, plus a back-link that opens an earlier seed.
//! The entry commits to the set's digest, so a relay stores a set only beside the
//! entry naming it and nobody can swap a copy.

use thiserror::Error;

use crate::bytes::{put_prefixed16, put_prefixed32, ReadError, Reader};

use crate::idlog::{AccountKeyState, Recipient, RecipientKind};

pub const ACCOUNT_KEY_SET_VERSION: u8 = 0x01;

/// Largest encoded set: a copy for every device and the recovery key, with room to spare.
pub const ACCOUNT_KEY_SET_MAX_BYTES: usize = 16 * 1024;

/// HPKE `info` prefix for a copy, so a copy opens only for its recipient, generation and account.
pub const COPY_INFO_PREFIX: &[u8] = b"ghost/account-key-box/v1";

/// AEAD associated-data prefix for a back-link.
pub const BACK_LINK_AAD_PREFIX: &[u8] = b"ghost/account-key-backlink/v1";

pub const ENCAPSULATED_KEY_LEN: usize = 32;
pub const BACK_LINK_NONCE_LEN: usize = 12;

#[derive(Debug, Error)]
pub enum AccountKeySetError {
    #[error("account key set: {0}")]
    Format(String),
}

impl From<ReadError> for AccountKeySetError {
    fn from(e: ReadError) -> Self {
        AccountKeySetError::Format(e.to_string())
    }
}

/// The seed of one generation sealed to one recipient with HPKE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedCopy {
    pub recipient: Recipient,
    pub encapsulated_key: [u8; ENCAPSULATED_KEY_LEN],
    pub ciphertext: Vec<u8>,
}

/// An earlier generation's seed encrypted under this generation's back-link key, so
/// whoever holds this seed can walk back. It may skip generations the writer could
/// not open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackLink {
    pub generation: u32,
    pub nonce: [u8; BACK_LINK_NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountKeySet {
    pub account_fp: [u8; 32],
    pub generation: u32,
    /// Sorted by recipient, the order the entry lists them in.
    pub copies: Vec<SealedCopy>,
    pub back_link: Option<BackLink>,
}

impl AccountKeySet {
    /// `[version:1][account_fp:32][generation:4][count:1] count × ([kind:1][id:32][enc:32][ct_len:2][ct])
    ///  [link_len:2][prev_generation:4][nonce:12][ct]` (link_len 0 when there is no back-link)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![ACCOUNT_KEY_SET_VERSION];
        buf.extend_from_slice(&self.account_fp);
        buf.extend_from_slice(&self.generation.to_be_bytes());
        buf.push(self.copies.len() as u8);
        for copy in &self.copies {
            buf.push(copy.recipient.kind as u8);
            buf.extend_from_slice(&copy.recipient.id);
            buf.extend_from_slice(&copy.encapsulated_key);
            put_prefixed16(&mut buf, &copy.ciphertext);
        }
        match &self.back_link {
            Some(link) => {
                let mut body = link.generation.to_be_bytes().to_vec();
                body.extend_from_slice(&link.nonce);
                body.extend_from_slice(&link.ciphertext);
                put_prefixed16(&mut buf, &body);
            }
            None => put_prefixed16(&mut buf, &[]),
        }
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, AccountKeySetError> {
        if data.len() > ACCOUNT_KEY_SET_MAX_BYTES {
            return Err(AccountKeySetError::Format("too large".into()));
        }
        let mut r = Reader::new(data);
        if r.u8()? != ACCOUNT_KEY_SET_VERSION {
            return Err(AccountKeySetError::Format("unknown version".into()));
        }
        let account_fp = r.array()?;
        let generation = r.u32()?;
        let count = r.u8()? as usize;
        let mut copies = Vec::with_capacity(count);
        for _ in 0..count {
            let kind = RecipientKind::try_from(r.u8()?)
                .map_err(|v| AccountKeySetError::Format(format!("unknown recipient kind {v:#x}")))?;
            let id = r.array()?;
            let encapsulated_key = r.array()?;
            let ciphertext = r.prefixed16()?.to_vec();
            copies.push(SealedCopy { recipient: Recipient { kind, id }, encapsulated_key, ciphertext });
        }
        let link = r.prefixed16()?;
        let back_link = if link.is_empty() {
            None
        } else {
            let mut body = Reader::new(link);
            let generation = body.u32()?;
            let nonce = body.array()?;
            Some(BackLink { generation, nonce, ciphertext: body.rest().to_vec() })
        };
        r.finish()?;
        Ok(Self { account_fp, generation, copies, back_link })
    }

    /// The digest an `AccountKey` entry commits to.
    pub fn digest(&self) -> [u8; 32] {
        blake3::hash(&self.to_bytes()).into()
    }

    pub fn recipients(&self) -> Vec<Recipient> {
        self.copies.iter().map(|c| c.recipient).collect()
    }

    /// Whether this is the set `key`, a generation of `account_fp`, commits to.
    pub fn matches(&self, account_fp: &[u8; 32], key: &AccountKeyState) -> bool {
        self.account_fp == *account_fp
            && self.generation == key.generation
            && self.recipients() == key.recipients
            && self.digest() == key.set_digest
    }

    pub fn copy_for(&self, recipient: &Recipient) -> Option<&SealedCopy> {
        self.copies.iter().find(|c| c.recipient == *recipient)
    }
}

/// Sets back to back for transfer: `[count:2] ([len:4][AccountKeySet])…`.
pub fn encode_key_sets(sets: &[AccountKeySet]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(sets.len() as u16).to_be_bytes());
    for set in sets {
        put_prefixed32(&mut buf, &set.to_bytes());
    }
    buf
}

pub fn decode_key_sets(data: &[u8]) -> Result<Vec<AccountKeySet>, AccountKeySetError> {
    let mut r = Reader::new(data);
    let count = r.u16()? as usize;
    let mut sets = Vec::with_capacity(count.min(64));
    for _ in 0..count {
        sets.push(AccountKeySet::from_bytes(r.prefixed32()?)?);
    }
    r.finish()?;
    Ok(sets)
}

/// HPKE `info` for the copy of `generation` sealed to `recipient`.
pub fn copy_info(account_fp: &[u8; 32], generation: u32, recipient: &Recipient) -> Vec<u8> {
    let mut info = Vec::with_capacity(COPY_INFO_PREFIX.len() + 32 + 4 + 33);
    info.extend_from_slice(COPY_INFO_PREFIX);
    info.extend_from_slice(account_fp);
    info.extend_from_slice(&generation.to_be_bytes());
    info.push(recipient.kind as u8);
    info.extend_from_slice(&recipient.id);
    info
}

/// AEAD associated data for the back-link in `generation` that opens `prev_generation`.
pub fn back_link_aad(account_fp: &[u8; 32], generation: u32, prev_generation: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(BACK_LINK_AAD_PREFIX.len() + 32 + 8);
    aad.extend_from_slice(BACK_LINK_AAD_PREFIX);
    aad.extend_from_slice(account_fp);
    aad.extend_from_slice(&generation.to_be_bytes());
    aad.extend_from_slice(&prev_generation.to_be_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> AccountKeySet {
        AccountKeySet {
            account_fp: [0x11; 32],
            generation: 3,
            copies: vec![
                SealedCopy { recipient: Recipient::device([0x01; 32]), encapsulated_key: [0x21; 32], ciphertext: vec![0x31; 48] },
                SealedCopy { recipient: Recipient::recovery([0x02; 32]), encapsulated_key: [0x22; 32], ciphertext: vec![0x32; 48] },
            ],
            back_link: Some(BackLink { generation: 2, nonce: [0x41; 12], ciphertext: vec![0x51; 48] }),
        }
    }

    #[test]
    fn roundtrips_with_and_without_a_back_link() {
        let set = sample();
        assert_eq!(AccountKeySet::from_bytes(&set.to_bytes()).unwrap(), set);
        let unlinked = AccountKeySet { back_link: None, ..sample() };
        assert_eq!(AccountKeySet::from_bytes(&unlinked.to_bytes()).unwrap(), unlinked);
    }

    #[test]
    fn rejects_truncation_trailing_bytes_and_unknown_versions() {
        let bytes = sample().to_bytes();
        assert!(AccountKeySet::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(AccountKeySet::from_bytes(&longer).is_err());
        let mut versioned = bytes;
        versioned[0] = 0x02;
        assert!(AccountKeySet::from_bytes(&versioned).is_err());
    }

    #[test]
    fn matches_only_the_entry_naming_its_digest() {
        let set = sample();
        let key = AccountKeyState {
            generation: 3,
            verifying_key: [0; 32],
            encryption_key: [0; 32],
            set_digest: set.digest(),
            recipients: set.recipients(),
            writer: [0; 32],
            entry_hash: [0; 32],
        };
        assert!(set.matches(&[0x11; 32], &key));
        assert!(!set.matches(&[0x12; 32], &key), "another account");
        let mut swapped = set.clone();
        swapped.copies[0].ciphertext[0] ^= 1;
        assert!(!swapped.matches(&[0x11; 32], &key), "a swapped copy changes the digest");
    }

    #[test]
    fn set_lists_roundtrip() {
        let sets = vec![sample(), AccountKeySet { generation: 4, back_link: None, ..sample() }];
        assert_eq!(decode_key_sets(&encode_key_sets(&sets)).unwrap(), sets);
        assert!(decode_key_sets(&encode_key_sets(&[])).unwrap().is_empty());
        let bytes = encode_key_sets(&sets);
        assert!(decode_key_sets(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn copy_info_binds_recipient_generation_and_account() {
        let device = Recipient::device([0x01; 32]);
        let base = copy_info(&[0x11; 32], 3, &device);
        assert_ne!(base, copy_info(&[0x11; 32], 4, &device));
        assert_ne!(base, copy_info(&[0x12; 32], 3, &device));
        assert_ne!(base, copy_info(&[0x11; 32], 3, &Recipient::recovery([0x01; 32])));
    }
}
