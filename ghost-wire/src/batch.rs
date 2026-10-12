//! Entries a home relay appends together or not at all, with the account key sets
//! their `AccountKey` entries commit to. A revocation and the account key that
//! excludes the revoked device, or a recovery and its new root, never land apart.

use thiserror::Error;

use crate::account_key::{AccountKeySet, AccountKeySetError};
use crate::bytes::{put_prefixed32, ReadError, Reader};
use crate::idlog::{validate_entry, EntryBody, IdlogError, LogEntry, LogState};

pub const LOG_BATCH_VERSION: u8 = 0x01;

/// Most entries in one batch; the longest flow, recovery through a new home, needs five.
pub const MAX_BATCH_ENTRIES: usize = 8;

/// Largest encoded batch.
pub const MAX_BATCH_BYTES: usize = 64 * 1024;

#[derive(Debug, Error)]
pub enum BatchError {
    #[error("batch format: {0}")]
    Format(String),
    #[error(transparent)]
    Chain(#[from] IdlogError),
    #[error(transparent)]
    KeySet(#[from] AccountKeySetError),
    #[error("account key generation {0} arrived without the set it commits to")]
    MissingKeySet(u32),
    #[error("a key set matches no account key entry in the batch")]
    UnexpectedKeySet,
}

impl From<ReadError> for BatchError {
    fn from(e: ReadError) -> Self {
        BatchError::Format(e.to_string())
    }
}

#[derive(Debug, Clone)]
pub struct LogBatch {
    pub entries: Vec<LogEntry>,
    pub key_sets: Vec<AccountKeySet>,
}

impl LogBatch {
    /// `[version:1][count:1] ([len:4][LogEntry])… [sets:1] ([len:4][AccountKeySet])…`
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![LOG_BATCH_VERSION];
        put_entries(&mut buf, &self.entries);
        put_key_sets(&mut buf, &self.key_sets);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, BatchError> {
        if data.len() > MAX_BATCH_BYTES {
            return Err(BatchError::Format("too large".into()));
        }
        let mut r = Reader::new(data);
        if r.u8()? != LOG_BATCH_VERSION {
            return Err(BatchError::Format("unknown version".into()));
        }
        let entries = read_entries(&mut r)?;
        let key_sets = read_key_sets(&mut r)?;
        r.finish()?;
        if entries.is_empty() || entries.len() > MAX_BATCH_ENTRIES {
            return Err(BatchError::Format(format!("a batch holds 1 to {MAX_BATCH_ENTRIES} entries")));
        }
        Ok(Self { entries, key_sets })
    }
}

/// Apply `entries` to a copy of `state` in order, requiring every `AccountKey` entry
/// to arrive with exactly the set it commits to and no other sets. Returns the state
/// after the batch; `state` is untouched if anything fails.
pub fn apply_batch(state: &LogState, entries: &[LogEntry], key_sets: &[AccountKeySet]) -> Result<LogState, BatchError> {
    let mut next = state.clone();
    let mut matched = vec![false; key_sets.len()];
    for entry in entries {
        validate_entry(&mut next, entry)?;
        if let EntryBody::AccountKey { generation, .. } = &entry.body {
            let key = next.account_key().expect("validated AccountKey sets the current generation");
            let index = key_sets
                .iter()
                .position(|set| set.matches(&next.account_fp, key))
                .ok_or(BatchError::MissingKeySet(*generation))?;
            matched[index] = true;
        }
    }
    if matched.contains(&false) {
        return Err(BatchError::UnexpectedKeySet);
    }
    Ok(next)
}

pub(crate) fn put_entries(buf: &mut Vec<u8>, entries: &[LogEntry]) {
    buf.push(entries.len() as u8);
    for entry in entries {
        put_prefixed32(buf, &entry.to_bytes());
    }
}

pub(crate) fn put_key_sets(buf: &mut Vec<u8>, key_sets: &[AccountKeySet]) {
    buf.push(key_sets.len() as u8);
    for set in key_sets {
        put_prefixed32(buf, &set.to_bytes());
    }
}

pub(crate) fn read_entries(r: &mut Reader) -> Result<Vec<LogEntry>, BatchError> {
    let count = r.u8()? as usize;
    (0..count).map(|_| Ok(LogEntry::from_bytes(r.prefixed32()?)?)).collect()
}

pub(crate) fn read_key_sets(r: &mut Reader) -> Result<Vec<AccountKeySet>, BatchError> {
    let count = r.u8()? as usize;
    (0..count).map(|_| Ok(AccountKeySet::from_bytes(r.prefixed32()?)?)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log_entries::*;
    use crate::test_support::*;

    /// A revocation batch on a rotated account with a second device: the revoke and
    /// the generation that leaves the revoked device out.
    fn revocation() -> (LogState, Vec<LogEntry>, AccountKeySet) {
        let rotated = build_rotated();
        let mut state = rotated.state;
        let second = random_key();
        let add = create_add_device(&state, &rotated.device, &second, "phone");
        validate_entry(&mut state, &add).unwrap();
        let key = create_device_key(&state, &rotated.device, &second, [0x03; 32]);
        validate_entry(&mut state, &key).unwrap();
        let covering = key_set_for(&state);
        let entry = create_account_key(&state, &rotated.device, &random_key(), [0x77; 32], &covering);
        validate_entry(&mut state, &entry).unwrap();

        let revoke = create_revoke_device(&state, &rotated.device, &second.verifying_key().to_bytes());
        let mut after_revoke = state.clone();
        validate_entry(&mut after_revoke, &revoke).unwrap();
        let set = key_set_for(&after_revoke);
        let rekey = create_account_key(&after_revoke, &rotated.device, &random_key(), [0x77; 32], &set);
        (state, vec![revoke, rekey], set)
    }

    #[test]
    fn batch_roundtrips_bytes() {
        let (_, entries, set) = revocation();
        let batch = LogBatch { entries, key_sets: vec![set] };
        let decoded = LogBatch::from_bytes(&batch.to_bytes()).unwrap();
        assert_eq!(decoded.to_bytes(), batch.to_bytes());
        assert!(LogBatch::from_bytes(&[LOG_BATCH_VERSION, 0, 0]).is_err(), "empty batch");
    }

    #[test]
    fn apply_batch_is_all_or_nothing() {
        let (state, entries, set) = revocation();
        let after = apply_batch(&state, &entries, std::slice::from_ref(&set)).unwrap();
        assert!(!after.rekey_needed());
        assert_eq!(after.head_seq, state.head_seq + 2);

        let mut broken = entries.clone();
        broken[1].signature[0] ^= 1;
        assert!(apply_batch(&state, &broken, &[set]).is_err());
    }

    #[test]
    fn every_account_key_needs_exactly_its_set() {
        let (state, entries, set) = revocation();
        assert!(matches!(apply_batch(&state, &entries, &[]), Err(BatchError::MissingKeySet(_))));

        let mut swapped = set.clone();
        swapped.copies[0].ciphertext[0] ^= 1;
        assert!(matches!(apply_batch(&state, &entries, &[swapped]), Err(BatchError::MissingKeySet(_))));

        let extra = key_set_for(&state);
        assert!(matches!(apply_batch(&state, &entries, &[set, extra]), Err(BatchError::UnexpectedKeySet)));
    }
}
