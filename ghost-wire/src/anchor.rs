//! An identity log entry together with the home relay's proof that it
//! sequenced the entry: a key-transparency inclusion proof and the signed
//! checkpoint it verifies against. Mirrors and clients accept an entry only
//! in this form, so no relay other than the home can extend a chain.

use ed25519_dalek::VerifyingKey;
use thiserror::Error;

use crate::account_key::AccountKeySet;
use crate::batch::{put_entries, put_key_sets, read_entries, read_key_sets, BatchError};
use crate::bytes::{put_prefixed16, put_prefixed32, ReadError, Reader};
use crate::idlog::{validate_entry, IdlogError, LogEntry, LogState};
use crate::merkle::{leaf_hash, Checkpoint, InclusionProof, CHECKPOINT_TOTAL_LEN};

#[derive(Debug, Error)]
pub enum AnchorError {
    #[error("anchor format: {0}")]
    Format(String),
    #[error(transparent)]
    Chain(#[from] IdlogError),
    #[error("account has no home relay to verify the anchor against")]
    NoHomeRelay,
    #[error("checkpoint is not signed by the account's home relay")]
    BadCheckpointSignature,
    #[error("inclusion proof tree size does not match the checkpoint")]
    ProofSizeMismatch,
    #[error("inclusion proof does not reach the checkpoint root")]
    InclusionFailed,
    #[error("checkpoint is older than one already seen from this home relay")]
    CheckpointRegression,
}

impl From<ReadError> for AnchorError {
    fn from(e: ReadError) -> Self {
        AnchorError::Format(e.to_string())
    }
}

#[derive(Debug, Clone)]
pub struct AnchoredEntry {
    pub entry: LogEntry,
    pub inclusion_proof: InclusionProof,
    pub checkpoint: Checkpoint,
}

impl AnchoredEntry {
    /// `[entry_len:4][entry][proof_len:2][inclusion_proof][checkpoint:116]`
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_prefixed32(&mut buf, &self.entry.to_bytes());
        put_prefixed16(&mut buf, &self.inclusion_proof.to_bytes());
        buf.extend_from_slice(&self.checkpoint.to_bytes());
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, AnchorError> {
        let mut r = Reader::new(data);
        let anchored = Self::read(&mut r)?;
        r.finish()?;
        Ok(anchored)
    }

    /// One anchored entry from the front of what `r` has left.
    fn read(r: &mut Reader) -> Result<Self, AnchorError> {
        let entry = LogEntry::from_bytes(r.prefixed32()?)?;
        let inclusion_proof = InclusionProof::from_bytes(r.prefixed16()?)
            .map_err(|e| AnchorError::Format(format!("inclusion proof: {e}")))?;
        let checkpoint = Checkpoint::from_bytes(r.take(CHECKPOINT_TOTAL_LEN)?)
            .map_err(|e| AnchorError::Format(format!("checkpoint: {e}")))?;
        Ok(Self { entry, inclusion_proof, checkpoint })
    }

    /// Check the anchor alone: checkpoint signed by `home_relay_vk`, proof
    /// sizes agree, the entry is in the tree, and the checkpoint has not moved
    /// backwards relative to `prior` from the same home.
    pub fn verify_anchor(
        &self,
        home_relay_vk: &[u8; 32],
        prior: Option<&Checkpoint>,
    ) -> Result<(), AnchorError> {
        let vk = VerifyingKey::from_bytes(home_relay_vk)
            .map_err(|_| AnchorError::BadCheckpointSignature)?;
        self.checkpoint
            .verify(&vk)
            .map_err(|_| AnchorError::BadCheckpointSignature)?;
        if self.inclusion_proof.tree_size != self.checkpoint.tree_size {
            return Err(AnchorError::ProofSizeMismatch);
        }
        let lh = leaf_hash(&self.entry.to_bytes());
        if !self.inclusion_proof.verify(&lh, &self.checkpoint.root_hash) {
            return Err(AnchorError::InclusionFailed);
        }
        if let Some(prior) = prior {
            let regressed = self.checkpoint.tree_size < prior.tree_size
                || (self.checkpoint.tree_size == prior.tree_size
                    && self.checkpoint.root_hash != prior.root_hash);
            if regressed {
                return Err(AnchorError::CheckpointRegression);
            }
        }
        Ok(())
    }
}

/// Anchored entries back to back, in chain order; each is self-delimiting.
pub fn encode_sequence(entries: &[AnchoredEntry]) -> Vec<u8> {
    let mut buf = Vec::new();
    for e in entries {
        buf.extend_from_slice(&e.to_bytes());
    }
    buf
}

pub fn decode_sequence(data: &[u8]) -> Result<Vec<AnchoredEntry>, AnchorError> {
    let mut r = Reader::new(data);
    let mut entries = Vec::new();
    while !r.is_empty() {
        entries.push(AnchoredEntry::read(&mut r)?);
    }
    Ok(entries)
}

pub const IMPORT_REQUEST_VERSION: u8 = 0x02;

/// Ask a relay to become an account's home: the existing chain with its
/// current anchors, then the raw entries the new home sequences (a
/// `SetHomeRelay` naming the new home, then for a recovery the rest of the
/// recovery batch), with the key sets those entries commit to.
#[derive(Debug, Clone)]
pub struct ImportRequest {
    pub prefix: Vec<AnchoredEntry>,
    pub new_entries: Vec<LogEntry>,
    pub key_sets: Vec<AccountKeySet>,
}

impl ImportRequest {
    /// `[version:1][prefix_count:2] AnchoredEntry… [new_count:1] ([len:4][LogEntry])…
    ///  [sets:1] ([len:4][AccountKeySet])…`
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![IMPORT_REQUEST_VERSION];
        buf.extend_from_slice(&(self.prefix.len() as u16).to_be_bytes());
        for anchored in &self.prefix {
            buf.extend_from_slice(&anchored.to_bytes());
        }
        put_entries(&mut buf, &self.new_entries);
        put_key_sets(&mut buf, &self.key_sets);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, AnchorError> {
        let err = |msg: &str| AnchorError::Format(format!("import request: {msg}"));
        let batch_err = |e: BatchError| AnchorError::Format(format!("import request: {e}"));
        let mut r = Reader::new(data);
        let version = r.u8()?;
        if version != IMPORT_REQUEST_VERSION {
            return Err(err("unknown version"));
        }
        let prefix_count = r.u16()? as usize;
        let mut prefix = Vec::with_capacity(prefix_count);
        for _ in 0..prefix_count {
            prefix.push(AnchoredEntry::read(&mut r)?);
        }
        let new_entries = read_entries(&mut r).map_err(batch_err)?;
        let key_sets = read_key_sets(&mut r).map_err(batch_err)?;
        r.finish().map_err(|e| err(&e.to_string()))?;
        Ok(Self { prefix, new_entries, key_sets })
    }
}

/// Extend `state` with an anchored entry. The chain is advanced only if both
/// the entry and its anchor are valid. The anchor is checked against the home
/// relay the chain names after this entry, so a `SetHomeRelay` is anchored by
/// the relay it names; `implied_home` covers entries before the chain names a
/// home. `prior_for_home` returns the last checkpoint this account was anchored
/// with by the given home, so a re-home starts a fresh monotonic sequence.
pub fn validate_anchored_entry(
    state: &mut LogState,
    anchored: &AnchoredEntry,
    implied_home: Option<&[u8; 32]>,
    prior_for_home: impl FnOnce(&[u8; 32]) -> Option<Checkpoint>,
) -> Result<(), AnchorError> {
    let mut next = state.clone();
    validate_entry(&mut next, &anchored.entry)?;
    let home = next
        .home_relay_vk
        .as_ref()
        .or(implied_home)
        .ok_or(AnchorError::NoHomeRelay)?;
    let prior = prior_for_home(home);
    anchored.verify_anchor(home, prior.as_ref())?;
    *state = next;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::MerkleTree;
    use crate::relay_ref::RelayRef;
    use crate::log_entries::{create_genesis, create_set_home_relay};
    use crate::test_support::random_key;
    use ed25519_dalek::SigningKey;

    fn genesis(mk: &SigningKey, dk: &SigningKey) -> LogEntry {
        create_genesis(mk, dk, "d1")
    }

    fn set_home(state: &LogState, dk: &SigningKey, relay_vk: [u8; 32]) -> LogEntry {
        create_set_home_relay(state, dk, RelayRef::key_only(relay_vk))
    }

    /// A relay's KT tree: append entries, return (anchors, final checkpoint).
    struct FakeHome {
        sk: SigningKey,
        leaves: Vec<[u8; 32]>,
    }

    impl FakeHome {
        fn new() -> Self {
            Self { sk: random_key(), leaves: Vec::new() }
        }

        fn vk(&self) -> [u8; 32] {
            self.sk.verifying_key().to_bytes()
        }

        fn anchor(&mut self, entry: &LogEntry) -> AnchoredEntry {
            self.leaves.push(leaf_hash(&entry.to_bytes()));
            let mut tree = MerkleTree::new();
            for l in &self.leaves {
                tree.append(*l);
            }
            let index = self.leaves.len() as u64 - 1;
            let checkpoint = Checkpoint::sign(tree.size(), tree.root(), 1000, &self.sk);
            AnchoredEntry {
                entry: entry.clone(),
                inclusion_proof: InclusionProof::generate(index, &self.leaves),
                checkpoint,
            }
        }
    }

    #[test]
    fn anchored_entry_roundtrips_bytes() {
        let (mk, dk) = (random_key(), random_key());
        let mut home = FakeHome::new();
        let anchored = home.anchor(&genesis(&mk, &dk));
        let decoded = AnchoredEntry::from_bytes(&anchored.to_bytes()).unwrap();
        assert_eq!(decoded.to_bytes(), anchored.to_bytes());
        assert_eq!(decoded.checkpoint.tree_size, 1);
    }

    #[test]
    fn sequence_roundtrips_and_rejects_truncation() {
        let (mk, dk) = (random_key(), random_key());
        let mut home = FakeHome::new();
        let g = genesis(&mk, &dk);
        let mut state = LogState::empty(g.account_fp);
        let a1 = home.anchor(&g);
        validate_anchored_entry(&mut state, &a1, Some(&home.vk()), |_| None).unwrap();
        let a2 = home.anchor(&set_home(&state, &dk, home.vk()));
        let bytes = encode_sequence(&[a1.clone(), a2.clone()]);
        let decoded = decode_sequence(&bytes).unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].to_bytes(), a1.to_bytes());
        assert_eq!(decoded[1].to_bytes(), a2.to_bytes());
        assert!(decode_sequence(&bytes[..bytes.len() - 1]).is_err());
        assert!(decode_sequence(&[]).unwrap().is_empty());
    }

    #[test]
    fn import_request_roundtrips_and_rejects_trailing_bytes() {
        let (mk, dk) = (random_key(), random_key());
        let mut home = FakeHome::new();
        let g = genesis(&mk, &dk);
        let mut state = LogState::empty(g.account_fp);
        let a1 = home.anchor(&g);
        validate_anchored_entry(&mut state, &a1, Some(&home.vk()), |_| None).unwrap();
        let move_entry = set_home(&state, &dk, [0x42; 32]);
        let request = ImportRequest { prefix: vec![a1.clone()], new_entries: vec![move_entry.clone()], key_sets: Vec::new() };

        let mut bytes = request.to_bytes();
        let decoded = ImportRequest::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.prefix.len(), 1);
        assert_eq!(decoded.prefix[0].to_bytes(), a1.to_bytes());
        assert_eq!(decoded.new_entries[0].to_bytes(), move_entry.to_bytes());

        bytes.push(0);
        assert!(ImportRequest::from_bytes(&bytes).is_err());
    }

    #[test]
    fn v2_chain_validates_against_named_home() {
        let (mk, dk) = (random_key(), random_key());
        let mut home = FakeHome::new();
        let g = genesis(&mk, &dk);
        let mut state = LogState::empty(g.account_fp);
        let a1 = home.anchor(&g);
        // Genesis predates SetHomeRelay, so the reader supplies the home.
        validate_anchored_entry(&mut state, &a1, Some(&home.vk()), |_| None).unwrap();

        let a2 = home.anchor(&set_home(&state, &dk, home.vk()));
        validate_anchored_entry(&mut state, &a2, None, |_| Some(a1.checkpoint.clone())).unwrap();
        assert_eq!(state.head_seq, 2);
        assert_eq!(state.home_relay_vk, Some(home.vk()));
    }

    #[test]
    fn rejects_checkpoint_from_other_relay() {
        let (mk, dk) = (random_key(), random_key());
        let home = FakeHome::new();
        let mut impostor = FakeHome::new();
        let g = genesis(&mk, &dk);
        let mut state = LogState::empty(g.account_fp);
        let forged = impostor.anchor(&g);
        let err = validate_anchored_entry(&mut state, &forged, Some(&home.vk()), |_| None).unwrap_err();
        assert!(matches!(err, AnchorError::BadCheckpointSignature));
        assert_eq!(state.head_seq, 0, "chain must not advance on a bad anchor");
    }

    #[test]
    fn rejects_entry_not_in_tree() {
        let (mk, dk) = (random_key(), random_key());
        let mut home = FakeHome::new();
        let g = genesis(&mk, &dk);
        let mut anchored = home.anchor(&g);
        // Swap in a checkpoint over a different leaf set signed by the real home.
        let other_root = leaf_hash(b"not this entry");
        anchored.checkpoint = Checkpoint::sign(1, other_root, 1000, &home.sk);
        let mut state = LogState::empty(g.account_fp);
        let err = validate_anchored_entry(&mut state, &anchored, Some(&home.vk()), |_| None).unwrap_err();
        assert!(matches!(err, AnchorError::InclusionFailed));
    }

    #[test]
    fn rejects_proof_size_mismatch() {
        let (mk, dk) = (random_key(), random_key());
        let mut home = FakeHome::new();
        let g = genesis(&mk, &dk);
        let mut anchored = home.anchor(&g);
        anchored.inclusion_proof.tree_size = 2;
        let err = anchored.verify_anchor(&home.vk(), None).unwrap_err();
        assert!(matches!(err, AnchorError::ProofSizeMismatch));
    }

    #[test]
    fn rejects_checkpoint_regression() {
        let (mk, dk) = (random_key(), random_key());
        let mut home = FakeHome::new();
        let g = genesis(&mk, &dk);
        let a1 = home.anchor(&g);
        let mut state = LogState::empty(g.account_fp);
        validate_anchored_entry(&mut state, &a1, Some(&home.vk()), |_| None).unwrap();
        let a2 = home.anchor(&set_home(&state, &dk, home.vk()));
        // Presenting the first anchor again after seeing the second is a rollback.
        let err = a1.verify_anchor(&home.vk(), Some(&a2.checkpoint)).unwrap_err();
        assert!(matches!(err, AnchorError::CheckpointRegression));
        // Same size, different root is also a regression (equivocation).
        let forked = Checkpoint::sign(a2.checkpoint.tree_size, [0xEE; 32], 1000, &home.sk);
        let err = a2.verify_anchor(&home.vk(), Some(&forked)).unwrap_err();
        assert!(matches!(err, AnchorError::CheckpointRegression));
        // Equal checkpoint is fine.
        a2.verify_anchor(&home.vk(), Some(&a2.checkpoint)).unwrap();
    }

    #[test]
    fn v1_chain_without_home_or_hint_is_rejected() {
        let (mk, dk) = (random_key(), random_key());
        let mut home = FakeHome::new();
        let g = genesis(&mk, &dk);
        let anchored = home.anchor(&g);
        let mut state = LogState::empty(g.account_fp);
        let err = validate_anchored_entry(&mut state, &anchored, None, |_| None).unwrap_err();
        assert!(matches!(err, AnchorError::NoHomeRelay));
    }

    #[test]
    fn rehome_entry_is_anchored_by_new_home() {
        let (mk, dk) = (random_key(), random_key());
        let mut old_home = FakeHome::new();
        let mut new_home = FakeHome::new();
        let g = genesis(&mk, &dk);
        let mut state = LogState::empty(g.account_fp);
        validate_anchored_entry(&mut state, &old_home.anchor(&g), Some(&old_home.vk()), |_| None).unwrap();
        let stay = old_home.anchor(&set_home(&state, &dk, old_home.vk()));
        validate_anchored_entry(&mut state, &stay, None, |_| None).unwrap();

        let move_entry = set_home(&state, &dk, new_home.vk());
        // The old home cannot anchor a move away from itself.
        let by_old = old_home.anchor(&move_entry);
        let err = validate_anchored_entry(&mut state.clone(), &by_old, None, |_| None).unwrap_err();
        assert!(matches!(err, AnchorError::BadCheckpointSignature));
        // The new home can. Its tree is smaller than the old home's, which is
        // not a regression because the prior lookup is per home.
        let by_new = new_home.anchor(&move_entry);
        let old_vk = old_home.vk();
        let stay_cp = stay.checkpoint.clone();
        validate_anchored_entry(&mut state, &by_new, None, |home| {
            (*home == old_vk).then(|| stay_cp.clone())
        })
        .unwrap();
        assert_eq!(state.home_relay_vk, Some(new_home.vk()));
    }
}
