//! Append-only Merkle tree for key transparency.
//!
//! Uses blake3 with domain separation (RFC 6962-style). The relay builds
//! the tree incrementally; clients verify inclusion and consistency proofs.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use thiserror::Error;

const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;
const CHECKPOINT_MAGIC: &[u8; 4] = b"KTCP";

#[derive(Debug, Error)]
pub enum MerkleError {
    #[error("invalid proof")]
    InvalidProof,
    #[error("invalid checkpoint: {0}")]
    InvalidCheckpoint(String),
    #[error("signature verification failed")]
    BadSignature,
}

// ── Hashing ─────────────────────────────────────────────────────────────

/// Hash a leaf value with domain separation: H(0x00 || data).
pub fn leaf_hash(data: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(1 + data.len());
    buf.push(LEAF_PREFIX);
    buf.extend_from_slice(data);
    blake3::hash(&buf).into()
}

/// Hash two child nodes: H(0x01 || left || right).
pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 65];
    buf[0] = NODE_PREFIX;
    buf[1..33].copy_from_slice(left);
    buf[33..65].copy_from_slice(right);
    blake3::hash(&buf).into()
}

/// Compute tree root from all leaf hashes (RFC 6962 recursive definition).
pub fn compute_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves.len() {
        0 => [0u8; 32],
        1 => leaves[0],
        n => {
            let k = split_point(n as u64) as usize;
            node_hash(&compute_root(&leaves[..k]), &compute_root(&leaves[k..]))
        }
    }
}

/// Largest power of 2 strictly less than n. Panics if n <= 1.
fn split_point(n: u64) -> u64 {
    debug_assert!(n > 1);
    1u64 << (u64::BITS - 1 - (n - 1).leading_zeros())
}

// ── Frontier-based tree ─────────────────────────────────────────────────

/// Append-only Merkle tree storing only O(log N) hashes.
///
/// `frontier[i]` holds the root of a complete subtree at height i along
/// the right edge of the tree. The relay persists the frontier to resume
/// after restart without replaying all leaves.
pub struct MerkleTree {
    frontier: Vec<Option<[u8; 32]>>,
    size: u64,
}

impl MerkleTree {
    pub fn new() -> Self {
        Self {
            frontier: Vec::new(),
            size: 0,
        }
    }

    /// Reconstruct from a persisted frontier.
    pub fn from_frontier(frontier: Vec<Option<[u8; 32]>>, size: u64) -> Self {
        Self { frontier, size }
    }

    /// Append a pre-hashed leaf. Use `leaf_hash()` on raw data first.
    pub fn append(&mut self, leaf: [u8; 32]) {
        let mut hash = leaf;
        let mut level = 0usize;
        while level < self.frontier.len() {
            match self.frontier[level].take() {
                Some(existing) => {
                    hash = node_hash(&existing, &hash);
                    level += 1;
                }
                None => {
                    self.frontier[level] = Some(hash);
                    self.size += 1;
                    return;
                }
            }
        }
        self.frontier.push(Some(hash));
        self.size += 1;
    }

    /// Current tree root. Returns all-zeros for an empty tree.
    pub fn root(&self) -> [u8; 32] {
        if self.size == 0 {
            return [0u8; 32];
        }
        // Fold from lowest to highest: frontier[i] is the left subtree,
        // accumulator is the right (more recent leaves).
        let mut acc: Option<[u8; 32]> = None;
        for entry in &self.frontier {
            if let Some(h) = entry {
                acc = Some(match acc {
                    None => *h,
                    Some(a) => node_hash(h, &a),
                });
            }
        }
        acc.unwrap()
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn frontier(&self) -> &[Option<[u8; 32]>] {
        &self.frontier
    }
}

// ── Inclusion proof ─────────────────────────────────────────────────────

/// Proof that a leaf at `leaf_index` is in a tree of `tree_size` leaves.
pub struct InclusionProof {
    pub leaf_index: u64,
    pub tree_size: u64,
    pub path: Vec<[u8; 32]>,
}

impl InclusionProof {
    /// Build proof from all leaf hashes (relay-side).
    pub fn generate(index: u64, leaves: &[[u8; 32]]) -> Self {
        let size = leaves.len() as u64;
        assert!(index < size, "leaf index out of range");
        Self {
            leaf_index: index,
            tree_size: size,
            path: gen_inclusion_path(index, leaves),
        }
    }

    /// Verify against a known leaf hash and expected root.
    pub fn verify(&self, leaf_hash: &[u8; 32], expected_root: &[u8; 32]) -> bool {
        if self.tree_size == 0 || self.leaf_index >= self.tree_size {
            return false;
        }
        let dirs = compute_directions(self.leaf_index, self.tree_size);
        if dirs.len() != self.path.len() {
            return false;
        }
        let mut hash = *leaf_hash;
        for (i, sibling) in self.path.iter().enumerate() {
            // dirs are root-to-leaf; proof entries are leaf-to-root
            if dirs[dirs.len() - 1 - i] {
                hash = node_hash(&hash, sibling); // we're left child
            } else {
                hash = node_hash(sibling, &hash); // we're right child
            }
        }
        hash == *expected_root
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(16 + self.path.len() * 32);
        buf.extend_from_slice(&self.leaf_index.to_be_bytes());
        buf.extend_from_slice(&self.tree_size.to_be_bytes());
        for h in &self.path {
            buf.extend_from_slice(h);
        }
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, MerkleError> {
        if data.len() < 16 || (data.len() - 16) % 32 != 0 {
            return Err(MerkleError::InvalidProof);
        }
        let leaf_index = u64::from_be_bytes(data[..8].try_into().unwrap());
        let tree_size = u64::from_be_bytes(data[8..16].try_into().unwrap());
        let path = data[16..]
            .chunks_exact(32)
            .map(|c| {
                let mut h = [0u8; 32];
                h.copy_from_slice(c);
                h
            })
            .collect();
        Ok(Self {
            leaf_index,
            tree_size,
            path,
        })
    }
}

/// Root-to-leaf splitting decisions: true = go left, false = go right.
fn compute_directions(index: u64, size: u64) -> Vec<bool> {
    let mut dirs = Vec::new();
    let (mut idx, mut sz) = (index, size);
    while sz > 1 {
        let k = split_point(sz);
        if idx < k {
            dirs.push(true);
            sz = k;
        } else {
            dirs.push(false);
            idx -= k;
            sz -= k;
        }
    }
    dirs
}

/// Sibling hashes from leaf to root.
fn gen_inclusion_path(index: u64, leaves: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let n = leaves.len() as u64;
    if n <= 1 {
        return vec![];
    }
    let k = split_point(n) as usize;
    if (index as usize) < k {
        let mut path = gen_inclusion_path(index, &leaves[..k]);
        path.push(compute_root(&leaves[k..]));
        path
    } else {
        let mut path = gen_inclusion_path(index - k as u64, &leaves[k..]);
        path.push(compute_root(&leaves[..k]));
        path
    }
}

// ── Persistent node storage ────────────────────────────────────────────
//
// Nodes are keyed by (start, count): the leaf index range they cover.
// On each append, only O(log N) nodes along the right edge change.
// Proof generation reads O(log N) sibling nodes.

/// After appending a leaf (making tree_size the new size), recompute and
/// store the O(log N) internal nodes along the right edge.
///
/// The leaf hash must already be loadable via `load` (e.g. from kt_leaves).
/// `load` reads a stored hash by (start_index, leaf_count).
/// `store` persists a node hash at (start_index, leaf_count, hash).
pub fn update_stored_nodes(
    tree_size: u64,
    load: &dyn Fn(u64, u64) -> Option<[u8; 32]>,
    store: &mut dyn FnMut(u64, u64, [u8; 32]),
) {
    update_path(0, tree_size, load, store);
}

/// Recursively recompute nodes along the path to the rightmost leaf.
/// Returns the subtree hash.
fn update_path(
    start: u64,
    count: u64,
    load: &dyn Fn(u64, u64) -> Option<[u8; 32]>,
    store: &mut dyn FnMut(u64, u64, [u8; 32]),
) -> [u8; 32] {
    if count == 1 {
        // Leaf — stored by kt_append_leaf, read back here via load
        return load(start, 1).expect("leaf must be stored before update_path");
    }
    let k = split_point(count);
    // Left subtree is complete and unchanged — read from storage
    let left = load(start, k)
        .expect("left subtree must already be stored");
    // Right subtree contains the new leaf — recurse
    let right = update_path(start + k, count - k, load, store);
    let h = node_hash(&left, &right);
    store(start, count, h);
    h
}

impl InclusionProof {
    /// Build proof by reading stored node hashes — O(log N) lookups.
    ///
    /// `load` returns the hash of the subtree covering `[start, start+count)`.
    pub fn generate_from_store(
        index: u64,
        tree_size: u64,
        load: &dyn Fn(u64, u64) -> Option<[u8; 32]>,
    ) -> Self {
        assert!(index < tree_size, "leaf index out of range");
        let path = gen_path_from_store(index, 0, tree_size, load);
        Self {
            leaf_index: index,
            tree_size,
            path,
        }
    }
}

fn gen_path_from_store(
    index: u64,
    start: u64,
    count: u64,
    load: &dyn Fn(u64, u64) -> Option<[u8; 32]>,
) -> Vec<[u8; 32]> {
    if count <= 1 {
        return vec![];
    }
    let k = split_point(count);
    if index < k {
        let mut path = gen_path_from_store(index, start, k, load);
        let sibling = load(start + k, count - k)
            .expect("sibling node must be stored");
        path.push(sibling);
        path
    } else {
        let mut path = gen_path_from_store(index - k, start + k, count - k, load);
        let sibling = load(start, k)
            .expect("sibling node must be stored");
        path.push(sibling);
        path
    }
}

/// Generate a consistency proof by reading stored nodes — O(log N) lookups.
pub fn consistency_proof_from_store(
    old_size: u64,
    new_size: u64,
    load: &dyn Fn(u64, u64) -> Option<[u8; 32]>,
) -> ConsistencyProof {
    assert!(old_size > 0 && old_size <= new_size);
    if old_size == new_size {
        return ConsistencyProof {
            old_size,
            new_size,
            path: vec![],
        };
    }
    let path = subproof_from_store(old_size, 0, new_size, true, load);
    ConsistencyProof {
        old_size,
        new_size,
        path,
    }
}

fn subproof_from_store(
    m: u64,
    start: u64,
    n: u64,
    is_complete: bool,
    load: &dyn Fn(u64, u64) -> Option<[u8; 32]>,
) -> Vec<[u8; 32]> {
    if m == n {
        if is_complete {
            return vec![];
        } else {
            let h = load(start, n).expect("node must be stored");
            return vec![h];
        }
    }
    let k = split_point(n);
    if m <= k {
        let mut path = subproof_from_store(m, start, k, is_complete, load);
        let right = load(start + k, n - k).expect("node must be stored");
        path.push(right);
        path
    } else {
        let mut path = subproof_from_store(m - k, start + k, n - k, false, load);
        let left = load(start, k).expect("node must be stored");
        path.push(left);
        path
    }
}

// ── Consistency proof ───────────────────────────────────────────────────

/// Proof that an older tree of `old_size` is a prefix of a newer tree.
pub struct ConsistencyProof {
    pub old_size: u64,
    pub new_size: u64,
    pub path: Vec<[u8; 32]>,
}

impl ConsistencyProof {
    /// Build proof from all leaf hashes of the new tree (relay-side).
    pub fn generate(old_size: u64, leaves: &[[u8; 32]]) -> Self {
        let new_size = leaves.len() as u64;
        assert!(old_size > 0 && old_size <= new_size);
        let path = if old_size == new_size {
            vec![]
        } else {
            subproof(old_size, leaves, true)
        };
        Self {
            old_size,
            new_size,
            path,
        }
    }

    /// Verify that `old_root` is a prefix of `new_root`.
    pub fn verify(&self, old_root: &[u8; 32], new_root: &[u8; 32]) -> bool {
        if self.old_size == 0 || self.old_size > self.new_size {
            return false;
        }
        if self.old_size == self.new_size {
            return self.path.is_empty() && old_root == new_root;
        }
        match verify_subproof(
            self.old_size,
            self.new_size,
            &self.path,
            0,
            true,
            old_root,
        ) {
            Some((computed_old, computed_new, consumed)) => {
                consumed == self.path.len()
                    && computed_old == *old_root
                    && computed_new == *new_root
            }
            None => false,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(16 + self.path.len() * 32);
        buf.extend_from_slice(&self.old_size.to_be_bytes());
        buf.extend_from_slice(&self.new_size.to_be_bytes());
        for h in &self.path {
            buf.extend_from_slice(h);
        }
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, MerkleError> {
        if data.len() < 16 || (data.len() - 16) % 32 != 0 {
            return Err(MerkleError::InvalidProof);
        }
        let old_size = u64::from_be_bytes(data[..8].try_into().unwrap());
        let new_size = u64::from_be_bytes(data[8..16].try_into().unwrap());
        let path = data[16..]
            .chunks_exact(32)
            .map(|c| {
                let mut h = [0u8; 32];
                h.copy_from_slice(c);
                h
            })
            .collect();
        Ok(Self {
            old_size,
            new_size,
            path,
        })
    }
}

/// RFC 6962 SUBPROOF(m, D[n], b) — generate consistency proof entries.
fn subproof(m: u64, leaves: &[[u8; 32]], b: bool) -> Vec<[u8; 32]> {
    let n = leaves.len() as u64;
    if m == n {
        return if b {
            vec![]
        } else {
            vec![compute_root(leaves)]
        };
    }
    let k = split_point(n) as usize;
    if m <= k as u64 {
        let mut path = subproof(m, &leaves[..k], b);
        path.push(compute_root(&leaves[k..]));
        path
    } else {
        let mut path = subproof(m - k as u64, &leaves[k..], false);
        path.push(compute_root(&leaves[..k]));
        path
    }
}

/// Recursive consistency verification. Returns (old_hash, new_hash, entries_consumed).
fn verify_subproof(
    m: u64,
    n: u64,
    proof: &[[u8; 32]],
    offset: usize,
    b: bool,
    old_root: &[u8; 32],
) -> Option<([u8; 32], [u8; 32], usize)> {
    if m == n {
        return if b {
            // This subtree IS the old tree — its hash is old_root (not in proof)
            Some((*old_root, *old_root, offset))
        } else {
            // Hash is in the proof
            proof.get(offset).map(|h| (*h, *h, offset + 1))
        };
    }
    let k = split_point(n);
    if m <= k {
        // Old tree is entirely within the left subtree
        let (old_h, left_h, consumed) =
            verify_subproof(m, k, proof, offset, b, old_root)?;
        let right_h = *proof.get(consumed)?;
        Some((old_h, node_hash(&left_h, &right_h), consumed + 1))
    } else {
        // Old tree extends into the right subtree
        let (r_old, r_new, consumed) =
            verify_subproof(m - k, n - k, proof, offset, false, old_root)?;
        let left_h = *proof.get(consumed)?;
        Some((
            node_hash(&left_h, &r_old),
            node_hash(&left_h, &r_new),
            consumed + 1,
        ))
    }
}

// ── Checkpoint ──────────────────────────────────────────────────────────

const CHECKPOINT_SIGNED_LEN: usize = 4 + 8 + 32 + 8; // magic + size + root + timestamp
const CHECKPOINT_TOTAL_LEN: usize = CHECKPOINT_SIGNED_LEN + 64; // + Ed25519 signature

/// Signed tree head. The relay signs a checkpoint after each append;
/// clients store the latest and verify consistency on updates.
pub struct Checkpoint {
    pub tree_size: u64,
    pub root_hash: [u8; 32],
    pub timestamp: u64,
    pub signature: [u8; 64],
}

impl Checkpoint {
    /// Sign a new checkpoint.
    pub fn sign(tree_size: u64, root_hash: [u8; 32], timestamp: u64, sk: &SigningKey) -> Self {
        let payload = Self::signed_payload(tree_size, &root_hash, timestamp);
        let sig: Signature = sk.sign(&payload);
        Self {
            tree_size,
            root_hash,
            timestamp,
            signature: sig.to_bytes(),
        }
    }

    /// Verify checkpoint signature against the relay's verifying key.
    pub fn verify(&self, vk: &VerifyingKey) -> Result<(), MerkleError> {
        let payload = Self::signed_payload(self.tree_size, &self.root_hash, self.timestamp);
        let sig = Signature::from_bytes(&self.signature);
        vk.verify(&payload, &sig)
            .map_err(|_| MerkleError::BadSignature)
    }

    fn signed_payload(
        tree_size: u64,
        root_hash: &[u8; 32],
        timestamp: u64,
    ) -> [u8; CHECKPOINT_SIGNED_LEN] {
        let mut buf = [0u8; CHECKPOINT_SIGNED_LEN];
        buf[..4].copy_from_slice(CHECKPOINT_MAGIC);
        buf[4..12].copy_from_slice(&tree_size.to_be_bytes());
        buf[12..44].copy_from_slice(root_hash);
        buf[44..52].copy_from_slice(&timestamp.to_be_bytes());
        buf
    }

    pub fn to_bytes(&self) -> [u8; CHECKPOINT_TOTAL_LEN] {
        let mut buf = [0u8; CHECKPOINT_TOTAL_LEN];
        buf[..CHECKPOINT_SIGNED_LEN]
            .copy_from_slice(&Self::signed_payload(
                self.tree_size,
                &self.root_hash,
                self.timestamp,
            ));
        buf[CHECKPOINT_SIGNED_LEN..].copy_from_slice(&self.signature);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, MerkleError> {
        if data.len() != CHECKPOINT_TOTAL_LEN {
            return Err(MerkleError::InvalidCheckpoint(format!(
                "expected {} bytes, got {}",
                CHECKPOINT_TOTAL_LEN,
                data.len()
            )));
        }
        if &data[..4] != CHECKPOINT_MAGIC {
            return Err(MerkleError::InvalidCheckpoint("bad magic".into()));
        }
        let tree_size = u64::from_be_bytes(data[4..12].try_into().unwrap());
        let mut root_hash = [0u8; 32];
        root_hash.copy_from_slice(&data[12..44]);
        let timestamp = u64::from_be_bytes(data[44..52].try_into().unwrap());
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&data[52..CHECKPOINT_TOTAL_LEN]);
        Ok(Self {
            tree_size,
            root_hash,
            timestamp,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    fn test_signing_key() -> SigningKey {
        let secret: [u8; 32] = rand::thread_rng().gen();
        SigningKey::from_bytes(&secret)
    }

    fn test_leaves(n: usize) -> Vec<[u8; 32]> {
        (0..n)
            .map(|i| leaf_hash(&(i as u64).to_be_bytes()))
            .collect()
    }

    // ── Tree basics ──

    #[test]
    fn empty_tree_root() {
        let tree = MerkleTree::new();
        assert_eq!(tree.root(), [0u8; 32]);
        assert_eq!(tree.size(), 0);
    }

    #[test]
    fn single_leaf() {
        let h = leaf_hash(b"hello");
        let mut tree = MerkleTree::new();
        tree.append(h);
        assert_eq!(tree.root(), h);
        assert_eq!(tree.size(), 1);
    }

    #[test]
    fn frontier_matches_full_computation() {
        for n in 1..=33 {
            let leaves = test_leaves(n);
            let expected = compute_root(&leaves);
            let mut tree = MerkleTree::new();
            for &l in &leaves {
                tree.append(l);
            }
            assert_eq!(tree.root(), expected, "mismatch at n={n}");
            assert_eq!(tree.size(), n as u64);
        }
    }

    #[test]
    fn frontier_roundtrip() {
        let leaves = test_leaves(13);
        let mut tree = MerkleTree::new();
        for &l in &leaves {
            tree.append(l);
        }
        let root_before = tree.root();
        let restored = MerkleTree::from_frontier(tree.frontier().to_vec(), tree.size());
        assert_eq!(restored.root(), root_before);
    }

    // ── Inclusion proofs ──

    #[test]
    fn inclusion_proof_all_positions() {
        for n in 1..=17 {
            let leaves = test_leaves(n);
            let root = compute_root(&leaves);
            for i in 0..n {
                let proof = InclusionProof::generate(i as u64, &leaves);
                assert!(
                    proof.verify(&leaves[i], &root),
                    "failed for leaf {i} in tree of {n}"
                );
            }
        }
    }

    #[test]
    fn tampered_leaf_rejected() {
        let leaves = test_leaves(8);
        let root = compute_root(&leaves);
        let proof = InclusionProof::generate(3, &leaves);
        let fake = leaf_hash(b"fake");
        assert!(!proof.verify(&fake, &root));
    }

    #[test]
    fn tampered_proof_rejected() {
        let leaves = test_leaves(8);
        let root = compute_root(&leaves);
        let mut proof = InclusionProof::generate(3, &leaves);
        proof.path[0][0] ^= 0xff;
        assert!(!proof.verify(&leaves[3], &root));
    }

    #[test]
    fn inclusion_proof_serialization() {
        let leaves = test_leaves(10);
        let proof = InclusionProof::generate(7, &leaves);
        let bytes = proof.to_bytes();
        let restored = InclusionProof::from_bytes(&bytes).unwrap();
        assert_eq!(restored.leaf_index, proof.leaf_index);
        assert_eq!(restored.tree_size, proof.tree_size);
        assert_eq!(restored.path, proof.path);
    }

    // ── Consistency proofs ──

    #[test]
    fn consistency_same_size() {
        let leaves = test_leaves(5);
        let root = compute_root(&leaves);
        let proof = ConsistencyProof::generate(5, &leaves);
        assert!(proof.path.is_empty());
        assert!(proof.verify(&root, &root));
    }

    #[test]
    fn consistency_all_combinations() {
        for old in 1..=16u64 {
            for new in old..=17 {
                let leaves = test_leaves(new as usize);
                let old_root = compute_root(&leaves[..old as usize]);
                let new_root = compute_root(&leaves);
                let proof = ConsistencyProof::generate(old, &leaves);
                assert!(
                    proof.verify(&old_root, &new_root),
                    "failed for old={old} new={new}"
                );
            }
        }
    }

    #[test]
    fn tampered_consistency_rejected() {
        let leaves = test_leaves(8);
        let old_root = compute_root(&leaves[..4]);
        let new_root = compute_root(&leaves);
        let mut proof = ConsistencyProof::generate(4, &leaves);
        proof.path[0][0] ^= 0xff;
        assert!(!proof.verify(&old_root, &new_root));
    }

    #[test]
    fn consistency_wrong_old_root() {
        let leaves = test_leaves(8);
        let new_root = compute_root(&leaves);
        let proof = ConsistencyProof::generate(4, &leaves);
        assert!(!proof.verify(&[0xaa; 32], &new_root));
    }

    #[test]
    fn consistency_proof_serialization() {
        let leaves = test_leaves(12);
        let proof = ConsistencyProof::generate(5, &leaves);
        let bytes = proof.to_bytes();
        let restored = ConsistencyProof::from_bytes(&bytes).unwrap();
        assert_eq!(restored.old_size, proof.old_size);
        assert_eq!(restored.new_size, proof.new_size);
        assert_eq!(restored.path, proof.path);
    }

    // ── Checkpoint ──

    #[test]
    fn checkpoint_sign_verify() {
        let sk = test_signing_key();
        let vk = sk.verifying_key();
        let cp = Checkpoint::sign(100, [0x42; 32], 1700000000, &sk);
        assert!(cp.verify(&vk).is_ok());
        assert_eq!(cp.tree_size, 100);
        assert_eq!(cp.root_hash, [0x42; 32]);
        assert_eq!(cp.timestamp, 1700000000);
    }

    #[test]
    fn checkpoint_tampered_signature() {
        let sk = test_signing_key();
        let vk = sk.verifying_key();
        let mut cp = Checkpoint::sign(100, [0x42; 32], 1700000000, &sk);
        cp.signature[0] ^= 0xff;
        assert!(cp.verify(&vk).is_err());
    }

    #[test]
    fn checkpoint_wrong_key() {
        let sk = test_signing_key();
        let other_vk = test_signing_key().verifying_key();
        let cp = Checkpoint::sign(100, [0x42; 32], 1700000000, &sk);
        assert!(cp.verify(&other_vk).is_err());
    }

    #[test]
    fn checkpoint_serialization() {
        let sk = test_signing_key();
        let cp = Checkpoint::sign(42, [0xab; 32], 999, &sk);
        let bytes = cp.to_bytes();
        let restored = Checkpoint::from_bytes(&bytes).unwrap();
        assert_eq!(restored.tree_size, 42);
        assert_eq!(restored.root_hash, [0xab; 32]);
        assert_eq!(restored.timestamp, 999);
        assert_eq!(restored.signature, cp.signature);
    }

    // ── Domain separation ──

    #[test]
    fn domain_separation_prevents_collision() {
        let data = [0x42; 32];
        let lh = leaf_hash(&data);
        let nh = node_hash(&data, &[0u8; 32]);
        assert_ne!(lh, nh);
    }
}
