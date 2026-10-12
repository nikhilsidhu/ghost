//! Key transparency anchoring: sequencing an identity log entry into this relay's
//! Merkle tree and signing the checkpoint that vouches for it. Each anchor is made on
//! the storage writer, in the job that stores the entries, so an entry is never held
//! without its anchor nor anchored without being held. The tree itself lives in the
//! database: its frontier is a handful of rows, loaded and stored with every anchor.

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use ghost_wire::account_key::AccountKeySet;
use ghost_wire::anchor::AnchoredEntry;
use ghost_wire::idlog::LogEntry;
use ghost_wire::merkle::{leaf_hash, update_stored_nodes, Checkpoint, InclusionProof, MerkleTree};
use rusqlite::Connection;

use crate::error::RelayError;
use crate::state::Inner;
use crate::storage::{sql, IdlogChange};
use crate::util::now_millis;

/// Append the entry's hash to the tree, sign the new head and store the proof beside
/// the entry.
fn anchor(conn: &Connection, relay_key: &SigningKey, entry: &LogEntry) -> Result<AnchoredEntry, RelayError> {
    let (frontier, size) = sql::kt_load_frontier(conn)?;
    let mut tree = MerkleTree::from_frontier(frontier, size);
    let hash = leaf_hash(&entry.to_bytes());
    let leaf_index = sql::kt_append_leaf(conn, &hash, &entry.account_fp, entry.seq)?;
    tree.append(hash);
    let (root, size) = (tree.root(), tree.size());

    let load = |start: u64, count: u64| sql::kt_load_hash(conn, start, count).ok().flatten();
    let mut nodes = Vec::new();
    update_stored_nodes(size, &load, &mut |start, count, hash| nodes.push((start, count, hash)));
    sql::kt_store_nodes(conn, &nodes)?;

    let checkpoint = Checkpoint::sign(size, root, now_millis(), relay_key);
    let checkpoint_bytes = checkpoint.to_bytes();
    sql::kt_persist_state(conn, tree.frontier(), size, &root, &checkpoint_bytes)?;
    let inclusion_proof = InclusionProof::generate_from_store(leaf_index, size, &load);
    sql::store_anchor(conn, &entry.account_fp, entry.seq, &inclusion_proof.to_bytes(), &checkpoint_bytes)?;
    Ok(AnchoredEntry { entry: entry.clone(), inclusion_proof, checkpoint })
}

fn relay_key(bytes: &[u8; 64]) -> Result<SigningKey, RelayError> {
    SigningKey::from_keypair_bytes(bytes).map_err(|e| RelayError::Storage(format!("relay key: {e}")))
}

impl Inner {
    /// Home path: store entries from one of the account's devices with the key sets
    /// they commit to, and anchor each. All or nothing.
    pub async fn sequence_entries(
        self: &Arc<Self>,
        account_fp: [u8; 32],
        entries: Vec<LogEntry>,
        key_sets: Vec<AccountKeySet>,
    ) -> Result<(IdlogChange, Vec<AnchoredEntry>), RelayError> {
        let inner = self.clone();
        let pushed_sets = key_sets.clone();
        let (change, anchors) = self
            .storage
            .write(move |conn| {
                let change = sql::append_batch(conn, inner.relay_vk, &account_fp, &entries, &key_sets)?;
                let key = relay_key(&inner.relay_sk_bytes)?;
                let anchors = entries.iter().map(|entry| anchor(conn, &key, entry)).collect::<Result<Vec<_>, _>>()?;
                Ok((change, anchors))
            })
            .await?;
        crate::federation::push_to_mirrors(self.clone(), account_fp, anchors.clone(), &pushed_sets);
        Ok((change, anchors))
    }

    /// Become the account's home: store the chain its previous home anchored, then
    /// sequence and anchor the entries that move it here. All or nothing.
    pub async fn import_account(
        self: &Arc<Self>,
        account_fp: [u8; 32],
        prefix: Vec<AnchoredEntry>,
        new_entries: Vec<LogEntry>,
        key_sets: Vec<AccountKeySet>,
    ) -> Result<(IdlogChange, Vec<AnchoredEntry>), RelayError> {
        let inner = self.clone();
        let pushed_sets = key_sets.clone();
        let (change, anchors) = self
            .storage
            .write(move |conn| {
                let change = sql::import_account(conn, inner.relay_vk, &account_fp, &prefix, &new_entries, &key_sets)?;
                let key = relay_key(&inner.relay_sk_bytes)?;
                let anchors = new_entries.iter().map(|entry| anchor(conn, &key, entry)).collect::<Result<Vec<_>, _>>()?;
                Ok((change, anchors))
            })
            .await?;
        crate::federation::push_to_mirrors(self.clone(), account_fp, anchors.clone(), &pushed_sets);
        Ok((change, anchors))
    }

    /// Anchor for an entry this relay sequenced before anchors were stored with
    /// entries: a fresh proof against the current tree head.
    pub async fn regenerate_anchor(&self, entry: LogEntry) -> Result<Option<AnchoredEntry>, RelayError> {
        self.storage
            .read(move |conn| {
                let Some(leaf_index) = sql::kt_get_leaf_index(conn, &entry.account_fp, entry.seq)? else {
                    return Ok(None);
                };
                let (checkpoint_bytes, size) = sql::kt_load_checkpoint_with_size(conn)?;
                if leaf_index >= size {
                    return Ok(None);
                }
                let checkpoint = Checkpoint::from_bytes(&checkpoint_bytes)
                    .map_err(|e| RelayError::Storage(format!("stored checkpoint: {e}")))?;
                let load = |start: u64, count: u64| sql::kt_load_hash(conn, start, count).ok().flatten();
                let inclusion_proof = InclusionProof::generate_from_store(leaf_index, size, &load);
                Ok(Some(AnchoredEntry { entry, inclusion_proof, checkpoint }))
            })
            .await
    }

    /// Proof that the tree of `to` leaves extends the tree of `from`.
    pub async fn consistency_proof(&self, from: u64, to: u64) -> Result<Vec<u8>, RelayError> {
        self.storage
            .read(move |conn| {
                let (_, size) = sql::kt_load_checkpoint_with_size(conn)?;
                if to > size {
                    return Err(RelayError::BadRequest(format!("to ({to}) exceeds tree size ({size})")));
                }
                let load = |start: u64, count: u64| sql::kt_load_hash(conn, start, count).ok().flatten();
                Ok(ghost_wire::merkle::consistency_proof_from_store(from, to, &load).to_bytes())
            })
            .await
    }
}
