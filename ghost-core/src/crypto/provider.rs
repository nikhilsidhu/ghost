//! The OpenMLS provider: the crypto backend and the SQLite storage every group lives in.
//! The storage is this module's own type over the connection, so the connection stays
//! reachable for what OpenMLS itself has no call for: putting a group back as it was.

use openmls_rust_crypto::RustCrypto;
use openmls_sqlite_storage::{Codec, SqliteStorageProvider};
use openmls_traits::storage::{traits, StorageProvider, CURRENT_VERSION};
use openmls_traits::OpenMlsProvider;
use rusqlite::types::Value;
use rusqlite::Connection;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::error::{GhostError, Result};

#[derive(Default)]
pub struct JsonCodec;

impl Codec for JsonCodec {
    type Error = serde_json::Error;

    fn to_vec<T: Serialize>(value: &T) -> std::result::Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    fn from_slice<T: DeserializeOwned>(slice: &[u8]) -> std::result::Result<T, Self::Error> {
        serde_json::from_slice(slice)
    }
}

/// The tables OpenMLS keeps a group's own rows in, keyed by its group id. The rest of
/// the schema is keyed by public keys and references and is not a group's to restore.
const GROUP_TABLES: [&str; 4] = ["openmls_group_data", "openmls_epoch_keys_pairs", "openmls_own_leaf_nodes", "openmls_proposals"];

/// Every row the storage held for one group at a moment, table by table.
pub struct GroupRows {
    tables: Vec<TableRows>,
}

struct TableRows {
    table: &'static str,
    columns: Vec<String>,
    rows: Vec<Vec<Value>>,
}

/// OpenMLS storage in SQLite, with the connection kept at hand.
pub struct GhostStorage {
    conn: Connection,
}

impl GhostStorage {
    fn view(&self) -> SqliteStorageProvider<JsonCodec, &Connection> {
        SqliteStorageProvider::new(&self.conn)
    }

    fn db(context: &'static str) -> impl Fn(rusqlite::Error) -> GhostError {
        move |e| GhostError::Database(format!("mls storage: {context}: {e}"))
    }

    /// A group id as the storage keys its rows by: the codec's encoding of OpenMLS's type.
    fn group_key(group_id: &[u8]) -> Result<Vec<u8>> {
        JsonCodec::to_vec(&openmls::group::GroupId::from_slice(group_id)).map_err(|e| GhostError::Database(format!("mls storage: group key: {e}")))
    }

    /// Everything the storage holds for the group right now.
    pub fn group_rows(&self, group_id: &[u8]) -> Result<GroupRows> {
        let key = Self::group_key(group_id)?;
        let mut tables = Vec::new();
        for table in GROUP_TABLES {
            let mut stmt = self.conn.prepare(&format!("SELECT * FROM {table} WHERE group_id = ?1")).map_err(Self::db("read group rows"))?;
            let columns: Vec<String> = stmt.column_names().iter().map(|c| c.to_string()).collect();
            let rows = stmt
                .query_map([key.as_slice()], |row| (0..columns.len()).map(|i| row.get::<_, Value>(i)).collect::<rusqlite::Result<Vec<Value>>>())
                .map_err(Self::db("read group rows"))?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(Self::db("read group rows"))?;
            tables.push(TableRows { table, columns, rows });
        }
        Ok(GroupRows { tables })
    }

    /// Make the storage hold exactly `rows` for the group again.
    pub fn restore_group_rows(&self, group_id: &[u8], rows: &GroupRows) -> Result<()> {
        let key = Self::group_key(group_id)?;
        let tx = self.conn.unchecked_transaction().map_err(Self::db("restore group rows"))?;
        for table in &rows.tables {
            tx.execute(&format!("DELETE FROM {} WHERE group_id = ?1", table.table), [key.as_slice()]).map_err(Self::db("restore group rows"))?;
            let placeholders: Vec<String> = (1..=table.columns.len()).map(|i| format!("?{i}")).collect();
            let sql = format!("INSERT INTO {} ({}) VALUES ({})", table.table, table.columns.join(", "), placeholders.join(", "));
            for row in &table.rows {
                tx.execute(&sql, rusqlite::params_from_iter(row.iter())).map_err(Self::db("restore group rows"))?;
            }
        }
        tx.commit().map_err(Self::db("restore group rows"))
    }

    /// Drop the rows of `rows` the storage still holds unchanged: what an old copy of a
    /// group left behind once a new copy under the same id has written its own. A row
    /// the new copy overwrote differs and stays; the group data table is left alone,
    /// since the new copy rewrites every row of it.
    pub fn delete_rows_still_held(&self, rows: &GroupRows) -> Result<()> {
        let tx = self.conn.unchecked_transaction().map_err(Self::db("drop old group rows"))?;
        for table in rows.tables.iter().filter(|t| t.table != "openmls_group_data") {
            let conditions: Vec<String> = table.columns.iter().enumerate().map(|(i, c)| format!("{c} IS ?{}", i + 1)).collect();
            let sql = format!("DELETE FROM {} WHERE {}", table.table, conditions.join(" AND "));
            for row in &table.rows {
                tx.execute(&sql, rusqlite::params_from_iter(row.iter())).map_err(Self::db("drop old group rows"))?;
            }
        }
        tx.commit().map_err(Self::db("drop old group rows"))
    }
}

impl StorageProvider<CURRENT_VERSION> for GhostStorage {
    type Error = rusqlite::Error;

        fn write_mls_join_config<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        config: &MlsGroupJoinConfig,
    ) -> std::result::Result<(), Self::Error> {
        self.view().write_mls_join_config::<GroupId, MlsGroupJoinConfig>(group_id, config)
    }

    fn append_own_leaf_node<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNode: traits::LeafNode<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        leaf_node: &LeafNode,
    ) -> std::result::Result<(), Self::Error> {
        self.view().append_own_leaf_node::<GroupId, LeafNode>(group_id, leaf_node)
    }

    fn queue_proposal<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
        proposal: &QueuedProposal,
    ) -> std::result::Result<(), Self::Error> {
        self.view().queue_proposal::<GroupId, ProposalRef, QueuedProposal>(group_id, proposal_ref, proposal)
    }

    fn write_tree<GroupId: traits::GroupId<CURRENT_VERSION>, TreeSync: traits::TreeSync<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
        tree: &TreeSync,
    ) -> std::result::Result<(), Self::Error> {
        self.view().write_tree::<GroupId, TreeSync>(group_id, tree)
    }

    fn write_interim_transcript_hash<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        interim_transcript_hash: &InterimTranscriptHash,
    ) -> std::result::Result<(), Self::Error> {
        self.view().write_interim_transcript_hash::<GroupId, InterimTranscriptHash>(group_id, interim_transcript_hash)
    }

    fn write_context<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupContext: traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_context: &GroupContext,
    ) -> std::result::Result<(), Self::Error> {
        self.view().write_context::<GroupId, GroupContext>(group_id, group_context)
    }

    fn write_confirmation_tag<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        confirmation_tag: &ConfirmationTag,
    ) -> std::result::Result<(), Self::Error> {
        self.view().write_confirmation_tag::<GroupId, ConfirmationTag>(group_id, confirmation_tag)
    }

    fn write_group_state<
        GroupState: traits::GroupState<CURRENT_VERSION>,
        GroupId: traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_state: &GroupState,
    ) -> std::result::Result<(), Self::Error> {
        self.view().write_group_state::<GroupState, GroupId>(group_id, group_state)
    }

    fn write_message_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        message_secrets: &MessageSecrets,
    ) -> std::result::Result<(), Self::Error> {
        self.view().write_message_secrets::<GroupId, MessageSecrets>(group_id, message_secrets)
    }

    fn write_resumption_psk_store<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        resumption_psk_store: &ResumptionPskStore,
    ) -> std::result::Result<(), Self::Error> {
        self.view().write_resumption_psk_store::<GroupId, ResumptionPskStore>(group_id, resumption_psk_store)
    }

    fn write_own_leaf_index<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        own_leaf_index: &LeafNodeIndex,
    ) -> std::result::Result<(), Self::Error> {
        self.view().write_own_leaf_index::<GroupId, LeafNodeIndex>(group_id, own_leaf_index)
    }

    fn write_group_epoch_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_epoch_secrets: &GroupEpochSecrets,
    ) -> std::result::Result<(), Self::Error> {
        self.view().write_group_epoch_secrets::<GroupId, GroupEpochSecrets>(group_id, group_epoch_secrets)
    }

    fn write_signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
        signature_key_pair: &SignatureKeyPair,
    ) -> std::result::Result<(), Self::Error> {
        self.view().write_signature_key_pair::<SignaturePublicKey, SignatureKeyPair>(public_key, signature_key_pair)
    }

    fn write_encryption_key_pair<
        EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
        key_pair: &HpkeKeyPair,
    ) -> std::result::Result<(), Self::Error> {
        self.view().write_encryption_key_pair::<EncryptionKey, HpkeKeyPair>(public_key, key_pair)
    }

    fn write_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
        key_pairs: &[HpkeKeyPair],
    ) -> std::result::Result<(), Self::Error> {
        self.view().write_encryption_epoch_key_pairs::<GroupId, EpochKey, HpkeKeyPair>(group_id, epoch, leaf_index, key_pairs)
    }

    fn write_key_package<
        HashReference: traits::HashReference<CURRENT_VERSION>,
        KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &HashReference,
        key_package: &KeyPackage,
    ) -> std::result::Result<(), Self::Error> {
        self.view().write_key_package::<HashReference, KeyPackage>(hash_ref, key_package)
    }

    fn write_psk<PskId: traits::PskId<CURRENT_VERSION>, PskBundle: traits::PskBundle<CURRENT_VERSION>>(
        &self,
        psk_id: &PskId,
        psk: &PskBundle,
    ) -> std::result::Result<(), Self::Error> {
        self.view().write_psk::<PskId, PskBundle>(psk_id, psk)
    }

    fn mls_group_join_config<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> std::result::Result<Option<MlsGroupJoinConfig>, Self::Error> {
        self.view().mls_group_join_config::<GroupId, MlsGroupJoinConfig>(group_id)
    }

    fn own_leaf_nodes<GroupId: traits::GroupId<CURRENT_VERSION>, LeafNode: traits::LeafNode<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> std::result::Result<Vec<LeafNode>, Self::Error> {
        self.view().own_leaf_nodes::<GroupId, LeafNode>(group_id)
    }

    fn queued_proposal_refs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> std::result::Result<Vec<ProposalRef>, Self::Error> {
        self.view().queued_proposal_refs::<GroupId, ProposalRef>(group_id)
    }

    fn queued_proposals<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> std::result::Result<Vec<(ProposalRef, QueuedProposal)>, Self::Error> {
        self.view().queued_proposals::<GroupId, ProposalRef, QueuedProposal>(group_id)
    }

    fn tree<GroupId: traits::GroupId<CURRENT_VERSION>, TreeSync: traits::TreeSync<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> std::result::Result<Option<TreeSync>, Self::Error> {
        self.view().tree::<GroupId, TreeSync>(group_id)
    }

    fn group_context<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupContext: traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> std::result::Result<Option<GroupContext>, Self::Error> {
        self.view().group_context::<GroupId, GroupContext>(group_id)
    }

    fn interim_transcript_hash<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> std::result::Result<Option<InterimTranscriptHash>, Self::Error> {
        self.view().interim_transcript_hash::<GroupId, InterimTranscriptHash>(group_id)
    }

    fn confirmation_tag<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> std::result::Result<Option<ConfirmationTag>, Self::Error> {
        self.view().confirmation_tag::<GroupId, ConfirmationTag>(group_id)
    }

    fn group_state<GroupState: traits::GroupState<CURRENT_VERSION>, GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> std::result::Result<Option<GroupState>, Self::Error> {
        self.view().group_state::<GroupState, GroupId>(group_id)
    }

    fn message_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> std::result::Result<Option<MessageSecrets>, Self::Error> {
        self.view().message_secrets::<GroupId, MessageSecrets>(group_id)
    }

    fn resumption_psk_store<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> std::result::Result<Option<ResumptionPskStore>, Self::Error> {
        self.view().resumption_psk_store::<GroupId, ResumptionPskStore>(group_id)
    }

    fn own_leaf_index<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> std::result::Result<Option<LeafNodeIndex>, Self::Error> {
        self.view().own_leaf_index::<GroupId, LeafNodeIndex>(group_id)
    }

    fn group_epoch_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> std::result::Result<Option<GroupEpochSecrets>, Self::Error> {
        self.view().group_epoch_secrets::<GroupId, GroupEpochSecrets>(group_id)
    }

    fn signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> std::result::Result<Option<SignatureKeyPair>, Self::Error> {
        self.view().signature_key_pair::<SignaturePublicKey, SignatureKeyPair>(public_key)
    }

    fn encryption_key_pair<
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
        EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
    ) -> std::result::Result<Option<HpkeKeyPair>, Self::Error> {
        self.view().encryption_key_pair::<HpkeKeyPair, EncryptionKey>(public_key)
    }

    fn encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> std::result::Result<Vec<HpkeKeyPair>, Self::Error> {
        self.view().encryption_epoch_key_pairs::<GroupId, EpochKey, HpkeKeyPair>(group_id, epoch, leaf_index)
    }

    fn key_package<
        KeyPackageRef: traits::HashReference<CURRENT_VERSION>,
        KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> std::result::Result<Option<KeyPackage>, Self::Error> {
        self.view().key_package::<KeyPackageRef, KeyPackage>(hash_ref)
    }

    fn psk<PskBundle: traits::PskBundle<CURRENT_VERSION>, PskId: traits::PskId<CURRENT_VERSION>>(
        &self,
        psk_id: &PskId,
    ) -> std::result::Result<Option<PskBundle>, Self::Error> {
        self.view().psk::<PskBundle, PskId>(psk_id)
    }

    fn remove_proposal<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
    ) -> std::result::Result<(), Self::Error> {
        self.view().remove_proposal::<GroupId, ProposalRef>(group_id, proposal_ref)
    }

    fn delete_own_leaf_nodes<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> std::result::Result<(), Self::Error> {
        self.view().delete_own_leaf_nodes::<GroupId>(group_id)
    }

    fn delete_group_config<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> std::result::Result<(), Self::Error> {
        self.view().delete_group_config::<GroupId>(group_id)
    }

    fn delete_tree<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> std::result::Result<(), Self::Error> {
        self.view().delete_tree::<GroupId>(group_id)
    }

    fn delete_confirmation_tag<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> std::result::Result<(), Self::Error> {
        self.view().delete_confirmation_tag::<GroupId>(group_id)
    }

    fn delete_group_state<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> std::result::Result<(), Self::Error> {
        self.view().delete_group_state::<GroupId>(group_id)
    }

    fn delete_context<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> std::result::Result<(), Self::Error> {
        self.view().delete_context::<GroupId>(group_id)
    }

    fn delete_interim_transcript_hash<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> std::result::Result<(), Self::Error> {
        self.view().delete_interim_transcript_hash::<GroupId>(group_id)
    }

    fn delete_message_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> std::result::Result<(), Self::Error> {
        self.view().delete_message_secrets::<GroupId>(group_id)
    }

    fn delete_all_resumption_psk_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> std::result::Result<(), Self::Error> {
        self.view().delete_all_resumption_psk_secrets::<GroupId>(group_id)
    }

    fn delete_own_leaf_index<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> std::result::Result<(), Self::Error> {
        self.view().delete_own_leaf_index::<GroupId>(group_id)
    }

    fn delete_group_epoch_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> std::result::Result<(), Self::Error> {
        self.view().delete_group_epoch_secrets::<GroupId>(group_id)
    }

    fn clear_proposal_queue<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> std::result::Result<(), Self::Error> {
        self.view().clear_proposal_queue::<GroupId, ProposalRef>(group_id)
    }

    fn delete_signature_key_pair<SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>>(
        &self,
        public_key: &SignaturePublicKey,
    ) -> std::result::Result<(), Self::Error> {
        self.view().delete_signature_key_pair::<SignaturePublicKey>(public_key)
    }

    fn delete_encryption_key_pair<EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>>(
        &self,
        public_key: &EncryptionKey,
    ) -> std::result::Result<(), Self::Error> {
        self.view().delete_encryption_key_pair::<EncryptionKey>(public_key)
    }

    fn delete_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> std::result::Result<(), Self::Error> {
        self.view().delete_encryption_epoch_key_pairs::<GroupId, EpochKey>(group_id, epoch, leaf_index)
    }

    fn delete_key_package<KeyPackageRef: traits::HashReference<CURRENT_VERSION>>(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> std::result::Result<(), Self::Error> {
        self.view().delete_key_package::<KeyPackageRef>(hash_ref)
    }

    fn delete_psk<PskKey: traits::PskId<CURRENT_VERSION>>(
        &self,
        psk_id: &PskKey,
    ) -> std::result::Result<(), Self::Error> {
        self.view().delete_psk::<PskKey>(psk_id)
    }
}

/// Holds the OpenMLS crypto backend and persistent SQLite storage.
pub struct GhostProvider {
    crypto: RustCrypto,
    storage: GhostStorage,
}

impl GhostProvider {
    /// Create a provider backed by a persistent SQLite connection (already opened/encrypted).
    pub fn new(mut conn: Connection) -> Result<Self> {
        SqliteStorageProvider::<JsonCodec, &mut Connection>::new(&mut conn)
            .run_migrations()
            .map_err(|e| GhostError::Database(format!("mls migrations: {e}")))?;
        Ok(Self { crypto: RustCrypto::default(), storage: GhostStorage { conn } })
    }

    /// Create a provider backed by an in-memory SQLite database (for testing).
    pub fn new_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()
            .map_err(|e| GhostError::Database(format!("mls in-memory: {e}")))?;
        Self::new(conn)
    }
}

impl OpenMlsProvider for GhostProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = GhostStorage;

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }
}
