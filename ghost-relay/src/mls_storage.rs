//! OpenMLS public group state over the relay's SQLite store. A value lives as long
//! as the borrowed connection: the writer job that validates a commit, or the
//! connection that loads groups at startup.

use openmls_traits::public_storage::PublicStorageProvider;
use openmls_traits::storage::traits as mls_traits;
use openmls_traits::storage::CURRENT_VERSION;
use rusqlite::{params, Connection, OptionalExtension};
use serde::de::DeserializeOwned;
use serde::Serialize;

#[derive(Debug, thiserror::Error)]
#[error("MLS storage error: {0}")]
pub struct MlsStorageError(String);

pub struct MlsPublicStorage<'a> {
    conn: &'a Connection,
}

impl<'a> MlsPublicStorage<'a> {
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }

    fn write_component(&self, group_id: &[u8], component: &str, data: &[u8]) -> Result<(), MlsStorageError> {
        self.conn
            .execute(
                "INSERT INTO mls_public_group (group_id, component, data)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT (group_id, component) DO UPDATE SET data = ?3",
                params![group_id, component, data],
            )
            .map_err(|e| MlsStorageError(e.to_string()))?;
        Ok(())
    }

    fn read_component(&self, group_id: &[u8], component: &str) -> Result<Option<Vec<u8>>, MlsStorageError> {
        self.conn
            .query_row(
                "SELECT data FROM mls_public_group WHERE group_id = ?1 AND component = ?2",
                params![group_id, component],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| MlsStorageError(e.to_string()))
    }

    fn delete_component(&self, group_id: &[u8], component: &str) -> Result<(), MlsStorageError> {
        self.conn
            .execute(
                "DELETE FROM mls_public_group WHERE group_id = ?1 AND component = ?2",
                params![group_id, component],
            )
            .map_err(|e| MlsStorageError(e.to_string()))?;
        Ok(())
    }

    fn read_deserialized<T: DeserializeOwned>(&self, group_id: &[u8], component: &str) -> Result<Option<T>, MlsStorageError> {
        match self.read_component(group_id, component)? {
            Some(bytes) => Ok(Some(deser(&bytes)?)),
            None => Ok(None),
        }
    }
}

fn ser<T: Serialize>(v: &T) -> Result<Vec<u8>, MlsStorageError> {
    serde_json::to_vec(v).map_err(|e| MlsStorageError(e.to_string()))
}

fn deser<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, MlsStorageError> {
    serde_json::from_slice(bytes).map_err(|e| MlsStorageError(e.to_string()))
}

impl<'a> PublicStorageProvider<CURRENT_VERSION> for MlsPublicStorage<'a> {
    type PublicError = MlsStorageError;

    // --- Writers ---

    fn write_tree<
        GroupId: mls_traits::GroupId<CURRENT_VERSION>,
        TreeSync: mls_traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        tree: &TreeSync,
    ) -> Result<(), Self::PublicError> {
        self.write_component(&ser(group_id)?, "tree", &ser(tree)?)
    }

    fn write_interim_transcript_hash<
        GroupId: mls_traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: mls_traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        interim_transcript_hash: &InterimTranscriptHash,
    ) -> Result<(), Self::PublicError> {
        self.write_component(&ser(group_id)?, "interim_transcript_hash", &ser(interim_transcript_hash)?)
    }

    fn write_context<
        GroupId: mls_traits::GroupId<CURRENT_VERSION>,
        GroupContext: mls_traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_context: &GroupContext,
    ) -> Result<(), Self::PublicError> {
        self.write_component(&ser(group_id)?, "context", &ser(group_context)?)
    }

    fn write_confirmation_tag<
        GroupId: mls_traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: mls_traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        confirmation_tag: &ConfirmationTag,
    ) -> Result<(), Self::PublicError> {
        self.write_component(&ser(group_id)?, "confirmation_tag", &ser(confirmation_tag)?)
    }

    fn queue_proposal<
        GroupId: mls_traits::GroupId<CURRENT_VERSION>,
        ProposalRef: mls_traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: mls_traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
        proposal: &QueuedProposal,
    ) -> Result<(), Self::PublicError> {
        self.conn
            .execute(
                "INSERT INTO mls_proposals (group_id, proposal_ref, data)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT (group_id, proposal_ref) DO UPDATE SET data = ?3",
                params![ser(group_id)?, ser(proposal_ref)?, ser(proposal)?],
            )
            .map_err(|e| MlsStorageError(e.to_string()))?;
        Ok(())
    }

    // --- Readers ---

    fn queued_proposals<
        GroupId: mls_traits::GroupId<CURRENT_VERSION>,
        ProposalRef: mls_traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: mls_traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<(ProposalRef, QueuedProposal)>, Self::PublicError> {
        let gid = ser(group_id)?;
        let mut stmt = self
            .conn
            .prepare_cached("SELECT proposal_ref, data FROM mls_proposals WHERE group_id = ?1")
            .map_err(|e| MlsStorageError(e.to_string()))?;

        let rows: Vec<(Vec<u8>, Vec<u8>)> = stmt
            .query_map(params![gid], |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)))
            .map_err(|e| MlsStorageError(e.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| MlsStorageError(e.to_string()))?;

        let mut result = Vec::with_capacity(rows.len());
        for (ref_bytes, data_bytes) in rows {
            result.push((deser(&ref_bytes)?, deser(&data_bytes)?));
        }
        Ok(result)
    }

    fn tree<
        GroupId: mls_traits::GroupId<CURRENT_VERSION>,
        TreeSync: mls_traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<TreeSync>, Self::PublicError> {
        self.read_deserialized(&ser(group_id)?, "tree")
    }

    fn group_context<
        GroupId: mls_traits::GroupId<CURRENT_VERSION>,
        GroupContext: mls_traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupContext>, Self::PublicError> {
        self.read_deserialized(&ser(group_id)?, "context")
    }

    fn interim_transcript_hash<
        GroupId: mls_traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: mls_traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<InterimTranscriptHash>, Self::PublicError> {
        self.read_deserialized(&ser(group_id)?, "interim_transcript_hash")
    }

    fn confirmation_tag<
        GroupId: mls_traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: mls_traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ConfirmationTag>, Self::PublicError> {
        self.read_deserialized(&ser(group_id)?, "confirmation_tag")
    }

    // --- Deleters ---

    fn delete_tree<GroupId: mls_traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::PublicError> {
        self.delete_component(&ser(group_id)?, "tree")
    }

    fn delete_confirmation_tag<GroupId: mls_traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::PublicError> {
        self.delete_component(&ser(group_id)?, "confirmation_tag")
    }

    fn delete_context<GroupId: mls_traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::PublicError> {
        self.delete_component(&ser(group_id)?, "context")
    }

    fn delete_interim_transcript_hash<GroupId: mls_traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::PublicError> {
        self.delete_component(&ser(group_id)?, "interim_transcript_hash")
    }

    fn remove_proposal<
        GroupId: mls_traits::GroupId<CURRENT_VERSION>,
        ProposalRef: mls_traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
    ) -> Result<(), Self::PublicError> {
        self.conn
            .execute(
                "DELETE FROM mls_proposals WHERE group_id = ?1 AND proposal_ref = ?2",
                params![ser(group_id)?, ser(proposal_ref)?],
            )
            .map_err(|e| MlsStorageError(e.to_string()))?;
        Ok(())
    }

    fn clear_proposal_queue<
        GroupId: mls_traits::GroupId<CURRENT_VERSION>,
        ProposalRef: mls_traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::PublicError> {
        self.conn
            .execute("DELETE FROM mls_proposals WHERE group_id = ?1", params![ser(group_id)?])
            .map_err(|e| MlsStorageError(e.to_string()))?;
        Ok(())
    }
}
