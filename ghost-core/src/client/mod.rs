//! The client: this device's account, the groups it is in, and the one database holding
//! their state beside everything else it keeps. Its methods are spread over this
//! module's files by concern; each file's header says which. Nothing here talks to a
//! relay: the flows and the session do, locking the client for each step.

mod channels;
mod commits;
mod groups;
mod identity;
mod idlog;
mod invites;
mod members;
mod policy;
mod presence;
mod receive;
mod registry;
mod send;
mod servers;
mod sync;
#[cfg(test)]
pub(crate) mod testing;
#[cfg(test)]
mod tests;

use std::collections::{HashMap, HashSet};
use std::path::Path;

use ghost_wire::short_id;

use crate::crypto::GhostProvider;
use crate::error::Result;
use crate::identity::Identity;
use crate::idlog_cache::IdLogCache;
use crate::mls::group::GhostGroup;
use crate::storage::GhostStore;

pub use channels::{ChannelOpOutcome, NewPrivateChannel};
use commits::PendingRejoin;
use groups::Groups;
pub use invites::{NewInvite, ServerStateOutcome};
pub use receive::{BlobOrigin, MetadataApplied, ReceiveResult};
use sync::SnapshotPush;

/// This device's view of its account: its identity, the groups it is in, and the
/// database holding their state beside everything else it keeps. Every change to a
/// group and the rows that go with it is made in one write (`mls_step`), so memory and
/// storage never part. One lock serializes all use.
pub struct GhostClient {
    identity: Identity,
    /// OpenMLS's crypto and storage, the storage being the app's database: the store
    /// lives here, reached through `provider.store()`.
    provider: GhostProvider,
    /// The groups held, with the channel and server each belongs to.
    groups: Groups,
    /// Relay's Ed25519 verifying key for ExternalSendersExtension
    relay_vk: Option<[u8; 32]>,
    /// Cached identity log states for credential validation
    idlog_cache: IdLogCache,
    /// A snapshot push owed to the relays since sync state changed, if one is.
    snapshot_push: SnapshotPush,
    /// Rejoins whose commit the relay has not answered: the group each channel had, to
    /// go back to if the relay refuses.
    pending_rejoins: HashMap<[u8; 32], PendingRejoin>,
    /// Private channels whose name this device asked for in this run: one still unnamed
    /// is asked again in the next run, and one whose request failed at the next discovery.
    names_asked: HashSet<[u8; 32]>,
}

impl GhostClient {
    /// Open the device's database at `db_path` under `db_key`. `mls_db_key` opens the file
    /// MLS state was kept in before it moved into that database, brought in on the first
    /// open after.
    pub fn open(identity: Identity, db_key: [u8; 32], mls_db_key: [u8; 32], db_path: &Path) -> Result<Self> {
        let store = GhostStore::open(&db_key, db_path)?;
        // Nothing answers for a message handed to a connection of an earlier run: it is
        // sent again. Failing here fails the open rather than leaving it "sending".
        store.reset_in_flight()?;

        let provider = GhostProvider::new(store)?;
        provider.import_mls_file(&db_path.with_extension("mls.db"), &mls_db_key)?;
        let store = provider.store();

        // Reload per-channel MLS groups from previous sessions. A server none of whose
        // groups was ever stored is the leftover of an interrupted join, and goes so the
        // account's other devices can provision it again. One whose group fails to load
        // stays, with its history, until it loads: its rows are the only copy.
        let mut groups = Groups::default();
        if let Ok(stored_servers) = store.list_servers() {
            for s in &stored_servers {
                let channels = store.list_channels(&s.server_id).unwrap_or_default();
                let mut loaded_any = false;
                let mut load_failed = false;
                for ch in &channels {
                    match GhostGroup::load(&provider, &identity, &s.server_id, &ch.channel_id) {
                        Ok(Some(group)) => {
                            groups.insert(ch.channel_id, s.server_id, group);
                            loaded_any = true;
                        }
                        Ok(None) => {}
                        Err(e) => {
                            load_failed = true;
                            tracing::error!("group of channel {} not loaded: {e}", short_id(&ch.channel_id));
                        }
                    }
                }
                if !loaded_any && !load_failed {
                    let _ = store.delete_server(&s.server_id);
                }
            }
        }

        let client = Self {
            identity,
            provider,
            groups,
            relay_vk: None,
            idlog_cache: IdLogCache::new(),
            snapshot_push: SnapshotPush::default(),
            pending_rejoins: HashMap::new(),
            names_asked: HashSet::new(),
        };
        // Servers joined before views were recorded start their history here.
        for server_id in client.groups.servers() {
            if let Err(e) = client.record_server_view(&server_id) {
                tracing::error!("server view for {}: {e}", short_id(&server_id));
            }
        }
        Ok(client)
    }

    pub fn open_in_memory(identity: Identity, db_key: [u8; 32]) -> Result<Self> {
        let provider = GhostProvider::new(GhostStore::open_in_memory(&db_key)?)?;
        Ok(Self {
            identity,
            provider,
            groups: Groups::default(),
            relay_vk: None,
            idlog_cache: IdLogCache::new(),
            snapshot_push: SnapshotPush::default(),
            pending_rejoins: HashMap::new(),
            names_asked: HashSet::new(),
        })
    }

    /// Run `step`, which moves channel groups on and writes the rows that go with that,
    /// as one write of the database both live in: a crash or an error lands none of it.
    /// After an error the groups of `channels` are put back in memory as storage holds
    /// them once rolled back, so memory never runs ahead of storage.
    fn mls_step<T>(&mut self, channels: &[[u8; 32]], step: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        let servers: Vec<([u8; 32], Option<[u8; 32]>)> = channels.iter().map(|channel_id| (*channel_id, self.groups.server_of(channel_id))).collect();
        self.provider.store().begin_whole()?;
        let stepped = step(self).and_then(|value| self.provider.store().end_whole().map(|()| value));
        if stepped.is_err() {
            self.provider.store().abandon_whole();
            for (channel_id, server_id) in servers {
                self.restore_group(&channel_id, server_id);
            }
        }
        stepped
    }

    /// Put a channel's group in memory back as storage holds it, after a step that
    /// touched it was rolled back: read back if it was there before the step, forgotten
    /// if the step made it.
    fn restore_group(&mut self, channel_id: &[u8; 32], server_id: Option<[u8; 32]>) {
        self.groups.remove(channel_id);
        let Some(server_id) = server_id else { return };
        match GhostGroup::load(&self.provider, &self.identity, &server_id, channel_id) {
            Ok(Some(group)) => {
                self.groups.insert(*channel_id, server_id, group);
            }
            Ok(None) => {}
            Err(e) => tracing::error!("group of channel {} not read back after a failed step: {e}", short_id(channel_id)),
        }
    }

    /// Load a channel's group from the MLS storage again, as a restart would.
    #[cfg(test)]
    pub(crate) fn reload_group(&mut self, channel_id: &[u8; 32]) {
        let server_id = self.groups.server_of(channel_id).expect("the channel is held");
        let group = GhostGroup::load(&self.provider, &self.identity, &server_id, channel_id).unwrap().expect("the group is in storage");
        self.groups.replace(channel_id, group);
    }
}
