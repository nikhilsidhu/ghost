use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::{broadcast, watch, RwLock};

use crate::config::Config;
use crate::mailbox::Mailbox;
use crate::storage::Storage;
use crate::voice::{RoutingTable, VoiceChannel};

pub struct Invite {
    pub expires_at: u64,
    pub join: Option<Vec<u8>>,
    pub accept: Option<Vec<u8>>,
    pub seq: u64,
    pub join_notify: broadcast::Sender<()>,
    pub accept_notify: broadcast::Sender<()>,
}

/// Cached voice presence entry for mailbox WS broadcast
pub struct VpEntry {
    pub mailbox_id: [u8; 32],
    pub channel_id: [u8; 32],
    pub conn_id: u64,
    pub blob: Vec<u8>,
}

/// Cached online presence entry for mailbox WS broadcast
pub struct OpEntry {
    pub mailbox_id: [u8; 32],
    pub conn_id: u64,
    pub blob: Vec<u8>,
}

pub struct Inner {
    pub mailboxes: RwLock<HashMap<[u8; 32], Mailbox>>,
    pub invites: RwLock<HashMap<String, Invite>>,
    pub voice_channels: RwLock<HashMap<[u8; 32], VoiceChannel>>,
    pub routing: RoutingTable,
    pub voice_udp_port: watch::Sender<u16>,
    pub voice_udp_port_rx: watch::Receiver<u16>,
    pub config: Config,
    pub start_time: Instant,
    pub storage: Storage,
    pub voice_presence: RwLock<Vec<VpEntry>>,
    pub online_presence: RwLock<Vec<OpEntry>>,
    pub next_conn_id: AtomicU64,
}

impl Inner {
    pub async fn store_blob(&self, mailbox_id: &[u8; 32], data: &[u8]) -> crate::error::Result<(u64, bool)> {
        if data.len() > self.config.max_blob_size {
            return Err(crate::error::RelayError::PayloadTooLarge);
        }
        let (envelope_type, epoch) = ghost_wire::decode_envelope(data)
            .map_err(|e| crate::error::RelayError::BadRequest(format!("envelope: {e}")))?;
        let relay_epoch = self.storage.get_epoch(mailbox_id)?;
        let (seq, _) = self.storage.append(mailbox_id, envelope_type as u8, epoch, data)?;
        if envelope_type == ghost_wire::EnvelopeType::Commit {
            self.storage.set_epoch(mailbox_id, epoch.saturating_add(1))?;
        }
        let epoch_mismatch = epoch != relay_epoch;
        let map = self.mailboxes.read().await;
        if let Some(mailbox) = map.get(mailbox_id) {
            let _ = mailbox.seq_tx.send(seq);
        }
        Ok((seq, epoch_mismatch))
    }
}

pub type AppState = Arc<Inner>;

pub fn new_state(config: Config, storage: Storage) -> AppState {
    let (voice_udp_port, voice_udp_port_rx) = watch::channel(0);
    Arc::new(Inner {
        mailboxes: RwLock::new(HashMap::new()),
        invites: RwLock::new(HashMap::new()),
        voice_channels: RwLock::new(HashMap::new()),
        routing: RoutingTable::new(),
        voice_udp_port,
        voice_udp_port_rx,
        config,
        start_time: Instant::now(),
        storage,
        voice_presence: RwLock::new(Vec::new()),
        online_presence: RwLock::new(Vec::new()),
        next_conn_id: AtomicU64::new(1),
    })
}
