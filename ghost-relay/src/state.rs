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

/// Ephemeral pairing session for device linking (5-minute TTL, in-memory only)
pub struct PairingSession {
    pub offer: Vec<u8>,
    pub response: Option<Vec<u8>>,
    pub expires_at: Instant,
}

/// One-shot provision blob posted by device A after pairing, fetched by device B
pub struct ProvisionEntry {
    pub data: Vec<u8>,
    pub expires_at: Instant,
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
    pub pairing: RwLock<HashMap<[u8; 32], PairingSession>>,
    pub provision: RwLock<HashMap<[u8; 32], ProvisionEntry>>,
    pub next_conn_id: AtomicU64,
    /// Broadcast (account_fp, device_vk) when a device is revoked, so WS
    /// connections belonging to that device can close immediately.
    pub revocation_tx: broadcast::Sender<([u8; 32], [u8; 32])>,
}

impl Inner {
    pub async fn store_blob(&self, mailbox_id: &[u8; 32], data: &[u8]) -> crate::error::Result<(u64, bool)> {
        if data.len() > self.config.max_blob_size {
            return Err(crate::error::RelayError::PayloadTooLarge);
        }
        let (envelope_type, epoch) = ghost_wire::decode_envelope(data)
            .map_err(|e| crate::error::RelayError::BadRequest(format!("envelope: {e}")))?;
        let (seq, _, epoch_mismatch) =
            self.storage
                .append(mailbox_id, envelope_type as u8, epoch, data)?;
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
    let (revocation_tx, _) = broadcast::channel(16);
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
        pairing: RwLock::new(HashMap::new()),
        provision: RwLock::new(HashMap::new()),
        next_conn_id: AtomicU64::new(1),
        revocation_tx,
    })
}
