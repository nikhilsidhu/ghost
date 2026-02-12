use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::{broadcast, watch, RwLock};

use crate::config::Config;
use crate::mailbox::Mailbox;
use crate::voice::{RoutingTable, VoiceChannel};

pub struct Invite {
    pub expires_at: u64,
    pub join: Option<Vec<u8>>,
    pub accept: Option<Vec<u8>>,
    pub seq: u64,
    pub join_notify: broadcast::Sender<()>,
    pub accept_notify: broadcast::Sender<()>,
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
    pub memory_used: AtomicUsize,
}

impl Inner {
    /// Try to reserve `size` bytes. Returns false if over limit.
    pub fn try_reserve(&self, size: usize) -> bool {
        let prev = self.memory_used.fetch_add(size, Ordering::Relaxed);
        if prev + size > self.config.max_memory {
            self.memory_used.fetch_sub(size, Ordering::Relaxed);
            false
        } else {
            true
        }
    }

    pub fn release(&self, size: usize) {
        self.memory_used.fetch_sub(size, Ordering::Relaxed);
    }
}

pub type AppState = Arc<Inner>;

pub fn new_state(config: Config) -> AppState {
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
        memory_used: AtomicUsize::new(0),
    })
}
