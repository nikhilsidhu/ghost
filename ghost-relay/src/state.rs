use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::{broadcast, RwLock};

use crate::config::Config;
use crate::mailbox::Mailbox;

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
    Arc::new(Inner {
        mailboxes: RwLock::new(HashMap::new()),
        invites: RwLock::new(HashMap::new()),
        config,
        start_time: Instant::now(),
        memory_used: AtomicUsize::new(0),
    })
}
