use std::collections::HashMap;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::{broadcast, RwLock};

use crate::config::Config;
use crate::mailbox::Mailbox;

pub struct Invite {
    pub max_uses: u32,
    pub uses: u32,
    pub expires_at: u64,
    pub joins: Vec<Vec<u8>>,
    pub accept: Option<Vec<u8>>,
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
