use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use openmls_rust_crypto::RustCrypto;
use tokio::sync::{broadcast, watch};

use crate::auth::ReplayCache;
use crate::config::Config;
use crate::constants::{MAX_KEY_SETS_BODY, MIRROR_FETCH_TIMEOUT_SECS};
use crate::error::RelayError;
use crate::group_state::{self, Committed, GroupTable};
use crate::mailbox::Mailbox;
use crate::rate_limit::{IpLimits, RateLimiter};
use crate::storage::Storage;
use crate::voice::{RoutingTable, VoiceChannel};

/// An account removed from a mailbox's group by the commit at `seq`, the last entry
/// it may still read there.
#[derive(Clone, Copy, Debug)]
pub struct Departure {
    pub mailbox_id: [u8; 32],
    pub account_fp: [u8; 32],
    pub seq: u64,
}

pub struct Inner {
    pub mailboxes: RwLock<HashMap<[u8; 32], Mailbox>>,
    /// Wakes the long polls waiting for an invite's payload, by token.
    pub invite_waiters: Mutex<HashMap<String, broadcast::Sender<()>>>,
    pub voice_channels: tokio::sync::RwLock<HashMap<[u8; 32], VoiceChannel>>,
    pub routing: RoutingTable,
    pub voice_udp_port: watch::Sender<u16>,
    pub voice_udp_port_rx: watch::Receiver<u16>,
    pub config: Config,
    pub start_time: Instant,
    pub storage: Storage,
    pub next_conn_id: AtomicU64,
    /// Broadcast (account_fp, device_vk) when a device is revoked, so WS
    /// connections belonging to that device can close immediately.
    pub revocation_tx: broadcast::Sender<([u8; 32], [u8; 32])>,
    /// Broadcast when a commit removes an account from a mailbox's group, so that
    /// account's live mailbox and voice connections end.
    pub departure_tx: broadcast::Sender<Departure>,
    /// Broadcast (account_fp) when the account's home moves away from this relay, so its
    /// devices' live mailbox connections are admitted again or closed.
    pub readmission_tx: broadcast::Sender<[u8; 32]>,
    /// Locked by the storage writer while a job changes a group, and briefly by
    /// readers judging a request against the group as last committed.
    pub groups: RwLock<GroupTable>,
    pub relay_crypto: RustCrypto,
    pub relay_vk: [u8; 32],
    /// Raw ed25519 keypair bytes (64) for constructing OpenMLS signer
    pub relay_sk_bytes: [u8; 64],
    /// Requests to other relays: pulling mirrored logs, pushing sequenced entries.
    pub http: reqwest::Client,
    /// Device signatures already accepted, so none is accepted twice.
    pub replay_cache: ReplayCache,
    /// Per-address limits on failed authentication and unauthenticated requests.
    pub ip_limits: IpLimits,
    /// Anchored-entry pushes per account, since the route takes no credentials.
    pub idlog_anchored_limiter: RateLimiter,
    /// Home imports per account; a move is rare and the route takes no credentials.
    pub idlog_import_limiter: RateLimiter,
    /// Per-account rate limiter for identity log Recovery entries (account takeover defense)
    pub idlog_recovery_limiter: RateLimiter,
    /// Device batches per account, so a stolen device cannot flood the log.
    pub idlog_batch_limiter: RateLimiter,
    /// Mirrored accounts whose home names no address to pull from, said once each.
    pub unaddressed_homes: Mutex<std::collections::HashSet<[u8; 32]>>,
}

impl Inner {
    /// The largest body any route takes, which is how much of a request is read before
    /// its signature is checked.
    pub fn body_limit(&self) -> usize {
        self.config.max_blob_size.max(MAX_KEY_SETS_BODY).max(ghost_wire::batch::MAX_BATCH_BYTES)
    }

    /// Tell live connections what a writer job committed: new log entries to their
    /// subscribers, departures to the accounts they concern, and private channels that
    /// became joinable to the accounts waiting on them.
    pub(crate) fn announce(&self, committed: Committed) {
        let mailboxes = self.mailboxes.read().unwrap();
        for entry in &committed.appended {
            if let Some(mailbox) = mailboxes.get(&entry.mailbox_id) {
                mailbox.publish(entry.seq, entry.received_at, &entry.payload);
            }
        }
        for departure in committed.departed {
            let _ = self.departure_tx.send(departure);
        }
        // Only accounts a private channel admits are told to look for channels, on their
        // connections to its server's mailbox, so it stays hidden from everyone else.
        for joinable in committed.joinable {
            if let Some(mailbox) = mailboxes.get(&joinable.server_mailbox) {
                for account in joinable.accounts {
                    let _ = mailbox.channels_tx.send(account);
                }
            }
        }
    }

    /// The live state of a mailbox, made on first use.
    pub fn subscribe<R>(&self, mailbox_id: [u8; 32], f: impl FnOnce(&Mailbox) -> R) -> R {
        let mut mailboxes = self.mailboxes.write().unwrap();
        f(mailboxes.entry(mailbox_id).or_default())
    }

    /// How far the account may read a mailbox: without limit (`None`) for a member or a
    /// mailbox without membership data, up to the commit that removed it for an account
    /// that left, and not at all for anyone else.
    pub async fn read_limit(&self, mailbox_id: [u8; 32], account_fp: [u8; 32]) -> Result<Option<u64>, RelayError> {
        if self.check_membership(mailbox_id, account_fp).await.is_ok() {
            return Ok(None);
        }
        match self.storage.departure_seq(mailbox_id, account_fp).await? {
            Some(seq) => Ok(Some(seq)),
            None => Err(RelayError::Forbidden("not a member of this mailbox".into())),
        }
    }

    /// Whether the account is in the mailbox's group as the relay last validated it. Unlike
    /// `check_membership`, a mailbox without group state admits nobody.
    pub async fn is_group_member(&self, mailbox_id: [u8; 32], account_fp: [u8; 32]) -> Result<bool, RelayError> {
        Ok(self.storage.has_mailbox_members(mailbox_id).await? && self.storage.is_mailbox_member(mailbox_id, account_fp).await?)
    }

    /// Store a blob a device posted, over HTTP or on its mailbox connection alike. An
    /// application message needs the account in the mailbox's group now, which a removing
    /// commit ends in the same write; commits and proposals are judged by MLS validation,
    /// and external commits come from non-members by definition.
    pub async fn accept_post(self: &Arc<Self>, mailbox_id: [u8; 32], account_fp: [u8; 32], data: Vec<u8>) -> Result<group_state::Stored, RelayError> {
        let (envelope_type, _) = ghost_wire::decode_envelope(&data).map_err(|e| RelayError::BadRequest(format!("envelope: {e}")))?;
        if envelope_type == ghost_wire::EnvelopeType::Application {
            self.check_membership(mailbox_id, account_fp).await?;
        }
        self.store_blob(mailbox_id, data).await
    }

    /// Check if account is a member of this mailbox. Skips if no ACL data exists. An
    /// account's sync mailbox admits that account alone.
    pub async fn check_membership(&self, mailbox_id: [u8; 32], account_fp: [u8; 32]) -> Result<(), RelayError> {
        if let Some(owner) = self.storage.sync_mailbox_owner(mailbox_id).await? {
            if owner != account_fp {
                return Err(RelayError::Forbidden("another account's sync mailbox".into()));
            }
            return Ok(());
        }
        if self.storage.has_mailbox_members(mailbox_id).await? && !self.storage.is_mailbox_member(mailbox_id, account_fp).await? {
            return Err(RelayError::Forbidden("not a member of this mailbox".into()));
        }
        Ok(())
    }

    /// Whether the account may replace the group state from a GroupInfo.
    pub fn may_initialize(&self, mailbox_id: &[u8; 32], account_fp: &[u8; 32]) -> bool {
        self.groups.read().unwrap().may_initialize(mailbox_id, account_fp)
    }

    /// Whether the account may delete the mailbox.
    pub fn may_delete(&self, mailbox_id: &[u8; 32], account_fp: &[u8; 32]) -> Result<(), RelayError> {
        self.groups.read().unwrap().may_delete(mailbox_id, account_fp)
    }

    /// Mailboxes of a server's private channel groups whose policy admits the account.
    pub fn admitted_channels(&self, server_mailbox: &[u8; 32], account_fp: &[u8; 32]) -> Result<Vec<[u8; 32]>, RelayError> {
        self.groups.read().unwrap().admitted_channels(server_mailbox, account_fp)
    }

    /// Wake whoever waits for the invite's payload.
    pub fn notify_invite(&self, token: &str) {
        if let Some(waiters) = self.invite_waiters.lock().unwrap().get(token) {
            let _ = waiters.send(());
        }
    }

    /// A receiver that fires when the invite's payload changes.
    pub fn invite_waiter(&self, token: &str) -> broadcast::Receiver<()> {
        let mut waiters = self.invite_waiters.lock().unwrap();
        waiters
            .entry(token.to_string())
            .or_insert_with(|| broadcast::channel(1).0)
            .subscribe()
    }

    /// Drop the wakeups of invites that no longer exist.
    pub fn forget_invite_waiters(&self, live: impl Fn(&str) -> bool) {
        self.invite_waiters.lock().unwrap().retain(|token, _| live(token));
    }
}

pub type AppState = Arc<Inner>;

pub async fn new_state(config: Config, storage: Storage) -> Result<AppState, RelayError> {
    let (voice_udp_port, voice_udp_port_rx) = watch::channel(0);
    let (revocation_tx, _) = broadcast::channel(16);
    let (departure_tx, _) = broadcast::channel(64);
    let (readmission_tx, _) = broadcast::channel(16);
    let (relay_vk, relay_sk_bytes) = storage.relay_keypair().await?;
    let groups = storage.write(group_state::load_groups).await?;
    // Identity log Recovery entries: 3 per 24-hour sliding window
    let idlog_recovery_limiter = RateLimiter::new(3, std::time::Duration::from_secs(24 * 60 * 60));
    // Anchored pushes are self-verifying but unauthenticated: 60 per account per hour
    let idlog_anchored_limiter = RateLimiter::new(60, std::time::Duration::from_secs(60 * 60));
    // Home imports: 5 per account per 24 hours
    let idlog_import_limiter = RateLimiter::new(5, std::time::Duration::from_secs(24 * 60 * 60));
    // Device batches: 30 per account per minute
    let idlog_batch_limiter = RateLimiter::new(30, std::time::Duration::from_secs(60));
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(MIRROR_FETCH_TIMEOUT_SECS))
        .build()
        .map_err(|e| RelayError::Storage(format!("http client: {e}")))?;
    Ok(Arc::new(Inner {
        mailboxes: RwLock::new(HashMap::new()),
        invite_waiters: Mutex::new(HashMap::new()),
        voice_channels: tokio::sync::RwLock::new(HashMap::new()),
        routing: RoutingTable::new(),
        voice_udp_port,
        voice_udp_port_rx,
        config,
        start_time: Instant::now(),
        storage,
        next_conn_id: AtomicU64::new(1),
        revocation_tx,
        departure_tx,
        readmission_tx,
        groups: RwLock::new(groups),
        relay_crypto: RustCrypto::default(),
        relay_vk,
        relay_sk_bytes,
        http,
        replay_cache: ReplayCache::default(),
        ip_limits: IpLimits::default(),
        idlog_anchored_limiter,
        idlog_import_limiter,
        idlog_recovery_limiter,
        idlog_batch_limiter,
        unaddressed_homes: Mutex::default(),
    }))
}
