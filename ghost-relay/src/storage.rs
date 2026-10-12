//! The relay's SQLite store. One writer thread owns the connection every write goes
//! through: writes queue up and run in order, several to a transaction, each inside a
//! savepoint of its own so one that fails leaves the others standing, and a batch costs
//! one commit however many writes it holds. A pool of readers serves everything else
//! in parallel under WAL, and both run off the async workers, which never block on the
//! database. The SQL lives in [`sql`] as functions over a connection, so the writer-side
//! composites in `state` (a commit's validation, append and proposals; a KT anchor) run
//! several of them inside one job.

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use ghost_wire::account_key::AccountKeySet;
use ghost_wire::anchor::AnchoredEntry;
use ghost_wire::idlog;
use ghost_wire::relay_ref::RelayRef;
use rusqlite::Connection;
use tokio::sync::{mpsc, oneshot};

use crate::error::RelayError;

pub struct LogEntry {
    pub seq: u64,
    pub received_at: u64,
    pub envelope_type: u8,
    pub epoch: u64,
    pub payload: Vec<u8>,
}

/// One identity log entry as stored. The anchor columns are empty only for
/// entries this relay sequenced before anchoring existed; the home regenerates
/// those from its KT tree on read.
pub struct IdLogRow {
    pub seq: u64,
    pub payload: Vec<u8>,
    pub inclusion_proof: Option<Vec<u8>>,
    pub checkpoint: Option<Vec<u8>>,
}

/// What this relay knows about an account whose log it holds or mirrors.
#[derive(Debug, Clone)]
pub struct AccountRow {
    pub account_fp: [u8; 32],
    pub home_relay_vk: [u8; 32],
    pub home_relay_ref: Vec<u8>,
    pub home_set_at_seq: u64,
    pub is_home: bool,
    pub head_seq: u64,
    /// Devices of this account may authenticate here until this time (millis)
    /// even without a mailbox membership; set when an invite admits the account.
    pub guest_until: u64,
    /// When this relay last appended to the log or last asked the home for it (millis).
    pub last_refresh: u64,
    /// Pulls in a row that the home refused because the account has not granted this relay.
    pub pull_refusals: u32,
}

/// The oldest grant time still in force at `now`.
fn grants_since(now: u64) -> u64 {
    now.saturating_sub(crate::constants::MIRROR_GRANT_TTL_MS)
}

/// Doublings of the refresh interval a refused mirror waits at most: about a day at the
/// default interval, so an account that no longer uses this relay costs one probe a day.
const MAX_PULL_BACKOFF_DOUBLINGS: u32 = 12;

impl AccountRow {
    /// Whether to pull the log from the home now: always, unless the home refused the
    /// last pulls, each of which doubles the wait.
    pub fn pull_due(&self, now: u64, interval_ms: u64) -> bool {
        if self.pull_refusals == 0 {
            return true;
        }
        let wait = interval_ms.saturating_mul(1u64 << self.pull_refusals.min(MAX_PULL_BACKOFF_DOUBLINGS));
        now >= self.last_refresh.saturating_add(wait)
    }
}

/// One device-linking rendezvous, addressed by account and a random token that
/// only the pairing code carries.
pub struct PairingRow {
    pub offer: Vec<u8>,
    pub response: Option<Vec<u8>>,
    /// The existing device's AddDevice for the new device to counter-sign.
    pub draft: Option<Vec<u8>>,
    /// The new device's counter-signature on the draft.
    pub signatures: Option<Vec<u8>>,
    pub provision: Option<Vec<u8>>,
}

/// An open invite as stored.
pub struct InviteRow {
    /// The server mailbox the invite is into.
    pub mailbox: [u8; 32],
    pub expires_at: u64,
    /// What joiners fetch, once the inviter has uploaded it.
    pub payload: Option<Vec<u8>>,
}

/// Where a mailbox's log stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogPosition {
    /// The first sequence still kept; `None` when the log keeps nothing.
    pub first: Option<u64>,
    /// The last sequence given out, kept or swept; 0 for a log that never had an entry.
    pub head: u64,
}

/// What accepting identity log entries did to the account at this relay.
#[derive(Debug)]
pub struct IdlogChange {
    /// Devices active before and not after, whose sessions and leaves must go.
    pub revoked: Vec<[u8; 32]>,
    pub home_relay_vk: [u8; 32],
    pub is_home: bool,
    /// This relay was the account's home until this change, so devices it admitted as
    /// the home's may no longer be admitted.
    pub left_home: bool,
}

/// On what footing a device may act at this relay, from its account's standing here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    /// The account is homed here: everything is open to it.
    Home,
    /// The account belongs to a group here.
    Member,
    /// An invite admitted the account for a while, so it can post its first commits.
    Guest,
}

/// What a blob append did.
#[derive(Debug)]
pub struct Appended {
    pub seq: u64,
    pub received_at: u64,
}

/// Jobs the writer takes from its queue before committing them together. Enough to
/// absorb a burst, few enough that one commit never holds a request long.
const WRITE_BATCH: usize = 64;
/// Writes waiting for the writer before callers are held back.
const WRITE_QUEUE: usize = 1024;
/// Readers for a machine with few cores; more on bigger ones, up to the cap.
const READERS_MIN: usize = 2;
const READERS_MAX: usize = 8;

fn storage_error(e: rusqlite::Error) -> RelayError {
    RelayError::Storage(e.to_string())
}

pub struct Storage {
    writer: mpsc::Sender<writer::Job>,
    readers: Arc<ReadPool>,
    relay_vk: [u8; 32],
    /// A test store's folder, which goes with the store.
    _ephemeral: Option<tempfile::TempDir>,
}

impl Storage {
    /// The store at `path`, made if it does not exist.
    pub fn open(path: &Path) -> Result<Self, RelayError> {
        Self::open_at(path, None)
    }

    /// A store that lasts as long as this value: in a folder of its own, so it runs
    /// under the same WAL mode as a real one.
    pub fn open_ephemeral() -> Result<Self, RelayError> {
        let dir = tempfile::tempdir().map_err(|e| RelayError::Storage(format!("ephemeral store: {e}")))?;
        Self::open_at(&dir.path().join("relay.db"), Some(dir))
    }

    fn open_at(path: &Path, ephemeral: Option<tempfile::TempDir>) -> Result<Self, RelayError> {
        let writer_conn = Connection::open(path).map_err(storage_error)?;
        sql::configure(&writer_conn)?;
        sql::init(&writer_conn)?;
        let relay_vk = sql::get_or_create_relay_keypair(&writer_conn)?.0;
        sql::backfill_accounts(&writer_conn, relay_vk)?;
        sql::backfill_sync_mailboxes(&writer_conn)?;

        let reader_count = std::thread::available_parallelism().map_or(READERS_MIN, |n| n.get()).clamp(READERS_MIN, READERS_MAX);
        let mut readers = Vec::with_capacity(reader_count);
        for _ in 0..reader_count {
            let conn = Connection::open(path).map_err(storage_error)?;
            sql::configure(&conn)?;
            conn.execute_batch("PRAGMA query_only = ON;").map_err(storage_error)?;
            readers.push(Mutex::new(conn));
        }

        Ok(Self {
            writer: writer::spawn(writer_conn),
            readers: Arc::new(ReadPool { conns: readers, next: AtomicUsize::new(0) }),
            relay_vk,
            _ephemeral: ephemeral,
        })
    }

    /// This relay's Ed25519 verifying key, which names it in RelayRefs.
    pub fn relay_vk(&self) -> [u8; 32] {
        self.relay_vk
    }

    /// Run `query` on a reader connection, off the async workers.
    pub async fn read<R, F>(&self, query: F) -> Result<R, RelayError>
    where
        R: Send + 'static,
        F: FnOnce(&Connection) -> Result<R, RelayError> + Send + 'static,
    {
        let readers = self.readers.clone();
        tokio::task::spawn_blocking(move || {
            let conn = readers.pick().lock().unwrap();
            query(&conn)
        })
        .await
        .map_err(|e| RelayError::Storage(format!("read task: {e}")))?
    }

    /// Run `job` on the writer, inside a savepoint of the batch it lands in; the result
    /// comes back once the batch has committed. A job that fails is rolled back alone.
    pub async fn write<R, F>(&self, job: F) -> Result<R, RelayError>
    where
        R: Send + 'static,
        F: FnOnce(&Connection) -> Result<R, RelayError> + Send + 'static,
    {
        let (tx, rx) = oneshot::channel();
        self.writer
            .send(writer::job(job, tx))
            .await
            .map_err(|_| RelayError::Storage("storage writer stopped".into()))?;
        rx.await.map_err(|_| RelayError::Storage("storage writer dropped a write".into()))?
    }

    /// Raise a mailbox's commit epoch to `epoch`, never lowering it. Group state
    /// established from GroupInfo (a new group, or one moved here from another relay)
    /// sets the epoch the next commit must carry.
    pub async fn raise_mailbox_epoch(&self, mailbox_id: [u8; 32], epoch: u64) -> Result<(), RelayError> {
        self.write(move |conn| sql::raise_mailbox_epoch(conn, &mailbox_id, epoch)).await
    }

    /// Store a blob, enforcing epoch ordering: a commit or proposal must name the
    /// mailbox's epoch, a message may also name the one before it. Anything else is
    /// refused with `Conflict`, so the sender catches up and tries again.
    pub async fn append(&self, mailbox_id: [u8; 32], envelope_type: u8, epoch: u64, payload: Vec<u8>) -> Result<Appended, RelayError> {
        self.write(move |conn| sql::append(conn, &mailbox_id, envelope_type, epoch, &payload)).await
    }

    /// Log entries after `after_seq`, oldest first, at most `limit`.
    pub async fn read_from(&self, mailbox_id: [u8; 32], after_seq: u64, limit: u32) -> Result<Vec<LogEntry>, RelayError> {
        self.read(move |conn| sql::read_from(conn, &mailbox_id, after_seq, limit)).await
    }

    /// Delete log entries older than `cutoff_ms`, keeping at least `min_entries` per
    /// mailbox. Returns how many went.
    pub async fn sweep_log(&self, cutoff_ms: u64, min_entries: u64) -> Result<u64, RelayError> {
        self.write(move |conn| sql::sweep_log(conn, cutoff_ms, min_entries)).await
    }

    /// Where a mailbox's log stands: the first sequence still kept, and the last one
    /// given out, which the sweep leaves as it is.
    pub async fn log_position(&self, mailbox_id: [u8; 32]) -> Result<LogPosition, RelayError> {
        self.read(move |conn| sql::log_position(conn, &mailbox_id)).await
    }

    /// The mailbox's commit epoch; 0 when it has none.
    pub async fn get_epoch(&self, mailbox_id: [u8; 32]) -> Result<u64, RelayError> {
        self.read(move |conn| sql::get_epoch(conn, &mailbox_id)).await
    }

    pub async fn put_server_info(&self, mailbox_id: [u8; 32], data: Vec<u8>) -> Result<(), RelayError> {
        self.write(move |conn| sql::put_server_info(conn, &mailbox_id, &data)).await
    }

    pub async fn get_server_info(&self, mailbox_id: [u8; 32]) -> Result<Option<Vec<u8>>, RelayError> {
        self.read(move |conn| sql::get_server_info(conn, &mailbox_id)).await
    }

    pub async fn put_avatar(&self, mailbox_id: [u8; 32], fingerprint: [u8; 32], data: Vec<u8>) -> Result<(), RelayError> {
        self.write(move |conn| sql::put_avatar(conn, &mailbox_id, &fingerprint, &data)).await
    }

    pub async fn get_avatar(&self, mailbox_id: [u8; 32], fingerprint: [u8; 32]) -> Result<Option<Vec<u8>>, RelayError> {
        self.read(move |conn| sql::get_avatar(conn, &mailbox_id, &fingerprint)).await
    }

    pub async fn delete_avatar(&self, mailbox_id: [u8; 32], fingerprint: [u8; 32]) -> Result<(), RelayError> {
        self.write(move |conn| sql::delete_avatar(conn, &mailbox_id, &fingerprint)).await
    }

    /// Home path: validate entries from one of the account's devices (or a
    /// self-authenticating genesis or recovery) against the stored chain, with the key
    /// sets they commit to, and store them unanchored as the account's home. The
    /// caller anchors each entry afterwards. A batch starting below the head is a
    /// fork, settled by the shared rule. Mirrors must use `append_anchored_entries`.
    pub async fn append_batch(
        &self,
        account_fp: [u8; 32],
        entries: Vec<idlog::LogEntry>,
        key_sets: Vec<AccountKeySet>,
    ) -> Result<IdlogChange, RelayError> {
        let relay_vk = self.relay_vk;
        self.write(move |conn| sql::append_batch(conn, relay_vk, &account_fp, &entries, &key_sets)).await
    }

    /// Mirror path: accept entries another relay sequenced, each carrying that
    /// home's proof. Also the path for registering a foreign account (full
    /// chain from genesis) and for learning that an account moved home.
    /// Entries already held are skipped if identical; a different entry at a held
    /// position is a fork, settled by the shared rule.
    pub async fn append_anchored_entries(&self, account_fp: [u8; 32], entries: Vec<AnchoredEntry>) -> Result<IdlogChange, RelayError> {
        let relay_vk = self.relay_vk;
        self.write(move |conn| sql::append_anchored_entries(conn, relay_vk, &account_fp, &entries)).await
    }

    /// Make this relay the account's home: store the existing chain with the
    /// anchors its previous home issued, then sequence `new_entries` here with the
    /// key sets they commit to. The first new entry must be a `SetHomeRelay` naming
    /// this relay, so every entry this relay anchors comes after the move that makes
    /// it home. All or nothing.
    pub async fn import_account(
        &self,
        account_fp: [u8; 32],
        prefix: Vec<AnchoredEntry>,
        new_entries: Vec<idlog::LogEntry>,
        key_sets: Vec<AccountKeySet>,
    ) -> Result<IdlogChange, RelayError> {
        let relay_vk = self.relay_vk;
        self.write(move |conn| sql::import_account(conn, relay_vk, &account_fp, &prefix, &new_entries, &key_sets)).await
    }

    /// Accounts this relay holds but does not home, for pulling from their homes.
    pub async fn mirrored_accounts(&self) -> Result<Vec<AccountRow>, RelayError> {
        self.read(sql::mirrored_accounts).await
    }

    /// The home refused this relay's pull of the account: the next pull waits longer.
    pub async fn record_pull_refusal(&self, account_fp: [u8; 32]) -> Result<(), RelayError> {
        self.write(move |conn| sql::record_pull_refusal(conn, &account_fp)).await
    }

    /// The home served the account's log, or someone pushed it here: pulls are due again.
    pub async fn clear_pull_refusals(&self, account_fp: [u8; 32]) -> Result<(), RelayError> {
        self.write(move |conn| sql::clear_pull_refusals(conn, &account_fp)).await
    }

    pub async fn get_account(&self, account_fp: [u8; 32]) -> Result<Option<AccountRow>, RelayError> {
        self.read(move |conn| sql::load_account(conn, &account_fp)).await
    }

    /// Let the account's devices authenticate here until `until` (millis),
    /// which an invite grants so a joiner can post its first commits.
    pub async fn set_account_guest_until(&self, account_fp: [u8; 32], until: u64) -> Result<(), RelayError> {
        self.write(move |conn| sql::set_account_guest_until(conn, &account_fp, until)).await
    }

    /// The account whose sync mailbox this is, if it is one.
    pub async fn sync_mailbox_owner(&self, mailbox_id: [u8; 32]) -> Result<Option<[u8; 32]>, RelayError> {
        self.read(move |conn| sql::sync_mailbox_owner(conn, &mailbox_id)).await
    }

    /// Whether the account's log, as this relay holds it, revokes the device.
    pub async fn is_revoked_device(&self, account_fp: [u8; 32], device_vk: [u8; 32]) -> Result<bool, RelayError> {
        self.read(move |conn| sql::is_revoked_device(conn, &account_fp, &device_vk)).await
    }

    /// What revoked the device, as the account's log says: a recovery, the recovery key,
    /// or another of its devices. `None` for a device the log does not revoke.
    pub async fn revocation_cause(&self, account_fp: [u8; 32], device_vk: [u8; 32]) -> Result<Option<ghost_wire::RevocationCause>, RelayError> {
        self.read(move |conn| sql::revocation_cause(conn, &account_fp, &device_vk)).await
    }

    /// On what footing the device may make authenticated requests here, if at all: it
    /// must be an active device of an account this relay homes, that belongs to a
    /// mailbox here, or that an invite admitted recently.
    pub async fn may_authenticate(&self, account_fp: [u8; 32], device_vk: [u8; 32], now: u64) -> Result<Option<Admission>, RelayError> {
        self.read(move |conn| sql::may_authenticate(conn, &account_fp, &device_vk, now)).await
    }

    /// Whether the device key is active for the account, as the held log says.
    pub async fn is_active_device(&self, account_fp: [u8; 32], device_vk: [u8; 32]) -> Result<bool, RelayError> {
        self.read(move |conn| sql::is_active_device(conn, &account_fp, &device_vk)).await
    }

    /// The account's identity log entries after `after_seq`.
    pub async fn get_idlog(&self, account_fp: [u8; 32], after_seq: u64) -> Result<Vec<IdLogRow>, RelayError> {
        self.read(move |conn| sql::get_idlog(conn, &account_fp, after_seq)).await
    }

    /// Store where a server created by this account now lives, unless the stored
    /// record has an equal or newer generation.
    pub async fn put_server_location(&self, account_fp: [u8; 32], server_id: [u8; 32], generation: u64, data: Vec<u8>) -> Result<(), RelayError> {
        self.write(move |conn| sql::put_server_location(conn, &account_fp, &server_id, generation, &data)).await
    }

    pub async fn get_server_location(&self, account_fp: [u8; 32], server_id: [u8; 32]) -> Result<Option<Vec<u8>>, RelayError> {
        self.read(move |conn| sql::get_server_location(conn, &account_fp, &server_id)).await
    }

    /// Whether the account belongs to a group this relay holds state for, which
    /// a group creator established by uploading the group's GroupInfo here.
    pub async fn is_listed_member(&self, account_fp: [u8; 32]) -> Result<bool, RelayError> {
        self.read(move |conn| sql::is_listed_member(conn, &account_fp)).await
    }

    /// Grant relays, or grant them again, the right to pull the account's log from here
    /// and to be pushed new entries, until `MIRROR_GRANT_TTL_MS` after `now`. Grants
    /// add up: devices that know different servers each keep theirs.
    pub async fn grant_mirrors(&self, account_fp: [u8; 32], relays: Vec<RelayRef>, now: u64) -> Result<(), RelayError> {
        self.write(move |conn| sql::grant_mirrors(conn, &account_fp, &relays, now)).await
    }

    /// The relays the account granted and that have not lapsed, as it named them.
    pub async fn mirror_grants(&self, account_fp: [u8; 32], now: u64) -> Result<Vec<RelayRef>, RelayError> {
        self.read(move |conn| sql::mirror_grants(conn, &account_fp, grants_since(now))).await
    }

    pub async fn is_mirror_granted(&self, account_fp: [u8; 32], relay_vk: [u8; 32], now: u64) -> Result<bool, RelayError> {
        self.read(move |conn| sql::is_mirror_granted(conn, &account_fp, &relay_vk, grants_since(now))).await
    }

    /// Delete lapsed grants; returns how many.
    pub async fn sweep_mirror_grants(&self, now: u64) -> Result<usize, RelayError> {
        self.write(move |conn| sql::sweep_mirror_grants(conn, grants_since(now))).await
    }

    /// The account's state as this relay holds it, replayed from the chain.
    pub async fn account_state(&self, account_fp: [u8; 32]) -> Result<Option<idlog::LogState>, RelayError> {
        self.read(move |conn| {
            let state = sql::replay(conn, &account_fp)?;
            Ok((state.head_seq > 0).then_some(state))
        })
        .await
    }

    /// The account whose current root is `root_vk`, for a recovering device that
    /// knows only its recovery key.
    pub async fn account_by_root(&self, root_vk: [u8; 32]) -> Result<Option<AccountRow>, RelayError> {
        self.read(move |conn| sql::account_by_root(conn, &root_vk)).await
    }

    /// Stored key sets of the held chain from `from_generation` on, oldest first.
    pub async fn get_key_sets(&self, account_fp: [u8; 32], from_generation: u32) -> Result<Vec<AccountKeySet>, RelayError> {
        self.read(move |conn| sql::get_key_sets(conn, &account_fp, from_generation)).await
    }

    /// The earliest generation of the held chain whose key set this relay lacks.
    pub async fn first_missing_key_set(&self, account_fp: [u8; 32]) -> Result<Option<u32>, RelayError> {
        self.read(move |conn| sql::first_missing_key_set(conn, &account_fp)).await
    }

    /// Hash of the stored entry at `seq`, if any.
    pub async fn entry_hash_at(&self, account_fp: [u8; 32], seq: u64) -> Result<Option<[u8; 32]>, RelayError> {
        self.read(move |conn| sql::stored_entry_hash(conn, &account_fp, seq)).await
    }

    /// Mirror path for key sets: keep each set that matches an `AccountKey` entry of
    /// the held chain. The entry commits to the set, so pushing one needs no credentials.
    pub async fn put_key_sets(&self, account_fp: [u8; 32], key_sets: Vec<AccountKeySet>) -> Result<(), RelayError> {
        self.write(move |conn| sql::put_key_sets(conn, &account_fp, &key_sets)).await
    }

    /// Open a pairing session, replacing any other session for the account.
    pub async fn pairing_open(&self, account_fp: [u8; 32], token: Vec<u8>, offer: Vec<u8>, expires_at: u64) -> Result<(), RelayError> {
        self.write(move |conn| sql::pairing_open(conn, &account_fp, &token, &offer, expires_at)).await
    }

    /// A live (unexpired) pairing session.
    pub async fn pairing_get(&self, account_fp: [u8; 32], token: Vec<u8>, now: u64) -> Result<Option<PairingRow>, RelayError> {
        self.read(move |conn| sql::pairing_get(conn, &account_fp, &token, now)).await
    }

    /// Record the new device's response. Only the first response is kept, so
    /// nobody can replace it once the new device has answered.
    pub async fn pairing_set_response(&self, account_fp: [u8; 32], token: Vec<u8>, response: Vec<u8>, now: u64) -> Result<(), RelayError> {
        self.write(move |conn| sql::pairing_fill(conn, &account_fp, &token, "response", &response, now)).await
    }

    /// Record the existing device's draft AddDevice. A later draft replaces it,
    /// since the log's head may have moved, and clears the counter-signature made
    /// for the old one.
    pub async fn pairing_set_draft(&self, account_fp: [u8; 32], token: Vec<u8>, draft: Vec<u8>, now: u64) -> Result<(), RelayError> {
        self.write(move |conn| sql::pairing_set_draft(conn, &account_fp, &token, &draft, now)).await
    }

    /// Record the new device's counter-signature on the draft, once.
    pub async fn pairing_set_signatures(&self, account_fp: [u8; 32], token: Vec<u8>, signatures: Vec<u8>, now: u64) -> Result<(), RelayError> {
        self.write(move |conn| sql::pairing_fill(conn, &account_fp, &token, "signatures", &signatures, now)).await
    }

    /// Record the existing device's provision; a later one replaces it.
    pub async fn pairing_set_provision(&self, account_fp: [u8; 32], token: Vec<u8>, provision: Vec<u8>, now: u64) -> Result<(), RelayError> {
        self.write(move |conn| sql::pairing_set_provision(conn, &account_fp, &token, &provision, now)).await
    }

    /// End a pairing session; ending one that is gone already is no error.
    pub async fn pairing_close(&self, account_fp: [u8; 32], token: Vec<u8>) -> Result<(), RelayError> {
        self.write(move |conn| sql::pairing_close(conn, &account_fp, &token)).await
    }

    /// Delete expired pairing sessions; returns how many.
    pub async fn pairing_sweep(&self, now: u64) -> Result<usize, RelayError> {
        self.write(move |conn| sql::pairing_sweep(conn, now)).await
    }

    /// Store a sealed sync snapshot unless the stored one has an equal or newer generation.
    pub async fn put_sync_state(&self, account_fp: [u8; 32], generation: u64, data: Vec<u8>) -> Result<(), RelayError> {
        self.write(move |conn| sql::put_generational(conn, "sync_state", &account_fp, generation, &data)).await
    }

    pub async fn get_sync_state(&self, account_fp: [u8; 32]) -> Result<Option<(u64, Vec<u8>)>, RelayError> {
        self.read(move |conn| sql::get_generational(conn, "sync_state", &account_fp)).await
    }

    pub async fn is_mailbox_member(&self, mailbox_id: [u8; 32], account_fp: [u8; 32]) -> Result<bool, RelayError> {
        self.read(move |conn| sql::is_mailbox_member(conn, &mailbox_id, &account_fp)).await
    }

    /// Whether the relay holds membership data for the mailbox at all.
    pub async fn has_mailbox_members(&self, mailbox_id: [u8; 32]) -> Result<bool, RelayError> {
        self.read(move |conn| sql::has_mailbox_members(conn, &mailbox_id)).await
    }

    /// The last sequence an account that left the mailbox's group may read.
    pub async fn departure_seq(&self, mailbox_id: [u8; 32], account_fp: [u8; 32]) -> Result<Option<u64>, RelayError> {
        self.read(move |conn| sql::departure_seq(conn, &mailbox_id, &account_fp)).await
    }

    /// The relay's Ed25519 keypair, made at the first open.
    pub async fn relay_keypair(&self) -> Result<([u8; 32], [u8; 64]), RelayError> {
        self.read(sql::get_or_create_relay_keypair).await
    }

    /// Every mailbox the account is a member of.
    pub async fn mailboxes_for_account(&self, account_fp: [u8; 32]) -> Result<Vec<[u8; 32]>, RelayError> {
        self.read(move |conn| sql::mailboxes_for_account(conn, &account_fp)).await
    }

    /// The latest signed KT checkpoint.
    pub async fn kt_load_checkpoint(&self) -> Result<Option<Vec<u8>>, RelayError> {
        self.read(sql::kt_load_checkpoint).await
    }

    /// Open an invite into the server at `mailbox`; refused if the token is in use.
    pub async fn invite_register(&self, token: String, mailbox: [u8; 32], creator: [u8; 32], expires_at: u64) -> Result<(), RelayError> {
        self.write(move |conn| sql::invite_register(conn, &token, &mailbox, &creator, expires_at)).await
    }

    /// Set the invite's payload, if nobody set it since `expected_seq`. Only the
    /// inviter or a member of the server may.
    pub async fn invite_set_payload(&self, token: String, payload: Vec<u8>, now: u64, by: [u8; 32]) -> Result<(), RelayError> {
        self.write(move |conn| sql::invite_set_payload(conn, &token, &payload, now, &by)).await
    }

    pub async fn invite_get(&self, token: String) -> Result<Option<InviteRow>, RelayError> {
        self.read(move |conn| sql::invite_get(conn, &token)).await
    }

    /// Delete expired invites, returning their tokens.
    pub async fn invite_sweep(&self, now: u64) -> Result<Vec<String>, RelayError> {
        self.write(move |conn| sql::invite_sweep(conn, now)).await
    }
}

/// Reader connections handed out in turn.
struct ReadPool {
    conns: Vec<Mutex<Connection>>,
    next: AtomicUsize,
}

impl ReadPool {
    fn pick(&self) -> &Mutex<Connection> {
        let index = self.next.fetch_add(1, Ordering::Relaxed) % self.conns.len();
        // A reader still busy is skipped for one that is free, if any is.
        for offset in 0..self.conns.len() {
            let candidate = &self.conns[(index + offset) % self.conns.len()];
            if candidate.try_lock().is_ok() {
                return candidate;
            }
        }
        &self.conns[index]
    }
}

/// The writer thread: jobs in, results out after the batch they ran in commits. A
/// transaction that cannot begin or commit means the store itself is failing, and the
/// relay stops rather than serve state its disk does not hold.
mod writer {
    use super::*;

    /// A write as queued: runs against the connection and hands back how to deliver
    /// its result once the batch has committed.
    pub(super) struct Job {
        run: Box<dyn FnOnce(&Connection) -> Done + Send>,
    }

    /// A job that ran: whether its statements stood, and how to deliver its result.
    struct Done {
        ok: bool,
        deliver: Box<dyn FnOnce() + Send>,
    }

    pub(super) fn job<R, F>(run: F, tx: oneshot::Sender<Result<R, RelayError>>) -> Job
    where
        R: Send + 'static,
        F: FnOnce(&Connection) -> Result<R, RelayError> + Send + 'static,
    {
        Job {
            run: Box::new(move |conn| {
                let result = run(conn);
                Done {
                    ok: result.is_ok(),
                    deliver: Box::new(move || {
                        let _ = tx.send(result);
                    }),
                }
            }),
        }
    }

    pub(super) fn spawn(conn: Connection) -> mpsc::Sender<Job> {
        let (tx, rx) = mpsc::channel(WRITE_QUEUE);
        std::thread::Builder::new()
            .name("relay-storage-writer".into())
            .spawn(move || run(conn, rx))
            .expect("spawn the storage writer thread");
        tx
    }

    fn run(conn: Connection, mut queue: mpsc::Receiver<Job>) {
        while let Some(first) = queue.blocking_recv() {
            let mut batch = vec![first];
            while batch.len() < WRITE_BATCH {
                match queue.try_recv() {
                    Ok(job) => batch.push(job),
                    Err(_) => break,
                }
            }
            commit_batch(&conn, batch);
        }
    }

    /// Run the jobs in one transaction, each in a savepoint so a failed one is rolled
    /// back alone, and deliver every result after the commit.
    fn commit_batch(conn: &Connection, batch: Vec<Job>) {
        if let Err(e) = conn.execute_batch("BEGIN IMMEDIATE") {
            fail_stop("begin a transaction", &e);
        }
        let mut dones = Vec::with_capacity(batch.len());
        for job in batch {
            let opened = conn.execute_batch("SAVEPOINT job");
            let mut done = (job.run)(conn);
            let kept = if done.ok && opened.is_ok() {
                conn.execute_batch("RELEASE job")
            } else {
                conn.execute_batch("ROLLBACK TO job; RELEASE job")
            };
            if kept.is_err() {
                done.ok = false;
            }
            dones.push(done);
        }
        if let Err(e) = conn.execute_batch("COMMIT") {
            fail_stop("commit", &e);
        }
        for done in dones {
            (done.deliver)();
        }
    }

    fn fail_stop(what: &str, e: &rusqlite::Error) -> ! {
        tracing::error!("the relay store could not {what}: {e}; stopping so no state is served that the disk does not hold");
        std::process::exit(1)
    }
}

/// Every statement the store runs, each over the connection it is given, so the
/// writer-side composites in `state` can run several within one job.
pub(crate) mod sql {
    use ghost_wire::account_key::AccountKeySet;
    use ghost_wire::short_id;
    use ghost_wire::anchor::{validate_anchored_entry, AnchoredEntry};
    use ghost_wire::batch;
    use ghost_wire::idlog;
    use ghost_wire::merkle::Checkpoint;
    use ghost_wire::relay_ref::RelayRef;
    use rusqlite::{params, Connection, OptionalExtension};

    use super::{storage_error, AccountRow, Admission, Appended, IdLogRow, IdlogChange, InviteRow, LogEntry, PairingRow};
    use crate::error::RelayError;
    use crate::util::now_millis;

    /// How every connection to the store runs.
    pub(super) fn configure(conn: &Connection) -> Result<(), RelayError> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA busy_timeout = 5000;
             PRAGMA cache_size = -8000;",
        )
        .map_err(storage_error)
    }

    pub(super) fn init(conn: &Connection) -> Result<(), RelayError> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS log (
                 mailbox_id BLOB NOT NULL,
                 seq INTEGER NOT NULL,
                 received_at INTEGER NOT NULL,
                 envelope_type INTEGER NOT NULL,
                 epoch INTEGER NOT NULL,
                 payload BLOB NOT NULL,
                 PRIMARY KEY (mailbox_id, seq)
             ) WITHOUT ROWID;

             CREATE TABLE IF NOT EXISTS server_info (
                 mailbox_id BLOB PRIMARY KEY,
                 data BLOB NOT NULL,
                 updated_at INTEGER NOT NULL
             );

             CREATE TABLE IF NOT EXISTS avatar (
                 mailbox_id BLOB NOT NULL,
                 fingerprint BLOB NOT NULL,
                 data BLOB NOT NULL,
                 updated_at INTEGER NOT NULL,
                 PRIMARY KEY (mailbox_id, fingerprint)
             ) WITHOUT ROWID;

             CREATE TABLE IF NOT EXISTS mailbox_state (
                 mailbox_id BLOB NOT NULL PRIMARY KEY,
                 current_epoch INTEGER NOT NULL DEFAULT 0,
                 next_seq INTEGER NOT NULL DEFAULT 1
             );

             CREATE TABLE IF NOT EXISTS identity_log (
                 account_fp BLOB NOT NULL,
                 seq INTEGER NOT NULL,
                 prev_hash BLOB NOT NULL,
                 payload BLOB NOT NULL,
                 received_at INTEGER NOT NULL,
                 PRIMARY KEY (account_fp, seq)
             ) WITHOUT ROWID;

             CREATE TABLE IF NOT EXISTS device_keys (
                 account_fp BLOB NOT NULL,
                 device_vk BLOB NOT NULL,
                 active INTEGER NOT NULL DEFAULT 1,
                 added_seq INTEGER NOT NULL,
                 revoked_seq INTEGER,
                 PRIMARY KEY (account_fp, device_vk)
             ) WITHOUT ROWID;

             CREATE TABLE IF NOT EXISTS sync_state (
                 account_fp BLOB NOT NULL PRIMARY KEY,
                 data BLOB NOT NULL,
                 updated_at INTEGER NOT NULL
             );

             CREATE TABLE IF NOT EXISTS mls_public_group (
                 group_id BLOB NOT NULL,
                 component TEXT NOT NULL,
                 data BLOB NOT NULL,
                 PRIMARY KEY (group_id, component)
             ) WITHOUT ROWID;

             CREATE TABLE IF NOT EXISTS mls_proposals (
                 group_id BLOB NOT NULL,
                 proposal_ref BLOB NOT NULL,
                 data BLOB NOT NULL,
                 PRIMARY KEY (group_id, proposal_ref)
             ) WITHOUT ROWID;

             CREATE TABLE IF NOT EXISTS mailbox_members (
                 mailbox_id BLOB NOT NULL,
                 account_fp BLOB NOT NULL,
                 PRIMARY KEY (mailbox_id, account_fp)
             ) WITHOUT ROWID;

             -- Each known account's sync mailbox: its active devices alone use it, and
             -- it carries no MLS messages.
             CREATE TABLE IF NOT EXISTS sync_mailboxes (
                 mailbox_id BLOB PRIMARY KEY,
                 account_fp BLOB NOT NULL
             ) WITHOUT ROWID;

             -- Accounts removed from a mailbox's group, and the sequence of the commit
             -- that removed them: the last entry they may still read.
             CREATE TABLE IF NOT EXISTS mailbox_departures (
                 mailbox_id BLOB NOT NULL,
                 account_fp BLOB NOT NULL,
                 last_seq INTEGER NOT NULL,
                 PRIMARY KEY (mailbox_id, account_fp)
             ) WITHOUT ROWID;

             CREATE TABLE IF NOT EXISTS mailbox_group_map (
                 mailbox_id BLOB PRIMARY KEY,
                 group_id BLOB NOT NULL
             );

             CREATE TABLE IF NOT EXISTS relay_keypair (
                 id INTEGER PRIMARY KEY CHECK (id = 1),
                 signing_key BLOB NOT NULL,
                 verifying_key BLOB NOT NULL
             );

             CREATE TABLE IF NOT EXISTS kt_leaves (
                 leaf_index INTEGER PRIMARY KEY,
                 leaf_hash  BLOB NOT NULL
             );

             CREATE TABLE IF NOT EXISTS kt_frontier (
                 level INTEGER PRIMARY KEY,
                 hash  BLOB NOT NULL
             );

             CREATE TABLE IF NOT EXISTS kt_head (
                 id         INTEGER PRIMARY KEY CHECK (id = 1),
                 tree_size  INTEGER NOT NULL,
                 root_hash  BLOB NOT NULL,
                 checkpoint BLOB NOT NULL
             );

             CREATE TABLE IF NOT EXISTS kt_nodes (
                 start  INTEGER NOT NULL,
                 count  INTEGER NOT NULL,
                 hash   BLOB NOT NULL,
                 PRIMARY KEY (start, count)
             ) WITHOUT ROWID;

             CREATE TABLE IF NOT EXISTS kt_entry_index (
                 account_fp BLOB NOT NULL,
                 seq        INTEGER NOT NULL,
                 leaf_index INTEGER NOT NULL,
                 PRIMARY KEY (account_fp, seq)
             ) WITHOUT ROWID;

             CREATE TABLE IF NOT EXISTS pairing (
                 account_fp BLOB NOT NULL,
                 token      BLOB NOT NULL,
                 offer      BLOB NOT NULL,
                 response   BLOB,
                 provision  BLOB,
                 expires_at INTEGER NOT NULL,
                 PRIMARY KEY (account_fp, token)
             ) WITHOUT ROWID;

             CREATE TABLE IF NOT EXISTS server_locations (
                 account_fp BLOB NOT NULL,
                 server_id  BLOB NOT NULL,
                 generation INTEGER NOT NULL,
                 data       BLOB NOT NULL,
                 updated_at INTEGER NOT NULL,
                 PRIMARY KEY (account_fp, server_id)
             ) WITHOUT ROWID;

             CREATE TABLE IF NOT EXISTS mirror_grants (
                 account_fp BLOB NOT NULL,
                 relay_vk   BLOB NOT NULL,
                 PRIMARY KEY (account_fp, relay_vk)
             ) WITHOUT ROWID;

             CREATE TABLE IF NOT EXISTS accounts (
                 account_fp      BLOB PRIMARY KEY,
                 home_relay_vk   BLOB NOT NULL,
                 home_relay_ref  BLOB NOT NULL,
                 home_set_at_seq INTEGER NOT NULL,
                 is_home         INTEGER NOT NULL,
                 head_seq        INTEGER NOT NULL,
                 guest_until     INTEGER NOT NULL DEFAULT 0,
                 last_refresh    INTEGER NOT NULL
             );

             CREATE TABLE IF NOT EXISTS account_key_sets (
                 account_fp BLOB NOT NULL,
                 entry_hash BLOB NOT NULL,
                 generation INTEGER NOT NULL,
                 data       BLOB NOT NULL,
                 PRIMARY KEY (account_fp, entry_hash)
             ) WITHOUT ROWID;

             -- Open invites: into which server (mailbox) and by whom, the payload joiners
             -- fetch, and how many times it has been replaced, so two refreshes cannot cross.
             CREATE TABLE IF NOT EXISTS invites (
                 token      TEXT PRIMARY KEY,
                 mailbox    BLOB NOT NULL,
                 creator    BLOB NOT NULL,
                 expires_at INTEGER NOT NULL,
                 payload    BLOB
             ) WITHOUT ROWID;",
        )
        .map_err(storage_error)?;

        add_column_if_missing(conn, "identity_log", "inclusion_proof", "BLOB")?;
        add_column_if_missing(conn, "identity_log", "checkpoint", "BLOB")?;
        conn.execute_batch("DROP TABLE IF EXISTS recovery_blob;").map_err(storage_error)?;
        add_column_if_missing(conn, "sync_state", "generation", "INTEGER NOT NULL DEFAULT 0")?;
        // Written with every identity log change; accounts untouched since stay NULL,
        // which only matters for finding a rotated account by its root.
        add_column_if_missing(conn, "accounts", "root_vk", "BLOB")?;
        conn.execute("CREATE INDEX IF NOT EXISTS accounts_by_root ON accounts (root_vk)", []).map_err(storage_error)?;
        add_column_if_missing(conn, "pairing", "draft", "BLOB")?;
        add_column_if_missing(conn, "pairing", "signatures", "BLOB")?;
        // How to reach a granted relay, so the home can push to it; grants from before
        // carry only the key and are pulled from instead.
        add_column_if_missing(conn, "mirror_grants", "relay_ref", "BLOB")?;
        add_column_if_missing(conn, "mirror_grants", "granted_at", "INTEGER NOT NULL DEFAULT 0")?;
        // Pulls the home refused in a row, which back off until the log is pushed here.
        add_column_if_missing(conn, "accounts", "pull_refusals", "INTEGER NOT NULL DEFAULT 0")?;
        Ok(())
    }

    fn add_column_if_missing(conn: &Connection, table: &str, column: &str, decl: &str) -> Result<(), RelayError> {
        let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})")).map_err(storage_error)?;
        let exists = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(storage_error)?
            .filter_map(|r| r.ok())
            .any(|name| name == column);
        if !exists {
            conn.execute(&format!("ALTER TABLE {table} ADD COLUMN {column} {decl}"), []).map_err(storage_error)?;
        }
        Ok(())
    }

    /// Accounts recorded before sync mailboxes were, so their devices are admitted there.
    pub(super) fn backfill_sync_mailboxes(conn: &Connection) -> Result<(), RelayError> {
        let accounts: Vec<Vec<u8>> = conn
            .prepare("SELECT account_fp FROM accounts")
            .map_err(storage_error)?
            .query_map([], |row| row.get(0))
            .map_err(storage_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage_error)?;
        for fp in accounts {
            let Ok(fp) = <[u8; 32]>::try_from(fp.as_slice()) else { continue };
            conn.execute(
                "INSERT OR IGNORE INTO sync_mailboxes (mailbox_id, account_fp) VALUES (?1, ?2)",
                params![ghost_wire::sync_mailbox_id(&fp).as_slice(), fp.as_slice()],
            )
            .map_err(storage_error)?;
        }
        Ok(())
    }

    /// Accounts whose logs predate the accounts table were all created here,
    /// so this relay is their home.
    pub(super) fn backfill_accounts(conn: &Connection, relay_vk: [u8; 32]) -> Result<(), RelayError> {
        let mut stmt = conn
            .prepare(
                "SELECT account_fp, MAX(seq) FROM identity_log
                 WHERE account_fp NOT IN (SELECT account_fp FROM accounts)
                 GROUP BY account_fp",
            )
            .map_err(storage_error)?;
        let rows: Vec<(Vec<u8>, i64)> = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(storage_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage_error)?;
        let home_ref = RelayRef::key_only(relay_vk).to_bytes();
        for (fp, head_seq) in rows {
            conn.execute(
                "INSERT INTO accounts (account_fp, home_relay_vk, home_relay_ref, home_set_at_seq,
                                       is_home, head_seq, guest_until, last_refresh)
                 VALUES (?1, ?2, ?3, 0, 1, ?4, 0, ?5)",
                params![fp, relay_vk.as_slice(), home_ref, head_seq, now_millis() as i64],
            )
            .map_err(storage_error)?;
        }
        Ok(())
    }

    pub(crate) fn raise_mailbox_epoch(conn: &Connection, mailbox_id: &[u8; 32], epoch: u64) -> Result<(), RelayError> {
        conn.execute(
            "INSERT INTO mailbox_state (mailbox_id, current_epoch, next_seq) VALUES (?1, ?2, 1)
             ON CONFLICT (mailbox_id) DO UPDATE SET current_epoch = MAX(current_epoch, ?2)",
            params![mailbox_id.as_slice(), epoch as i64],
        )
        .map_err(storage_error)?;
        Ok(())
    }

    /// Whether a blob naming `epoch` may enter a mailbox whose epoch is `relay_epoch`: a
    /// commit or proposal must name it exactly; a message may be one epoch behind, which
    /// members still open while a commit is landing. Anything older is refused.
    pub(crate) fn epoch_accepted(envelope_type: u8, epoch: u64, relay_epoch: u64) -> bool {
        let exact = envelope_type == ghost_wire::EnvelopeType::Commit as u8 || envelope_type == ghost_wire::EnvelopeType::Proposal as u8;
        epoch == relay_epoch || (!exact && epoch + 1 == relay_epoch)
    }

    pub(crate) fn append(conn: &Connection, mailbox_id: &[u8; 32], envelope_type: u8, epoch: u64, payload: &[u8]) -> Result<Appended, RelayError> {
        let received_at = now_millis();
        let is_commit = envelope_type == ghost_wire::EnvelopeType::Commit as u8;

        conn.execute(
            "INSERT INTO mailbox_state (mailbox_id, current_epoch, next_seq)
             VALUES (?1, 0, 1)
             ON CONFLICT (mailbox_id) DO NOTHING",
            params![mailbox_id.as_slice()],
        )
        .map_err(storage_error)?;

        let relay_epoch: u64 = conn
            .query_row(
                "SELECT current_epoch FROM mailbox_state WHERE mailbox_id = ?1",
                params![mailbox_id.as_slice()],
                |row| row.get::<_, i64>(0).map(|v| v as u64),
            )
            .map_err(storage_error)?;

        if !epoch_accepted(envelope_type, epoch, relay_epoch) {
            tracing::debug!(
                "mailbox {}: envelope type {envelope_type} at epoch {epoch} refused; the mailbox is at epoch {relay_epoch}",
                short_id(mailbox_id)
            );
            return Err(RelayError::Conflict);
        }

        let seq: u64 = conn
            .query_row(
                "UPDATE mailbox_state SET next_seq = next_seq + 1
                 WHERE mailbox_id = ?1
                 RETURNING next_seq - 1",
                params![mailbox_id.as_slice()],
                |row| row.get(0),
            )
            .map_err(storage_error)?;

        conn.execute(
            "INSERT INTO log (mailbox_id, seq, received_at, envelope_type, epoch, payload)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![mailbox_id.as_slice(), seq, received_at as i64, envelope_type as i64, epoch as i64, payload],
        )
        .map_err(storage_error)?;

        if is_commit {
            conn.execute(
                "UPDATE mailbox_state SET current_epoch = MAX(current_epoch, ?2)
                 WHERE mailbox_id = ?1",
                params![mailbox_id.as_slice(), epoch.saturating_add(1) as i64],
            )
            .map_err(storage_error)?;
        }

        Ok(Appended { seq, received_at })
    }

    pub(crate) fn read_from(conn: &Connection, mailbox_id: &[u8; 32], after_seq: u64, limit: u32) -> Result<Vec<LogEntry>, RelayError> {
        let mut stmt = conn
            .prepare_cached(
                "SELECT seq, received_at, envelope_type, epoch, payload
                 FROM log
                 WHERE mailbox_id = ?1 AND seq > ?2
                 ORDER BY seq
                 LIMIT ?3",
            )
            .map_err(storage_error)?;
        let rows = stmt
            .query_map(params![mailbox_id.as_slice(), after_seq, limit], |row| {
                Ok(LogEntry {
                    seq: row.get(0)?,
                    received_at: row.get::<_, i64>(1)? as u64,
                    envelope_type: row.get::<_, i64>(2)? as u8,
                    epoch: row.get::<_, i64>(3)? as u64,
                    payload: row.get(4)?,
                })
            })
            .map_err(storage_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(storage_error)
    }

    pub(crate) fn sweep_log(conn: &Connection, cutoff_ms: u64, min_entries: u64) -> Result<u64, RelayError> {
        let deleted: usize = conn
            .execute(
                "DELETE FROM log WHERE received_at < ?1
                 AND seq <= (
                     SELECT MAX(ms.next_seq - ?2 - 1, 0)
                     FROM mailbox_state ms
                     WHERE ms.mailbox_id = log.mailbox_id
                 )",
                params![cutoff_ms as i64, min_entries as i64],
            )
            .map_err(storage_error)?;
        Ok(deleted as u64)
    }

    /// Delete all persistent state for a mailbox (logs, state, ACL, GroupInfo, proposals, avatars).
    pub(crate) fn delete_mailbox(conn: &Connection, mailbox_id: &[u8; 32]) -> Result<(), RelayError> {
        let mid = mailbox_id.as_slice();
        let group_id: Option<Vec<u8>> = conn
            .query_row("SELECT group_id FROM mailbox_group_map WHERE mailbox_id = ?1", params![mid], |row| row.get(0))
            .optional()
            .map_err(storage_error)?;
        for table in ["log", "mailbox_state", "server_info", "mailbox_members", "mailbox_departures"] {
            conn.execute(&format!("DELETE FROM {table} WHERE mailbox_id = ?1"), params![mid]).map_err(storage_error)?;
        }
        if let Some(gid) = &group_id {
            conn.execute("DELETE FROM mls_public_group WHERE group_id = ?1", params![gid.as_slice()]).map_err(storage_error)?;
            conn.execute("DELETE FROM mls_proposals WHERE group_id = ?1", params![gid.as_slice()]).map_err(storage_error)?;
        }
        conn.execute("DELETE FROM mailbox_group_map WHERE mailbox_id = ?1", params![mid]).map_err(storage_error)?;
        conn.execute("DELETE FROM avatar WHERE mailbox_id = ?1", params![mid]).map_err(storage_error)?;
        Ok(())
    }

    pub(crate) fn get_epoch(conn: &Connection, mailbox_id: &[u8; 32]) -> Result<u64, RelayError> {
        let epoch: Option<i64> = conn
            .query_row("SELECT current_epoch FROM mailbox_state WHERE mailbox_id = ?1", params![mailbox_id.as_slice()], |row| row.get(0))
            .optional()
            .map_err(storage_error)?;
        Ok(epoch.unwrap_or(0) as u64)
    }

    pub(crate) fn log_position(conn: &Connection, mailbox_id: &[u8; 32]) -> Result<super::LogPosition, RelayError> {
        let first: Option<i64> = conn
            .query_row("SELECT MIN(seq) FROM log WHERE mailbox_id = ?1", params![mailbox_id.as_slice()], |row| row.get(0))
            .map_err(storage_error)?;
        let next: Option<i64> = conn
            .query_row("SELECT next_seq FROM mailbox_state WHERE mailbox_id = ?1", params![mailbox_id.as_slice()], |row| row.get(0))
            .optional()
            .map_err(storage_error)?;
        Ok(super::LogPosition { first: first.map(|s| s as u64), head: next.map_or(0, |n| (n as u64).saturating_sub(1)) })
    }

    pub(crate) fn put_server_info(conn: &Connection, mailbox_id: &[u8; 32], data: &[u8]) -> Result<(), RelayError> {
        conn.execute(
            "INSERT INTO server_info (mailbox_id, data, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT (mailbox_id) DO UPDATE SET data = ?2, updated_at = ?3",
            params![mailbox_id.as_slice(), data, now_millis() as i64],
        )
        .map_err(storage_error)?;
        Ok(())
    }

    pub(crate) fn get_server_info(conn: &Connection, mailbox_id: &[u8; 32]) -> Result<Option<Vec<u8>>, RelayError> {
        conn.query_row("SELECT data FROM server_info WHERE mailbox_id = ?1", params![mailbox_id.as_slice()], |row| row.get(0))
            .optional()
            .map_err(storage_error)
    }

    pub(crate) fn put_avatar(conn: &Connection, mailbox_id: &[u8; 32], fingerprint: &[u8; 32], data: &[u8]) -> Result<(), RelayError> {
        conn.execute(
            "INSERT INTO avatar (mailbox_id, fingerprint, data, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (mailbox_id, fingerprint) DO UPDATE SET data = ?3, updated_at = ?4",
            params![mailbox_id.as_slice(), fingerprint.as_slice(), data, now_millis() as i64],
        )
        .map_err(storage_error)?;
        Ok(())
    }

    pub(crate) fn get_avatar(conn: &Connection, mailbox_id: &[u8; 32], fingerprint: &[u8; 32]) -> Result<Option<Vec<u8>>, RelayError> {
        conn.query_row(
            "SELECT data FROM avatar WHERE mailbox_id = ?1 AND fingerprint = ?2",
            params![mailbox_id.as_slice(), fingerprint.as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(storage_error)
    }

    pub(crate) fn delete_avatar(conn: &Connection, mailbox_id: &[u8; 32], fingerprint: &[u8; 32]) -> Result<(), RelayError> {
        conn.execute(
            "DELETE FROM avatar WHERE mailbox_id = ?1 AND fingerprint = ?2",
            params![mailbox_id.as_slice(), fingerprint.as_slice()],
        )
        .map_err(storage_error)?;
        Ok(())
    }

    pub(crate) fn append_batch(
        conn: &Connection,
        relay_vk: [u8; 32],
        account_fp: &[u8; 32],
        entries: &[idlog::LogEntry],
        key_sets: &[AccountKeySet],
    ) -> Result<IdlogChange, RelayError> {
        if entries.is_empty() {
            return Err(RelayError::BadRequest("empty batch".into()));
        }
        if entries.iter().any(|e| e.account_fp != *account_fp) {
            return Err(RelayError::BadRequest("account_fp mismatch with URL".into()));
        }
        if let Some(account) = load_account(conn, account_fp)? {
            if !account.is_home {
                return Err(RelayError::WrongHome(format!(
                    "account is homed at relay {}; this relay only mirrors it",
                    hex::encode(account.home_relay_vk),
                )));
            }
        }
        for entry in entries {
            if let idlog::EntryBody::SetHomeRelay { relay_vk: named, .. } = &entry.body {
                if *named != relay_vk {
                    return Err(RelayError::WrongHome("a move to another relay must be imported at that relay".into()));
                }
            }
        }

        let before = replay(conn, account_fp)?;
        let base = settle_fork(conn, account_fp, &before, entries)?;
        let after = batch::apply_batch(&base, entries, key_sets).map_err(|e| RelayError::BadRequest(format!("validation failed: {e}")))?;
        for entry in entries {
            insert_entry(conn, account_fp, entry, None)?;
        }
        store_key_sets(conn, account_fp, &after, key_sets)?;
        record_state(conn, account_fp, &before, &after, Some(relay_vk), relay_vk)
    }

    /// Attach the home's inclusion proof and checkpoint to an entry this relay
    /// sequenced, once the KT tree has absorbed it.
    pub(crate) fn store_anchor(conn: &Connection, account_fp: &[u8; 32], seq: u64, inclusion_proof: &[u8], checkpoint: &[u8]) -> Result<(), RelayError> {
        conn.execute(
            "UPDATE identity_log SET inclusion_proof = ?3, checkpoint = ?4
             WHERE account_fp = ?1 AND seq = ?2",
            params![account_fp.as_slice(), seq as i64, inclusion_proof, checkpoint],
        )
        .map_err(storage_error)?;
        Ok(())
    }

    pub(crate) fn append_anchored_entries(
        conn: &Connection,
        relay_vk: [u8; 32],
        account_fp: &[u8; 32],
        entries: &[AnchoredEntry],
    ) -> Result<IdlogChange, RelayError> {
        let before = replay(conn, account_fp)?;
        let after = apply_anchored_entries(conn, account_fp, &before, entries)?;
        record_state(conn, account_fp, &before, &after, first_home_relay(conn, account_fp)?, relay_vk)
    }

    pub(crate) fn import_account(
        conn: &Connection,
        relay_vk: [u8; 32],
        account_fp: &[u8; 32],
        prefix: &[AnchoredEntry],
        new_entries: &[idlog::LogEntry],
        key_sets: &[AccountKeySet],
    ) -> Result<IdlogChange, RelayError> {
        match new_entries.first().map(|e| &e.body) {
            Some(idlog::EntryBody::SetHomeRelay { relay_vk: named, .. }) if *named == relay_vk => {}
            _ => return Err(RelayError::BadRequest("the first imported entry must be a SetHomeRelay naming this relay".into())),
        }
        if new_entries.iter().chain(prefix.iter().map(|a| &a.entry)).any(|e| e.account_fp != *account_fp) {
            return Err(RelayError::BadRequest("account_fp mismatch with URL".into()));
        }
        let before = replay(conn, account_fp)?;
        let held = apply_anchored_entries(conn, account_fp, &before, prefix)?;
        let base = settle_fork(conn, account_fp, &held, new_entries)?;
        let after = batch::apply_batch(&base, new_entries, key_sets).map_err(|e| RelayError::BadRequest(format!("validation failed: {e}")))?;
        for entry in new_entries {
            insert_entry(conn, account_fp, entry, None)?;
        }
        store_key_sets(conn, account_fp, &after, key_sets)?;
        record_state(conn, account_fp, &before, &after, Some(relay_vk), relay_vk)
    }

    /// Validate anchored entries against `held` and store them with their anchors,
    /// returning the state after them. Only accounts whose chain names a home are
    /// accepted: a chain without a `SetHomeRelay` gives no relay key to verify its
    /// anchors against.
    fn apply_anchored_entries(
        conn: &Connection,
        account_fp: &[u8; 32],
        held: &idlog::LogState,
        entries: &[AnchoredEntry],
    ) -> Result<idlog::LogState, RelayError> {
        let mut state = held.clone();
        if entries.is_empty() {
            return Ok(state);
        }
        if entries.iter().any(|a| a.entry.account_fp != *account_fp) {
            return Err(RelayError::BadRequest("account_fp mismatch with URL".into()));
        }
        // Entries before the chain's first SetHomeRelay were anchored by the
        // relay that entry names, which is where the account was created.
        let implied_home = |conn: &Connection| -> Result<[u8; 32], RelayError> {
            let first_home = first_home_relay(conn, account_fp)?.or_else(|| {
                entries.iter().find_map(|a| match &a.entry.body {
                    idlog::EntryBody::SetHomeRelay { relay_vk, .. } => Some(*relay_vk),
                    _ => None,
                })
            });
            first_home.ok_or_else(|| {
                RelayError::Unprocessable("account names no home relay; it must append SetHomeRelay at its home first".into())
            })
        };
        let mut implied = implied_home(conn)?;

        for (index, anchored) in entries.iter().enumerate() {
            let entry = &anchored.entry;
            if entry.seq <= state.head_seq {
                if stored_entry_hash(conn, account_fp, entry.seq)? == Some(idlog::entry_hash(entry)) {
                    continue;
                }
                let incoming: Vec<idlog::LogEntry> = entries[index..].iter().map(|a| a.entry.clone()).collect();
                state = settle_fork(conn, account_fp, &state, &incoming)?;
                // The replaced entries may have named the first home.
                implied = implied_home(conn)?;
            }
            let prior_for_home = |home: &[u8; 32]| last_checkpoint_from(conn, account_fp, home);
            validate_anchored_entry(&mut state, anchored, Some(&implied), prior_for_home)
                .map_err(|e| RelayError::Unprocessable(format!("anchored entry {}: {e}", entry.seq)))?;
            insert_entry(conn, account_fp, entry, Some(anchored))?;
        }
        Ok(state)
    }

    /// When `incoming` starts at or below the head of `held`, decide the fork with
    /// the shared rule. Keeping the held chain refuses the incoming branch;
    /// replacing it deletes the held suffix (its rows and this relay's KT index of
    /// them) so the branch can be stored. Returns the state the branch extends.
    fn settle_fork(
        conn: &Connection,
        account_fp: &[u8; 32],
        held: &idlog::LogState,
        incoming: &[idlog::LogEntry],
    ) -> Result<idlog::LogState, RelayError> {
        let Some(first) = incoming.first() else { return Ok(held.clone()) };
        if first.seq > held.head_seq {
            return Ok(held.clone());
        }
        if first.seq <= 1 {
            return Err(RelayError::Conflict);
        }
        let chain = load_chain(conn, account_fp)?;
        let fork_at = first.seq as usize - 1;
        let (prefix_entries, held_suffix) = chain.split_at(fork_at.min(chain.len()));
        let prefix = idlog::validate_chain(prefix_entries)
            .map_err(|e| RelayError::Storage(format!("stored identity log no longer validates: {e}")))?;
        match idlog::choose_branch(&prefix, held_suffix, incoming) {
            Ok(idlog::BranchChoice::Replace) => {
                for (table, column) in [("identity_log", "seq"), ("kt_entry_index", "seq")] {
                    conn.execute(
                        &format!("DELETE FROM {table} WHERE account_fp = ?1 AND {column} >= ?2"),
                        params![account_fp.as_slice(), first.seq as i64],
                    )
                    .map_err(storage_error)?;
                }
                tracing::warn!(
                    account = %short_id(account_fp),
                    from_seq = first.seq,
                    "identity log fork: a root-signed branch replaced device-signed entries",
                );
                Ok(prefix)
            }
            Ok(idlog::BranchChoice::Keep) => {
                tracing::warn!(
                    account = %short_id(account_fp),
                    from_seq = first.seq,
                    "identity log equivocation: kept the held chain over a valid conflicting branch",
                );
                Err(RelayError::Conflict)
            }
            Err(e) => Err(RelayError::Unprocessable(format!("conflicting branch is invalid: {e}"))),
        }
    }

    fn insert_entry(conn: &Connection, account_fp: &[u8; 32], entry: &idlog::LogEntry, anchor: Option<&AnchoredEntry>) -> Result<(), RelayError> {
        conn.execute(
            "INSERT INTO identity_log (account_fp, seq, prev_hash, payload, received_at,
                                       inclusion_proof, checkpoint)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                account_fp.as_slice(),
                entry.seq as i64,
                entry.prev_hash.as_slice(),
                entry.to_bytes(),
                now_millis() as i64,
                anchor.map(|a| a.inclusion_proof.to_bytes()),
                anchor.map(|a| a.checkpoint.to_bytes().to_vec()),
            ],
        )
        .map_err(storage_error)?;
        Ok(())
    }

    pub(crate) fn stored_entry_hash(conn: &Connection, account_fp: &[u8; 32], seq: u64) -> Result<Option<[u8; 32]>, RelayError> {
        let payload: Option<Vec<u8>> = conn
            .query_row(
                "SELECT payload FROM identity_log WHERE account_fp = ?1 AND seq = ?2",
                params![account_fp.as_slice(), seq as i64],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage_error)?;
        Ok(payload.map(|p| blake3::hash(&p).into()))
    }

    /// Store each set beside the `AccountKey` entry of `state` it matches.
    fn store_key_sets(conn: &Connection, account_fp: &[u8; 32], state: &idlog::LogState, key_sets: &[AccountKeySet]) -> Result<(), RelayError> {
        for set in key_sets {
            let key = state
                .account_key_by_digest(&set.digest())
                .filter(|key| set.matches(account_fp, key))
                .ok_or_else(|| RelayError::Unprocessable("key set matches no account key entry".into()))?;
            conn.execute(
                "INSERT OR IGNORE INTO account_key_sets (account_fp, entry_hash, generation, data)
                 VALUES (?1, ?2, ?3, ?4)",
                params![account_fp.as_slice(), key.entry_hash.as_slice(), key.generation as i64, set.to_bytes()],
            )
            .map_err(storage_error)?;
        }
        Ok(())
    }

    /// Bring everything derived from the chain in line with `after`, in the
    /// transaction that changed it: the device index, the account row and the key sets
    /// of generations no longer in the chain. Returns the devices `after` no longer lists
    /// as active.
    fn record_state(
        conn: &Connection,
        account_fp: &[u8; 32],
        before: &idlog::LogState,
        after: &idlog::LogState,
        implied_home: Option<[u8; 32]>,
        own_vk: [u8; 32],
    ) -> Result<IdlogChange, RelayError> {
        conn.execute(
            "INSERT OR IGNORE INTO sync_mailboxes (mailbox_id, account_fp) VALUES (?1, ?2)",
            params![ghost_wire::sync_mailbox_id(account_fp).as_slice(), account_fp.as_slice()],
        )
        .map_err(storage_error)?;
        conn.execute("DELETE FROM device_keys WHERE account_fp = ?1", params![account_fp.as_slice()]).map_err(storage_error)?;
        for device in after.devices.values() {
            conn.execute(
                "INSERT INTO device_keys (account_fp, device_vk, active, added_seq, revoked_seq)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    account_fp.as_slice(),
                    device.verifying_key.as_slice(),
                    device.is_active() as i64,
                    device.added_at_seq as i64,
                    device.revoked_at_seq.map(|s| s as i64),
                ],
            )
            .map_err(storage_error)?;
        }

        let kept: Vec<&[u8]> = after.account_keys.iter().map(|k| k.entry_hash.as_slice()).collect();
        let stored: Vec<Vec<u8>> = conn
            .prepare_cached("SELECT entry_hash FROM account_key_sets WHERE account_fp = ?1")
            .map_err(storage_error)?
            .query_map(params![account_fp.as_slice()], |row| row.get(0))
            .map_err(storage_error)?
            .collect::<Result<_, _>>()
            .map_err(storage_error)?;
        for hash in stored.iter().filter(|h| !kept.contains(&h.as_slice())) {
            conn.execute(
                "DELETE FROM account_key_sets WHERE account_fp = ?1 AND entry_hash = ?2",
                params![account_fp.as_slice(), hash],
            )
            .map_err(storage_error)?;
        }

        let was_home = load_account(conn, account_fp)?.is_some_and(|account| account.is_home);
        let (home_relay_vk, is_home) = upsert_account(conn, account_fp, after, implied_home, own_vk)?;
        let revoked = before
            .active_devices()
            .filter(|d| !after.is_active_device(&d.verifying_key))
            .map(|d| d.verifying_key)
            .collect();
        Ok(IdlogChange { revoked, home_relay_vk, is_home, left_home: was_home && !is_home })
    }

    /// Relay named by the account's earliest stored `SetHomeRelay`, if any.
    fn first_home_relay(conn: &Connection, account_fp: &[u8; 32]) -> Result<Option<[u8; 32]>, RelayError> {
        Ok(load_chain(conn, account_fp)?.into_iter().find_map(|entry| match entry.body {
            idlog::EntryBody::SetHomeRelay { relay_vk, .. } => Some(relay_vk),
            _ => None,
        }))
    }

    /// Newest stored checkpoint for the account that was signed by `home`.
    fn last_checkpoint_from(conn: &Connection, account_fp: &[u8; 32], home: &[u8; 32]) -> Option<Checkpoint> {
        let vk = ed25519_dalek::VerifyingKey::from_bytes(home).ok()?;
        let mut stmt = conn
            .prepare_cached(
                "SELECT checkpoint FROM identity_log
                 WHERE account_fp = ?1 AND checkpoint IS NOT NULL
                 ORDER BY seq DESC",
            )
            .ok()?;
        let stored: Vec<Vec<u8>> = stmt.query_map(params![account_fp.as_slice()], |row| row.get(0)).ok()?.filter_map(|r| r.ok()).collect();
        stored.iter().filter_map(|bytes| Checkpoint::from_bytes(bytes).ok()).find(|cp| cp.verify(&vk).is_ok())
    }

    /// Record the chain's current home, head and root. A chain that names no home
    /// is homed at `implied_home`, falling back to this relay. Returns
    /// (home_relay_vk, is_home).
    fn upsert_account(
        conn: &Connection,
        account_fp: &[u8; 32],
        state: &idlog::LogState,
        implied_home: Option<[u8; 32]>,
        own_vk: [u8; 32],
    ) -> Result<([u8; 32], bool), RelayError> {
        let home_relay_vk = state.home_relay_vk.or(implied_home).unwrap_or(own_vk);
        let home_relay_ref = state.home_relay_ref.clone().unwrap_or_else(|| RelayRef::key_only(home_relay_vk)).to_bytes();
        let is_home = home_relay_vk == own_vk;
        conn.execute(
            "INSERT INTO accounts (account_fp, home_relay_vk, home_relay_ref, home_set_at_seq,
                                   is_home, head_seq, guest_until, last_refresh, root_vk)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7, ?8)
             ON CONFLICT (account_fp) DO UPDATE SET
                 home_relay_vk = ?2, home_relay_ref = ?3, home_set_at_seq = ?4,
                 is_home = ?5, head_seq = ?6, last_refresh = ?7, root_vk = ?8",
            params![
                account_fp.as_slice(),
                home_relay_vk.as_slice(),
                home_relay_ref,
                state.home_set_at_seq as i64,
                is_home as i64,
                state.head_seq as i64,
                now_millis() as i64,
                state.root_verifying_key.map(|k| k.to_vec()),
            ],
        )
        .map_err(storage_error)?;
        Ok((home_relay_vk, is_home))
    }

    pub(crate) fn load_account(conn: &Connection, account_fp: &[u8; 32]) -> Result<Option<AccountRow>, RelayError> {
        conn.query_row(
            "SELECT home_relay_vk, home_relay_ref, home_set_at_seq, is_home, head_seq, guest_until, last_refresh, pull_refusals
             FROM accounts WHERE account_fp = ?1",
            params![account_fp.as_slice()],
            |row| {
                let vk: Vec<u8> = row.get(0)?;
                Ok(AccountRow {
                    account_fp: *account_fp,
                    home_relay_vk: vk.try_into().map_err(|_| {
                        rusqlite::Error::InvalidColumnType(0, "home_relay_vk".into(), rusqlite::types::Type::Blob)
                    })?,
                    home_relay_ref: row.get(1)?,
                    home_set_at_seq: row.get::<_, i64>(2)? as u64,
                    is_home: row.get::<_, i64>(3)? == 1,
                    head_seq: row.get::<_, i64>(4)? as u64,
                    guest_until: row.get::<_, i64>(5)? as u64,
                    last_refresh: row.get::<_, i64>(6)? as u64,
                    pull_refusals: row.get::<_, i64>(7)? as u32,
                })
            },
        )
        .optional()
        .map_err(storage_error)
    }

    pub(crate) fn record_pull_refusal(conn: &Connection, account_fp: &[u8; 32]) -> Result<(), RelayError> {
        conn.execute(
            "UPDATE accounts SET pull_refusals = pull_refusals + 1, last_refresh = ?2 WHERE account_fp = ?1",
            params![account_fp.as_slice(), now_millis() as i64],
        )
        .map_err(storage_error)?;
        Ok(())
    }

    pub(crate) fn clear_pull_refusals(conn: &Connection, account_fp: &[u8; 32]) -> Result<(), RelayError> {
        conn.execute("UPDATE accounts SET pull_refusals = 0 WHERE account_fp = ?1", params![account_fp.as_slice()])
            .map_err(storage_error)?;
        Ok(())
    }

    pub(crate) fn mirrored_accounts(conn: &Connection) -> Result<Vec<AccountRow>, RelayError> {
        let mut stmt = conn.prepare_cached("SELECT account_fp FROM accounts WHERE is_home = 0").map_err(storage_error)?;
        let fps: Vec<Vec<u8>> = stmt
            .query_map([], |row| row.get(0))
            .map_err(storage_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage_error)?;
        let mut rows = Vec::with_capacity(fps.len());
        for fp in fps {
            let fp: [u8; 32] = fp.try_into().map_err(|_| RelayError::Storage("corrupt account_fp in accounts".into()))?;
            if let Some(row) = load_account(conn, &fp)? {
                rows.push(row);
            }
        }
        Ok(rows)
    }

    pub(crate) fn set_account_guest_until(conn: &Connection, account_fp: &[u8; 32], until: u64) -> Result<(), RelayError> {
        let updated = conn
            .execute(
                "UPDATE accounts SET guest_until = MAX(guest_until, ?2) WHERE account_fp = ?1",
                params![account_fp.as_slice(), until as i64],
            )
            .map_err(storage_error)?;
        if updated == 0 {
            return Err(RelayError::NotFound);
        }
        Ok(())
    }

    pub(crate) fn sync_mailbox_owner(conn: &Connection, mailbox_id: &[u8; 32]) -> Result<Option<[u8; 32]>, RelayError> {
        let owner: Option<Vec<u8>> = conn
            .query_row("SELECT account_fp FROM sync_mailboxes WHERE mailbox_id = ?1", [mailbox_id.as_slice()], |row| row.get(0))
            .optional()
            .map_err(storage_error)?;
        owner.map(|fp| fp.try_into().map_err(|_| RelayError::Storage("sync mailbox owner is not 32 bytes".into()))).transpose()
    }

    /// The `active` column of the device's row: 1 while it is active, 0 once revoked,
    /// `None` when the held log never listed it.
    fn device_active(conn: &Connection, account_fp: &[u8; 32], device_vk: &[u8; 32]) -> Result<Option<i64>, RelayError> {
        conn.query_row(
            "SELECT active FROM device_keys WHERE account_fp = ?1 AND device_vk = ?2",
            params![account_fp.as_slice(), device_vk.as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(storage_error)
    }

    pub(crate) fn is_revoked_device(conn: &Connection, account_fp: &[u8; 32], device_vk: &[u8; 32]) -> Result<bool, RelayError> {
        Ok(device_active(conn, account_fp, device_vk)? == Some(0))
    }

    /// The entry that revoked the device, read as its cause.
    pub(crate) fn revocation_cause(conn: &Connection, account_fp: &[u8; 32], device_vk: &[u8; 32]) -> Result<Option<ghost_wire::RevocationCause>, RelayError> {
        use ghost_wire::RevocationCause;
        let chain = load_chain(conn, account_fp)?;
        if chain.is_empty() {
            return Ok(None);
        }
        let state = idlog::validate_chain(&chain).map_err(|e| RelayError::Storage(format!("stored identity log no longer validates: {e}")))?;
        let Some(seq) = state.devices.get(device_vk).and_then(|d| d.revoked_at_seq) else { return Ok(None) };
        Ok(chain.iter().find(|entry| entry.seq == seq).and_then(|entry| match &entry.body {
            idlog::EntryBody::Recovery { .. } => Some(RevocationCause::Recovery),
            idlog::EntryBody::RevokeDevice { revoker_key, .. } => Some(match state.devices.get(revoker_key) {
                Some(revoker) => RevocationCause::Device(revoker.label.clone()),
                None => RevocationCause::RecoveryKey,
            }),
            _ => None,
        }))
    }

    pub(crate) fn is_active_device(conn: &Connection, account_fp: &[u8; 32], device_vk: &[u8; 32]) -> Result<bool, RelayError> {
        Ok(device_active(conn, account_fp, device_vk)? == Some(1))
    }

    pub(crate) fn may_authenticate(conn: &Connection, account_fp: &[u8; 32], device_vk: &[u8; 32], now: u64) -> Result<Option<Admission>, RelayError> {
        if device_active(conn, account_fp, device_vk)? != Some(1) {
            return Ok(None);
        }
        let Some(account) = load_account(conn, account_fp)? else {
            return Ok(None);
        };
        if account.is_home {
            return Ok(Some(Admission::Home));
        }
        if is_listed_member(conn, account_fp)? {
            return Ok(Some(Admission::Member));
        }
        Ok((account.guest_until > now).then_some(Admission::Guest))
    }

    /// Every stored entry of the account, in chain order.
    fn load_chain(conn: &Connection, account_fp: &[u8; 32]) -> Result<Vec<idlog::LogEntry>, RelayError> {
        let rows: Vec<(i64, Vec<u8>)> = conn
            .prepare_cached("SELECT seq, payload FROM identity_log WHERE account_fp = ?1 ORDER BY seq")
            .map_err(storage_error)?
            .query_map(params![account_fp.as_slice()], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(storage_error)?
            .collect::<Result<_, _>>()
            .map_err(storage_error)?;
        rows.into_iter()
            .map(|(seq, payload)| idlog::LogEntry::from_bytes(&payload).map_err(|e| RelayError::Storage(format!("corrupt idlog entry {seq}: {e}"))))
            .collect()
    }

    /// The account's state, replayed from its stored chain through the shared
    /// validator, so the relay keeps no second copy of the rules.
    pub(crate) fn replay(conn: &Connection, account_fp: &[u8; 32]) -> Result<idlog::LogState, RelayError> {
        let chain = load_chain(conn, account_fp)?;
        if chain.is_empty() {
            return Ok(idlog::LogState::empty(*account_fp));
        }
        idlog::validate_chain(&chain).map_err(|e| RelayError::Storage(format!("stored identity log no longer validates: {e}")))
    }

    pub(crate) fn get_idlog(conn: &Connection, account_fp: &[u8; 32], after_seq: u64) -> Result<Vec<IdLogRow>, RelayError> {
        let mut stmt = conn
            .prepare_cached(
                "SELECT seq, payload, inclusion_proof, checkpoint FROM identity_log
                 WHERE account_fp = ?1 AND seq > ?2
                 ORDER BY seq",
            )
            .map_err(storage_error)?;
        let rows = stmt
            .query_map(params![account_fp.as_slice(), after_seq as i64], |row| {
                Ok(IdLogRow {
                    seq: row.get::<_, i64>(0)? as u64,
                    payload: row.get(1)?,
                    inclusion_proof: row.get(2)?,
                    checkpoint: row.get(3)?,
                })
            })
            .map_err(storage_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(storage_error)
    }

    pub(crate) fn put_server_location(conn: &Connection, account_fp: &[u8; 32], server_id: &[u8; 32], generation: u64, data: &[u8]) -> Result<(), RelayError> {
        let stored: Option<i64> = conn
            .query_row(
                "SELECT generation FROM server_locations WHERE account_fp = ?1 AND server_id = ?2",
                params![account_fp.as_slice(), server_id.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage_error)?;
        if stored.is_some_and(|g| generation <= g as u64) {
            return Err(RelayError::Conflict);
        }
        conn.execute(
            "INSERT INTO server_locations (account_fp, server_id, generation, data, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (account_fp, server_id) DO UPDATE SET generation = ?3, data = ?4, updated_at = ?5",
            params![account_fp.as_slice(), server_id.as_slice(), generation as i64, data, now_millis() as i64],
        )
        .map_err(storage_error)?;
        Ok(())
    }

    pub(crate) fn get_server_location(conn: &Connection, account_fp: &[u8; 32], server_id: &[u8; 32]) -> Result<Option<Vec<u8>>, RelayError> {
        conn.query_row(
            "SELECT data FROM server_locations WHERE account_fp = ?1 AND server_id = ?2",
            params![account_fp.as_slice(), server_id.as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(storage_error)
    }

    pub(crate) fn is_listed_member(conn: &Connection, account_fp: &[u8; 32]) -> Result<bool, RelayError> {
        conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM mailbox_members WHERE account_fp = ?1)",
            params![account_fp.as_slice()],
            |row| row.get(0),
        )
        .map_err(storage_error)
    }

    pub(crate) fn grant_mirrors(conn: &Connection, account_fp: &[u8; 32], relays: &[RelayRef], now: u64) -> Result<(), RelayError> {
        for relay in relays {
            conn.execute(
                "INSERT INTO mirror_grants (account_fp, relay_vk, relay_ref, granted_at) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (account_fp, relay_vk) DO UPDATE SET relay_ref = ?3, granted_at = ?4",
                params![account_fp.as_slice(), relay.relay_vk.as_slice(), relay.to_bytes(), now as i64],
            )
            .map_err(storage_error)?;
        }
        Ok(())
    }

    /// The relays the account granted since `since`; one recorded by key alone is
    /// returned key-only.
    pub(crate) fn mirror_grants(conn: &Connection, account_fp: &[u8; 32], since: u64) -> Result<Vec<RelayRef>, RelayError> {
        let rows: Vec<(Vec<u8>, Option<Vec<u8>>)> = conn
            .prepare_cached("SELECT relay_vk, relay_ref FROM mirror_grants WHERE account_fp = ?1 AND granted_at >= ?2")
            .map_err(storage_error)?
            .query_map(params![account_fp.as_slice(), since as i64], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(storage_error)?
            .collect::<Result<_, _>>()
            .map_err(storage_error)?;
        rows.into_iter()
            .map(|(vk, relay_ref)| {
                let relay_vk: [u8; 32] = vk.try_into().map_err(|_| RelayError::Storage("corrupt relay_vk in mirror_grants".into()))?;
                match relay_ref {
                    Some(bytes) => RelayRef::from_bytes(&bytes).map_err(|e| RelayError::Storage(format!("stored mirror ref: {e}"))),
                    None => Ok(RelayRef::key_only(relay_vk)),
                }
            })
            .collect()
    }

    pub(crate) fn is_mirror_granted(conn: &Connection, account_fp: &[u8; 32], relay_vk: &[u8; 32], since: u64) -> Result<bool, RelayError> {
        conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM mirror_grants WHERE account_fp = ?1 AND relay_vk = ?2 AND granted_at >= ?3)",
            params![account_fp.as_slice(), relay_vk.as_slice(), since as i64],
            |row| row.get(0),
        )
        .map_err(storage_error)
    }

    pub(crate) fn sweep_mirror_grants(conn: &Connection, since: u64) -> Result<usize, RelayError> {
        conn.execute("DELETE FROM mirror_grants WHERE granted_at < ?1", params![since as i64]).map_err(storage_error)
    }

    pub(crate) fn account_by_root(conn: &Connection, root_vk: &[u8; 32]) -> Result<Option<AccountRow>, RelayError> {
        let account_fp: Option<Vec<u8>> = conn
            .query_row("SELECT account_fp FROM accounts WHERE root_vk = ?1 LIMIT 1", params![root_vk.as_slice()], |row| row.get(0))
            .optional()
            .map_err(storage_error)?;
        let Some(account_fp) = account_fp else { return Ok(None) };
        let account_fp: [u8; 32] = account_fp.try_into().map_err(|_| RelayError::Storage("corrupt account_fp in accounts".into()))?;
        load_account(conn, &account_fp)
    }

    pub(crate) fn get_key_sets(conn: &Connection, account_fp: &[u8; 32], from_generation: u32) -> Result<Vec<AccountKeySet>, RelayError> {
        let rows: Vec<Vec<u8>> = conn
            .prepare_cached("SELECT data FROM account_key_sets WHERE account_fp = ?1 AND generation >= ?2 ORDER BY generation")
            .map_err(storage_error)?
            .query_map(params![account_fp.as_slice(), from_generation as i64], |row| row.get(0))
            .map_err(storage_error)?
            .collect::<Result<_, _>>()
            .map_err(storage_error)?;
        rows.iter()
            .map(|data| AccountKeySet::from_bytes(data).map_err(|e| RelayError::Storage(format!("stored key set: {e}"))))
            .collect()
    }

    pub(crate) fn first_missing_key_set(conn: &Connection, account_fp: &[u8; 32]) -> Result<Option<u32>, RelayError> {
        let state = replay(conn, account_fp)?;
        for key in &state.account_keys {
            let held: bool = conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM account_key_sets WHERE account_fp = ?1 AND entry_hash = ?2)",
                    params![account_fp.as_slice(), key.entry_hash.as_slice()],
                    |row| row.get(0),
                )
                .map_err(storage_error)?;
            if !held {
                return Ok(Some(key.generation));
            }
        }
        Ok(None)
    }

    pub(crate) fn put_key_sets(conn: &Connection, account_fp: &[u8; 32], key_sets: &[AccountKeySet]) -> Result<(), RelayError> {
        let state = replay(conn, account_fp)?;
        store_key_sets(conn, account_fp, &state, key_sets)
    }

    pub(crate) fn pairing_open(conn: &Connection, account_fp: &[u8; 32], token: &[u8], offer: &[u8], expires_at: u64) -> Result<(), RelayError> {
        conn.execute("DELETE FROM pairing WHERE account_fp = ?1", params![account_fp.as_slice()]).map_err(storage_error)?;
        conn.execute(
            "INSERT INTO pairing (account_fp, token, offer, expires_at) VALUES (?1, ?2, ?3, ?4)",
            params![account_fp.as_slice(), token, offer, expires_at as i64],
        )
        .map_err(storage_error)?;
        Ok(())
    }

    pub(crate) fn pairing_get(conn: &Connection, account_fp: &[u8; 32], token: &[u8], now: u64) -> Result<Option<PairingRow>, RelayError> {
        conn.query_row(
            "SELECT offer, response, draft, signatures, provision FROM pairing
             WHERE account_fp = ?1 AND token = ?2 AND expires_at > ?3",
            params![account_fp.as_slice(), token, now as i64],
            |row| {
                Ok(PairingRow {
                    offer: row.get(0)?,
                    response: row.get(1)?,
                    draft: row.get(2)?,
                    signatures: row.get(3)?,
                    provision: row.get(4)?,
                })
            },
        )
        .optional()
        .map_err(storage_error)
    }

    pub(crate) fn pairing_set_draft(conn: &Connection, account_fp: &[u8; 32], token: &[u8], draft: &[u8], now: u64) -> Result<(), RelayError> {
        let updated = conn
            .execute(
                "UPDATE pairing SET draft = ?4, signatures = NULL
                 WHERE account_fp = ?1 AND token = ?2 AND expires_at > ?3",
                params![account_fp.as_slice(), token, now as i64, draft],
            )
            .map_err(storage_error)?;
        if updated == 0 {
            return Err(RelayError::NotFound);
        }
        Ok(())
    }

    pub(crate) fn pairing_set_provision(conn: &Connection, account_fp: &[u8; 32], token: &[u8], provision: &[u8], now: u64) -> Result<(), RelayError> {
        let updated = conn
            .execute(
                "UPDATE pairing SET provision = ?4 WHERE account_fp = ?1 AND token = ?2 AND expires_at > ?3",
                params![account_fp.as_slice(), token, now as i64, provision],
            )
            .map_err(storage_error)?;
        if updated == 0 {
            return Err(RelayError::NotFound);
        }
        Ok(())
    }

    pub(crate) fn pairing_close(conn: &Connection, account_fp: &[u8; 32], token: &[u8]) -> Result<(), RelayError> {
        conn.execute("DELETE FROM pairing WHERE account_fp = ?1 AND token = ?2", params![account_fp.as_slice(), token])
            .map_err(storage_error)?;
        Ok(())
    }

    /// Set a column of a live session once: 404 for no live session, 409 if already set.
    pub(crate) fn pairing_fill(conn: &Connection, account_fp: &[u8; 32], token: &[u8], column: &str, data: &[u8], now: u64) -> Result<(), RelayError> {
        let updated = conn
            .execute(
                &format!(
                    "UPDATE pairing SET {column} = ?4
                     WHERE account_fp = ?1 AND token = ?2 AND expires_at > ?3 AND {column} IS NULL"
                ),
                params![account_fp.as_slice(), token, now as i64, data],
            )
            .map_err(storage_error)?;
        if updated == 1 {
            return Ok(());
        }
        let live: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pairing WHERE account_fp = ?1 AND token = ?2 AND expires_at > ?3)",
                params![account_fp.as_slice(), token, now as i64],
                |row| row.get(0),
            )
            .map_err(storage_error)?;
        Err(if live { RelayError::Conflict } else { RelayError::NotFound })
    }

    pub(crate) fn pairing_sweep(conn: &Connection, now: u64) -> Result<usize, RelayError> {
        conn.execute("DELETE FROM pairing WHERE expires_at <= ?1", params![now as i64]).map_err(storage_error)
    }

    /// Last-writer-wins upsert for per-account replicated objects. Devices write
    /// these to every relay they use, so a stale copy must never replace a newer one.
    pub(crate) fn put_generational(conn: &Connection, table: &str, account_fp: &[u8; 32], generation: u64, data: &[u8]) -> Result<(), RelayError> {
        let stored: Option<i64> = conn
            .query_row(&format!("SELECT generation FROM {table} WHERE account_fp = ?1"), params![account_fp.as_slice()], |row| row.get(0))
            .optional()
            .map_err(storage_error)?;
        if let Some(stored) = stored {
            if generation <= stored as u64 {
                return Err(RelayError::Conflict);
            }
        }
        conn.execute(
            &format!(
                "INSERT INTO {table} (account_fp, data, updated_at, generation) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (account_fp) DO UPDATE SET data = ?2, updated_at = ?3, generation = ?4"
            ),
            params![account_fp.as_slice(), data, now_millis() as i64, generation as i64],
        )
        .map_err(storage_error)?;
        Ok(())
    }

    pub(crate) fn get_generational(conn: &Connection, table: &str, account_fp: &[u8; 32]) -> Result<Option<(u64, Vec<u8>)>, RelayError> {
        conn.query_row(
            &format!("SELECT generation, data FROM {table} WHERE account_fp = ?1"),
            params![account_fp.as_slice()],
            |row| Ok((row.get::<_, i64>(0)? as u64, row.get(1)?)),
        )
        .optional()
        .map_err(storage_error)
    }

    /// Distinct serialized group ids of the public groups held.
    pub(crate) fn stored_mls_group_ids(conn: &Connection) -> Result<Vec<Vec<u8>>, RelayError> {
        let mut stmt = conn.prepare_cached("SELECT DISTINCT group_id FROM mls_public_group").map_err(storage_error)?;
        let rows = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0)).map_err(storage_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(storage_error)
    }

    /// Replace the member set for a mailbox with the given account fingerprints.
    pub(crate) fn update_mailbox_members(conn: &Connection, mailbox_id: &[u8; 32], members: &[[u8; 32]]) -> Result<(), RelayError> {
        conn.execute("DELETE FROM mailbox_members WHERE mailbox_id = ?1", params![mailbox_id.as_slice()]).map_err(storage_error)?;
        for fp in members {
            conn.execute(
                "INSERT OR IGNORE INTO mailbox_members (mailbox_id, account_fp) VALUES (?1, ?2)",
                params![mailbox_id.as_slice(), fp.as_slice()],
            )
            .map_err(storage_error)?;
        }
        Ok(())
    }

    /// Store the mapping from mailbox_id to MLS group_id for cleanup.
    pub(crate) fn set_mailbox_group_id(conn: &Connection, mailbox_id: &[u8; 32], group_id: &[u8]) -> Result<(), RelayError> {
        conn.execute(
            "INSERT OR REPLACE INTO mailbox_group_map (mailbox_id, group_id) VALUES (?1, ?2)",
            params![mailbox_id.as_slice(), group_id],
        )
        .map_err(storage_error)?;
        Ok(())
    }

    pub(crate) fn is_mailbox_member(conn: &Connection, mailbox_id: &[u8; 32], account_fp: &[u8; 32]) -> Result<bool, RelayError> {
        conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM mailbox_members WHERE mailbox_id = ?1 AND account_fp = ?2)",
            params![mailbox_id.as_slice(), account_fp.as_slice()],
            |row| row.get(0),
        )
        .map_err(storage_error)
    }

    pub(crate) fn has_mailbox_members(conn: &Connection, mailbox_id: &[u8; 32]) -> Result<bool, RelayError> {
        conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM mailbox_members WHERE mailbox_id = ?1)",
            params![mailbox_id.as_slice()],
            |row| row.get(0),
        )
        .map_err(storage_error)
    }

    /// Record that accounts left a mailbox's group with the commit at `seq`. They may
    /// still read up to that commit, which is how their devices learn of the removal.
    pub(crate) fn record_departures(conn: &Connection, mailbox_id: &[u8; 32], accounts: &[[u8; 32]], seq: u64) -> Result<(), RelayError> {
        for account in accounts {
            conn.execute(
                "INSERT OR REPLACE INTO mailbox_departures (mailbox_id, account_fp, last_seq) VALUES (?1, ?2, ?3)",
                params![mailbox_id.as_slice(), account.as_slice(), seq as i64],
            )
            .map_err(storage_error)?;
        }
        Ok(())
    }

    pub(crate) fn departure_seq(conn: &Connection, mailbox_id: &[u8; 32], account_fp: &[u8; 32]) -> Result<Option<u64>, RelayError> {
        conn.query_row(
            "SELECT last_seq FROM mailbox_departures WHERE mailbox_id = ?1 AND account_fp = ?2",
            params![mailbox_id.as_slice(), account_fp.as_slice()],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map(|seq| seq.map(|s| s as u64))
        .map_err(storage_error)
    }

    /// Load or generate the relay Ed25519 keypair.
    pub(crate) fn get_or_create_relay_keypair(conn: &Connection) -> Result<([u8; 32], [u8; 64]), RelayError> {
        let existing: Option<(Vec<u8>, Vec<u8>)> = conn
            .query_row("SELECT signing_key, verifying_key FROM relay_keypair WHERE id = 1", [], |row| Ok((row.get(0)?, row.get(1)?)))
            .optional()
            .map_err(storage_error)?;
        if let Some((sk, vk)) = existing {
            let vk: [u8; 32] = vk.try_into().map_err(|_| RelayError::Storage("corrupt relay vk".into()))?;
            let sk: [u8; 64] = sk.try_into().map_err(|_| RelayError::Storage("corrupt relay sk".into()))?;
            return Ok((vk, sk));
        }
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;
        let sk = SigningKey::generate(&mut OsRng);
        let sk_bytes = sk.to_keypair_bytes();
        let vk_bytes = sk.verifying_key().to_bytes();
        conn.execute(
            "INSERT INTO relay_keypair (id, signing_key, verifying_key) VALUES (1, ?1, ?2)",
            params![sk_bytes.as_slice(), vk_bytes.as_slice()],
        )
        .map_err(storage_error)?;
        Ok((vk_bytes, sk_bytes))
    }

    pub(crate) fn mailboxes_for_account(conn: &Connection, account_fp: &[u8; 32]) -> Result<Vec<[u8; 32]>, RelayError> {
        let mut stmt = conn.prepare_cached("SELECT mailbox_id FROM mailbox_members WHERE account_fp = ?1").map_err(storage_error)?;
        let rows: Vec<Vec<u8>> = stmt
            .query_map(params![account_fp.as_slice()], |row| row.get(0))
            .map_err(storage_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage_error)?;
        rows.into_iter()
            .map(|r| r.try_into().map_err(|_| RelayError::Storage("corrupt mailbox_id".into())))
            .collect()
    }

    /// Open an invite under a token nobody has used.
    pub(crate) fn invite_register(conn: &Connection, token: &str, mailbox: &[u8; 32], creator: &[u8; 32], expires_at: u64) -> Result<(), RelayError> {
        let inserted = conn
            .execute(
                "INSERT OR IGNORE INTO invites (token, mailbox, creator, expires_at) VALUES (?1, ?2, ?3, ?4)",
                params![token, mailbox.as_slice(), creator.as_slice(), expires_at as i64],
            )
            .map_err(storage_error)?;
        if inserted == 0 {
            return Err(RelayError::BadRequest("token already registered".into()));
        }
        Ok(())
    }

    /// Set the invite's payload, once. 404 for an unknown token, 410 once it expired, 409
    /// when it is already set, 403 unless `by` is the inviter or a member of the server
    /// the invite is into: others holding the link cannot poison it.
    pub(crate) fn invite_set_payload(conn: &Connection, token: &str, payload: &[u8], now: u64, by: &[u8; 32]) -> Result<(), RelayError> {
        let Some(invite) = invite_get(conn, token)? else {
            return Err(RelayError::NotFound);
        };
        if invite.expires_at <= now {
            return Err(RelayError::Gone("invite expired".into()));
        }
        if invite.payload.is_some() {
            return Err(RelayError::Conflict);
        }
        let (mailbox, creator): (Vec<u8>, Vec<u8>) = conn
            .query_row("SELECT mailbox, creator FROM invites WHERE token = ?1", params![token], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(storage_error)?;
        let mailbox: [u8; 32] = mailbox.try_into().map_err(|_| RelayError::Storage("corrupt invite mailbox".into()))?;
        if creator != by.as_slice() && !is_mailbox_member(conn, &mailbox, by)? {
            return Err(RelayError::Forbidden("only the inviter or a member of the server may set the payload".into()));
        }
        conn.execute("UPDATE invites SET payload = ?2 WHERE token = ?1", params![token, payload])
        .map_err(storage_error)?;
        Ok(())
    }

    pub(crate) fn invite_get(conn: &Connection, token: &str) -> Result<Option<InviteRow>, RelayError> {
        conn.query_row(
            "SELECT mailbox, expires_at, payload FROM invites WHERE token = ?1",
            params![token],
            |row| {
                let mailbox: Vec<u8> = row.get(0)?;
                Ok(InviteRow {
                    mailbox: mailbox.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?,
                    expires_at: row.get::<_, i64>(1)? as u64,
                    payload: row.get(2)?,
                })
            },
        )
        .optional()
        .map_err(storage_error)
    }

    /// Delete expired invites, returning the tokens that went.
    pub(crate) fn invite_sweep(conn: &Connection, now: u64) -> Result<Vec<String>, RelayError> {
        let mut stmt = conn
            .prepare_cached("DELETE FROM invites WHERE expires_at <= ?1 RETURNING token")
            .map_err(storage_error)?;
        let rows = stmt.query_map(params![now as i64], |row| row.get(0)).map_err(storage_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(storage_error)
    }

    // ── Key transparency ────────────────────────────────────────────────

    /// Append a leaf hash to the KT tree and record the (account_fp, seq) mapping.
    /// Returns the assigned leaf index.
    pub(crate) fn kt_append_leaf(conn: &Connection, leaf_hash: &[u8; 32], account_fp: &[u8; 32], seq: u64) -> Result<u64, RelayError> {
        let leaf_index: i64 = conn
            .query_row("SELECT COALESCE(MAX(leaf_index), -1) + 1 FROM kt_leaves", [], |row| row.get(0))
            .map_err(storage_error)?;
        conn.execute("INSERT INTO kt_leaves (leaf_index, leaf_hash) VALUES (?1, ?2)", params![leaf_index, leaf_hash.as_slice()])
            .map_err(storage_error)?;
        conn.execute(
            "INSERT INTO kt_entry_index (account_fp, seq, leaf_index) VALUES (?1, ?2, ?3)",
            params![account_fp.as_slice(), seq as i64, leaf_index],
        )
        .map_err(storage_error)?;
        Ok(leaf_index as u64)
    }

    /// The Merkle tree's right edge, one hash per level, as `MerkleTree` keeps it.
    pub(crate) type Frontier = Vec<Option<[u8; 32]>>;

    /// The persisted tree frontier and the tree size it describes.
    pub(crate) fn kt_load_frontier(conn: &Connection) -> Result<(Frontier, u64), RelayError> {
        let tree_size: i64 = conn
            .query_row("SELECT COALESCE(tree_size, 0) FROM kt_head WHERE id = 1", [], |row| row.get(0))
            .optional()
            .map_err(storage_error)?
            .unwrap_or(0);
        if tree_size == 0 {
            return Ok((Vec::new(), 0));
        }
        let mut stmt = conn.prepare_cached("SELECT level, hash FROM kt_frontier ORDER BY level").map_err(storage_error)?;
        let rows: Vec<(i64, Vec<u8>)> = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(storage_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage_error)?;
        let max_level = rows.iter().map(|(l, _)| *l).max().unwrap_or(0) as usize;
        let mut frontier = vec![None; max_level + 1];
        for (level, hash_bytes) in rows {
            let mut h = [0u8; 32];
            h.copy_from_slice(&hash_bytes);
            frontier[level as usize] = Some(h);
        }
        Ok((frontier, tree_size as u64))
    }

    /// Persist the frontier and checkpoint together.
    pub(crate) fn kt_persist_state(conn: &Connection, frontier: &[Option<[u8; 32]>], tree_size: u64, root_hash: &[u8; 32], checkpoint_bytes: &[u8]) -> Result<(), RelayError> {
        conn.execute("DELETE FROM kt_frontier", []).map_err(storage_error)?;
        for (level, slot) in frontier.iter().enumerate() {
            if let Some(h) = slot {
                conn.execute("INSERT INTO kt_frontier (level, hash) VALUES (?1, ?2)", params![level as i64, h.as_slice()])
                    .map_err(storage_error)?;
            }
        }
        conn.execute(
            "INSERT INTO kt_head (id, tree_size, root_hash, checkpoint)
             VALUES (1, ?1, ?2, ?3)
             ON CONFLICT (id) DO UPDATE SET tree_size = ?1, root_hash = ?2, checkpoint = ?3",
            params![tree_size as i64, root_hash.as_slice(), checkpoint_bytes],
        )
        .map_err(storage_error)?;
        Ok(())
    }

    pub(crate) fn kt_load_checkpoint(conn: &Connection) -> Result<Option<Vec<u8>>, RelayError> {
        conn.query_row("SELECT checkpoint FROM kt_head WHERE id = 1", [], |row| row.get(0))
            .optional()
            .map_err(storage_error)
    }

    /// The checkpoint and the tree size it describes, in one read.
    pub(crate) fn kt_load_checkpoint_with_size(conn: &Connection) -> Result<(Vec<u8>, u64), RelayError> {
        let result: Option<(Vec<u8>, i64)> = conn
            .query_row("SELECT checkpoint, tree_size FROM kt_head WHERE id = 1", [], |row| Ok((row.get(0)?, row.get(1)?)))
            .optional()
            .map_err(storage_error)?;
        Ok(match result {
            Some((cp, size)) => (cp, size as u64),
            None => (Vec::new(), 0),
        })
    }

    pub(crate) fn kt_get_leaf_index(conn: &Connection, account_fp: &[u8; 32], seq: u64) -> Result<Option<u64>, RelayError> {
        conn.query_row(
            "SELECT leaf_index FROM kt_entry_index WHERE account_fp = ?1 AND seq = ?2",
            params![account_fp.as_slice(), seq as i64],
            |row| Ok(row.get::<_, i64>(0)? as u64),
        )
        .optional()
        .map_err(storage_error)
    }

    fn hash32(bytes: Vec<u8>, what: &str) -> Result<[u8; 32], RelayError> {
        bytes.try_into().map_err(|_| RelayError::Storage(format!("corrupt {what}")))
    }

    /// The hash for a subtree range: the leaf hash for `count` 1, else the stored node.
    pub(crate) fn kt_load_hash(conn: &Connection, start: u64, count: u64) -> Result<Option<[u8; 32]>, RelayError> {
        let stored: Option<Vec<u8>> = if count == 1 {
            conn.query_row("SELECT leaf_hash FROM kt_leaves WHERE leaf_index = ?1", params![start as i64], |row| row.get(0))
        } else {
            conn.query_row("SELECT hash FROM kt_nodes WHERE start = ?1 AND count = ?2", params![start as i64, count as i64], |row| row.get(0))
        }
        .optional()
        .map_err(storage_error)?;
        stored.map(|h| hash32(h, "tree hash")).transpose()
    }

    /// Store Merkle tree nodes, each as (start, count, hash).
    pub(crate) fn kt_store_nodes(conn: &Connection, nodes: &[(u64, u64, [u8; 32])]) -> Result<(), RelayError> {
        let mut stmt = conn
            .prepare_cached(
                "INSERT INTO kt_nodes (start, count, hash) VALUES (?1, ?2, ?3)
                 ON CONFLICT (start, count) DO UPDATE SET hash = ?3",
            )
            .map_err(storage_error)?;
        for &(start, count, ref hash) in nodes {
            stmt.execute(params![start as i64, count as i64, hash.as_slice()]).map_err(storage_error)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_wire::account_key::SealedCopy;
    use ghost_wire::log_entries::{
        create_account_key, create_add_device, create_device_key, create_genesis, create_recovery, create_revoke_device,
        create_rotate_root, create_set_home_relay,
    };
    use ghost_wire::merkle::Checkpoint;
    use ghost_wire::relay_ref::RelayRef;
    use ghost_wire::EnvelopeType;

    const APP: u8 = EnvelopeType::Application as u8;
    const COMMIT: u8 = EnvelopeType::Commit as u8;

    fn test_mailbox() -> [u8; 32] {
        [0xAA; 32]
    }

    async fn append_blob(store: &Storage, mailbox: [u8; 32], kind: u8, epoch: u64, payload: &[u8]) -> Result<Appended, RelayError> {
        store.append(mailbox, kind, epoch, payload.to_vec()).await
    }

    #[tokio::test]
    async fn appends_number_each_mailbox_on_its_own() {
        let store = Storage::open_ephemeral().unwrap();
        let (mb_a, mb_b) = ([0xAA; 32], [0xBB; 32]);
        assert_eq!(append_blob(&store, mb_a, APP, 0, b"a1").await.unwrap().seq, 1);
        assert_eq!(append_blob(&store, mb_b, APP, 0, b"b1").await.unwrap().seq, 1);
        assert_eq!(append_blob(&store, mb_a, APP, 0, b"a2").await.unwrap().seq, 2);
        assert_eq!(append_blob(&store, mb_a, COMMIT, 0, b"commit").await.unwrap().seq, 3);
    }

    #[tokio::test]
    async fn read_from_pages_the_entries_after_a_sequence() {
        let store = Storage::open_ephemeral().unwrap();
        let mb = test_mailbox();
        for i in 0..10 {
            append_blob(&store, mb, APP, 0, format!("msg{i}").as_bytes()).await.unwrap();
        }
        let entries = store.read_from(mb, 1, 100).await.unwrap();
        assert_eq!(entries.len(), 9);
        assert_eq!(entries[0].seq, 2);
        assert_eq!(entries[0].payload, b"msg1");
        let page = store.read_from(mb, 0, 3).await.unwrap();
        assert_eq!(page.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![1, 2, 3]);
        assert_eq!(store.log_position(mb).await.unwrap(), LogPosition { first: Some(1), head: 10 });
        assert_eq!(store.log_position([0xCC; 32]).await.unwrap(), LogPosition { first: None, head: 0 });
        // The sweep empties the log; the head stays where it was.
        store.sweep_log(crate::util::now_millis() + 3_600_000, 0).await.unwrap();
        assert_eq!(store.log_position(mb).await.unwrap(), LogPosition { first: None, head: 10 });
    }

    #[tokio::test]
    async fn commits_advance_the_epoch_and_a_stale_one_is_refused() {
        let store = Storage::open_ephemeral().unwrap();
        let mb = test_mailbox();
        assert_eq!(store.get_epoch(mb).await.unwrap(), 0);
        append_blob(&store, mb, COMMIT, 0, b"commit-a").await.unwrap();
        assert_eq!(store.get_epoch(mb).await.unwrap(), 1);

        let err = append_blob(&store, mb, COMMIT, 0, b"commit-b").await.unwrap_err();
        assert!(matches!(err, RelayError::Conflict));

        // A message one epoch behind is still taken: members still open it.
        assert_eq!(append_blob(&store, mb, APP, 0, b"app-msg").await.unwrap().seq, 2);

        assert_eq!(append_blob(&store, mb, COMMIT, 1, b"commit-c").await.unwrap().seq, 3);
        assert_eq!(store.get_epoch(mb).await.unwrap(), 2);
        // Two epochs behind, nobody could open it: refused, so the sender seals it again.
        assert!(matches!(append_blob(&store, mb, APP, 0, b"too old").await.unwrap_err(), RelayError::Conflict));
        assert_eq!(append_blob(&store, mb, APP, 1, b"still open").await.unwrap().seq, 4);

        // The epoch set from a GroupInfo never goes backwards.
        store.raise_mailbox_epoch(mb, 1).await.unwrap();
        assert_eq!(store.get_epoch(mb).await.unwrap(), 2);
        store.raise_mailbox_epoch(mb, 5).await.unwrap();
        assert_eq!(store.get_epoch(mb).await.unwrap(), 5);
    }

    #[tokio::test]
    async fn a_failed_write_in_a_batch_leaves_the_others_standing() {
        let store = Storage::open_ephemeral().unwrap();
        let mb = test_mailbox();
        append_blob(&store, mb, COMMIT, 0, b"commit").await.unwrap();
        // Queued together: a stale commit fails on its own; the messages around it land.
        let (first, stale, last) = tokio::join!(
            append_blob(&store, mb, APP, 1, b"before"),
            append_blob(&store, mb, COMMIT, 0, b"stale"),
            append_blob(&store, mb, APP, 1, b"after"),
        );
        assert!(matches!(stale.unwrap_err(), RelayError::Conflict));
        let mut seqs = vec![first.unwrap().seq, last.unwrap().seq];
        seqs.sort();
        assert_eq!(seqs, vec![2, 3]);
        assert_eq!(store.read_from(mb, 0, 10).await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn avatars_are_kept_per_member_and_replaced() {
        let store = Storage::open_ephemeral().unwrap();
        let mb = test_mailbox();
        let (fp_a, fp_b) = ([0xAA; 32], [0xBB; 32]);
        assert!(store.get_avatar(mb, fp_a).await.unwrap().is_none());
        store.put_avatar(mb, fp_a, b"alice".to_vec()).await.unwrap();
        store.put_avatar(mb, fp_b, b"bob".to_vec()).await.unwrap();
        store.put_avatar(mb, fp_a, b"updated".to_vec()).await.unwrap();
        assert_eq!(store.get_avatar(mb, fp_a).await.unwrap().unwrap(), b"updated");
        store.delete_avatar(mb, fp_a).await.unwrap();
        assert!(store.get_avatar(mb, fp_a).await.unwrap().is_none());
        assert_eq!(store.get_avatar(mb, fp_b).await.unwrap().unwrap(), b"bob");
    }

    fn random_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng)
    }

    fn test_account() -> ([u8; 32], ed25519_dalek::SigningKey, ed25519_dalek::SigningKey) {
        let mk = random_key();
        let dk = random_key();
        let fp: [u8; 32] = blake3::hash(mk.verifying_key().as_bytes()).into();
        (fp, mk, dk)
    }

    fn make_genesis(mk: &ed25519_dalek::SigningKey, dk: &ed25519_dalek::SigningKey) -> idlog::LogEntry {
        create_genesis(mk, dk, "test")
    }

    /// Append one entry on the home path, as a batch of one.
    async fn append(store: &Storage, fp: &[u8; 32], entry: &idlog::LogEntry) -> Result<IdlogChange, RelayError> {
        store.append_batch(*fp, vec![entry.clone()], Vec::new()).await
    }

    fn chain_state(entries: &[idlog::LogEntry]) -> idlog::LogState {
        idlog::validate_chain(entries).unwrap()
    }

    /// A set for the generation after `state`'s, with a stand-in copy for everyone
    /// `state` must cover; the relay never opens copies.
    fn stand_in_key_set(state: &idlog::LogState) -> AccountKeySet {
        AccountKeySet {
            account_fp: state.account_fp,
            generation: state.account_key().map_or(1, |k| k.generation + 1),
            copies: state
                .coverage()
                .into_iter()
                .map(|recipient| SealedCopy { recipient, encapsulated_key: [0x5A; 32], ciphertext: vec![0xA5; 48] })
                .collect(),
            back_link: None,
        }
    }

    /// The account key entry covering `state` and the set it commits to.
    fn rekey(state: &idlog::LogState, authorizer: &ed25519_dalek::SigningKey) -> (idlog::LogEntry, AccountKeySet) {
        let set = stand_in_key_set(state);
        (create_account_key(state, authorizer, &random_key(), [0x77; 32], &set), set)
    }

    /// An account homed at `store` whose root has rotated: genesis, the device's
    /// encryption key, the rotation and the first account key, appended as one batch.
    async fn rotated_account(store: &Storage) -> ([u8; 32], ed25519_dalek::SigningKey, ed25519_dalek::SigningKey, Vec<idlog::LogEntry>) {
        let (fp, mk, dk) = test_account();
        let root = random_key();
        let mut entries = vec![make_genesis(&mk, &dk)];
        entries.push(create_device_key(&chain_state(&entries), &dk, &dk, [0x01; 32]));
        entries.push(create_rotate_root(&chain_state(&entries), &mk, &root, [0x02; 32], &dk));
        let (key, set) = rekey(&chain_state(&entries), &dk);
        entries.push(key);
        store.append_batch(fp, entries.clone(), vec![set]).await.unwrap();
        (fp, root, dk, entries)
    }

    #[tokio::test]
    async fn idlog_append_and_fetch() {
        let store = Storage::open_ephemeral().unwrap();
        let (fp, mk, dk) = test_account();
        let genesis = make_genesis(&mk, &dk);
        append(&store, &fp, &genesis).await.unwrap();
        let add = create_add_device(&chain_state(std::slice::from_ref(&genesis)), &dk, &random_key(), "device-2");
        append(&store, &fp, &add).await.unwrap();

        let all = store.get_idlog(fp, 0).await.unwrap();
        assert_eq!(all.iter().map(|r| r.seq).collect::<Vec<_>>(), vec![1, 2]);
        let after1 = store.get_idlog(fp, 1).await.unwrap();
        assert_eq!(after1.len(), 1);
        assert_eq!(after1[0].seq, 2);
        assert!(store.get_idlog([0xCC; 32], 0).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn idlog_refuses_a_second_genesis() {
        let store = Storage::open_ephemeral().unwrap();
        let (fp, mk, dk) = test_account();
        let genesis = make_genesis(&mk, &dk);
        append(&store, &fp, &genesis).await.unwrap();
        let err = append(&store, &fp, &genesis).await.unwrap_err();
        assert!(matches!(err, RelayError::Conflict), "{err}");
    }

    #[tokio::test]
    async fn idlog_device_keys_tracked() {
        let store = Storage::open_ephemeral().unwrap();
        let (fp, mk, dk) = test_account();
        let dk_vk = dk.verifying_key().to_bytes();
        assert!(!store.is_active_device(fp, dk_vk).await.unwrap());

        let mut chain = vec![make_genesis(&mk, &dk)];
        append(&store, &fp, &chain[0]).await.unwrap();
        assert!(store.is_active_device(fp, dk_vk).await.unwrap());

        let dk2 = random_key();
        let dk2_vk = dk2.verifying_key().to_bytes();
        chain.push(create_add_device(&chain_state(&chain), &dk, &dk2, "device-2"));
        append(&store, &fp, chain.last().unwrap()).await.unwrap();
        assert!(store.is_active_device(fp, dk2_vk).await.unwrap());

        let revoke = create_revoke_device(&chain_state(&chain), &dk, &dk2_vk);
        let change = append(&store, &fp, &revoke).await.unwrap();
        assert_eq!(change.revoked, vec![dk2_vk]);
        assert!(!store.is_active_device(fp, dk2_vk).await.unwrap());
        assert!(store.is_revoked_device(fp, dk2_vk).await.unwrap());
        assert!(store.is_active_device(fp, dk_vk).await.unwrap());
    }

    // ── Account keys ────────────────────────────────────────────────────

    #[tokio::test]
    async fn an_account_key_needs_its_set_and_the_set_is_kept() {
        let store = Storage::open_ephemeral().unwrap();
        let (fp, _root, dk, entries) = rotated_account(&store).await;
        let sets = store.get_key_sets(fp, 1).await.unwrap();
        assert_eq!(sets.len(), 1);
        assert_eq!(sets[0].generation, 1);

        let state = chain_state(&entries);
        let (key, set) = rekey(&state, &dk);
        let err = append(&store, &fp, &key).await.unwrap_err();
        assert!(matches!(err, RelayError::BadRequest(_)), "missing set: {err}");
        let mut swapped = set.clone();
        swapped.copies[0].ciphertext[0] ^= 1;
        let err = store.append_batch(fp, vec![key.clone()], vec![swapped]).await.unwrap_err();
        assert!(matches!(err, RelayError::BadRequest(_)), "swapped copy: {err}");
        store.append_batch(fp, vec![key], vec![set]).await.unwrap();
        assert_eq!(store.get_key_sets(fp, 2).await.unwrap().len(), 1);
        assert_eq!(store.first_missing_key_set(fp).await.unwrap(), None);
    }

    #[tokio::test]
    async fn a_pushed_set_must_match_a_held_account_key() {
        let store = Storage::open_ephemeral().unwrap();
        let (fp, _root, _dk, entries) = rotated_account(&store).await;
        let stranger = stand_in_key_set(&chain_state(&entries));
        let err = store.put_key_sets(fp, vec![stranger]).await.unwrap_err();
        assert!(matches!(err, RelayError::Unprocessable(_)), "{err}");
    }

    #[tokio::test]
    async fn a_rotated_root_finds_the_account_and_the_genesis_key_no_longer_does() {
        let store = Storage::open_ephemeral().unwrap();
        let (fp, mk, dk) = test_account();
        let mut entries = vec![make_genesis(&mk, &dk)];
        append(&store, &fp, &entries[0]).await.unwrap();

        let root = random_key();
        entries.push(create_device_key(&chain_state(&entries), &dk, &dk, [0x01; 32]));
        entries.push(create_rotate_root(&chain_state(&entries), &mk, &root, [0x02; 32], &dk));
        let (key, set) = rekey(&chain_state(&entries), &dk);
        entries.push(key);
        store.append_batch(fp, entries[1..].to_vec(), vec![set]).await.unwrap();
        assert_eq!(store.account_by_root(root.verifying_key().to_bytes()).await.unwrap().unwrap().account_fp, fp);
        assert!(store.account_by_root(mk.verifying_key().to_bytes()).await.unwrap().is_none(), "the genesis key is no root");
    }

    #[tokio::test]
    async fn the_home_settles_a_recovery_built_on_an_older_head() {
        let store = Storage::open_ephemeral().unwrap();
        let (fp, root, dk, entries) = rotated_account(&store).await;
        let owner_view = chain_state(&entries);

        // A thief's device adds a device the owner never sees.
        let thief = random_key();
        let add = create_add_device(&owner_view, &dk, &thief, "thief");
        append(&store, &fp, &add).await.unwrap();

        // The owner recovers from the head they knew; the root-signed branch wins.
        let device = random_key();
        let recovery = create_recovery(&owner_view, &root, &device, "owner");
        let change = append(&store, &fp, &recovery).await.unwrap();
        assert!(change.revoked.contains(&thief.verifying_key().to_bytes()));
        assert!(change.revoked.contains(&dk.verifying_key().to_bytes()));
        assert!(store.is_active_device(fp, device.verifying_key().to_bytes()).await.unwrap());
        assert!(!store.is_active_device(fp, thief.verifying_key().to_bytes()).await.unwrap());
        let held = store.get_idlog(fp, 0).await.unwrap();
        assert_eq!(held.len(), entries.len() + 1);
        assert_eq!(held.last().unwrap().payload, recovery.to_bytes());

        // Device history never displaces root history.
        let late = create_add_device(&owner_view, &dk, &random_key(), "late");
        assert!(matches!(append(&store, &fp, &late).await.unwrap_err(), RelayError::Conflict));
    }

    // -- Mailbox members --

    #[tokio::test]
    async fn mailbox_members_set_check_replace() {
        let store = Storage::open_ephemeral().unwrap();
        let mb = [0xAA; 32];
        let (fp_a, fp_b, fp_c) = ([0x01; 32], [0x02; 32], [0x03; 32]);
        assert!(!store.has_mailbox_members(mb).await.unwrap());
        assert!(!store.is_mailbox_member(mb, fp_a).await.unwrap());

        store.write(move |conn| sql::update_mailbox_members(conn, &mb, &[fp_a, fp_b])).await.unwrap();
        assert!(store.has_mailbox_members(mb).await.unwrap());
        assert!(store.is_mailbox_member(mb, fp_a).await.unwrap());
        assert!(store.is_mailbox_member(mb, fp_b).await.unwrap());
        assert!(!store.is_mailbox_member(mb, fp_c).await.unwrap());

        store.write(move |conn| sql::update_mailbox_members(conn, &mb, &[fp_b, fp_c])).await.unwrap();
        assert!(!store.is_mailbox_member(mb, fp_a).await.unwrap());
        assert!(store.is_mailbox_member(mb, fp_b).await.unwrap());
        assert!(store.is_mailbox_member(mb, fp_c).await.unwrap());

        let mb2 = [0xBB; 32];
        store.write(move |conn| sql::update_mailbox_members(conn, &mb2, &[fp_b])).await.unwrap();
        let mailboxes = store.mailboxes_for_account(fp_b).await.unwrap();
        assert_eq!(mailboxes.len(), 2);
        assert!(mailboxes.contains(&mb) && mailboxes.contains(&mb2));
    }

    #[tokio::test]
    async fn the_relay_keypair_is_made_once_and_signs() {
        let store = Storage::open_ephemeral().unwrap();
        let (vk1, sk1) = store.relay_keypair().await.unwrap();
        let (vk2, sk2) = store.relay_keypair().await.unwrap();
        assert_eq!((vk1, sk1), (vk2, sk2));
        assert_eq!(vk1, store.relay_vk());
        let sk = ed25519_dalek::SigningKey::from_keypair_bytes(&sk1).unwrap();
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&vk1).unwrap();
        use ed25519_dalek::Signer;
        vk.verify_strict(b"test", &sk.sign(b"test")).unwrap();
    }

    // ── Anchored (mirror) path ──────────────────────────────────────────

    /// Stand-in for another relay's KT tree: anchors entries under its own key.
    struct FakeHome {
        sk: ed25519_dalek::SigningKey,
        leaves: Vec<[u8; 32]>,
    }

    impl FakeHome {
        fn new() -> Self {
            Self { sk: random_key(), leaves: Vec::new() }
        }

        fn vk(&self) -> [u8; 32] {
            self.sk.verifying_key().to_bytes()
        }

        fn anchor(&mut self, entry: &idlog::LogEntry) -> AnchoredEntry {
            use ghost_wire::merkle::{leaf_hash, InclusionProof, MerkleTree};
            self.leaves.push(leaf_hash(&entry.to_bytes()));
            let mut tree = MerkleTree::new();
            for l in &self.leaves {
                tree.append(*l);
            }
            let index = self.leaves.len() as u64 - 1;
            AnchoredEntry {
                entry: entry.clone(),
                inclusion_proof: InclusionProof::generate(index, &self.leaves),
                checkpoint: Checkpoint::sign(tree.size(), tree.root(), 1000, &self.sk),
            }
        }
    }

    fn make_set_home_relay(state: &idlog::LogState, auth: &ed25519_dalek::SigningKey, relay_vk: [u8; 32]) -> idlog::LogEntry {
        create_set_home_relay(state, auth, RelayRef::key_only(relay_vk))
    }

    /// A v2 account created at `home`: genesis + SetHomeRelay, both anchored.
    struct ForeignAccount {
        fp: [u8; 32],
        genesis_key: ed25519_dalek::SigningKey,
        device: ed25519_dalek::SigningKey,
        anchored: Vec<AnchoredEntry>,
        raw: Vec<idlog::LogEntry>,
    }

    fn foreign_account(home: &mut FakeHome) -> ForeignAccount {
        let (fp, mk, dk) = test_account();
        let genesis = make_genesis(&mk, &dk);
        let set_home = make_set_home_relay(&chain_state(std::slice::from_ref(&genesis)), &dk, home.vk());
        let anchored = vec![home.anchor(&genesis), home.anchor(&set_home)];
        ForeignAccount { fp, genesis_key: mk, device: dk, anchored, raw: vec![genesis, set_home] }
    }

    #[tokio::test]
    async fn home_append_records_account_as_homed_here() {
        let store = Storage::open_ephemeral().unwrap();
        let (fp, mk, dk) = test_account();
        let change = append(&store, &fp, &make_genesis(&mk, &dk)).await.unwrap();
        assert!(change.is_home);
        assert_eq!(change.home_relay_vk, store.relay_vk());
        let account = store.get_account(fp).await.unwrap().unwrap();
        assert!(account.is_home);
        assert_eq!(account.head_seq, 1);
        assert_eq!(account.home_set_at_seq, 0, "v1 chain names no home");
    }

    #[tokio::test]
    async fn home_accepts_set_home_relay_naming_itself_and_rejects_others() {
        let store = Storage::open_ephemeral().unwrap();
        let (fp, mk, dk) = test_account();
        let genesis = make_genesis(&mk, &dk);
        append(&store, &fp, &genesis).await.unwrap();
        let state = chain_state(std::slice::from_ref(&genesis));

        let elsewhere = make_set_home_relay(&state, &dk, [0x99; 32]);
        let err = append(&store, &fp, &elsewhere).await.unwrap_err();
        assert!(matches!(err, RelayError::WrongHome(_)), "{err}");

        let here = make_set_home_relay(&state, &dk, store.relay_vk());
        let change = append(&store, &fp, &here).await.unwrap();
        assert!(change.is_home);
        let account = store.get_account(fp).await.unwrap().unwrap();
        assert_eq!(account.home_set_at_seq, 2);
        // The replayed state carries the home for later validation.
        let replayed = store.account_state(fp).await.unwrap().unwrap();
        assert_eq!(replayed.home_relay_vk, Some(store.relay_vk()));
        assert_eq!(replayed.home_set_at_seq, 2);
    }

    #[tokio::test]
    async fn anchored_chain_registers_mirrored_account() {
        let store = Storage::open_ephemeral().unwrap();
        let mut home = FakeHome::new();
        let account = foreign_account(&mut home);

        let change = store.append_anchored_entries(account.fp, account.anchored.clone()).await.unwrap();
        assert!(!change.is_home);
        assert_eq!(change.home_relay_vk, home.vk());

        let row = store.get_account(account.fp).await.unwrap().unwrap();
        assert!(!row.is_home);
        assert_eq!(row.head_seq, 2);
        assert!(store.is_active_device(account.fp, account.device.verifying_key().to_bytes()).await.unwrap());

        let rows = store.get_idlog(account.fp, 0).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.inclusion_proof.is_some() && r.checkpoint.is_some()));
    }

    #[tokio::test]
    async fn anchored_chain_rejected_when_checkpoint_not_from_home() {
        let store = Storage::open_ephemeral().unwrap();
        let mut home = FakeHome::new();
        let mut impostor = FakeHome::new();
        let account = foreign_account(&mut home);
        // Same chain, but anchored by a relay the chain does not name.
        let forged = vec![impostor.anchor(&account.raw[0]), impostor.anchor(&account.raw[1])];
        let err = store.append_anchored_entries(account.fp, forged).await.unwrap_err();
        assert!(matches!(err, RelayError::Unprocessable(_)), "{err}");
        assert!(store.get_account(account.fp).await.unwrap().is_none(), "nothing persisted");
        assert!(store.get_idlog(account.fp, 0).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn anchored_chain_without_home_is_rejected() {
        let store = Storage::open_ephemeral().unwrap();
        let mut home = FakeHome::new();
        let (fp, mk, dk) = test_account();
        let anchored = vec![home.anchor(&make_genesis(&mk, &dk))];
        let err = store.append_anchored_entries(fp, anchored).await.unwrap_err();
        assert!(matches!(err, RelayError::Unprocessable(_)), "{err}");
        assert!(store.get_account(fp).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn mirror_rejects_raw_entries_and_replays_are_idempotent() {
        let store = Storage::open_ephemeral().unwrap();
        let mut home = FakeHome::new();
        let account = foreign_account(&mut home);
        store.append_anchored_entries(account.fp, account.anchored.clone()).await.unwrap();

        // A device must append at the home, not here.
        let add = create_add_device(&chain_state(&account.raw), &account.device, &random_key(), "phone");
        let err = append(&store, &account.fp, &add).await.unwrap_err();
        assert!(matches!(err, RelayError::WrongHome(_)), "{err}");

        // Pushing the same anchored chain again is a no-op.
        let again = store.append_anchored_entries(account.fp, account.anchored.clone()).await.unwrap();
        assert!(again.revoked.is_empty());
        assert_eq!(store.get_idlog(account.fp, 0).await.unwrap().len(), 2);

        // A tampered entry at a held seq is refused as invalid.
        let mut tampered = account.anchored[1].clone();
        tampered.entry.timestamp += 1;
        let err = store.append_anchored_entries(account.fp, vec![tampered]).await.unwrap_err();
        assert!(matches!(err, RelayError::Unprocessable(_)), "{err}");

        // A valid device-signed entry at a held seq is equivocation: the held one stays.
        let other = make_set_home_relay(&chain_state(&account.raw[..1]), &account.device, home.vk());
        let equivocation = home.anchor(&other);
        let err = store.append_anchored_entries(account.fp, vec![equivocation]).await.unwrap_err();
        assert!(matches!(err, RelayError::Conflict), "{err}");
        assert_eq!(store.get_idlog(account.fp, 0).await.unwrap()[1].payload, account.raw[1].to_bytes());
    }

    #[tokio::test]
    async fn a_mirror_takes_a_recovery_branch_and_reports_the_losers() {
        let store = Storage::open_ephemeral().unwrap();
        let mut home = FakeHome::new();
        let account = foreign_account(&mut home);
        let thief = random_key();
        let add = create_add_device(&chain_state(&account.raw), &account.device, &thief, "thief");
        let mut held = account.anchored.clone();
        held.push(home.anchor(&add));
        store.append_anchored_entries(account.fp, held).await.unwrap();

        // Before the root rotates, the genesis key is the root.
        let device = random_key();
        let recovery = create_recovery(&chain_state(&account.raw), &account.genesis_key, &device, "owner");
        let change = store.append_anchored_entries(account.fp, vec![home.anchor(&recovery)]).await.unwrap();
        assert!(change.revoked.contains(&thief.verifying_key().to_bytes()));
        assert!(change.revoked.contains(&account.device.verifying_key().to_bytes()));
        assert!(store.is_active_device(account.fp, device.verifying_key().to_bytes()).await.unwrap());
        assert_eq!(store.get_idlog(account.fp, 0).await.unwrap()[2].payload, recovery.to_bytes());
    }

    #[tokio::test]
    async fn anchored_revocation_updates_device_keys_and_reports_revoked() {
        let store = Storage::open_ephemeral().unwrap();
        let mut home = FakeHome::new();
        let mut account = foreign_account(&mut home);
        store.append_anchored_entries(account.fp, account.anchored.clone()).await.unwrap();

        let dk2 = random_key();
        let add = create_add_device(&chain_state(&account.raw), &account.device, &dk2, "device-2");
        account.raw.push(add.clone());
        let revoke = create_revoke_device(&chain_state(&account.raw), &account.device, &dk2.verifying_key().to_bytes());
        let tail = vec![home.anchor(&add), home.anchor(&revoke)];

        let change = store.append_anchored_entries(account.fp, tail).await.unwrap();
        assert_eq!(change.revoked, Vec::<[u8; 32]>::new(), "added and revoked within one push: never active here");
        assert!(!store.is_active_device(account.fp, dk2.verifying_key().to_bytes()).await.unwrap());
        assert!(store.is_active_device(account.fp, account.device.verifying_key().to_bytes()).await.unwrap());
    }

    #[tokio::test]
    async fn an_anchored_entry_is_rejected_on_checkpoint_regression() {
        let store = Storage::open_ephemeral().unwrap();
        let mut home = FakeHome::new();
        let account = foreign_account(&mut home);
        store.append_anchored_entries(account.fp, account.anchored.clone()).await.unwrap();

        // Anchor the next entry with a checkpoint older than the one already held.
        let add = create_add_device(&chain_state(&account.raw), &account.device, &random_key(), "device-2");
        let mut stale = home.anchor(&add);
        stale.checkpoint = account.anchored[0].checkpoint.clone();
        stale.inclusion_proof.tree_size = stale.checkpoint.tree_size;
        let err = store.append_anchored_entries(account.fp, vec![stale]).await.unwrap_err();
        assert!(matches!(err, RelayError::Unprocessable(_)), "{err}");
    }

    #[tokio::test]
    async fn anchored_rehome_switches_home_on_old_home_and_mirror() {
        let old_home_store = Storage::open_ephemeral().unwrap();
        let mirror = Storage::open_ephemeral().unwrap();
        let mut new_home = FakeHome::new();

        // Account lives at old_home_store, which anchors with its real KT key.
        let (fp, mk, dk) = test_account();
        let genesis = make_genesis(&mk, &dk);
        append(&old_home_store, &fp, &genesis).await.unwrap();
        let set_home = make_set_home_relay(&chain_state(std::slice::from_ref(&genesis)), &dk, old_home_store.relay_vk());
        append(&old_home_store, &fp, &set_home).await.unwrap();

        // Build the old home's anchors the way kt_append_and_sign would.
        let (_vk, sk_bytes) = old_home_store.relay_keypair().await.unwrap();
        let mut old_home_tree = FakeHome { sk: ed25519_dalek::SigningKey::from_keypair_bytes(&sk_bytes).unwrap(), leaves: Vec::new() };
        let a1 = old_home_tree.anchor(&genesis);
        let a2 = old_home_tree.anchor(&set_home);
        for (seq, anchored) in [(1, &a1), (2, &a2)] {
            let (proof, checkpoint) = (anchored.inclusion_proof.to_bytes(), anchored.checkpoint.to_bytes().to_vec());
            old_home_store.write(move |conn| sql::store_anchor(conn, &fp, seq, &proof, &checkpoint)).await.unwrap();
        }
        mirror.append_anchored_entries(fp, vec![a1.clone(), a2.clone()]).await.unwrap();

        // The device moves to new_home; the new home anchors the whole chain.
        let move_entry = make_set_home_relay(&chain_state(&[genesis.clone(), set_home.clone()]), &dk, new_home.vk());
        let _ = new_home.anchor(&genesis);
        let _ = new_home.anchor(&set_home);
        let moved = new_home.anchor(&move_entry);

        for store in [&old_home_store, &mirror] {
            let change = store.append_anchored_entries(fp, vec![moved.clone()]).await.unwrap();
            assert!(!change.is_home);
            assert_eq!(change.home_relay_vk, new_home.vk());
            let account = store.get_account(fp).await.unwrap().unwrap();
            assert!(!account.is_home);
            assert_eq!(account.home_relay_vk, new_home.vk());
            assert_eq!(account.home_set_at_seq, 3);
        }

        // The old home no longer sequences raw entries for the account.
        let add = create_add_device(&chain_state(&[genesis, set_home, move_entry]), &dk, &random_key(), "phone");
        let err = append(&old_home_store, &fp, &add).await.unwrap_err();
        assert!(matches!(err, RelayError::WrongHome(_)));
    }

    #[tokio::test]
    async fn may_authenticate_requires_home_membership_or_guest_window() {
        let store = Storage::open_ephemeral().unwrap();
        let mut home = FakeHome::new();
        let account = foreign_account(&mut home);
        let fp = account.fp;
        let dk_vk = account.device.verifying_key().to_bytes();
        let now = 10_000;

        assert_eq!(store.may_authenticate(fp, dk_vk, now).await.unwrap(), None, "unknown account");
        store.append_anchored_entries(fp, account.anchored.clone()).await.unwrap();
        assert_eq!(store.may_authenticate(fp, dk_vk, now).await.unwrap(), None, "mirrored but not a member");

        store.set_account_guest_until(fp, now + 1).await.unwrap();
        assert_eq!(store.may_authenticate(fp, dk_vk, now).await.unwrap(), Some(Admission::Guest), "guest window");
        assert_eq!(store.may_authenticate(fp, dk_vk, now + 1).await.unwrap(), None, "guest window closed");

        store.write(move |conn| sql::update_mailbox_members(conn, &[0xAB; 32], &[fp])).await.unwrap();
        assert_eq!(store.may_authenticate(fp, dk_vk, now + 1).await.unwrap(), Some(Admission::Member), "mailbox member");
        assert_eq!(store.may_authenticate(fp, [0x55; 32], now + 1).await.unwrap(), None, "unknown device");

        // Accounts homed here always authenticate.
        let (fp2, mk2, dk2) = test_account();
        append(&store, &fp2, &make_genesis(&mk2, &dk2)).await.unwrap();
        assert_eq!(store.may_authenticate(fp2, dk2.verifying_key().to_bytes(), now).await.unwrap(), Some(Admission::Home));
    }

    #[tokio::test]
    async fn backfill_marks_legacy_accounts_as_homed_here() {
        let store = Storage::open_ephemeral().unwrap();
        let (fp, mk, dk) = test_account();
        append(&store, &fp, &make_genesis(&mk, &dk)).await.unwrap();
        let relay_vk = store.relay_vk();
        store
            .write(move |conn| {
                conn.execute("DELETE FROM accounts", []).map_err(storage_error)?;
                sql::backfill_accounts(conn, relay_vk)
            })
            .await
            .unwrap();
        let account = store.get_account(fp).await.unwrap().unwrap();
        assert!(account.is_home);
        assert_eq!(account.home_relay_vk, store.relay_vk());
        assert_eq!(account.head_seq, 1);
    }
}

#[cfg(test)]
mod pull_backoff_tests {
    use super::*;

    #[test]
    fn refused_pulls_wait_longer_each_time() {
        let mut row = AccountRow {
            account_fp: [0; 32],
            home_relay_vk: [1; 32],
            home_relay_ref: Vec::new(),
            home_set_at_seq: 1,
            is_home: false,
            head_seq: 1,
            guest_until: 0,
            last_refresh: 1_000,
            pull_refusals: 0,
        };
        let interval = 30_000;
        assert!(row.pull_due(1_000, interval));
        row.pull_refusals = 1;
        assert!(!row.pull_due(1_000 + 2 * interval - 1, interval));
        assert!(row.pull_due(1_000 + 2 * interval, interval));
        row.pull_refusals = 3;
        assert!(!row.pull_due(1_000 + 8 * interval - 1, interval));
        assert!(row.pull_due(1_000 + 8 * interval, interval));
        row.pull_refusals = 100;
        assert!(row.pull_due(1_000 + interval * (1 << MAX_PULL_BACKOFF_DOUBLINGS), interval));
    }
}

#[cfg(test)]
mod mirror_grant_tests {
    use super::*;
    use crate::constants::MIRROR_GRANT_TTL_MS;

    #[tokio::test]
    async fn grants_add_up_and_lapse_unless_renewed() {
        let store = Storage::open_ephemeral().unwrap();
        let account = [7; 32];
        let (a, b) = (RelayRef::key_only([1; 32]), RelayRef::key_only([2; 32]));
        let now = 1_000_000;

        // Two devices each name the relay they know; neither takes the other's.
        store.grant_mirrors(account, vec![a.clone()], now).await.unwrap();
        store.grant_mirrors(account, vec![b.clone()], now + 10).await.unwrap();
        let mut granted: Vec<[u8; 32]> = store.mirror_grants(account, now + 10).await.unwrap().iter().map(|r| r.relay_vk).collect();
        granted.sort();
        assert_eq!(granted, vec![[1; 32], [2; 32]]);

        // One renewed, the other not: past the lapse only the renewed one holds.
        let later = now + MIRROR_GRANT_TTL_MS;
        store.grant_mirrors(account, vec![b.clone()], later).await.unwrap();
        assert!(!store.is_mirror_granted(account, [1; 32], later + 1).await.unwrap(), "not renewed, lapsed");
        assert!(store.is_mirror_granted(account, [2; 32], later + 1).await.unwrap());
        assert_eq!(store.sweep_mirror_grants(later + 1).await.unwrap(), 1);
        assert_eq!(store.mirror_grants(account, later + 1).await.unwrap().len(), 1);
    }
}
