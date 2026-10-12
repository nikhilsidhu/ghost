//! The client's event loop: everything a running device does with what its relays
//! deliver. The desktop app and headless clients run this same loop and differ only
//! in what they do with the events it reports.
//!
//! The loop itself never waits on the network. Work that needs a relay (fetching a
//! member's log, rejoining a group, publishing GroupInfo, committing proposals,
//! checking the account) runs in tasks that report back as events, and a mailbox whose
//! next step waits on such a task holds its later blobs until the task is done, so each
//! mailbox is still processed in order.

pub mod avatars;
mod events;
mod rosters;

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, Mutex};

use ghost_wire::EnvelopeType;
use ghost_wire::short_id;

use crate::client::{BlobOrigin, ChannelOpOutcome, ReceiveResult, ServerStateOutcome};
use crate::crypto::MessageType;
use crate::deferred::DeferredBlobs;
use crate::error::GhostError;
use crate::flows::presence::PresenceInfo;
use crate::flows::{self, SharedClient};
use crate::relay::RelayClient;
use crate::idlog_cache::{CredentialClaim, HeadClaim};
use crate::relay::{Ack, IncomingBlob, RelayEvent};
use crate::storage::{placeholder_name, Delivery, Member, OnConflict};
use crate::wire::{
    decode_metadata, derive_default_channel_id, ApplicationMessage, MetadataPayload, ProvisionPayload, SyncMessageType,
    SyncReceiveResult,
};

pub use avatars::AVATARS_DIR;
pub use events::{AccountAlert, ClientEvent, Connectivity, EventSink, OnlineMember, ServerScope, VoiceMember};

use rosters::{OnlineRoster, VoiceRoster};

/// Messages of this device's own epoch that failed to open in a row on one mailbox,
/// after which its own group state is taken to be off and it rejoins the group.
const EPOCH_RECOVERY_ERROR_THRESHOLD: u32 = 3;

/// How often a commit of queued proposals the relay refused (the group or the server
/// moved meanwhile) is tried again.
const PROPOSAL_RETRY_INTERVAL: Duration = Duration::from_secs(1);

/// Retries before giving up on committing a mailbox's queued proposals.
const PROPOSAL_RETRY_LIMIT: u32 = 30;

/// How often a running device checks its own account: new entries, account keys it
/// lacks, a generation that no longer covers the account.
const ACCOUNT_CHECK_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// How long a device that does not hold the current account key waits for one that
/// does to add a covering generation, before adding one itself without a back-link.
const REKEY_GRACE: Duration = Duration::from_secs(10 * 60);

/// Relays hosting the account's servers that must agree this device is revoked, while
/// the home cannot be reached, before the device takes it as the account's word.
const REVOCATION_CORROBORATION: usize = 2;

/// How long after the home denied a relay's claim that this device is revoked its
/// mailboxes on that relay are opened again.
const DISPUTED_RELAY_RETRY: Duration = ACCOUNT_CHECK_INTERVAL;

/// How often changed sync state is checked for having settled enough to push.
const SNAPSHOT_TICK: Duration = Duration::from_millis(500);
/// How often the sync relays' snapshots are merged while connected, for changes whose
/// mutations never reached this device (their writer queued them while offline and
/// restarted before they left).
const SNAPSHOT_MERGE_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// How long a private channel's blobs may wait for the server group before the channel
/// is reported as waiting.
const WAITING_REPORTED_AFTER: Duration = Duration::from_secs(60);
/// How often channels waiting on their server group, and groups whose refusal of a stale
/// message has not cleared, are looked at.
const WAITING_CHECK: Duration = Duration::from_secs(10);

/// How long a group may stay at the epoch the relay refused a message as stale at,
/// without catching up, before this device rejoins it at the relay's epoch.
const STALE_REFUSAL_WAIT: Duration = Duration::from_secs(30);

/// A running device: its client state, relay connections, announced presence and
/// where its events go.
#[derive(Clone)]
pub struct Session {
    pub client: Arc<SharedClient>,
    pub relay: Arc<RelayClient>,
    pub presence: Arc<Mutex<PresenceInfo>>,
    pub sink: Arc<dyn EventSink>,
    /// Holds the avatar cache.
    pub data_dir: PathBuf,
    /// One discovery run per server at a time: two at once would both join a new
    /// channel and the second join would replace the first's group state.
    pub discovery: Arc<DiscoveryLocks>,
    /// Accounts whose split view was reported, so each is reported once a session.
    pub split_views: Arc<SplitViews>,
}

/// Per-server locks serializing private channel discovery.
#[derive(Default)]
pub struct DiscoveryLocks(std::sync::Mutex<HashMap<[u8; 32], Arc<Mutex<()>>>>);

/// Accounts a split view of whose identity log this session has reported.
#[derive(Default)]
pub struct SplitViews(std::sync::Mutex<HashSet<[u8; 32]>>);

impl DiscoveryLocks {
    fn for_server(&self, server_id: &[u8; 32]) -> Arc<Mutex<()>> {
        self.0.lock().unwrap().entry(*server_id).or_default().clone()
    }
}

/// What a task reports back to the loop when its network work is done.
enum Report {
    /// A member's identity log was fetched (or could not be) for a blob held on it.
    MemberFetched { blob: IncomingBlob, held: HeldBlob, fetched: bool },
    /// The account check ran.
    AccountChecked(AccountCheck),
    /// A while has passed since the home denied the relay's claim that this device is
    /// revoked: its mailboxes there are opened again.
    ReopenRefusedMailboxes { relay_url: String, mailboxes: Vec<[u8; 32]> },
    /// A group rejoin ended.
    GroupRecovered { mailbox_id: [u8; 32], outcome: Rejoin },
    /// Another device of the account saw it removed from a server.
    RemovedElsewhere { server_id: [u8; 32], by: Option<[u8; 32]> },
    /// The home relay told its key, or did not answer.
    HomeKey(Result<[u8; 32], GhostError>),
    /// A commit of a group's queued proposals was tried.
    ProposalsCommitted { mailbox_id: [u8; 32], outcome: ProposalCommit },
}

/// How a group rejoin ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rejoin {
    /// The relay took the external commit.
    Rejoined,
    /// It did not; the group is as it was.
    NotRejoined,
    /// The relay no longer admits the account to the group: it was removed.
    Removed,
    /// A private channel whose server group the relay holds at a later epoch than this
    /// device: a rejoin naming this device's server epoch would be refused, so it waits
    /// until the server group reaches `epoch`.
    WaitsForServer { server_mailbox: [u8; 32], epoch: u64 },
}

/// A blob held while its sender's identity log is fetched, and how it goes on after.
enum HeldBlob {
    /// Processed again from the start.
    Receive,
    /// Its message was opened, but its sender's credential could not be checked yet.
    Unverified { message: ApplicationMessage, claim: CredentialClaim, received_at: u64 },
}

/// What the account check found, for the loop to act on.
struct AccountCheck {
    /// Whether this device is still one of the account's.
    standing: DeviceStanding,
    /// The log's current generation no longer covers exactly the account's devices.
    needs_rekey: bool,
    /// This device holds the current generation, so it may repair at once.
    holds_current: bool,
    /// The log and key sets were fetched, from the home or the relays mirroring them, so
    /// a sync blob that waited for them can be opened now if ever.
    keys_current: bool,
}

/// A mailbox with a task in flight that its next blobs must wait for.
#[derive(Default)]
struct Busy {
    tasks: u32,
    blobs: VecDeque<IncomingBlob>,
}

fn same_relay(a: &str, b: &str) -> bool {
    a.trim_end_matches('/') == b.trim_end_matches('/')
}

/// Whether a removal this device learned is passed on to the account's other devices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tell {
    OtherDevices,
    /// It came from them.
    Nobody,
}

/// State the loop keeps between events.
#[derive(Default)]
struct LoopState {
    voice: VoiceRoster,
    online: OnlineRoster,
    /// Each mailbox connection, by mailbox and relay, and whether it is up.
    links: HashMap<([u8; 32], String), bool>,
    /// Connections up and still delivering what the mailbox held for this device.
    catching_up: HashSet<([u8; 32], String)>,
    consecutive_errors: HashMap<[u8; 32], u32>,
    /// Private channel blobs waiting for the server group to reach the epoch they name.
    deferred: DeferredBlobs,
    /// Mailboxes reported as waiting on their server group, with the server and channel
    /// each belongs to, until reported as no longer waiting.
    waiting_reported: HashMap<[u8; 32], ([u8; 32], [u8; 32])>,
    /// Mailboxes whose relay refused a message as sealed too far back: the group's epoch
    /// then, and when, until the epoch moves.
    stale_refusals: HashMap<[u8; 32], (u64, std::time::Instant)>,
    /// Private channels whose rejoin waits for their server group to reach an epoch: by
    /// the channel's mailbox, the server mailbox, that epoch and since when.
    recoveries_waiting: HashMap<[u8; 32], ([u8; 32], u64, std::time::Instant)>,
    /// Blobs released from a hold, processed before new events.
    requeued: VecDeque<IncomingBlob>,
    /// Mailboxes with a task in flight, and the blobs waiting behind it.
    busy: HashMap<[u8; 32], Busy>,
    /// Groups being rejoined, so a second trigger starts no second rejoin.
    recovering: HashSet<[u8; 32]>,
    /// Groups whose queued proposals a task is committing right now.
    committing: HashSet<[u8; 32]>,
    /// Groups whose queued proposals still need committing, by mailbox.
    proposal_retries: HashMap<[u8; 32], ProposalRetry>,
    /// An account check is running; `true` once another was asked for meanwhile.
    account_check: Option<bool>,
    /// A sync blob that did not open and waits for the account check.
    sync_retry: Option<IncomingBlob>,
    /// The blob given back after a check that fetched what it waited for, by relay and
    /// sequence number: failing again, it is dropped rather than held once more.
    sync_retried: Option<(String, u64)>,
    /// When this device first saw its account needing a rekey, while it still does.
    rekey_needed_since: Option<std::time::Instant>,
    /// The sync mailbox's connection to the home dropped and has not come back yet.
    home_lost: bool,
    /// The account's word is that this device was removed; reported once.
    device_removed: bool,
    /// Relays other than the home that refused this device as revoked, with the mailboxes
    /// refused there, waiting for the account check to settle whether the account agrees.
    revocation_claims: HashMap<String, HashSet<[u8; 32]>>,
    /// Relays whose claim the home denied, named to the user once.
    disputed_relays: HashSet<String>,
    /// Mailboxes each relay answered but refused this device, until a connection there
    /// comes up again.
    refusing: HashMap<String, HashSet<[u8; 32]>>,
    /// Mailbox and relay pairs whose refusal a repair was started for, until the mailbox
    /// connects there.
    admission_repairs: HashSet<([u8; 32], String)>,
    /// The home relay's key is known: the account check compares the log's home with it.
    home_key_known: bool,
    /// A request for the home relay's key is out.
    home_key_asked: bool,
    /// An account check was asked for before the home's key was known; it runs once known.
    account_check_waits_for_home_key: bool,
}

/// Where this device stands with its account, as the account check found it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum DeviceStanding {
    /// The home served the log to this device.
    Active,
    /// The home refused this device as revoked, or enough of the servers' relays did
    /// while the home was out of reach; what revoked it, when they said.
    Removed(Option<ghost_wire::RevocationCause>),
    /// The home could not be reached and nothing settled it either way.
    Unknown,
}

impl LoopState {
    /// Where the connections stand, for whoever shows it.
    fn connectivity(&self, sync_mailbox: [u8; 32], home_url: &str) -> Connectivity {
        let home = self.links.iter().any(|((mailbox, url), up)| *up && *mailbox == sync_mailbox && same_relay(url, home_url));
        let mut relays_down: Vec<String> = self.links.iter().filter(|(_, up)| !**up).map(|((_, url), _)| url.clone()).collect();
        relays_down.sort();
        relays_down.dedup();
        let mut relays_refusing: Vec<String> = self.refusing.keys().cloned().collect();
        relays_refusing.sort();
        Connectivity { home, any: self.links.values().any(|up| *up), relays_down, relays_refusing, catching_up: !self.catching_up.is_empty() }
    }
}

impl LoopState {
    /// A task for the mailbox is in flight; its later blobs wait.
    fn hold(&mut self, mailbox_id: [u8; 32]) {
        self.busy.entry(mailbox_id).or_default().tasks += 1;
    }

    /// A task for the mailbox is done; once none is left, what waited goes on.
    fn release(&mut self, mailbox_id: [u8; 32]) {
        let Some(busy) = self.busy.get_mut(&mailbox_id) else { return };
        busy.tasks = busy.tasks.saturating_sub(1);
        if busy.tasks == 0 {
            let busy = self.busy.remove(&mailbox_id).expect("looked up above");
            self.requeued.extend(busy.blobs);
        }
    }
}

/// A group whose queued proposals this device has not managed to commit yet.
struct ProposalRetry {
    server_id: [u8; 32],
    channel_id: [u8; 32],
    attempts: u32,
}

/// What became of an attempt to commit a group's queued proposals.
enum ProposalCommit {
    /// Committed, or nothing left for this device to commit.
    Done,
    /// Not committed yet: the relay refused it (the group or its server moved
    /// meanwhile), or this device's view has not caught up with why it is allowed.
    Retry,
}

/// The session with the channel its tasks report back on.
#[derive(Clone)]
struct Runner {
    session: Session,
    reports: mpsc::UnboundedSender<Report>,
    tasks: Arc<SessionTasks>,
}

/// The work a session spawned, aborted when the session ends: a session replaced (the
/// app pointed at another relay, or another identity installed) leaves nothing running
/// on the client and relay client the next one shares.
#[derive(Default)]
struct SessionTasks(std::sync::Mutex<Vec<tokio::task::AbortHandle>>);

impl SessionTasks {
    fn spawn<F, T>(&self, work: F)
    where
        F: std::future::Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let handle = tokio::spawn(work).abort_handle();
        let mut tasks = self.0.lock().unwrap_or_else(|e| e.into_inner());
        tasks.retain(|task| !task.is_finished());
        tasks.push(handle);
    }

    fn abort_all(&self) {
        for task in self.0.lock().unwrap_or_else(|e| e.into_inner()).drain(..) {
            task.abort();
        }
    }
}

/// Ends the session's tasks with its loop, however the loop ends: its events closed, or
/// its task aborted.
struct EndTasksWithLoop(Arc<SessionTasks>);

impl Drop for EndTasksWithLoop {
    fn drop(&mut self) {
        self.0.abort_all();
    }
}

impl std::ops::Deref for Runner {
    type Target = Session;

    fn deref(&self) -> &Session {
        &self.session
    }
}

impl Session {
    /// Run the loop over `events` (the receiver the relay client was created with)
    /// until it closes, after subscribing and the start-up work.
    pub async fn run(self, mut events: mpsc::Receiver<RelayEvent>) {
        let (reports, mut reported) = mpsc::unbounded_channel();
        let tasks = Arc::new(SessionTasks::default());
        let _end_tasks = EndTasksWithLoop(tasks.clone());
        let runner = Runner { session: self, reports, tasks };
        let sync_mailbox = runner.start().await;
        let mut state = LoopState::default();
        state.home_key_known = runner.client.lock().await.relay_vk().is_some();
        if !state.home_key_known {
            runner.ask_home_key(&mut state);
        }
        let mut retry_tick = tokio::time::interval(PROPOSAL_RETRY_INTERVAL);
        retry_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // The first tick fires at once: the start-up check of the account.
        let mut account_tick = tokio::time::interval(ACCOUNT_CHECK_INTERVAL);
        account_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut snapshot_tick = tokio::time::interval(SNAPSHOT_TICK);
        snapshot_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // The sync mailbox's connection merges at start; the timer follows from there.
        let mut merge_tick = tokio::time::interval_at(tokio::time::Instant::now() + SNAPSHOT_MERGE_INTERVAL, SNAPSHOT_MERGE_INTERVAL);
        merge_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut waiting_tick = tokio::time::interval(WAITING_CHECK);
        waiting_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            if let Some(blob) = state.requeued.pop_front() {
                runner.handle_event(RelayEvent::Blob(blob), sync_mailbox, &mut state).await;
                continue;
            }
            tokio::select! {
                event = events.recv() => match event {
                    Some(event) => runner.handle_event(event, sync_mailbox, &mut state).await,
                    None => break,
                },
                Some(report) = reported.recv() => runner.handle_report(report, sync_mailbox, &mut state).await,
                _ = retry_tick.tick(), if !state.proposal_retries.is_empty() => runner.retry_proposal_commits(&mut state),
                _ = account_tick.tick() => {
                    runner.request_account_check(&mut state);
                    runner.look_for_moved_servers(&state);
                }
                _ = snapshot_tick.tick() => runner.push_snapshot_if_settled().await,
                _ = merge_tick.tick() => {
                    let merger = runner.clone();
                    runner.spawn(async move { merger.merge_sync_snapshots().await });
                }
                _ = waiting_tick.tick() => {
                    runner.report_waiting_channels(&mut state).await;
                    runner.recover_stale_refusals(&mut state).await;
                }
            }
        }
    }
}

/// What an application or unknown blob this device could not process leaves behind.
#[derive(Debug, PartialEq, Eq)]
struct UnprocessedEffects {
    /// A message lost here stands in the channel's history.
    stand_in: bool,
    /// The failure says this device's own group state is off, toward a rejoin.
    counts_against_own_state: bool,
}

/// A message refused for its sender (revoked, or contradicting its account's log) was
/// not lost, so nothing stands in for it; only a message of this device's own epoch that
/// does not decrypt says the device's group state is off.
fn unprocessed_effects(is_message: bool, at_own_epoch: bool, error: &GhostError) -> UnprocessedEffects {
    UnprocessedEffects {
        stand_in: is_message && !matches!(error, GhostError::SenderRefused(_)),
        counts_against_own_state: is_message && at_own_epoch && matches!(error, GhostError::Mls(_)),
    }
}

/// A store write the loop can only report when it fails: what it meant to keep is what
/// the next event or a restart redoes.
fn stored<T>(result: crate::error::Result<T>, what: &str) {
    if let Err(e) = result {
        tracing::error!("{what}: {e}");
    }
}

impl Runner {
    /// Run work beside the loop, for as long as the session lasts.
    fn spawn<F, T>(&self, work: F)
    where
        F: std::future::Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        self.tasks.spawn(work);
    }

    fn emit(&self, event: ClientEvent) {
        self.sink.emit(event);
    }

    /// Run `work` off the loop, reporting what it says back to it.
    fn spawn_reporting<F>(&self, work: F)
    where
        F: std::future::Future<Output = Report> + Send + 'static,
    {
        let reports = self.reports.clone();
        self.tasks.spawn(async move {
            let _ = reports.send(work.await);
        });
    }

    /// Report the private channels whose blobs, or whose rejoin, have waited on the server
    /// group for longer than `WAITING_REPORTED_AFTER`, and those reported that no longer wait.
    async fn report_waiting_channels(&self, state: &mut LoopState) {
        let rejoins_waiting = state
            .recoveries_waiting
            .iter()
            .filter(|(_, (_, _, since))| since.elapsed() > WAITING_REPORTED_AFTER)
            .map(|(mailbox_id, _)| *mailbox_id);
        let waiting: Vec<[u8; 32]> = state
            .deferred
            .held_longer_than(WAITING_REPORTED_AFTER)
            .into_iter()
            .chain(rejoins_waiting)
            .filter(|m| !state.waiting_reported.contains_key(m))
            .collect();
        let caught_up: Vec<[u8; 32]> = state
            .waiting_reported
            .keys()
            .filter(|m| !state.deferred.is_waiting(m) && !state.recoveries_waiting.contains_key(*m))
            .copied()
            .collect();
        for mailbox_id in caught_up {
            if let Some((server_id, channel_id)) = state.waiting_reported.remove(&mailbox_id) {
                self.emit(ClientEvent::ChannelWaiting { server_id, channel_id, waiting: false });
            }
        }
        let c = self.client.lock().await;
        for mailbox_id in waiting {
            let (Some(channel_id), Some(server_id)) = (c.channel_id_for_mailbox(&mailbox_id), c.server_id_for_mailbox(&mailbox_id)) else { continue };
            tracing::warn!("private channel {}: waiting for a change to its server's group", short_id(&channel_id));
            state.waiting_reported.insert(mailbox_id, (server_id, channel_id));
            self.emit(ClientEvent::ChannelWaiting { server_id, channel_id, waiting: true });
        }
    }

    /// Rejoin the groups whose relay refused a message as sealed too far back and that
    /// have not moved since, for `STALE_REFUSAL_WAIT`: the commits that moved the relay's
    /// epoch are not reaching this device, and the message would wait forever. A group
    /// held for its server group catches up with it instead.
    async fn recover_stale_refusals(&self, state: &mut LoopState) {
        let due: Vec<([u8; 32], u64)> = state
            .stale_refusals
            .iter()
            .filter(|(mailbox_id, (_, since))| since.elapsed() > STALE_REFUSAL_WAIT && !state.deferred.is_waiting(mailbox_id))
            .map(|(mailbox_id, (epoch, _))| (*mailbox_id, *epoch))
            .collect();
        for (mailbox_id, refused_at) in due {
            state.stale_refusals.remove(&mailbox_id);
            let now = {
                let c = self.client.lock().await;
                c.channel_id_for_mailbox(&mailbox_id).and_then(|channel_id| c.channel_epoch(&channel_id).ok())
            };
            if now == Some(refused_at) {
                tracing::warn!("mailbox {}: still behind the relay after it refused a message as stale; rejoining", short_id(&mailbox_id));
                self.start_recovery(mailbox_id, state);
            }
        }
    }

    /// Write this device's sync state to the relays once a burst of changes has settled.
    /// While it may not be written (a removal pause, a rekey), the push waits.
    async fn push_snapshot_if_settled(&self) {
        {
            let mut c = self.client.lock().await;
            if !flows::sync::snapshot_writable(&c) || !c.take_snapshot_push(flows::sync::SNAPSHOT_SETTLE) {
                return;
            }
        }
        let runner = self.clone();
        self.spawn(async move {
            // A relay's copy taken in on the way may change settings.
            if let Some(settings) = flows::sync::push_snapshot(&runner.client, &runner.relay).await {
                runner.apply_synced_settings(settings).await;
            }
        });
    }

    /// Check this device's own account, off the loop, once at a time. A check asked
    /// for while one runs follows it, so nothing it would have seen is missed.
    fn request_account_check(&self, state: &mut LoopState) {
        if state.device_removed {
            return;
        }
        // The check compares the home the log names with the connected relay's key.
        if !state.home_key_known {
            state.account_check_waits_for_home_key = true;
            self.ask_home_key(state);
            return;
        }
        match &mut state.account_check {
            Some(again) => *again = true,
            None => {
                state.account_check = Some(false);
                let runner = self.clone();
                let claims: Vec<String> = state.revocation_claims.keys().cloned().collect();
                self.spawn_reporting(async move { Report::AccountChecked(runner.check_account(claims).await) });
            }
        }
    }

    /// Servers whose mailbox connection is down may have moved off a relay that then went
    /// away before announcing it: the owner's home holds the record. Looked up at each
    /// account tick, with the move links shown and not followed yet.
    fn look_for_moved_servers(&self, state: &LoopState) {
        let down: HashSet<[u8; 32]> = state.links.iter().filter(|(_, up)| !**up).map(|((mailbox_id, _), _)| *mailbox_id).collect();
        let session = self.session.clone();
        self.spawn(async move {
            let servers: Vec<[u8; 32]> = {
                let c = session.client.lock().await;
                let mut servers: Vec<[u8; 32]> = down.iter().filter_map(|mailbox_id| c.server_id_for_mailbox(mailbox_id)).collect();
                servers.sort();
                servers.dedup();
                servers
            };
            let moved = flows::server::check_locations(&session.client, &session.relay, &servers).await
                + flows::server::retry_shown_moves(&session.client, &session.relay).await;
            if moved > 0 {
                tracing::info!("{moved} servers found moved");
                session.sink.emit(ClientEvent::ServerChanged(ServerScope::All));
            }
        });
    }

    /// Ask the home relay for its key, once at a time; the answer comes back as a report.
    fn ask_home_key(&self, state: &mut LoopState) {
        if std::mem::replace(&mut state.home_key_asked, true) {
            return;
        }
        let relay = self.relay.clone();
        self.spawn_reporting(async move { Report::HomeKey(relay.get_relay_info().await.map(|info| info.relay_vk)) });
    }

    /// Bring this device's view of its own account up to date: the log, the account key
    /// generations it lacks, and whether the log needs a covering generation. Reports
    /// changes this device did not make. `claims` are the relays that refused this
    /// device as revoked since the last check, which the home's answer settles.
    async fn check_account(&self, claims: Vec<String>) -> AccountCheck {
        let (before, was_paused) = {
            let c = self.client.lock().await;
            (c.own_log().map_or(0, |log| log.head_seq), flows::sync::paused(&c))
        };
        // Removals made while the home was unreachable land first, so the account key
        // made below already leaves those devices out.
        match flows::devices::finish_pending(&self.client, &self.relay).await {
            Ok(refused) => {
                for removal in refused {
                    let label = self.client.lock().await.own_log().and_then(|log| log.devices.get(&removal.device_vk).map(|d| d.label.clone()));
                    self.emit(ClientEvent::Account(AccountAlert::RemovalRefused { label: label.unwrap_or_default(), reason: removal.reason }));
                }
            }
            Err(e) => tracing::warn!("account: waiting removals not appended: {e}"),
        }
        if was_paused && !flows::sync::paused(&*self.client.lock().await) {
            // Sync writing resumes. What this device and the others changed during the
            // pause went into no message; the snapshots carry it, both ways.
            self.client.lock().await.request_snapshot_push();
            let merger = self.clone();
            self.spawn(async move { merger.merge_sync_snapshots().await });
        }
        let removed = |standing| AccountCheck { standing, needs_rekey: false, holds_current: false, keys_current: false };
        let mut standing = self.own_standing(&claims).await;
        if matches!(standing, DeviceStanding::Removed(_)) {
            return removed(standing);
        }
        // With the home out of reach, the relays mirroring the account serve the keys a
        // waiting sync blob needs; they cannot settle the device's standing.
        let keys_current = standing == DeviceStanding::Active || flows::account_keys::refresh_through_members(&self.client, &self.relay).await;
        // A move this device made whose follow-up failed part way is finished first.
        if let Err(e) = flows::account::resume_move(&self.client, &self.relay).await {
            tracing::warn!("account: the move not finished yet: {e}");
        }
        // The account may have moved home while this device was away, or through another
        // device: the relays hosting its servers know. A former home that missed the move
        // is told, so it stops taking changes no other relay accepts.
        match flows::account::follow_home(&self.client, &self.relay).await {
            Ok(Some(url)) => {
                tracing::info!("account: home moved; now connected to {url}");
                // Whoever keeps the address to connect at next time keeps the new one.
                self.emit(ClientEvent::HomeFollowed { url: url.clone() });
                // The new home's word settles this device's standing, not the old one's.
                standing = self.own_standing(&claims).await;
                if matches!(standing, DeviceStanding::Removed(_)) {
                    return removed(standing);
                }
            }
            Ok(None) => {}
            Err(e) => tracing::warn!("account: home not followed: {e}"),
        }
        flows::account::tell_former_homes(&self.client).await;
        if standing == DeviceStanding::Active {
            flows::account::keep_mirrors_current(&self.client, &self.relay).await;
        }
        flows::sync::ensure_sync_relays(&self.client, &self.relay).await;
        // History a root-signed branch replaced is told, and the branch's own entries
        // reported from where it diverged, even below the head held before.
        let replaced = match self.client.lock().await.store().take_replaced_history() {
            Ok(replaced) => replaced,
            Err(e) => {
                tracing::warn!("account: replaced history not read: {e}");
                Vec::new()
            }
        };
        let report_from = replaced.iter().map(|r| r.from_seq.saturating_sub(1)).fold(before, u64::min);
        for r in replaced {
            self.emit(ClientEvent::Account(AccountAlert::HistoryReplaced { discarded: r.discarded, lost_devices: r.lost_devices }));
        }
        self.report_account_changes(report_from).await;

        let c = self.client.lock().await;
        let Some(log) = c.own_log() else { return AccountCheck { standing, needs_rekey: false, holds_current: false, keys_current } };
        let current = log.account_key().map(|k| k.generation);
        let holds_current = current.is_some_and(|g| c.account_seed(g).ok().flatten().is_some());
        AccountCheck { standing, needs_rekey: log.rekey_needed(), holds_current, keys_current }
    }

    /// Whether this device is still one of the account's, by the home's word: the log
    /// served to it, or refused as revoked. While the home is out of reach and relays
    /// claim a revocation, the relays hosting the account's servers are asked instead,
    /// and `REVOCATION_CORROBORATION` of them refusing counts as the account's word.
    async fn own_standing(&self, claims: &[String]) -> DeviceStanding {
        match flows::account_keys::refresh(&self.client, &self.relay).await {
            Ok(()) => DeviceStanding::Active,
            Err(GhostError::BadAccountKeyCopy { generation }) => {
                self.report_bad_copy(generation).await;
                DeviceStanding::Active
            }
            Err(GhostError::DeviceRevoked(cause)) => DeviceStanding::Removed(cause),
            Err(e) => {
                tracing::warn!("account: keys not refreshed: {e}");
                if claims.is_empty() {
                    return DeviceStanding::Unknown;
                }
                let refusals = flows::account::relays_refusing_this_device(&self.client, &self.relay).await;
                if refusals.refusing >= REVOCATION_CORROBORATION {
                    DeviceStanding::Removed(refusals.cause)
                } else {
                    DeviceStanding::Unknown
                }
            }
        }
    }

    /// Act on what the account check found: a revocation, a rekey the account needs,
    /// and the sync blob that waited for the check.
    fn account_checked(&self, check: AccountCheck, sync_mailbox: [u8; 32], state: &mut LoopState) {
        let again = state.account_check.take().unwrap_or(false);
        let removed = matches!(check.standing, DeviceStanding::Removed(_));
        match check.standing {
            DeviceStanding::Removed(cause) => self.this_device_removed(cause, state),
            DeviceStanding::Active => self.dismiss_revocation_claims(state),
            DeviceStanding::Unknown => {}
        }
        if let Some(blob) = state.sync_retry.take() {
            if check.keys_current || removed {
                // Processed again now that the account is current; whatever still fails
                // is dropped, and the blobs that waited behind it go on.
                state.sync_retried = Some((blob.relay_url.clone(), blob.seq));
                state.requeued.push_front(blob);
                state.release(sync_mailbox);
            } else {
                // Nothing reached had the keys it waits for: it stays held, with what
                // came after it, for the next check (the home's return asks for one).
                state.sync_retry = Some(blob);
            }
        }
        if check.needs_rekey {
            let since = *state.rekey_needed_since.get_or_insert_with(std::time::Instant::now);
            if check.holds_current || since.elapsed() >= REKEY_GRACE {
                let session = self.session.clone();
                self.spawn(async move {
                    if let Err(e) = flows::account_keys::repair(&session.client, &session.relay).await {
                        tracing::error!("account: rekey failed: {e}");
                    }
                });
            }
        } else {
            state.rekey_needed_since = None;
        }
        if again && !removed {
            self.request_account_check(state);
        }
    }

    /// Relays refuse a revoked device, so it never reads its own revocation: the refusal
    /// is how it learns, and what revoked it is what the refusal says. Only the
    /// account's word (see `own_standing`) gets here.
    fn this_device_removed(&self, cause: Option<ghost_wire::RevocationCause>, state: &mut LoopState) {
        if !std::mem::replace(&mut state.device_removed, true) {
            self.emit(ClientEvent::Account(AccountAlert::ThisDeviceRemoved { cause }));
        }
    }

    /// The home says this device is active, so the relays that refused it as revoked
    /// are behind or lying. Each is named to the user once; its mailboxes are opened
    /// again after a while, and a relay still refusing raises a new claim.
    fn dismiss_revocation_claims(&self, state: &mut LoopState) {
        for (relay_url, mailboxes) in std::mem::take(&mut state.revocation_claims) {
            tracing::warn!("relay {relay_url} refuses this device as revoked, which the home denies; trying it again in {DISPUTED_RELAY_RETRY:?}");
            if state.disputed_relays.insert(relay_url.clone()) {
                self.emit(ClientEvent::Account(AccountAlert::RelayRefusesDevice { relay_url: relay_url.clone() }));
            }
            let mailboxes = mailboxes.into_iter().collect();
            self.spawn_reporting(async move {
                tokio::time::sleep(DISPUTED_RELAY_RETRY).await;
                Report::ReopenRefusedMailboxes { relay_url, mailboxes }
            });
        }
    }

    /// Open this device's mailboxes on a relay that refused it as revoked again.
    async fn reopen_refused_mailboxes(&self, relay_url: &str, mailboxes: &[[u8; 32]], state: &LoopState) {
        if state.device_removed {
            return;
        }
        let c = self.client.lock().await;
        let view = self.relay.at(relay_url);
        for mailbox_id in mailboxes {
            let last_seen = c.store().get_last_seen_seq(mailbox_id).unwrap_or(0);
            view.subscribe_here_too(*mailbox_id, last_seen);
        }
    }

    async fn report_bad_copy(&self, generation: u32) {
        let alert = {
            let c = self.client.lock().await;
            let Some(log) = c.own_log() else { return };
            let Some(key) = log.account_keys.iter().find(|k| k.generation == generation) else { return };
            let writer_label = log.devices.get(&key.writer).map(|d| d.label.clone()).unwrap_or_default();
            AccountAlert::BadAccountKey { generation, writer: key.writer, writer_label }
        };
        self.emit(ClientEvent::Account(alert));
    }

    /// Alert on the entries after `before` that another device or the recovery key made.
    /// A device's first look at its log (`before` 0) reports nothing: it is all history.
    async fn report_account_changes(&self, before: u64) {
        use ghost_wire::idlog::EntryBody;
        if before == 0 {
            return;
        }
        let alerts = {
            let c = self.client.lock().await;
            let own_vk = c.verifying_key_bytes();
            let (Some(log), Ok(chain)) = (c.own_log(), c.store().get_cached_anchored_entries(c.fingerprint())) else { return };
            let label = |vk: &[u8; 32]| log.devices.get(vk).map(|d| d.label.clone()).unwrap_or_default();
            chain
                .iter()
                .filter(|a| a.entry.seq > before)
                .filter_map(|a| match &a.entry.body {
                    EntryBody::AddDevice { device_label, authorizer_key, .. } if *authorizer_key != own_vk => {
                        Some(AccountAlert::DeviceLinked { label: device_label.clone() })
                    }
                    // A recovery elsewhere revokes this device too, which hears of it from
                    // the relays' refusal instead.
                    EntryBody::RevokeDevice { device_verifying_key, revoker_key } if *revoker_key != own_vk => {
                        let by = match log.devices.get(revoker_key) {
                            Some(revoker) => ghost_wire::RevocationCause::Device(revoker.label.clone()),
                            None => ghost_wire::RevocationCause::RecoveryKey,
                        };
                        Some(AccountAlert::DeviceRemoved { label: label(device_verifying_key), by })
                    }
                    EntryBody::RotateRoot { device_verifying_key, .. } if *device_verifying_key != own_vk => {
                        Some(AccountAlert::RecoveryKeyReplaced { by: label(device_verifying_key) })
                    }
                    EntryBody::SetHomeRelay { relay_vk, .. } => Some(AccountAlert::HomeMoved { relay_vk: *relay_vk }),
                    _ => None,
                })
                .collect::<Vec<_>>()
        };
        alerts.into_iter().for_each(|alert| self.emit(ClientEvent::Account(alert)));
    }

    /// Try again to commit the queued proposals the relay refused earlier.
    fn retry_proposal_commits(&self, state: &mut LoopState) {
        let due: Vec<([u8; 32], [u8; 32], [u8; 32])> = state
            .proposal_retries
            .iter()
            .filter(|(mailbox_id, _)| !state.committing.contains(*mailbox_id))
            .map(|(mailbox_id, retry)| (*mailbox_id, retry.server_id, retry.channel_id))
            .collect();
        for (mailbox_id, server_id, channel_id) in due {
            self.start_proposal_commit(server_id, channel_id, mailbox_id, state);
        }
    }

    /// Subscribe to every mailbox and start the start-up work. Returns the sync mailbox.
    async fn start(&self) -> [u8; 32] {
        // Each server mailbox on the relay hosting it, the sync mailbox on the home
        // relay, resuming from the persisted last_seen_seq.
        let sync_mailbox = {
            let c = self.client.lock().await;
            flows::subscribe_known_mailboxes(&c, &self.relay);
            c.account_sync_mailbox()
        };

        // Servers whose relay went away before announcing a move can be found through
        // their owners' home relays.
        let session = self.session.clone();
        self.spawn(async move {
            let moved = flows::server::check_all_locations(&session.client, &session.relay).await;
            if moved > 0 {
                tracing::info!("{moved} servers moved while this device was away");
            }
        });

        // Servers joined without the relay taking the request for their state, and servers
        // made without their group state reaching the relay.
        let session = self.session.clone();
        self.spawn(async move {
            flows::invite::ask_unrequested_server_states(&session.client, &session.relay).await;
            flows::server::publish_unpublished(&session.client, &session.relay).await;
        });

        // Join the private channels each server's relay lists for this account (granted
        // while this device was away).
        let runner = self.clone();
        self.spawn(async move {
            let servers: Vec<[u8; 32]> = {
                let c = runner.client.lock().await;
                c.store().list_servers().map(|list| list.into_iter().map(|s| s.server_id).collect()).unwrap_or_default()
            };
            for server_id in servers {
                runner.spawn_join_private_channels(server_id);
            }
        });

        sync_mailbox
    }

    /// Join the private channels of a server that the relay lists for this account, in
    /// the background so the loop keeps running.
    fn spawn_join_private_channels(&self, server_id: [u8; 32]) {
        let session = self.session.clone();
        self.spawn(async move {
            // A server this account is out of lists nothing for it.
            if session.client.lock().await.removed_from(&server_id).ok().flatten().is_some() {
                return;
            }
            let lock = session.discovery.for_server(&server_id);
            let _running = lock.lock().await;
            match flows::channels::join_admitted(&session.client, &session.relay, &server_id).await {
                Ok(joined) if !joined.is_empty() => session.sink.emit(ClientEvent::ServerChanged(ServerScope::One(server_id))),
                Ok(_) => {}
                Err(e) => tracing::warn!("private channels of {}: {e}", short_id(&server_id)),
            }
        });
    }

    /// Upload the current GroupInfo of a mailbox's group, so others can join by external
    /// commit. In the background: the group state is already right locally.
    fn spawn_publish_server_info(&self, mailbox_id: [u8; 32]) {
        let session = self.session.clone();
        self.spawn(async move { flows::publish_server_info(&session.client, &session.relay, &mailbox_id).await });
    }

    fn spawn_fetch_avatar(&self, server_id: [u8; 32], fingerprint: [u8; 32], hash: [u8; 32]) {
        let session = self.session.clone();
        self.spawn(async move {
            if avatars::fetch_if_missing(&session.client, &session.relay, &session.data_dir, &server_id, &fingerprint, &hash).await {
                session.sink.emit(ClientEvent::AvatarUpdated(fingerprint));
            }
        });
    }

    /// Take in the avatar a member's presence announced: their record names it, with its
    /// key, from now on (a member who joined after the avatar's announcement has no other
    /// way to learn the key), then the image is fetched if the cache lacks it.
    fn spawn_take_announced_avatar(&self, server_id: [u8; 32], fingerprint: [u8; 32], avatar: crate::mls::presence::AvatarRef) {
        let session = self.session.clone();
        self.spawn(async move {
            {
                let c = session.client.lock().await;
                let known = c.store().get_member(&server_id, &fingerprint).is_ok_and(|m| m.avatar_hash == Some(avatar.hash) && m.avatar_key == Some(avatar.key));
                if !known {
                    stored(c.store().update_member_avatar(&server_id, &fingerprint, &avatar.hash, &avatar.key), "announced avatar not kept");
                }
            }
            if avatars::fetch_if_missing(&session.client, &session.relay, &session.data_dir, &server_id, &fingerprint, &avatar.hash).await {
                session.sink.emit(ClientEvent::AvatarUpdated(fingerprint));
            }
        });
    }

    async fn rebroadcast_presence(&self, mailbox_id: &[u8; 32]) {
        let info = self.presence.lock().await.clone();
        flows::presence::broadcast_to_mailbox(&self.client, &self.relay, mailbox_id, &info).await;
    }

    async fn set_last_seen(&self, mailbox_id: &[u8; 32], seq: u64) {
        stored(self.client.lock().await.store().set_last_seen_seq(mailbox_id, seq), "last seen seq not kept");
    }

    #[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
    async fn handle_event(&self, event: RelayEvent, sync_mailbox: [u8; 32], state: &mut LoopState) {
        match event {
            RelayEvent::Blob(blob) if blob.mailbox_id == sync_mailbox => self.handle_sync_blob(blob, state).await,
            RelayEvent::Blob(blob) => {
                self.handle_blob(blob, state).await;
                // A server commit may have released held-back private channel blobs, and
                // private channel rejoins waiting for it.
                let ready = state.deferred.take_ready(&*self.client.lock().await);
                state.requeued.extend(ready);
                self.resume_waiting_recoveries(state).await;
            }
            RelayEvent::Ack(ack) => self.message_acked(&ack).await,
            RelayEvent::Error { mailbox_id, status, message, message_id } => {
                self.message_refused(mailbox_id, status, &message, message_id, state).await;
            }
            RelayEvent::SendLost { message_id, .. } => self.message_lost(message_id).await,
            // The sync mailbox missed messages the snapshots carry; it keeps a resume point
            // per relay.
            RelayEvent::Gap { mailbox_id, relay_url, head } if mailbox_id == sync_mailbox => {
                stored(self.client.lock().await.store().set_last_seen_seq_at(&mailbox_id, &relay_url, head), "gap's resume point not kept");
                let merger = self.clone();
                self.spawn(async move { merger.merge_sync_snapshots().await });
            }
            RelayEvent::Gap { mailbox_id, head, .. } => self.history_gap(mailbox_id, head, state).await,
            // A relay refuses this device as revoked. The home's word is the account's;
            // any other relay's is a claim the account check corroborates before this
            // device gives up on itself.
            RelayEvent::DeviceRevoked { mailbox_id, relay_url, cause } => {
                if same_relay(&relay_url, &self.relay.base_url()) {
                    self.this_device_removed(cause, state);
                } else {
                    tracing::warn!("relay {relay_url} refuses this device as revoked; asking the home");
                    state.revocation_claims.entry(relay_url).or_default().insert(mailbox_id);
                    self.request_account_check(state);
                }
            }
            // The home not knowing this device means the account moved or the device was
            // removed, which the account check settles; another relay not knowing it may
            // lack the device in its copy of the log.
            RelayEvent::Unauthorized { mailbox_id, relay_url } => {
                if same_relay(&relay_url, &self.relay.base_url()) {
                    self.request_account_check(state);
                } else {
                    self.not_admitted(mailbox_id, relay_url, sync_mailbox, state).await;
                }
            }
            RelayEvent::Refused { mailbox_id, relay_url } => self.not_admitted(mailbox_id, relay_url, sync_mailbox, state).await,
            RelayEvent::Removed { mailbox_id, .. } => self.closed_as_removed(mailbox_id, state).await,
            RelayEvent::ChannelsChanged { mailbox_id } => {
                let server_id = self.client.lock().await.server_id_for_mailbox(&mailbox_id);
                if let Some(server_id) = server_id {
                    self.spawn_join_private_channels(server_id);
                }
            }
            RelayEvent::VoiceState { mailbox_id, json } => {
                let events = state.voice.apply(&*self.client.lock().await, &mailbox_id, &json);
                events.into_iter().for_each(|e| self.emit(e));
            }
            RelayEvent::Presence { mailbox_id, json } => {
                let update = state.online.apply(&*self.client.lock().await, &mailbox_id, &json, flows::now_millis());
                update.events.into_iter().for_each(|e| self.emit(e));
                for (server_id, fingerprint, avatar) in update.avatars {
                    self.spawn_take_announced_avatar(server_id, fingerprint, avatar);
                }
            }
            // Every blob of the catch-up came before this, and was handled or queued.
            RelayEvent::CaughtUp { mailbox_id, relay_url } => {
                if state.catching_up.remove(&(mailbox_id, relay_url)) {
                    self.emit(ClientEvent::RelayConnectivity(state.connectivity(sync_mailbox, &self.relay.base_url())));
                }
            }
            RelayEvent::ConnectionState { mailbox_id, relay_url, connected } => {
                let home_url = self.relay.base_url();
                let at_home = same_relay(&relay_url, &home_url);
                if connected {
                    // Admitted again: whatever refused it before is over.
                    state.admission_repairs.remove(&(mailbox_id, relay_url.clone()));
                    if let Some(refused) = state.refusing.get_mut(&relay_url) {
                        refused.remove(&mailbox_id);
                        if refused.is_empty() {
                            state.refusing.remove(&relay_url);
                        }
                    }
                }
                if connected {
                    state.catching_up.insert((mailbox_id, relay_url.clone()));
                } else {
                    state.catching_up.remove(&(mailbox_id, relay_url.clone()));
                }
                state.links.insert((mailbox_id, relay_url), connected);
                if connected {
                    self.rebroadcast_presence(&mailbox_id).await;
                    if mailbox_id != sync_mailbox {
                        self.resend_pending(&mailbox_id).await;
                        // A name or avatar change the server missed is told now.
                        let server_id = self.client.lock().await.server_id_for_server_mailbox(&mailbox_id);
                        if let Some(server_id) = server_id {
                            let session = self.session.clone();
                            self.spawn(async move {
                                flows::profile::tell_owed(&session.client, &session.relay, &session.data_dir, &server_id).await;
                            });
                        }
                    }
                    // On (re)connecting the sync mailbox on any sync relay, catch up from the
                    // snapshots; the mailbox replays what that relay holds.
                    if mailbox_id == sync_mailbox {
                        let runner = self.clone();
                        self.spawn(async move { runner.merge_sync_snapshots().await });
                        // A removal still waiting for the home is said again.
                        let (client, relay) = (self.client.clone(), self.relay.clone());
                        self.spawn(async move { flows::sync::repeat_pauses(&client, &relay).await });
                        // The home is back after an outage: the account's log too, which
                        // finishes removals made while it was away and settles any relay's
                        // claim that this device is revoked.
                        if at_home && !state.home_key_known {
                            self.ask_home_key(state);
                        }
                        if at_home && (std::mem::take(&mut state.home_lost) || !state.revocation_claims.is_empty()) {
                            self.request_account_check(state);
                        }
                    }
                } else if mailbox_id == sync_mailbox && at_home {
                    state.home_lost = true;
                }
                self.emit(ClientEvent::RelayConnectivity(state.connectivity(sync_mailbox, &home_url)));
            }
        }
    }

    /// What a task reported back.
    async fn handle_report(&self, report: Report, sync_mailbox: [u8; 32], state: &mut LoopState) {
        match report {
            Report::MemberFetched { blob, held, fetched } => {
                let mailbox_id = blob.mailbox_id;
                self.resume_blob(blob, held, fetched, state).await;
                state.release(mailbox_id);
                let ready = state.deferred.take_ready(&*self.client.lock().await);
                state.requeued.extend(ready);
                self.resume_waiting_recoveries(state).await;
            }
            Report::AccountChecked(check) => self.account_checked(check, sync_mailbox, state),
            Report::ReopenRefusedMailboxes { relay_url, mailboxes } => self.reopen_refused_mailboxes(&relay_url, &mailboxes, state).await,
            Report::GroupRecovered { mailbox_id, outcome } => {
                state.recovering.remove(&mailbox_id);
                state.release(mailbox_id);
                match outcome {
                    // A rejoin moved this device's epoch like any commit it took in.
                    Rejoin::Rejoined => {
                        let server_id = self.client.lock().await.server_id_for_mailbox(&mailbox_id);
                        if let Some(server_id) = server_id {
                            self.after_epoch_change(&server_id, &mailbox_id, state).await;
                        }
                    }
                    Rejoin::NotRejoined => {}
                    // Past retention the removing commit is gone; the relay's refusal tells.
                    Rejoin::Removed => self.closed_as_removed(mailbox_id, state).await,
                    Rejoin::WaitsForServer { server_mailbox, epoch } => {
                        state.recoveries_waiting.insert(mailbox_id, (server_mailbox, epoch, std::time::Instant::now()));
                    }
                }
            }
            Report::RemovedElsewhere { server_id, by } => {
                self.server_removed(server_id, by, flows::now_millis(), Tell::Nobody, state).await;
            }
            Report::HomeKey(answer) => {
                state.home_key_asked = false;
                match answer {
                    Ok(vk) => {
                        // A move followed meanwhile set the new home's key already.
                        let mut c = self.client.lock().await;
                        if c.relay_vk().is_none() {
                            c.set_relay_vk(vk);
                        }
                        drop(c);
                        state.home_key_known = true;
                        if std::mem::take(&mut state.account_check_waits_for_home_key) {
                            self.request_account_check(state);
                        }
                    }
                    // Asked again when the home's sync connection comes up or the next check is due.
                    Err(e) => tracing::warn!("the home relay's key was not read: {e}"),
                }
            }
            Report::ProposalsCommitted { mailbox_id, outcome } => {
                state.committing.remove(&mailbox_id);
                state.release(mailbox_id);
                match outcome {
                    ProposalCommit::Done => {
                        state.proposal_retries.remove(&mailbox_id);
                    }
                    ProposalCommit::Retry => {
                        if let Some(retry) = state.proposal_retries.get_mut(&mailbox_id) {
                            retry.attempts += 1;
                            if retry.attempts >= PROPOSAL_RETRY_LIMIT {
                                tracing::error!("relay: giving up committing queued proposals on {}", short_id(&mailbox_id));
                                state.proposal_retries.remove(&mailbox_id);
                            }
                        }
                    }
                }
            }
        }
    }

    async fn handle_blob(&self, blob: IncomingBlob, state: &mut LoopState) {
        let mailbox_id = blob.mailbox_id;

        // Later blobs of a mailbox wait behind one already held back.
        if state.deferred.is_waiting(&mailbox_id) {
            tracing::debug!("blob seq={} on {}: queued behind a deferred one", blob.seq, short_id(&mailbox_id));
            state.deferred.queue(blob);
            return;
        }
        if let Some(busy) = state.busy.get_mut(&mailbox_id) {
            tracing::debug!("blob seq={} on {}: queued while the mailbox is busy", blob.seq, short_id(&mailbox_id));
            busy.blobs.push_back(blob);
            return;
        }

        let (server_id, group_channel, result) = {
            let mut c = self.client.lock().await;
            match (c.channel_id_for_mailbox(&mailbox_id), c.server_id_for_mailbox(&mailbox_id)) {
                (Some(cid), Some(sid)) => {
                    tracing::debug!("blob seq={} on {} from {}: {} bytes", blob.seq, short_id(&mailbox_id), blob.relay_url, blob.payload.len());
                    let origin = BlobOrigin { mailbox_id, seq: blob.seq };
                    (sid, cid, c.receive_at(&cid, &blob.payload, blob.received_at, origin))
                }
                _ => {
                    // A subscription that outlived its channel would replay the same blobs
                    // on every reconnect.
                    tracing::debug!("blob seq={} on {}: no channel here for that mailbox; closing it", blob.seq, short_id(&mailbox_id));
                    self.relay.unsubscribe(&mailbox_id);
                    return;
                }
            }
        };

        // A device this client's identity log does not list yet: fetch its account's log
        // from the server's relay, off the loop, then process a commit again or settle a
        // message that was held (its key is spent, so it cannot be opened twice).
        match result {
            Err(GhostError::UnknownDevice { account_fp }) => {
                tracing::debug!("blob seq={} on {}: from a device of {} this client has not seen; fetching its log", blob.seq, short_id(&mailbox_id), short_id(&account_fp));
                self.fetch_member_for(blob, server_id, account_fp, HeldBlob::Receive, state);
            }
            Ok(ReceiveResult::Unverified { message, claim, received_at }) => {
                let account_fp = claim.account_fp;
                tracing::debug!("blob seq={} on {}: held until {}'s log is fetched", blob.seq, short_id(&mailbox_id), short_id(&account_fp));
                self.fetch_member_for(blob, server_id, account_fp, HeldBlob::Unverified { message, claim, received_at }, state);
            }
            other => self.finish_blob(blob, server_id, group_channel, other, state).await,
        }
    }

    /// Hold the blob's mailbox while the sender's account log is fetched.
    fn fetch_member_for(&self, blob: IncomingBlob, server_id: [u8; 32], account_fp: [u8; 32], held: HeldBlob, state: &mut LoopState) {
        state.hold(blob.mailbox_id);
        let runner = self.clone();
        self.spawn_reporting(async move {
            let fetched = flows::idlog::refresh_member(&runner.client, &runner.relay, &server_id, &account_fp).await;
            Report::MemberFetched { blob, held, fetched }
        });
    }

    /// Go on with a blob whose sender's log was fetched. A sender the log still does not
    /// list is not waited for again: its blob fails like any other.
    async fn resume_blob(&self, blob: IncomingBlob, held: HeldBlob, fetched: bool, state: &mut LoopState) {
        let (server_id, group_channel, result) = {
            let mut c = self.client.lock().await;
            let (Some(cid), Some(sid)) = (c.channel_id_for_mailbox(&blob.mailbox_id), c.server_id_for_mailbox(&blob.mailbox_id)) else {
                return;
            };
            let origin = BlobOrigin { mailbox_id: blob.mailbox_id, seq: blob.seq };
            let result = match held {
                HeldBlob::Receive => c.receive_at(&cid, &blob.payload, blob.received_at, origin),
                HeldBlob::Unverified { message, claim, received_at } if fetched => c.accept_unverified(message, &claim, received_at, Some(origin)),
                HeldBlob::Unverified { .. } => Err(GhostError::IdentityLog("the sender's identity log could not be fetched".into())),
            };
            (sid, cid, result)
        };
        tracing::debug!(
            "blob seq={} on {}: resumed after the sender's log fetch (fetched={fetched}): {}",
            blob.seq,
            short_id(&blob.mailbox_id),
            if result.is_ok() { "processed" } else { "failed" }
        );
        self.finish_blob(blob, server_id, group_channel, result, state).await;
    }

    /// What a processed blob leads to.
    async fn finish_blob(
        &self,
        blob: IncomingBlob,
        server_id: [u8; 32],
        group_channel: [u8; 32],
        result: Result<ReceiveResult, GhostError>,
        state: &mut LoopState,
    ) {
        let (mailbox_id, seq, received_at) = (blob.mailbox_id, blob.seq, blob.received_at);

        // A private channel commit authorized at a server epoch this device has not
        // reached: hold it (and what follows it) until the server group catches up.
        if let Err(GhostError::PolicyBehind { server_mailbox, epoch }) = &result {
            // A server this account is out of never catches up: nothing more is read there.
            if self.client.lock().await.removed_from(&server_id).ok().flatten().is_some() {
                self.set_last_seen(&mailbox_id, seq).await;
                return;
            }
            let (server_mailbox, epoch) = (*server_mailbox, *epoch);
            state.deferred.hold(blob, server_mailbox, epoch);
            return;
        }
        if result.is_ok() {
            state.consecutive_errors.remove(&mailbox_id);
        }

        match result {
            Ok(ReceiveResult::Message(msg)) if msg.message_type == MessageType::Metadata => {
                self.check_head_claim(server_id, &msg).await;
                self.apply_metadata(server_id, group_channel, mailbox_id, seq, msg).await;
            }
            Ok(ReceiveResult::Message(message)) => {
                self.check_head_claim(server_id, &message).await;
                self.emit(ClientEvent::Message { message, received_at });
                self.set_last_seen(&mailbox_id, seq).await;
            }
            Ok(ReceiveResult::CommitProcessed) => {
                self.set_last_seen(&mailbox_id, seq).await;
                let server_group = group_channel == derive_default_channel_id(&server_id);
                if server_group {
                    self.record_new_members(&server_id, received_at).await;
                }
                self.spawn_publish_server_info(mailbox_id);
                // A server commit may have granted access to private channels.
                if server_group {
                    self.spawn_join_private_channels(server_id);
                }
                self.after_epoch_change(&server_id, &mailbox_id, state).await;
            }
            Ok(ReceiveResult::Kicked { by }) => {
                self.set_last_seen(&mailbox_id, seq).await;
                self.server_removed(server_id, Some(by), received_at, Tell::OtherDevices, state).await;
            }
            Ok(ReceiveResult::DeviceRemoved) => {
                // This device was revoked; the account's other devices are still members,
                // so nothing goes to sync.
                self.set_last_seen(&mailbox_id, seq).await;
                self.emit(ClientEvent::Kicked(server_id));
            }
            Ok(ReceiveResult::MembersRemoved(removed)) => {
                {
                    let c = self.client.lock().await;
                    stored(c.store().set_last_seen_seq(&mailbox_id, seq), "last seen seq not kept");
                    // Leaving a private channel does not end server membership.
                    if group_channel == derive_default_channel_id(&server_id) {
                        for fp in &removed {
                            stored(c.store().remove_member(&server_id, fp), "member not removed");
                        }
                    }
                }
                self.spawn_publish_server_info(mailbox_id);
                self.after_epoch_change(&server_id, &mailbox_id, state).await;
            }
            Ok(ReceiveResult::ProposalProcessed) => {
                self.set_last_seen(&mailbox_id, seq).await;
                state
                    .proposal_retries
                    .entry(mailbox_id)
                    .or_insert(ProposalRetry { server_id, channel_id: group_channel, attempts: 0 });
                self.start_proposal_commit(server_id, group_channel, mailbox_id, state);
            }
            Ok(ReceiveResult::ChannelAccessLost(_)) => {
                // Removed from a private channel; the server membership stands.
                self.set_last_seen(&mailbox_id, seq).await;
                self.relay.unsubscribe(&mailbox_id);
                self.emit(ClientEvent::ServerChanged(ServerScope::One(server_id)));
            }
            Ok(ReceiveResult::Unreadable) => {
                self.stand_in_for(&blob, group_channel).await;
                self.set_last_seen(&mailbox_id, seq).await;
            }
            Ok(ReceiveResult::Skipped) => self.set_last_seen(&mailbox_id, seq).await,
            // A held blob processed again after a fetch that still does not list its sender:
            // its key is spent, so it stands in, as one that could not be verified.
            Ok(ReceiveResult::Unverified { .. }) => {
                tracing::warn!("relay: blob seq={seq} on {}: its sender could not be checked", short_id(&mailbox_id));
                self.stand_in_for(&blob, group_channel).await;
                self.set_last_seen(&mailbox_id, seq).await;
            }
            Err(e) => {
                tracing::warn!("relay: blob seq={seq} on {} not processed: {e}", short_id(&mailbox_id));
                self.unprocessed_blob(&blob, group_channel, &e, state).await;
                self.set_last_seen(&mailbox_id, seq).await;
            }
        }
    }

    /// Judge the head a message's sender claims for its own identity log. A head this
    /// device's copy lacks is most often this device being behind, so the log is fetched
    /// again, off the loop, before a fork is reported.
    async fn check_head_claim(&self, server_id: [u8; 32], message: &ApplicationMessage) {
        let (account_fp, claimed) = (message.sender_fp, message.kt_head_hash);
        if self.client.lock().await.judge_head(&account_fp, &claimed) != HeadClaim::Fork {
            return;
        }
        if self.split_views.0.lock().unwrap().contains(&account_fp) {
            return;
        }
        let session = self.session.clone();
        self.spawn(async move {
            // A fetch that failed judges nothing; the sender's next message asks again.
            if !flows::idlog::refresh_member(&session.client, &session.relay, &server_id, &account_fp).await {
                return;
            }
            if session.client.lock().await.judge_head(&account_fp, &claimed) != HeadClaim::Fork {
                return;
            }
            if session.split_views.0.lock().unwrap().insert(account_fp) {
                session.sink.emit(ClientEvent::SplitView { server_id, account_fp });
            }
        });
    }

    /// A message this device cannot read stands in the channel's history, so nothing is
    /// lost without a trace.
    async fn stand_in_for(&self, blob: &IncomingBlob, group_channel: [u8; 32]) {
        let stored = self.client.lock().await.store_undecryptable(&group_channel, &blob.mailbox_id, blob.seq, blob.received_at);
        match stored {
            Ok(message) => self.emit(ClientEvent::Message { message, received_at: blob.received_at }),
            Err(e) => tracing::error!("relay: no stand-in for blob seq={} on {}: {e}", blob.seq, short_id(&blob.mailbox_id)),
        }
    }

    /// A blob this device could not process. What it carried and the epoch it names
    /// decide what follows: a blob from an epoch past this device's means the group
    /// moved on without it, as does a commit it could not apply, so it rejoins at the
    /// relay's epoch; a message it should have read stands in the channel's history;
    /// and messages of its own epoch failing in a row mean its own group state is off,
    /// which a rejoin also mends.
    async fn unprocessed_blob(&self, blob: &IncomingBlob, group_channel: [u8; 32], error: &GhostError, state: &mut LoopState) {
        // The rules this device holds forbid a commit the relay accepted: keep the copy
        // from before it and let the person decide. Nothing follows the relay on its own.
        if let GhostError::PolicyRefused(reason) = error {
            self.halt_server(&blob.mailbox_id, reason).await;
            return;
        }
        let envelope = ghost_wire::decode_envelope(&blob.payload).ok();
        let (own_epoch, halted) = {
            let c = self.client.lock().await;
            let halted = c.server_id_for_mailbox(&blob.mailbox_id).and_then(|s| c.halt(&s).ok().flatten()).is_some();
            (c.channel_epoch(&group_channel).ok(), halted)
        };
        let past_own_epoch = matches!((envelope, own_epoch), (Some((_, epoch)), Some(own)) if epoch > own);
        let kind = envelope.map(|(kind, _)| kind);
        let is_message = kind.is_none_or(|kind| kind == EnvelopeType::Application);
        let effects = unprocessed_effects(is_message, envelope.is_some() && !past_own_epoch, error);
        if effects.stand_in {
            self.stand_in_for(blob, group_channel).await;
        }
        // A halted server is never followed on its own: what cannot be read stands in.
        if halted {
            return;
        }
        let own_epoch_failures = if effects.counts_against_own_state {
            let count = state.consecutive_errors.entry(blob.mailbox_id).or_insert(0);
            *count += 1;
            *count
        } else {
            0
        };
        if past_own_epoch || kind == Some(EnvelopeType::Commit) || own_epoch_failures >= EPOCH_RECOVERY_ERROR_THRESHOLD {
            state.consecutive_errors.remove(&blob.mailbox_id);
            self.start_recovery(blob.mailbox_id, state);
        }
    }

    /// Stop following the mailbox's server: the first refusal is recorded and reported;
    /// later ones only log.
    async fn halt_server(&self, mailbox_id: &[u8; 32], reason: &str) {
        let (server_id, first) = {
            let c = self.client.lock().await;
            let Some(server_id) = c.server_id_for_mailbox(mailbox_id) else { return };
            let first = c.halt(&server_id).ok().flatten().is_none();
            stored(c.store().halt_server(&server_id, reason, flows::now_millis()), "server halt not kept");
            (server_id, first)
        };
        if first {
            tracing::warn!("server {}: its relay accepted a change the rules forbid ({reason}); read-only until the person decides", short_id(&server_id));
            self.emit(ClientEvent::ServerHalted { server_id, reason: reason.to_string() });
        }
    }

    /// After this device's epoch moved in a server's group: re-announce presence there,
    /// retry presence blobs sealed at the new epoch, send again what the relay refused
    /// as sealed too far back, and report the change.
    async fn after_epoch_change(&self, server_id: &[u8; 32], mailbox_id: &[u8; 32], state: &mut LoopState) {
        state.stale_refusals.remove(mailbox_id);
        self.rearm_proposal_commits(server_id, state).await;
        self.rebroadcast_presence(mailbox_id).await;
        let events = {
            let c = self.client.lock().await;
            let mut events = state.online.retry_pending(&c, server_id, flows::now_millis());
            // Voice presence goes over the server's own mailbox, whichever group carries the call.
            if let Some(server_mailbox) = c.mailbox_id_for_server(server_id) {
                events.extend(state.voice.retry_pending(&c, &server_mailbox));
            }
            events
        };
        events.into_iter().for_each(|e| self.emit(e));
        self.resend_pending(mailbox_id).await;
        self.emit(ClientEvent::ServerChanged(ServerScope::One(*server_id)));
    }

    async fn set_message_delivery(&self, message_id: [u8; 32], delivery: Delivery) {
        if let Err(e) = self.client.lock().await.store().set_delivery(&message_id, delivery) {
            tracing::error!("message delivery not recorded: {e}");
        }
    }

    /// The relay took a posted blob; a chat message it carried is delivered.
    async fn message_acked(&self, ack: &Ack) {
        let Some(message_id) = ack.message_id else { return };
        self.set_message_delivery(message_id, Delivery::Delivered).await;
        self.emit(ClientEvent::MessageDelivered { message_id });
    }

    /// The connection a chat message was posted on ended before the relay answered: the
    /// message is pending again and goes out when the mailbox reconnects.
    async fn message_lost(&self, message_id: [u8; 32]) {
        self.set_message_delivery(message_id, Delivery::Pending).await;
    }

    /// The relay refused a posted blob. A chat message sealed at an epoch the group has
    /// left stays pending and goes again once this device catches up; any other refusal
    /// is final, for the user to retry.
    async fn message_refused(&self, mailbox_id: [u8; 32], status: u16, message: &str, message_id: Option<[u8; 32]>, state: &mut LoopState) {
        let Some(message_id) = message_id else {
            tracing::warn!("relay: refused a blob on {}: {status} {message}", short_id(&mailbox_id));
            return;
        };
        if status == 409 {
            self.set_message_delivery(message_id, Delivery::Pending).await;
            // Catching up resends it; a group that does not move is rejoined.
            let epoch = {
                let c = self.client.lock().await;
                c.channel_id_for_mailbox(&mailbox_id).and_then(|channel_id| c.channel_epoch(&channel_id).ok())
            };
            if let Some(epoch) = epoch {
                state.stale_refusals.entry(mailbox_id).or_insert((epoch, std::time::Instant::now()));
            }
            return;
        }
        if let Err(e) = self.client.lock().await.store().set_delivery(&message_id, Delivery::Failed) {
            tracing::error!("message failure not recorded: {e}");
        }
        self.emit(ClientEvent::MessageFailed { message_id, reason: message.to_string() });
    }

    /// Send this device's unacknowledged messages for a mailbox again, oldest first,
    /// each sealed at the group's current epoch. One the account can no longer send,
    /// because it was removed from the server, fails for good; any other refusal leaves
    /// the message pending for the next connection or epoch.
    async fn resend_pending(&self, mailbox_id: &[u8; 32]) {
        let pending = match self.client.lock().await.pending_messages_for_mailbox(mailbox_id) {
            Ok(pending) => pending,
            Err(e) => {
                tracing::warn!("pending messages of {} not read: {e}", short_id(mailbox_id));
                return;
            }
        };
        for message in pending {
            match flows::messages::resend(&self.client, &self.relay, message.message_id).await {
                Ok(_) => {}
                Err(GhostError::RemovedFromServer) => {
                    self.set_message_delivery(message.message_id, Delivery::Failed).await;
                    self.emit(ClientEvent::MessageFailed {
                        message_id: message.message_id,
                        reason: "you were removed from this server before it was sent".into(),
                    });
                }
                Err(e) => tracing::warn!("message {} not sent again: {e}", short_id(&message.message_id)),
            }
        }
    }

    /// Record members a commit added to the server group (an external join). Their
    /// identity logs are fetched when their devices first speak.
    async fn record_new_members(&self, server_id: &[u8; 32], joined_at: u64) {
        let c = self.client.lock().await;
        let Ok(in_group) = c.mls_member_fingerprints(server_id) else { return };
        let known: HashSet<[u8; 32]> = c.store().list_members(server_id).unwrap_or_default().iter().map(|m| m.fingerprint).collect();
        for fp in in_group.into_iter().filter(|fp| !known.contains(fp)) {
            let member = Member {
                server_id: *server_id,
                fingerprint: fp,
                display_name: placeholder_name(&fp),
                joined_at,
                avatar_hash: None,
                avatar_key: None,
            };
            stored(c.store().insert_member(&member, OnConflict::Fail), "new member not kept");
        }
    }

    /// After a commit in a server, try again to commit the proposals still queued in any
    /// of its groups that no retry covers: a commit this device's view could not justify
    /// before (its server group behind, or the target's log not read) may be justified now.
    async fn rearm_proposal_commits(&self, server_id: &[u8; 32], state: &mut LoopState) {
        let waiting = self.client.lock().await.groups_awaiting_proposals(server_id);
        for (channel_id, mailbox_id) in waiting {
            if state.proposal_retries.contains_key(&mailbox_id) {
                continue;
            }
            state.proposal_retries.insert(mailbox_id, ProposalRetry { server_id: *server_id, channel_id, attempts: 0 });
            self.start_proposal_commit(*server_id, channel_id, mailbox_id, state);
        }
    }

    /// Commit a group's queued proposals (relay removals of revoked or excluded devices)
    /// off the loop, holding the mailbox meanwhile: a commit of this device's own is
    /// pending in the group until the relay answers. Every member's device tries; the
    /// relay takes the first and refuses the rest, whose devices then see the winner's.
    fn start_proposal_commit(&self, server_id: [u8; 32], channel_id: [u8; 32], mailbox_id: [u8; 32], state: &mut LoopState) {
        if !state.committing.insert(mailbox_id) {
            return;
        }
        state.hold(mailbox_id);
        let runner = self.clone();
        self.spawn_reporting(async move {
            // The logs of the accounts the proposals would remove, so the removals can be
            // judged against their revocations.
            let accounts = runner.client.lock().await.pending_removal_accounts(&channel_id);
            for account_fp in accounts {
                if runner.client.lock().await.cached_head(&account_fp).is_none() {
                    flows::idlog::refresh_member(&runner.client, &runner.relay, &server_id, &account_fp).await;
                }
            }
            let outcome = runner.commit_pending_proposals(server_id, channel_id, mailbox_id).await;
            Report::ProposalsCommitted { mailbox_id, outcome }
        });
    }

    async fn commit_pending_proposals(&self, server_id: [u8; 32], channel_id: [u8; 32], mailbox_id: [u8; 32]) -> ProposalCommit {
        let outbound = {
            let mut c = self.client.lock().await;
            c.commit_pending_proposals(&channel_id).map(|out| (out, c.awaiting_proposals(&channel_id)))
        };
        let out = match outbound {
            Ok((Some(out), _)) => out,
            // A removal this device's view cannot justify yet (e.g. its own policy commit
            // is not merged) may be committable once it catches up.
            Ok((None, true)) => return ProposalCommit::Retry,
            Ok((None, false)) => return ProposalCommit::Done,
            // The proposals stay queued: tried again, like a removal not justified yet.
            Err(e) => {
                tracing::warn!("relay: failed to build pending commit: {e}");
                return ProposalCommit::Retry;
            }
        };
        let posted = self.relay.post_blob(&out.mailbox_id, out.blob).await;
        match posted {
            Ok(_) => {
                let _ = self.client.lock().await.merge_pending_commit_for_channel(&channel_id);
                flows::publish_server_info(&self.client, &self.relay, &mailbox_id).await;
                self.rebroadcast_presence(&mailbox_id).await;
                self.emit(ClientEvent::ServerChanged(ServerScope::One(server_id)));
                ProposalCommit::Done
            }
            Err(e) => {
                let _ = self.client.lock().await.clear_pending_commit_for_channel(&channel_id);
                if matches!(e, GhostError::RelayStatus { status: 409, .. }) {
                    ProposalCommit::Retry
                } else {
                    tracing::warn!("relay: failed to post pending commit: {e}");
                    ProposalCommit::Done
                }
            }
        }
    }

    async fn apply_metadata(
        &self,
        server_id: [u8; 32],
        group_channel: [u8; 32],
        mailbox_id: [u8; 32],
        seq: u64,
        msg: crate::wire::ApplicationMessage,
    ) {
        let mut fetch_avatar = None;
        let mut own_name_changed = false;
        // Another device of this account changed the avatar: `Some(None)` took it down.
        let mut own_avatar = None;
        let mut server_move = None;
        let mut reply = None;
        let mut ask_state_again = false;
        let in_server_group = group_channel == derive_default_channel_id(&server_id);
        match decode_metadata(&msg.content) {
            Ok(payload) => {
                let mut c = self.client.lock().await;
                // What the metadata changes and the blob marked seen land together: a
                // restart replaying a blob whose key is spent would make it a stand-in.
                stored(c.store().begin_whole(), "metadata write not begun");
                match payload {
                    // Who may change channels comes from the server policy, checked in the client.
                    MetadataPayload::ChannelOp(op) => match c.apply_channel_op(&group_channel, &msg.sender_fp, op) {
                        Ok(ChannelOpOutcome::Reply(out)) => reply = Some(out),
                        // A server state as of before this change would undo it.
                        Ok(ChannelOpOutcome::Applied) if in_server_group => {
                            stored(c.store().note_server_change(&server_id, seq), "server change not noted");
                        }
                        Ok(_) => {}
                        Err(e) => tracing::warn!("channel op: {e}"),
                    },
                    MetadataPayload::RoleNames(names) => match c.apply_role_names(&server_id, &msg.sender_fp, &names) {
                        Ok(true) => stored(c.store().note_server_change(&server_id, seq), "server change not noted"),
                        Ok(false) => {}
                        Err(e) => tracing::warn!("role names: {e}"),
                    },
                    // A joiner asks; a member who may manage channels answers, as of the request.
                    MetadataPayload::ServerStateRequest if in_server_group => match c.server_state_reply(&server_id, seq) {
                        Ok(answer) => reply = answer,
                        Err(e) => tracing::warn!("server state not answered: {e}"),
                    },
                    MetadataPayload::ServerState(state) if in_server_group => match c.apply_server_state(&server_id, &msg.sender_fp, state) {
                        Ok(ServerStateOutcome::Stale) => ask_state_again = true,
                        Ok(_) => {}
                        Err(e) => tracing::warn!("server state not taken in: {e}"),
                    },
                    MetadataPayload::ServerStateRequest | MetadataPayload::ServerState(_) => {}
                    MetadataPayload::MemberAnnounce { display_name } => {
                        stored(c.store().update_member_name(&server_id, &msg.sender_fp, &display_name), "member name not kept");
                        if msg.sender_fp == *c.fingerprint() {
                            c.set_display_name(display_name);
                            own_name_changed = true;
                        }
                    }
                    MetadataPayload::AvatarUpdate { avatar_hash, avatar_key } => {
                        stored(c.store().update_member_avatar(&server_id, &msg.sender_fp, &avatar_hash, &avatar_key), "avatar not kept");
                        fetch_avatar = Some(avatar_hash);
                        if msg.sender_fp == *c.fingerprint() {
                            own_avatar = Some(Some(crate::mls::presence::AvatarRef { hash: avatar_hash, key: avatar_key }));
                        }
                    }
                    MetadataPayload::AvatarClear => {
                        stored(c.store().clear_member_avatar(&server_id, &msg.sender_fp), "avatar not cleared");
                        avatars::clear(&self.data_dir, &msg.sender_fp);
                        self.emit(ClientEvent::AvatarCleared(msg.sender_fp));
                        if msg.sender_fp == *c.fingerprint() {
                            own_avatar = Some(None);
                        }
                    }
                    MetadataPayload::ServerMoved(location) => {
                        // Only the owner may move a server; the record is verified when followed.
                        if c.server_owner(&server_id).is_ok_and(|owner| owner == msg.sender_fp) {
                            server_move = Some(location);
                        }
                    }
                }
                stored(c.store().set_last_seen_seq(&mailbox_id, seq), "last seen seq not kept");
                stored(c.store().end_whole(), "metadata write not landed");
            }
            // Its key is spent: replayed, it could only stand in. A kind of metadata from a
            // newer app has nothing to change here.
            Err(e) => {
                tracing::warn!("decode metadata: {e}");
                self.set_last_seen(&mailbox_id, seq).await;
            }
        }
        if let Some(out) = reply {
            if let Err(e) = self.relay.send(&out.mailbox_id, out.blob) {
                tracing::warn!("metadata reply not sent: {e}");
            }
        }
        if ask_state_again {
            let session = self.session.clone();
            self.spawn(async move { flows::invite::ask_server_state(&session.client, &session.relay, &server_id).await });
        }
        if let Some(hash) = fetch_avatar {
            self.spawn_fetch_avatar(server_id, msg.sender_fp, hash);
        }
        if let Some(location) = server_move {
            let session = self.session.clone();
            self.spawn(async move {
                match flows::server::follow_move(&session.client, &session.relay, &server_id, &location).await {
                    Ok(true) => tracing::info!("server {} moved to another relay", short_id(&server_id)),
                    Ok(false) => {}
                    Err(e) => tracing::warn!("server move not followed: {e}"),
                }
            });
        }
        if own_name_changed {
            self.emit(ClientEvent::DisplayNameSynced);
        }
        // This device announces the account's avatar as it is now, not the one it had.
        if let Some(avatar) = own_avatar {
            let info = {
                let mut p = self.presence.lock().await;
                let changed = p.avatar != avatar;
                p.avatar = avatar;
                changed.then(|| p.clone())
            };
            if let Some(info) = info {
                flows::presence::broadcast(&self.client, &self.relay, &info).await;
            }
        }
        self.emit(ClientEvent::ServerChanged(ServerScope::One(server_id)));
    }

    /// Rejoin the group of a mailbox this device fell out of step with (a gap past the
    /// relay's retention, or repeated errors), off the loop, holding the mailbox until
    /// the rejoin is settled either way.
    fn start_recovery(&self, mailbox_id: [u8; 32], state: &mut LoopState) {
        // A private channel waiting for its server group is rejoined once that arrives.
        if state.recoveries_waiting.contains_key(&mailbox_id) || !state.recovering.insert(mailbox_id) {
            return;
        }
        state.hold(mailbox_id);
        let runner = self.clone();
        self.spawn_reporting(async move {
            let outcome = runner.recover_group(&mailbox_id).await;
            Report::GroupRecovered { mailbox_id, outcome }
        });
    }

    /// The relay no longer kept what this device had not read on a mailbox: the channel's
    /// history shows where, the mailbox resumes after `head`, and the group is rejoined,
    /// its state being from before what was missed.
    async fn history_gap(&self, mailbox_id: [u8; 32], head: u64, state: &mut LoopState) {
        let marker = {
            let c = self.client.lock().await;
            stored(c.store().set_last_seen_seq(&mailbox_id, head), "gap's resume point not kept");
            c.channel_id_for_mailbox(&mailbox_id).map(|channel_id| c.store_history_gap(&channel_id, &mailbox_id, head, flows::now_millis()))
        };
        match marker {
            Some(Ok(message)) => {
                let received_at = message.timestamp;
                self.emit(ClientEvent::Message { message, received_at });
            }
            Some(Err(e)) => tracing::warn!("mailbox {}: history gap not marked: {e}", short_id(&mailbox_id)),
            None => {}
        }
        self.start_recovery(mailbox_id, state);
    }

    /// Rejoin the private channels whose server group has now reached the epoch their
    /// rejoin waited for.
    async fn resume_waiting_recoveries(&self, state: &mut LoopState) {
        if state.recoveries_waiting.is_empty() {
            return;
        }
        let ready: Vec<[u8; 32]> = {
            let c = self.client.lock().await;
            state
                .recoveries_waiting
                .iter()
                .filter(|(_, (server_mailbox, epoch, _))| c.server_epoch_reached(server_mailbox, *epoch))
                .map(|(mailbox_id, _)| *mailbox_id)
                .collect()
        };
        for mailbox_id in ready {
            state.recoveries_waiting.remove(&mailbox_id);
            self.start_recovery(mailbox_id, state);
        }
    }

    /// For a private channel: its server mailbox and the epoch the relay holds the server
    /// group at, when that is past this device's. `None` for a server group, or when the
    /// server group is current or the relay does not say.
    async fn server_group_ahead(&self, channel_id: &[u8; 32]) -> Option<([u8; 32], u64)> {
        let (server_mailbox, own_epoch) = {
            let c = self.client.lock().await;
            if !c.is_private_channel(channel_id) {
                return None;
            }
            let server_id = c.store().get_channel(channel_id).ok()?.server_id;
            (c.server_mailbox(&server_id).ok()?, c.channel_epoch(&derive_default_channel_id(&server_id)).ok()?)
        };
        let group_info = self.relay.get_server_info(&server_mailbox).await.ok()?;
        let relay_epoch = crate::mls::group::group_info_epoch(&group_info).ok()?;
        (relay_epoch > own_epoch).then_some((server_mailbox, relay_epoch))
    }

    /// Rejoin the group at the relay's epoch. A halted server is never rejoined on its own.
    async fn recover_group(&self, mailbox_id: &[u8; 32]) -> Rejoin {
        let Some(channel_id) = self.client.lock().await.channel_id_for_mailbox(mailbox_id) else { return Rejoin::NotRejoined };
        let halted = {
            let c = self.client.lock().await;
            c.server_id_for_mailbox(mailbox_id).and_then(|s| c.halt(&s).ok().flatten()).is_some()
        };
        if halted {
            return Rejoin::NotRejoined;
        }
        if let Some((server_mailbox, epoch)) = self.server_group_ahead(&channel_id).await {
            tracing::debug!("private channel {}: rejoin waits for its server group to reach epoch {epoch}", short_id(&channel_id));
            return Rejoin::WaitsForServer { server_mailbox, epoch };
        }
        match flows::epoch::recover(&self.client, &self.relay, &channel_id, mailbox_id, "gap recovery").await {
            Ok(true) => return Rejoin::Rejoined,
            Ok(false) => tracing::error!("gap recovery: failed after attempts"),
            Err(GhostError::RemovedFromServer) => return Rejoin::Removed,
            // Nothing to rejoin onto until a member publishes the group's state; the resume
            // point stands, since a relay whose log started over serves it from the start.
            Err(GhostError::RelayStatus { status: 404, .. }) => {
                tracing::warn!("gap recovery: the relay holds no group state for mailbox {}", short_id(mailbox_id));
            }
            Err(e) => tracing::error!("gap recovery: {e}"),
        }
        Rejoin::NotRejoined
    }

    /// The relay closed a mailbox because the account is out of its group: out of the
    /// server for its server group, out of the channel for a private channel. A removal
    /// this device already took in from the commit changes nothing.
    async fn closed_as_removed(&self, mailbox_id: [u8; 32], state: &mut LoopState) {
        let (server_id, private_channel) = {
            let c = self.client.lock().await;
            let Some(server_id) = c.server_id_for_mailbox(&mailbox_id) else { return };
            let private_channel = c.channel_id_for_mailbox(&mailbox_id).filter(|channel_id| c.is_private_channel(channel_id));
            (server_id, private_channel)
        };
        match private_channel {
            Some(channel_id) => {
                stored(self.client.lock().await.drop_private_channel(&channel_id), "lost private channel not dropped");
                self.relay.unsubscribe(&mailbox_id);
                state.deferred.forget(&mailbox_id);
                state.recoveries_waiting.remove(&mailbox_id);
                self.emit(ClientEvent::ServerChanged(ServerScope::One(server_id)));
            }
            None => self.server_removed(server_id, None, flows::now_millis(), Tell::OtherDevices, state).await,
        }
    }

    /// The account is out of the server: it stays listed, read-only, naming who removed it
    /// when known; nothing more is read from any of its mailboxes. A removal already known
    /// changes nothing unless it now learns who made it.
    async fn server_removed(&self, server_id: [u8; 32], by: Option<[u8; 32]>, at: u64, tell: Tell, state: &mut LoopState) {
        let mailboxes = {
            let c = self.client.lock().await;
            let known = c.removed_from(&server_id).ok().flatten();
            if known.is_some_and(|k| by.is_none() || k.by == by) {
                return;
            }
            stored(c.store().mark_server_removed(&server_id, by.as_ref(), at), "removal not kept");
            c.server_channel_mailboxes(&server_id)
        };
        for (_, mailbox_id) in &mailboxes {
            self.relay.unsubscribe(mailbox_id);
            state.deferred.forget(mailbox_id);
            state.recoveries_waiting.remove(mailbox_id);
        }
        if tell == Tell::OtherDevices {
            // The server's entry now says the account is out, for the other devices.
            flows::sync::server_entry(&self.client, &self.relay, &server_id).await;
        }
        self.emit(ClientEvent::Kicked(server_id));
    }

    /// A relay answered but refused this device one of the account's mailboxes. It shows
    /// as refusing until a connection there comes up; once per run of refusals the device
    /// tries what may fix it: registering the account there again, which pushes its log,
    /// and looking for a move of the server.
    async fn not_admitted(&self, mailbox_id: [u8; 32], relay_url: String, sync_mailbox: [u8; 32], state: &mut LoopState) {
        tracing::warn!("relay {relay_url} refuses this device the mailbox {}", short_id(&mailbox_id));
        state.refusing.entry(relay_url.clone()).or_default().insert(mailbox_id);
        self.emit(ClientEvent::RelayConnectivity(state.connectivity(sync_mailbox, &self.relay.base_url())));
        if !state.admission_repairs.insert((mailbox_id, relay_url.clone())) {
            return;
        }
        let server_id = self.client.lock().await.server_id_for_mailbox(&mailbox_id);
        let Some(server_id) = server_id else { return };
        let session = self.session.clone();
        self.spawn(async move {
            if !same_relay(&relay_url, &session.relay.base_url()) {
                match flows::account::register_at(&session.client, &session.relay, &session.relay.at(&relay_url), None).await {
                    Ok(_) => tracing::info!("account registered again at {relay_url}"),
                    Err(e) => tracing::warn!("account not registered again at {relay_url}: {e}"),
                }
            }
            match flows::server::check_location(&session.client, &session.relay, &server_id).await {
                Ok(true) => tracing::info!("server {} moved; following it", short_id(&server_id)),
                Ok(false) => {}
                Err(e) => tracing::debug!("server {} location not checked: {e}", short_id(&server_id)),
            }
        });
    }

    async fn handle_sync_blob(&self, blob: IncomingBlob, state: &mut LoopState) {
        let mailbox_id = blob.mailbox_id;
        if let Some(busy) = state.busy.get_mut(&mailbox_id) {
            busy.blobs.push_back(blob);
            return;
        }
        let result = self.client.lock().await.receive_sync(&blob.payload);
        // The sender may be a device this device's log does not list yet, or the message
        // sealed under a generation not fetched yet: the account check brings both, and
        // the blob is processed again once a check fetched them. One that fails again
        // then is dropped.
        let waits_for_account = matches!(result, Err(GhostError::UnknownDevice { .. } | GhostError::AccountKeyUnavailable(_)));
        let retried = state.sync_retried.take().is_some_and(|(relay_url, seq)| relay_url == blob.relay_url && seq == blob.seq);
        if waits_for_account && !retried && state.sync_retry.is_none() && !state.device_removed {
            state.hold(mailbox_id);
            state.sync_retry = Some(blob);
            self.request_account_check(state);
            return;
        }
        match result {
            Ok(SyncReceiveResult::Application { plaintext, gap, .. }) => {
                self.handle_sync_message(&plaintext, state).await;
                // Earlier messages of the sender never arrived from any relay: the snapshots
                // carry whatever they changed.
                if gap > 0 {
                    let runner = self.clone();
                    self.spawn(async move { runner.merge_sync_snapshots().await });
                }
            }
            Ok(SyncReceiveResult::Seen) => {}
            Err(e) => tracing::warn!("sync: process failed: {e}"),
        }
        // Each relay numbers the mailbox on its own.
        stored(self.client.lock().await.store().set_last_seen_seq_at(&blob.mailbox_id, &blob.relay_url, blob.seq), "last seen seq not kept");
    }

    /// A message from another device of this account, through the sync mailbox.
    async fn handle_sync_message(&self, plaintext: &[u8], state: &mut LoopState) {
        let Some((&msg_type, body)) = plaintext.split_first() else { return };
        match msg_type {
            x if x == SyncMessageType::ServerProvisioned as u8 => {
                // Another device joined or created a server: join it on the relay hosting it.
                let payload = match ProvisionPayload::from_bytes(body) {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::warn!("sync: bad provision payload: {e}");
                        return;
                    }
                };
                let runner = self.clone();
                self.spawn(async move {
                    if flows::provision::join_payload_if_unknown(&runner.client, &runner.relay, &payload, flows::now_millis()).await {
                        runner.emit(ClientEvent::ServerChanged(ServerScope::All));
                    } else {
                        // A known server: the other device may have made or entered a private channel.
                        runner.spawn_join_private_channels(payload.server_id);
                    }
                });
            }
            x if x == SyncMessageType::AccountChanged as u8 => self.request_account_check(state),
            x if x == SyncMessageType::SyncPause as u8 => {
                // Another device is removing one while the home is unreachable: this
                // device stops writing sync too, and finishes the removal if it reaches
                // the home first.
                let Some(target) = body.get(..32).and_then(|b| <[u8; 32]>::try_from(b).ok()) else {
                    tracing::warn!("sync: SyncPause body too short");
                    return;
                };
                {
                    let c = self.client.lock().await;
                    if target == c.verifying_key_bytes() {
                        return;
                    }
                    stored(c.store().add_pending_revocation(&target, flows::now_millis()), "pending revocation not kept");
                }
                self.request_account_check(state);
            }
            x if x == SyncMessageType::MutationSync as u8 => {
                use crate::wire::{decode_mutation, MUTATION_REMOVE, MUTATION_SET};
                let (op, ts, key, value) = match decode_mutation(body) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!("sync: bad mutation: {e}");
                        return;
                    }
                };
                let applied = {
                    let c = self.client.lock().await;
                    let ts = c.sync_observe(ts).unwrap_or(ts);
                    match op {
                        MUTATION_SET => c.sync_set(&key, &value, ts).unwrap_or(false),
                        MUTATION_REMOVE => c.sync_remove(&key, ts).unwrap_or(false),
                        _ => false,
                    }
                };
                if !applied {
                    return;
                }
                let entry = if op == MUTATION_SET { vec![(key, Some(value), ts)] } else { vec![(key, None, ts)] };
                self.apply_synced_settings(flows::sync::parse_entries(&entry)).await;
            }
            _ => tracing::warn!("sync: unknown message type {msg_type:#04x}"),
        }
    }

    /// Apply settings synced from another device: read marks, display name and presence
    /// status here; servers this device is missing are joined off the loop; the rest is
    /// reported.
    async fn apply_synced_settings(&self, settings: flows::sync::SyncSettings) {
        {
            let mut c = self.client.lock().await;
            for (channel_id, read_ts) in &settings.read_marks {
                stored(c.store().mark_channel_read(channel_id, *read_ts), "read marker not kept");
            }
            if let Some(name) = &settings.display_name {
                c.set_display_name(name.clone());
            }
        }
        if settings.status.is_some() || settings.status_message.is_some() {
            let info = {
                let mut p = self.presence.lock().await;
                if let Some(status) = &settings.status {
                    p.status = crate::mls::presence::OnlineStatus::from_config(status);
                }
                if let Some(message) = &settings.status_message {
                    p.status_message = message.as_ref().map(|m| m.text.clone());
                    p.status_expiry = message.as_ref().and_then(|m| m.expires_at);
                }
                p.clone()
            };
            flows::presence::broadcast(&self.client, &self.relay, &info).await;
        }
        for (server_id, meta) in &settings.server_entries {
            if let Some(removal) = meta.removal {
                // Another device saw the account removed from this server: read-only here
                // too, saying who removed it when that device knew.
                let known = self.client.lock().await.store().get_server(server_id).is_ok();
                if known {
                    let _ = self.reports.send(Report::RemovedElsewhere { server_id: *server_id, by: removal.by });
                }
                continue;
            }
            // A server listed in synced state that this device is missing (a provision it
            // missed), or that another device found moved: the owner's home confirms a move.
            let moved_elsewhere = {
                let c = self.client.lock().await;
                c.store().get_server(server_id).is_ok()
                    && meta.relay_ref.as_ref().is_some_and(|named| c.store().server_relay(server_id).ok().flatten().unwrap_or_default() != named.relay_vk)
            };
            let (session, server_id, meta) = (self.session.clone(), *server_id, meta.clone());
            self.spawn(async move {
                let changed = if moved_elsewhere {
                    match flows::server::check_location(&session.client, &session.relay, &server_id).await {
                        Ok(moved) => moved,
                        Err(e) => {
                            tracing::warn!("server {}: the move another device followed not confirmed here: {e}", short_id(&server_id));
                            false
                        }
                    }
                } else {
                    flows::provision::join_if_unknown(&session.client, &session.relay, server_id, &meta, flows::now_millis()).await
                };
                if changed {
                    session.sink.emit(ClientEvent::ServerChanged(ServerScope::One(server_id)));
                }
            });
        }
        self.emit(ClientEvent::SettingsSynced(settings));
    }

    /// Catch up from the snapshots on every sync relay, apply what changed, and write the
    /// merged state back where it differs.
    async fn merge_sync_snapshots(&self) {
        match flows::sync::merge_snapshots(&self.client, &self.relay).await {
            Ok(Some(settings)) => self.apply_synced_settings(settings).await,
            Ok(None) => {}
            Err(e) => tracing::warn!("sync: snapshots not merged: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_sessions_tasks_end_with_its_loop() {
        let tasks = Arc::new(SessionTasks::default());
        let (held, ended) = tokio::sync::oneshot::channel::<()>();
        tasks.spawn(async move {
            let _held = held;
            std::future::pending::<()>().await
        });
        drop(EndTasksWithLoop(tasks.clone()));
        assert!(ended.await.is_err(), "the task was aborted, and what it held went with it");
    }

    #[test]
    fn a_refused_sender_leaves_no_stand_in_and_only_undecryptable_messages_count() {
        let refused = GhostError::SenderRefused("sender device has been revoked".into());
        let unverifiable = GhostError::IdentityLog("the sender's identity log could not be fetched".into());
        let undecryptable = GhostError::Mls("decrypt".into());

        assert_eq!(unprocessed_effects(true, true, &refused), UnprocessedEffects { stand_in: false, counts_against_own_state: false });
        assert_eq!(unprocessed_effects(true, true, &unverifiable), UnprocessedEffects { stand_in: true, counts_against_own_state: false });
        assert_eq!(unprocessed_effects(true, true, &undecryptable), UnprocessedEffects { stand_in: true, counts_against_own_state: true });
        assert_eq!(unprocessed_effects(true, false, &undecryptable), UnprocessedEffects { stand_in: true, counts_against_own_state: false }, "an epoch past this device's rejoins on its own");
        assert_eq!(unprocessed_effects(false, true, &undecryptable), UnprocessedEffects { stand_in: false, counts_against_own_state: false }, "a commit is no message");
    }
}
