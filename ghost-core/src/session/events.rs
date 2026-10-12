//! What the session loop reports to whoever runs it: the desktop app turns these into
//! UI events, a headless client or a test records them.

use crate::flows::sync::SyncSettings;
use crate::mls::presence::OnlineStatus;
use crate::voice::VoiceEvent;
use crate::wire::ApplicationMessage;

/// Which servers an event concerns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerScope {
    One([u8; 32]),
    /// The server list itself changed (joined or left servers).
    All,
}

/// Someone in a voice channel, as their voice presence announces them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoiceMember {
    pub fingerprint: [u8; 32],
    pub muted: bool,
    pub deafened: bool,
}

/// A server member's announced online presence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnlineMember {
    pub fingerprint: [u8; 32],
    pub status: OnlineStatus,
    pub status_message: Option<String>,
    pub avatar_hash: Option<[u8; 32]>,
}

/// Something happened to this account that this device did not do, which the user
/// should hear about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountAlert {
    /// Another device of the account linked a new one.
    DeviceLinked { label: String },
    /// Another device of the account, or the recovery key, removed one of its devices.
    DeviceRemoved { label: String, by: ghost_wire::RevocationCause },
    /// The recovery key was replaced from another device.
    RecoveryKeyReplaced { by: String },
    /// The account's home relay moved.
    HomeMoved { relay_vk: [u8; 32] },
    /// A device published an account key generation this device cannot open. If the
    /// user does not recognise the writer, they should remove it.
    BadAccountKey { generation: u32, writer: [u8; 32], writer_label: String },
    /// This device was removed from the account: by a recovery on another device, the
    /// recovery key or another device, when the relay that refused it said.
    ThisDeviceRemoved { cause: Option<ghost_wire::RevocationCause> },
    /// A change signed with the recovery key replaced part of the account's history this
    /// device had been shown: `discarded` entries went, and with them `lost_devices`.
    HistoryReplaced { discarded: u32, lost_devices: Vec<String> },
    /// The home refused a removal waiting on this device for a reason a retry does not
    /// change by itself: the device stays in the account, and sync stays paused, until
    /// one of the account's devices records the removal.
    RemovalRefused { label: String, reason: String },
    /// A relay refused this device as revoked while the account's home says it is active:
    /// that relay is behind or not to be trusted. Its mailboxes are tried again later.
    RelayRefusesDevice { relay_url: String },
}

#[derive(Debug, Clone)]
pub enum ClientEvent {
    /// A server's channels, members or roles changed, or the server list did.
    ServerChanged(ServerScope),
    /// A chat message arrived (already stored).
    Message { message: ApplicationMessage, received_at: u64 },
    /// The relay took one of this device's messages.
    MessageDelivered { message_id: [u8; 32] },
    /// The relay refused one of this device's messages for good; the user may retry.
    MessageFailed { message_id: [u8; 32], reason: String },
    /// This account is no longer in the server, or this device was revoked from it.
    Kicked([u8; 32]),
    /// The account's home moved through another device and this device now connects to
    /// the new one at `url`; the address to connect at next time is that one.
    HomeFollowed { url: String },
    /// The server's relay accepted a change the rules this device holds forbid. The device
    /// keeps its copy from before it, read-only, until the person accepts the relay's
    /// state or leaves.
    ServerHalted { server_id: [u8; 32], reason: String },
    /// A private channel's messages wait for a change to the server's group this device
    /// has not read, and have for longer than a short delay; `waiting` is false once they
    /// no longer do. They are not lost: read when that change arrives, or at the next start.
    ChannelWaiting { server_id: [u8; 32], channel_id: [u8; 32], waiting: bool },
    /// A member's avatar was fetched into the avatar cache.
    AvatarUpdated([u8; 32]),
    /// A member removed their avatar; the cached copy is gone.
    AvatarCleared([u8; 32]),
    /// This account's display name changed on another device.
    DisplayNameSynced,
    /// Where this device's relay connections stand.
    RelayConnectivity(Connectivity),
    /// Who is in a voice channel now.
    VoiceChannelMembers { channel_id: [u8; 32], members: Vec<VoiceMember> },
    /// Who is online in a server now.
    OnlinePresence { server_id: [u8; 32], members: Vec<OnlineMember> },
    /// Settings changed on another device. Read marks, the display name and the
    /// presence status are already applied; the rest (configuration, audio) is the
    /// runner's to apply.
    SettingsSynced(SyncSettings),
    /// This device's own voice call (see `voice`).
    Voice(VoiceEvent),
    /// A change to the account this device did not make.
    Account(AccountAlert),
    /// A member of `server_id` sees a history of its own identity log that this device
    /// was not served, even after fetching the log again: a relay is showing the two of
    /// them different logs, which is how a device could be slipped into that account
    /// unseen. Reported once per account while the session runs.
    SplitView { server_id: [u8; 32], account_fp: [u8; 32] },
}

/// Receives the session's events. Called from the loop, so it must not block.
pub trait EventSink: Send + Sync + 'static {
    fn emit(&self, event: ClientEvent);
}

/// Where this device's relay connections stand.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Connectivity {
    /// The home relay answers: the sync mailbox is connected there.
    pub home: bool,
    /// Any mailbox connection is up.
    pub any: bool,
    /// Relays, by base URL, with a mailbox connection down.
    pub relays_down: Vec<String>,
    /// Relays, by base URL, that answer but refuse this device a mailbox.
    pub relays_refusing: Vec<String>,
    /// A connection that came up is still delivering what was missed while it was down.
    pub catching_up: bool,
}
