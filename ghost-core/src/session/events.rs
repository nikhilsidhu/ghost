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

#[derive(Debug, Clone)]
pub enum ClientEvent {
    /// A server's channels, members or roles changed, or the server list did.
    ServerChanged(ServerScope),
    /// A chat message arrived (already stored).
    Message { message: ApplicationMessage, received_at: u64 },
    /// This account is no longer in the server, or this device was revoked from it.
    Kicked([u8; 32]),
    /// A member's avatar was fetched into the avatar cache.
    AvatarUpdated([u8; 32]),
    /// A member removed their avatar; the cached copy is gone.
    AvatarCleared([u8; 32]),
    /// This account's display name changed on another device.
    DisplayNameSynced,
    /// Whether any relay connection is up.
    RelayConnectivity(bool),
    /// Another device of this account joined this voice channel; leave it here.
    VoiceTakeover([u8; 32]),
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
}

/// Receives the session's events. Called from the loop, so it must not block.
pub trait EventSink: Send + Sync + 'static {
    fn emit(&self, event: ClientEvent);
}
