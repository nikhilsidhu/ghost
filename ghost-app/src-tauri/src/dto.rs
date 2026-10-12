use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use ghost_audio::{AgcMode, InputMode, NoiseSuppressionMode};
use ghost_core::client::GhostClient;
use ghost_core::identity::Identity;
use ghost_core::mls::presence::OnlineStatus;
use ghost_core::storage::{Channel, ChannelKind, Delivery, Member, Server, ServerKind, StoredMessage};
use ghost_core::wire::ApplicationMessage;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "ChannelKind"))]
pub enum ChannelKindDto {
    Text,
    Voice,
}

impl From<ChannelKind> for ChannelKindDto {
    fn from(kind: ChannelKind) -> Self {
        match kind {
            ChannelKind::Text => Self::Text,
            ChannelKind::Voice => Self::Voice,
        }
    }
}

impl From<ChannelKindDto> for ChannelKind {
    fn from(kind: ChannelKindDto) -> Self {
        match kind {
            ChannelKindDto::Text => Self::Text,
            ChannelKindDto::Voice => Self::Voice,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "ServerKind"))]
pub enum ServerKindDto {
    Server,
    Group,
    Dm,
}

impl From<ServerKind> for ServerKindDto {
    fn from(kind: ServerKind) -> Self {
        match kind {
            ServerKind::Server => Self::Server,
            ServerKind::Group => Self::Group,
            ServerKind::Dm => Self::Dm,
        }
    }
}

/// A setting as the sync protocol and the config file carry it: its serialized name.
pub fn setting_name<T: Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(name)) => name,
        _ => unreachable!("settings serialize to their names"),
    }
}

/// A setting from its serialized name; `None` for a name this build does not know.
pub fn setting_from_name<T: DeserializeOwned>(name: &str) -> Option<T> {
    serde_json::from_value(serde_json::Value::String(name.to_string())).ok()
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "NoiseSuppression"))]
pub enum NoiseSuppressionDto {
    Off,
    #[default]
    Nnnoiseless,
}

impl From<NoiseSuppressionDto> for NoiseSuppressionMode {
    fn from(mode: NoiseSuppressionDto) -> Self {
        match mode {
            NoiseSuppressionDto::Off => Self::Off,
            NoiseSuppressionDto::Nnnoiseless => Self::Nnnoiseless,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "Agc"))]
pub enum AgcDto {
    Off,
    #[default]
    Auto,
}

impl From<AgcDto> for AgcMode {
    fn from(mode: AgcDto) -> Self {
        match mode {
            AgcDto::Off => Self::Off,
            AgcDto::Auto => Self::Auto,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "InputMode"))]
pub enum InputModeDto {
    #[default]
    VoiceActivity,
    PushToTalk,
}

impl From<InputModeDto> for InputMode {
    fn from(mode: InputModeDto) -> Self {
        match mode {
            InputModeDto::VoiceActivity => Self::VoiceActivity,
            InputModeDto::PushToTalk => Self::PushToTalk,
        }
    }
}

/// This account's own status: what the user chose, or idle while they are away from
/// the keyboard. Only the chosen ones are kept in settings.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "OnlineStatus"))]
pub enum OnlineStatusDto {
    #[default]
    Online,
    Idle,
    Away,
    Invisible,
}

impl From<OnlineStatusDto> for OnlineStatus {
    fn from(status: OnlineStatusDto) -> Self {
        match status {
            OnlineStatusDto::Online => Self::Online,
            OnlineStatusDto::Idle => Self::Idle,
            OnlineStatusDto::Away => Self::Away,
            OnlineStatusDto::Invisible => Self::Invisible,
        }
    }
}

impl From<OnlineStatus> for OnlineStatusDto {
    fn from(status: OnlineStatus) -> Self {
        match status {
            OnlineStatus::Online => Self::Online,
            OnlineStatus::Idle => Self::Idle,
            OnlineStatus::Away => Self::Away,
            OnlineStatus::Invisible => Self::Invisible,
        }
    }
}

/// A member's status as others see it: an invisible member shows as offline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "PresenceStatus"))]
pub enum PresenceStatusDto {
    Online,
    Idle,
    Away,
    Offline,
}

impl From<OnlineStatus> for PresenceStatusDto {
    fn from(status: OnlineStatus) -> Self {
        match status {
            OnlineStatus::Online => Self::Online,
            OnlineStatus::Idle => Self::Idle,
            OnlineStatus::Away => Self::Away,
            OnlineStatus::Invisible => Self::Offline,
        }
    }
}

#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "Identity"))]
pub struct IdentityDto {
    pub fingerprint: String,
    pub fingerprint_short: String,
    pub display_name: String,
}

#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "Server"))]
pub struct ServerDto {
    pub server_id: String,
    pub name: String,
    pub kind: ServerKindDto,
    /// Owner under the server's policy, who may do everything.
    pub owner_fp: String,
    /// This account's permission bits in the server (see `ghost_wire::policy`).
    pub permissions: u32,
    pub created_at: u64,
    pub has_unread: bool,
    /// Set when this account was removed from the server: it stays, read-only.
    pub removed: Option<RemovalDto>,
    /// Set when this device stopped following the server because its relay accepted a
    /// change the server's rules forbid: it stays, read-only, until the person decides.
    pub halted: Option<HaltDto>,
}

/// Why a server is read-only on this device: the change its rules refused, and the relay
/// that accepted it.
#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "Halt"))]
pub struct HaltDto {
    pub at: u64,
    pub reason: String,
    /// Address of the relay hosting the server, when this device knows it.
    pub relay: Option<String>,
}

/// How this account came to be out of a server it still shows, read-only.
#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "Removal"))]
pub struct RemovalDto {
    pub at: u64,
    /// Who removed this account, by name, when this device knows.
    pub by: Option<String>,
}

/// An account a server keeps from rejoining.
#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "KeptOut"))]
pub struct KeptOutDto {
    pub fingerprint: String,
    /// The name it had in the server, when this device saw it.
    pub display_name: Option<String>,
    pub removed_at: u64,
}

#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "Channel"))]
pub struct ChannelDto {
    pub channel_id: String,
    pub server_id: String,
    pub name: String,
    pub kind: ChannelKindDto,
    pub position: i32,
    pub unread_count: u32,
    /// Only the members its policy admits can see it.
    pub private: bool,
}

#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "Member"))]
pub struct MemberDto {
    pub server_id: String,
    pub fingerprint: String,
    pub display_name: String,
    pub joined_at: u64,
    /// Ids of the server roles assigned to this member, highest first.
    pub roles: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "Role"))]
pub struct RoleDto {
    pub id: u8,
    pub name: String,
    pub permissions: u32,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "RoleAssignment"))]
pub struct AssignmentDto {
    pub fingerprint: String,
    pub roles: Vec<u8>,
}

/// A server's policy with role names. Roles are listed by rank, highest first.
#[derive(Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "ServerPolicy"))]
pub struct PolicyDto {
    pub owner_fp: String,
    pub everyone: u32,
    pub roles: Vec<RoleDto>,
    pub assignments: Vec<AssignmentDto>,
}

#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "ServerRoles"))]
pub struct ServerRolesDto {
    pub policy: PolicyDto,
    pub my_permissions: u32,
}

/// Who a private channel admits besides the server's channel managers.
#[derive(Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "ChannelAccess"))]
pub struct ChannelAccessDto {
    pub roles: Vec<u8>,
    pub accounts: Vec<String>,
}

impl From<&Identity> for IdentityDto {
    fn from(id: &Identity) -> Self {
        Self {
            fingerprint: hex::encode(id.fingerprint),
            fingerprint_short: id.fingerprint_short(),
            display_name: id.display_name.clone(),
        }
    }
}

impl ServerDto {
    pub fn from_server(s: &Server, has_unread: bool, client: &GhostClient) -> Self {
        let policy = client.server_policy(&s.server_id).ok();
        let own = client.fingerprint();
        let removed = client.removed_from(&s.server_id).ok().flatten().map(|removal| RemovalDto {
            at: removal.at,
            by: removal.by.and_then(|by| client.member_name(&s.server_id, &by)),
        });
        let halted = client.halt(&s.server_id).ok().flatten().map(|halt| HaltDto {
            at: halt.at,
            reason: halt.reason,
            relay: ghost_core::flows::server_relay_url(client, &s.server_id),
        });
        Self {
            server_id: hex::encode(s.server_id),
            name: client.server_display_name(s),
            kind: s.kind.into(),
            owner_fp: policy.as_ref().map(|p| hex::encode(p.owner)).unwrap_or_default(),
            permissions: policy.as_ref().map_or(0, |p| p.permissions(own)),
            created_at: s.created_at,
            has_unread,
            removed,
            halted,
        }
    }
}

impl ChannelDto {
    pub fn from_channel(c: &Channel, unread_count: u32, private: bool) -> Self {
        Self {
            channel_id: hex::encode(c.channel_id),
            server_id: hex::encode(c.server_id),
            name: c.name.clone(),
            kind: c.kind.into(),
            position: c.position,
            unread_count,
            private,
        }
    }
}

/// Where one of this device's messages stands with the relay.
#[derive(Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "Delivery"))]
pub enum DeliveryDto {
    Delivered,
    Pending,
    Failed,
}

impl From<Delivery> for DeliveryDto {
    fn from(delivery: Delivery) -> Self {
        match delivery {
            Delivery::Delivered => Self::Delivered,
            // Queued and handed over both read as sending until the relay answers.
            Delivery::Pending | Delivery::Sent => Self::Pending,
            Delivery::Failed => Self::Failed,
        }
    }
}

#[derive(Clone, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "Message"))]
pub struct MessageDto {
    pub message_id: String,
    pub channel_id: String,
    pub sender_fp: String,
    pub message_type: u8,
    pub timestamp: u64,
    pub received_at: u64,
    pub content: String,
    pub delivery: DeliveryDto,
}

impl MessageDto {
    pub fn from_incoming(msg: &ApplicationMessage, received_at: u64) -> Self {
        Self {
            message_id: hex::encode(msg.message_id),
            channel_id: hex::encode(msg.channel_id),
            sender_fp: hex::encode(msg.sender_fp),
            message_type: msg.message_type as u8,
            timestamp: msg.timestamp,
            received_at,
            content: String::from_utf8_lossy(&msg.content).into_owned(),
            delivery: DeliveryDto::Delivered,
        }
    }
}

impl From<&StoredMessage> for MessageDto {
    fn from(m: &StoredMessage) -> Self {
        Self {
            message_id: hex::encode(m.message_id),
            channel_id: hex::encode(m.channel_id),
            sender_fp: hex::encode(m.sender_fp),
            message_type: m.message_type,
            timestamp: m.timestamp,
            received_at: m.received_at,
            content: String::from_utf8_lossy(&m.content).into_owned(),
            delivery: m.delivery.into(),
        }
    }
}

/// A change in where one of this device's messages stands with the relay.
#[derive(Clone, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "MessageDelivery"))]
pub struct MessageDeliveryDto {
    pub message_id: String,
    pub delivery: DeliveryDto,
    /// Why the relay refused it, when it did.
    pub reason: Option<String>,
}

#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "Invite"))]
pub struct InviteDto {
    pub token: String,
    pub link: String,
    /// When the invite ends, as the relay hosting the server applied it.
    pub expires_at: u64,
}

#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "Config"))]
pub struct ConfigDto {
    pub display_name: Option<String>,
    /// The relay this device connects to, which is the account's home.
    pub relay_url: String,
    pub input_device: Option<String>,
    pub output_device: Option<String>,
    pub noise_suppression: NoiseSuppressionDto,
    pub agc: AgcDto,
    pub input_mode: InputModeDto,
    pub vad_threshold: f32,
    pub input_gain: f32,
    /// Whether going idle mutes a call.
    pub auto_mute_on_idle: bool,
    pub status: OnlineStatusDto,
    pub status_message: Option<String>,
    /// When the status message expires, in milliseconds.
    pub status_expiry: Option<u64>,
}

/// How many of the account's servers a name or avatar change reached now; the rest are
/// told when they are reachable again.
#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "ProfileReach"))]
pub struct ProfileReachDto {
    pub reached: u32,
    pub servers: u32,
}

impl From<ghost_core::flows::profile::Reach> for ProfileReachDto {
    fn from(reach: ghost_core::flows::profile::Reach) -> Self {
        Self { reached: reach.reached as u32, servers: reach.servers as u32 }
    }
}

#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "KeybindConfig"))]
pub struct KeybindConfigDto {
    pub push_to_talk: Option<String>,
}

#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "Device"))]
pub struct DeviceDto {
    pub device_key: String,
    pub label: String,
    pub added_at_seq: u64,
    pub is_active: bool,
    pub is_current: bool,
    /// Its removal waits for the home on this device; sync is paused meanwhile.
    pub removal_pending: bool,
    /// Why the home refused that removal, when it did for a reason a retry does not
    /// change by itself.
    pub removal_refused: Option<String>,
}

/// The account's devices, and whether the list is the home's word now.
#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "DeviceList"))]
pub struct DeviceListDto {
    pub devices: Vec<DeviceDto>,
    /// `false` when the home could not be reached and the list is as this device last
    /// verified it.
    pub current: bool,
}

/// How far removing a device got.
#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "RevokeOutcome"))]
pub struct RevokeOutcomeDto {
    pub outcome: RevokeOutcomeKindDto,
    /// For `leaves_left`: the servers whose groups still hold the device, by name.
    pub servers: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "RevokeOutcomeKind"))]
pub enum RevokeOutcomeKindDto {
    Complete,
    /// Removed from the account, but some servers' groups still hold the device until
    /// their relays take it out, which they do on their own.
    LeavesLeft,
    /// Out of the groups this device reached; the removal waits for the home.
    LogPending,
}

/// Where this device stands with its account, which decides the screen the app opens on.
#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "AccountStatus"))]
pub struct AccountStatusDto {
    pub phase: AccountPhaseDto,
    /// The relay this device connects to.
    pub relay_url: String,
    /// What this device is called in the account's device list, or would be: the
    /// machine's name until the user picks another while setting up.
    pub device_label: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "AccountPhase"))]
pub enum AccountPhaseDto {
    /// No account yet.
    None,
    Ready,
}

/// How far a pairing this device opened has got.
#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "PairingStatus"))]
pub struct PairingStatusDto {
    pub stage: PairingStageDto,
    /// The six digits both screens show, while confirming.
    pub code: Option<String>,
    /// The new device's label, once linked.
    pub label: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "PairingStage"))]
pub enum PairingStageDto {
    /// For the new device to answer.
    Waiting,
    /// Its code is shown for the user to compare.
    Confirm,
    /// For the new device to sign the addition.
    Signing,
    Linked,
}

/// Whether a recovery key is the account's current one.
#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "KeyCheck"))]
pub struct KeyCheckDto {
    pub matches: bool,
    /// `false` when the home could not be reached and the answer is as of this device's
    /// last look at the account's log.
    pub current: bool,
}

/// What became of an account this device was making when the app last closed.
#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "UnfinishedOutcome"))]
pub struct UnfinishedOutcomeDto {
    pub outcome: UnfinishedOutcomeKindDto,
    /// The relay it was made at, for `finished` and `waiting`.
    pub relay_url: Option<String>,
}

impl UnfinishedOutcomeDto {
    pub fn none() -> Self {
        Self { outcome: UnfinishedOutcomeKindDto::None, relay_url: None }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "UnfinishedOutcomeKind"))]
pub enum UnfinishedOutcomeKindDto {
    /// No account was being made, or the relay never got it.
    None,
    /// The relay holds it, and it now runs on this device.
    Finished,
    /// The relay it was made at did not answer; asked again at the next try.
    Waiting,
}

/// What came of confirming a recovery.
#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "RecoveryOutcome"))]
pub struct RecoveryOutcomeDto {
    pub outcome: RecoveryOutcomeKindDto,
    pub home_url: Option<String>,
    /// Once recovered: what became of the snapshot holding the account's servers and
    /// settings.
    pub restore: Option<SnapshotRestoreDto>,
}

impl RecoveryOutcomeDto {
    pub fn recovered(restore: SnapshotRestoreDto) -> Self {
        Self { outcome: RecoveryOutcomeKindDto::Recovered, home_url: None, restore: Some(restore) }
    }
}

/// What a recovery made of the account's sync snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "SnapshotRestore"))]
pub enum SnapshotRestoreDto {
    Restored,
    /// There was none to restore: servers are joined again with invites.
    Missing,
    /// It no longer opens with any key the recovery reached: servers are joined again
    /// with invites.
    Unreadable,
    /// Its relay did not answer; the running session restores it when it does.
    NotReached,
}

impl From<ghost_core::flows::recovery::SnapshotRestore> for SnapshotRestoreDto {
    fn from(restore: ghost_core::flows::recovery::SnapshotRestore) -> Self {
        use ghost_core::flows::recovery::SnapshotRestore;
        match restore {
            SnapshotRestore::Restored => Self::Restored,
            SnapshotRestore::Missing => Self::Missing,
            SnapshotRestore::Unreadable => Self::Unreadable,
            SnapshotRestore::NotReached => Self::NotReached,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "RecoveryOutcomeKind"))]
pub enum RecoveryOutcomeKindDto {
    Recovered,
    /// The account's home relay did not answer; recovering through the relay given
    /// means making it the home.
    HomeUnreachable,
}

/// Something that happened to the account, from another device or the recovery key, or
/// to a member's account as this device sees it (`split_view`).
#[derive(Serialize, Clone)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "AccountAlert"))]
pub struct AccountAlertDto {
    /// Given when the alert is raised, so the front end can dismiss exactly this one.
    pub id: u64,
    pub kind: AccountAlertKindDto,
    /// The device the alert names, when it names one.
    pub device_label: Option<String>,
    pub device_key: Option<String>,
    pub relay_vk: Option<String>,
    pub generation: Option<u32>,
    /// The member a `split_view` alert concerns, as this device names them.
    pub account_name: Option<String>,
    /// The relay a `relay_refuses_device` alert names.
    pub relay_url: Option<String>,
    /// For `history_replaced`: how many entries went, and the devices that went with them.
    pub discarded: Option<u32>,
    pub lost_devices: Vec<String>,
    /// For `this_device_removed` and `device_removed`: what removed the device, when the
    /// relays said, and the removing device's label when it was one.
    pub removed_by: Option<RemovedByDto>,
    pub remover_label: Option<String>,
    /// For `removal_refused`: why the home refused it.
    pub reason: Option<String>,
}

/// What removed a device of the account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "RemovedBy"))]
pub enum RemovedByDto {
    /// The account was recovered on another device, which removes every other one.
    Recovery,
    RecoveryKey,
    /// Another device of the account; `remover_label` names it.
    Device,
}

impl AccountAlertDto {
    pub fn of(kind: AccountAlertKindDto) -> Self {
        Self {
            id: 0,
            kind,
            device_label: None,
            device_key: None,
            relay_vk: None,
            generation: None,
            account_name: None,
            relay_url: None,
            discarded: None,
            lost_devices: Vec::new(),
            removed_by: None,
            remover_label: None,
            reason: None,
        }
    }

    /// A removal alert, saying what removed the device when that is known.
    pub fn removal(kind: AccountAlertKindDto, by: Option<&ghost_wire::RevocationCause>) -> Self {
        use ghost_wire::RevocationCause;
        let (removed_by, remover_label) = match by {
            Some(RevocationCause::Recovery) => (Some(RemovedByDto::Recovery), None),
            Some(RevocationCause::RecoveryKey) => (Some(RemovedByDto::RecoveryKey), None),
            Some(RevocationCause::Device(label)) => (Some(RemovedByDto::Device), Some(label.clone())),
            None => (None, None),
        };
        Self { removed_by, remover_label, ..Self::of(kind) }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "AccountAlertKind"))]
pub enum AccountAlertKindDto {
    DeviceLinked,
    /// Another device of the account, or the recovery key, removed one of its devices.
    DeviceRemoved,
    /// The home refused a removal waiting on this device; sync stays paused until one of
    /// the account's devices records it.
    RemovalRefused,
    RecoveryKeyReplaced,
    HomeMoved,
    BadAccountKey,
    ThisDeviceRemoved,
    RelayRefusesDevice,
    HistoryReplaced,
    SplitView,
}

impl MemberDto {
    pub fn from_member(m: &Member, roles: Vec<u8>) -> Self {
        Self {
            server_id: hex::encode(m.server_id),
            fingerprint: hex::encode(m.fingerprint),
            display_name: m.display_name.clone(),
            joined_at: m.joined_at,
            roles,
        }
    }
}
