//! What a blueprint opens, window by window: each profile's servers with the channels it
//! can see and their unread counts, the members with their roles, its DMs, and notes on
//! anything unusual about how it opens. A built-in blueprint's preview is worked out from
//! its plan; a saved one's is read from its profiles' data when it is saved.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use ghost_core::storage::{ChannelKind, ServerKind};
use ghost_node::Device;
use serde::{Deserialize, Serialize};

use super::plan::{plan_profiles, plan_relays, Step, GENERAL};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
pub struct Preview {
    pub windows: Vec<WindowPreview>,
    pub counts: Counts,
}

/// How much of each thing the world holds, always in this order on the page.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
pub struct Counts {
    pub relays: u32,
    pub windows: u32,
    pub people: u32,
    pub servers: u32,
    pub channels: u32,
    pub roles: u32,
    pub dms: u32,
    pub messages: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
pub struct WindowPreview {
    pub profile: String,
    pub display: String,
    /// Its home relay, when the launcher runs it.
    pub relay: Option<String>,
    pub servers: Vec<ServerPreview>,
    pub dms: Vec<DmPreview>,
    pub notes: Vec<Note>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
pub struct ServerPreview {
    pub name: String,
    /// This profile was removed from it: it stays, read-only.
    pub removed: bool,
    pub channels: Vec<ChannelPreview>,
    /// Private channels this profile cannot see, when that is known (it is not, from a
    /// profile's own data).
    pub hidden_private: Option<u32>,
    pub members: Vec<MemberPreview>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
pub struct ChannelPreview {
    pub name: String,
    pub voice: bool,
    pub private: bool,
    pub unread: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
pub struct MemberPreview {
    pub display: String,
    /// "owner", or the name of their first role.
    pub role: Option<String>,
    /// Their home relay, when it is not the one hosting the server.
    pub home_relay: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
pub struct DmPreview {
    pub with: String,
    pub unread: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
pub struct Note {
    pub label: String,
    pub tone: Tone,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum Tone {
    Warn,
    Danger,
    Info,
}

const OWNER: &str = "owner";
/// The app settings file a profile's display name is in.
const APP_CONFIG: &str = "config.toml";

/// Members as a member list groups them: the owner, then role holders, then everyone
/// else, each group by name.
fn sort_members(members: &mut [MemberPreview]) {
    let rank = |m: &MemberPreview| match m.role.as_deref() {
        Some(OWNER) => 0,
        Some(_) => 1,
        None => 2,
    };
    members.sort_by(|a, b| rank(a).cmp(&rank(b)).then_with(|| a.display.cmp(&b.display)));
}

// ---- from a plan ----

struct SimPerson {
    display: String,
    relay: String,
    online: bool,
}

struct SimChannel {
    name: String,
    voice: bool,
    /// Roles that may enter; open to everyone when empty.
    roles: Vec<String>,
    /// Messages each account missed while offline, by account.
    unread: HashMap<String, u32>,
}

struct SimServer {
    name: String,
    host: String,
    owner: String,
    channels: Vec<SimChannel>,
    roles: Vec<(String, Vec<String>)>,
    members: Vec<String>,
    /// Kicked accounts, and whether each was offline at the time.
    kicked: Vec<(String, bool)>,
}

impl SimServer {
    fn can_see(&self, account: &str, channel: &SimChannel) -> bool {
        channel.roles.is_empty()
            || self.owner == account
            || self.roles.iter().any(|(role, holders)| channel.roles.contains(role) && holders.iter().any(|h| h == account))
    }

    fn role_of(&self, account: &str) -> Option<String> {
        if self.owner == account {
            return Some(OWNER.into());
        }
        self.roles.iter().find(|(_, holders)| holders.iter().any(|h| h == account)).map(|(role, _)| role.clone())
    }
}

struct SimDm {
    between: [String; 2],
    unread: HashMap<String, u32>,
}

/// The world `plan` builds, window by window.
pub fn of_plan(plan: &[Step]) -> Preview {
    let mut people: HashMap<String, SimPerson> = HashMap::new();
    let mut accounts: HashMap<String, String> = HashMap::new();
    let mut servers: Vec<SimServer> = Vec::new();
    let mut dms: Vec<SimDm> = Vec::new();
    let mut counts = Counts::default();
    let server_mut = |servers: &mut Vec<SimServer>, name: &str| servers.iter_mut().position(|s| s.name == name);

    for step in plan {
        match step {
            Step::Accounts(list) => {
                for p in list {
                    people.insert(p.name.clone(), SimPerson { display: p.display.clone(), relay: p.relay.clone(), online: true });
                    accounts.insert(p.name.clone(), p.name.clone());
                    counts.people += 1;
                }
            }
            Step::Server { owner, name } => {
                let host = people.get(owner).map(|p| p.relay.clone()).unwrap_or_default();
                let general = SimChannel { name: GENERAL.into(), voice: false, roles: Vec::new(), unread: HashMap::new() };
                servers.push(SimServer { name: name.clone(), host, owner: owner.clone(), channels: vec![general], roles: Vec::new(), members: vec![owner.clone()], kicked: Vec::new() });
            }
            Step::Channel { server, name, kind, .. } => {
                if let Some(i) = server_mut(&mut servers, server) {
                    servers[i].channels.push(SimChannel { name: name.clone(), voice: *kind == ChannelKind::Voice, roles: Vec::new(), unread: HashMap::new() });
                }
            }
            Step::Join { server, members, .. } => {
                if let Some(i) = server_mut(&mut servers, server) {
                    servers[i].members.extend(members.iter().cloned());
                }
            }
            Step::Role { server, name, holders, .. } => {
                if let Some(i) = server_mut(&mut servers, server) {
                    servers[i].roles.push((name.clone(), holders.clone()));
                }
            }
            Step::PrivateChannel { server, name, roles, .. } => {
                if let Some(i) = server_mut(&mut servers, server) {
                    servers[i].channels.push(SimChannel { name: name.clone(), voice: false, roles: roles.clone(), unread: HashMap::new() });
                }
            }
            Step::Chat { server, channel, count, .. } => {
                counts.messages += *count as u32;
                let Some(i) = server_mut(&mut servers, server) else { continue };
                let Some(c) = servers[i].channels.iter().position(|ch| ch.name == *channel) else { continue };
                let missing: Vec<String> = servers[i]
                    .members
                    .iter()
                    .filter(|m| people.get(*m).is_some_and(|p| !p.online) && servers[i].can_see(m, &servers[i].channels[c]))
                    .cloned()
                    .collect();
                for member in missing {
                    *servers[i].channels[c].unread.entry(member).or_default() += *count as u32;
                }
            }
            Step::Dm { owner, member, count } => {
                counts.messages += *count as u32;
                let mut unread = HashMap::new();
                for who in [owner, member] {
                    if people.get(who).is_some_and(|p| !p.online) {
                        unread.insert(who.clone(), *count as u32);
                    }
                }
                dms.push(SimDm { between: [owner.clone(), member.clone()], unread });
            }
            Step::GoOffline { name } => {
                if let Some(person) = people.get_mut(name) {
                    person.online = false;
                }
            }
            Step::Kick { server, member, .. } => {
                let offline = people.get(member).is_some_and(|p| !p.online);
                if let Some(i) = server_mut(&mut servers, server) {
                    servers[i].members.retain(|m| m != member);
                    // A kick takes the member's roles with it.
                    for (_, holders) in &mut servers[i].roles {
                        holders.retain(|h| h != member);
                    }
                    servers[i].kicked.push((member.clone(), offline));
                }
            }
            Step::Link { owner, profile, .. } => {
                accounts.insert(profile.clone(), owner.clone());
            }
        }
    }

    let profiles = plan_profiles(plan);
    let windows = profiles
        .iter()
        .map(|(profile, relay)| {
            let account = accounts.get(profile).cloned().unwrap_or_else(|| profile.clone());
            let person = people.get(&account);
            let display = person.map(|p| p.display.clone()).unwrap_or_else(|| profile.clone());
            let shown_servers: Vec<ServerPreview> = servers
                .iter()
                .filter(|s| s.members.contains(&account) || s.kicked.iter().any(|(k, _)| *k == account))
                .map(|s| {
                    let removed = !s.members.contains(&account);
                    let visible: Vec<&SimChannel> = s.channels.iter().filter(|c| s.can_see(&account, c)).collect();
                    let mut members: Vec<MemberPreview> = s
                        .members
                        .iter()
                        .map(|m| {
                            let member = people.get(m);
                            MemberPreview {
                                display: member.map(|p| p.display.clone()).unwrap_or_else(|| m.clone()),
                                role: s.role_of(m),
                                home_relay: member.filter(|p| p.relay != s.host).map(|p| p.relay.clone()),
                            }
                        })
                        .collect();
                    sort_members(&mut members);
                    ServerPreview {
                        name: s.name.clone(),
                        removed,
                        channels: visible
                            .iter()
                            .map(|c| ChannelPreview { name: c.name.clone(), voice: c.voice, private: !c.roles.is_empty(), unread: c.unread.get(&account).copied().unwrap_or(0) })
                            .collect(),
                        hidden_private: Some((s.channels.len() - visible.len()) as u32),
                        members,
                    }
                })
                .collect();
            let shown_dms: Vec<DmPreview> = dms
                .iter()
                .filter(|d| d.between.contains(&account))
                .map(|d| {
                    let other = d.between.iter().find(|who| **who != account).cloned().unwrap_or_default();
                    DmPreview { with: people.get(&other).map(|p| p.display.clone()).unwrap_or(other), unread: d.unread.get(&account).copied().unwrap_or(0) }
                })
                .collect();

            let mut notes = Vec::new();
            for s in servers.iter().filter(|s| s.kicked.contains(&(account.clone(), true))) {
                notes.push(Note { label: "kicked while offline".into(), tone: Tone::Danger, detail: format!("learns of it on opening; {} stays, read-only", s.name) });
            }
            let missed: u32 = shown_servers.iter().flat_map(|s| &s.channels).map(|c| c.unread).sum::<u32>() + shown_dms.iter().map(|d| d.unread).sum::<u32>();
            if missed > 0 {
                notes.push(Note { label: "opens offline".into(), tone: Tone::Warn, detail: format!("catches up on {missed} messages") });
            }
            let devices: Vec<&String> = profiles.iter().map(|(p, _)| p).filter(|p| accounts.get(*p) == Some(&account) && *p != profile).collect();
            if !devices.is_empty() {
                notes.push(Note { label: format!("{} devices", devices.len() + 1), tone: Tone::Info, detail: format!("same account as {}", devices.iter().map(|d| d.as_str()).collect::<Vec<_>>().join(", ")) });
            }
            WindowPreview { profile: profile.clone(), display, relay: Some(relay.clone()), servers: shown_servers, dms: shown_dms, notes }
        })
        .collect();

    counts.relays = plan_relays(plan).len() as u32;
    counts.windows = profiles.len() as u32;
    counts.servers = servers.len() as u32;
    counts.channels = servers.iter().map(|s| s.channels.len() as u32).sum();
    counts.roles = servers.iter().map(|s| s.roles.len() as u32).sum();
    counts.dms = dms.len() as u32;
    Preview { windows, counts }
}

// ---- from profiles' data ----

/// The display name a profile's app settings give it.
fn display_name(folder: &std::path::Path) -> Option<String> {
    let config: toml::Value = toml::from_str(&std::fs::read_to_string(folder.join(APP_CONFIG)).ok()?).ok()?;
    config.get("display_name")?.as_str().map(str::to_string)
}

/// A profile whose data a preview is read from.
pub struct ProfileData {
    pub name: String,
    pub folder: PathBuf,
    pub relay_url: String,
}

/// What `profiles` hold, read from their data while nothing runs. `relay_names` names the
/// launcher's relays by URL; `relays` is how many hold data.
pub async fn of_profiles(profiles: &[ProfileData], relay_names: &HashMap<String, String>, relays: u32) -> Result<Preview, String> {
    let name_of = |url: &str| relay_names.get(url.trim_end_matches('/')).cloned();
    let mut opened = Vec::new();
    for profile in profiles {
        let device = Device::open(&profile.folder, &profile.relay_url).map_err(|e| format!("open {}: {e}", profile.name))?;
        let account = device.fingerprint().await;
        opened.push((profile, device, account));
    }
    let homes: HashMap<[u8; 32], String> = opened.iter().filter_map(|(p, _, account)| name_of(&p.relay_url).map(|relay| (*account, relay))).collect();

    let (mut people, mut servers, mut channels, mut roles, mut dm_ids) = (HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new(), HashSet::new());
    let mut messages: HashMap<[u8; 32], u32> = HashMap::new();
    let mut windows = Vec::new();
    for (profile, device, account) in &opened {
        people.insert(*account);
        let client = device.client.lock().await;
        let store = client.store();
        let own_relay = name_of(&profile.relay_url);
        let read = |e: ghost_core::error::GhostError| format!("read {}: {e}", profile.name);
        let mut shown_servers = Vec::new();
        let mut shown_dms = Vec::new();
        let display = display_name(&profile.folder).unwrap_or_else(|| profile.name.clone());
        for server in store.list_servers().map_err(read)? {
            let members = store.list_members(&server.server_id).map_err(read)?;
            people.extend(members.iter().map(|m| m.fingerprint));
            let unread: HashMap<[u8; 32], u32> = store.get_unread_counts(&server.server_id).map_err(read)?.into_iter().collect();
            let server_channels = store.list_channels(&server.server_id).map_err(read)?;
            for channel in &server_channels {
                if server.kind != ServerKind::Dm {
                    channels.insert(channel.channel_id);
                }
                let count = store.count_messages(&channel.channel_id).map_err(read)?;
                let most = messages.entry(channel.channel_id).or_default();
                *most = (*most).max(count);
            }
            if server.kind == ServerKind::Dm {
                dm_ids.insert(server.server_id);
                shown_dms.push(DmPreview { with: client.server_display_name(&server), unread: unread.values().sum() });
                continue;
            }
            servers.insert(server.server_id);
            let names: HashMap<u8, String> = store.list_role_names(&server.server_id).map_err(read)?.into_iter().collect();
            roles.extend(names.keys().map(|id| (server.server_id, *id)));
            let policy = client.server_policy(&server.server_id).map_err(read)?;
            let host = ghost_core::flows::server_relay_url(&client, &server.server_id).and_then(|url| name_of(&url)).or_else(|| own_relay.clone());
            let mut shown_members: Vec<MemberPreview> = members
                .iter()
                .map(|m| {
                    let role = if policy.owner == m.fingerprint {
                        Some(OWNER.to_string())
                    } else {
                        policy.assignments.iter().find(|(holder, _)| *holder == m.fingerprint).and_then(|(_, held)| held.first()).and_then(|id| names.get(id).cloned())
                    };
                    let home = homes.get(&m.fingerprint).cloned().filter(|home| Some(home) != host.as_ref());
                    MemberPreview { display: m.display_name.clone(), role, home_relay: home }
                })
                .collect();
            sort_members(&mut shown_members);
            shown_servers.push(ServerPreview {
                name: server.name.clone(),
                removed: client.removed_from(&server.server_id).ok().flatten().is_some(),
                channels: server_channels
                    .iter()
                    .map(|c| ChannelPreview {
                        name: c.name.clone(),
                        voice: c.kind == ChannelKind::Voice,
                        private: client.is_private_channel(&c.channel_id),
                        unread: unread.get(&c.channel_id).copied().unwrap_or(0),
                    })
                    .collect(),
                hidden_private: None,
                members: shown_members,
            });
        }
        let same_account: Vec<&str> = opened.iter().filter(|(other, _, a)| a == account && other.name != profile.name).map(|(other, _, _)| other.name.as_str()).collect();
        let notes = if same_account.is_empty() {
            Vec::new()
        } else {
            vec![Note { label: format!("{} devices", same_account.len() + 1), tone: Tone::Info, detail: format!("same account as {}", same_account.join(", ")) }]
        };
        windows.push(WindowPreview { profile: profile.name.clone(), display, relay: own_relay, servers: shown_servers, dms: shown_dms, notes });
    }
    let counts = Counts {
        relays,
        windows: windows.len() as u32,
        people: people.len() as u32,
        servers: servers.len() as u32,
        channels: channels.len() as u32,
        roles: roles.len() as u32,
        dms: dm_ids.len() as u32,
        messages: messages.values().sum(),
    };
    Ok(Preview { windows, counts })
}
