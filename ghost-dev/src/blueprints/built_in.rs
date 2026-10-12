//! The blueprints that come with the launcher, each a plan. Each puts Ghost in a state
//! worth testing that takes a while to reach by hand: a team with roles and a private
//! channel, a member from another relay, catching up after being offline, two devices on
//! one account, being kicked, a busy server, and a clean start.

use ghost_core::storage::ChannelKind;
use ghost_wire::policy::{KICK, MANAGE_CHANNELS};
use serde::{Deserialize, Serialize};

use super::plan::{channel, chat, dm, go_offline, join, kick, link, private_channel, profiles, role, server, Person, Step, GENERAL};

/// How big the busy server is, as the page sets it.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
pub struct Sizes {
    /// Everyone in the server, the three profiles included.
    pub members: u32,
    pub channels: u32,
    pub messages: u32,
}

impl Default for Sizes {
    fn default() -> Self {
        Self { members: 8, channels: 6, messages: 2000 }
    }
}

const TEAM: [&str; 3] = ["alice", "bob", "carol"];

/// The smallest busy server: the three profiles in #general.
pub const MIN_SIZES: Sizes = Sizes { members: TEAM.len() as u32, channels: 1, messages: 0 };
/// The largest, so a typo cannot fill the disk.
pub const MAX_SIZES: Sizes = Sizes { members: 50, channels: 30, messages: 20_000 };

impl Sizes {
    fn clamped(self) -> Self {
        Self {
            members: self.members.clamp(MIN_SIZES.members, MAX_SIZES.members),
            channels: self.channels.clamp(MIN_SIZES.channels, MAX_SIZES.channels),
            messages: self.messages.clamp(MIN_SIZES.messages, MAX_SIZES.messages),
        }
    }
}

pub struct BuiltIn {
    pub id: &'static str,
    pub name: &'static str,
    /// What it is for, in a few words.
    pub purpose: &'static str,
    pub plan: fn(Sizes) -> Vec<Step>,
    /// Takes `Sizes`.
    pub sized: bool,
}

pub const BUILT_IN: &[BuiltIn] = &[
    BuiltIn { id: "team", name: "team", purpose: "roles, private channels, DMs and voice", plan: |_| team(), sized: false },
    BuiltIn { id: "across-relays", name: "across relays", purpose: "a member whose home is another relay", plan: |_| across_relays(), sized: false },
    BuiltIn { id: "catch-up", name: "catch-up", purpose: "catching up after time offline", plan: |_| catch_up(), sized: false },
    BuiltIn { id: "linked-devices", name: "linked devices", purpose: "one account on two devices", plan: |_| linked_devices(), sized: false },
    BuiltIn { id: "kicked", name: "kicked", purpose: "being removed from a server", plan: |_| kicked(), sized: false },
    BuiltIn { id: "busy", name: "busy server", purpose: "scrolling, search and load with lots of history", plan: busy, sized: true },
    BuiltIn { id: "fresh", name: "fresh accounts", purpose: "onboarding: accounts with no servers", plan: |_| vec![profiles(&["alice", "bob"], "A")], sized: false },
];

pub fn find(id: &str) -> Option<&'static BuiltIn> {
    BUILT_IN.iter().find(|b| b.id == id)
}

/// alice's server club with #random, the lounge and a moderators-only #mods; bob is its
/// moderator, carol a member outside #mods; history, and a DM between alice and bob.
fn team() -> Vec<Step> {
    vec![
        profiles(&TEAM, "A"),
        server("alice", "club"),
        channel("alice", "club", "random", ChannelKind::Text),
        channel("alice", "club", "lounge", ChannelKind::Voice),
        join("alice", "club", &["bob", "carol"]),
        role("alice", "club", "moderator", KICK | MANAGE_CHANNELS, &["bob"]),
        private_channel("alice", "club", "mods", &["moderator"]),
        chat("club", GENERAL, &TEAM, 120),
        chat("club", "random", &TEAM, 50),
        chat("club", "mods", &["alice", "bob"], 20),
        dm("alice", "bob", 12),
    ]
}

fn across_relays() -> Vec<Step> {
    let mut plan = team();
    plan.extend([profiles(&["dave"], "B"), join("alice", "club", &["dave"]), chat("club", GENERAL, &["dave", "alice"], 10)]);
    plan
}

fn catch_up() -> Vec<Step> {
    let mut plan = team();
    plan.extend([go_offline("carol"), chat("club", GENERAL, &["alice", "bob"], 300)]);
    plan
}

fn linked_devices() -> Vec<Step> {
    let mut plan = team();
    plan.push(link("alice", "alice-laptop", "laptop"));
    plan
}

fn kicked() -> Vec<Step> {
    let mut plan = team();
    plan.extend([
        profiles(&["eve"], "A"),
        join("alice", "club", &["eve"]),
        chat("club", GENERAL, &["eve"], 3),
        go_offline("eve"),
        kick("alice", "club", "eve"),
    ]);
    plan
}

/// More members for the busy server, after the profiles.
const EXTRA_NAMES: &[&str] = &[
    "Frank", "Grace", "Heidi", "Ivan", "Judy", "Mallory", "Niaj", "Olivia", "Peggy", "Rupert", "Sybil", "Trent", "Uma", "Victor",
    "Walter", "Xena", "Yusuf", "Zoe",
];
const EXTRA_CHANNELS: &[&str] = &[
    "random", "design", "ops", "music", "books", "games", "photos", "travel", "food", "help", "releases", "ideas", "jobs", "pets",
];

fn busy(sizes: Sizes) -> Vec<Step> {
    let sizes = sizes.clamped();
    let extras: Vec<Person> = (0..sizes.members as usize - TEAM.len())
        .map(|index| Person {
            name: format!("extra-{}", index + 1),
            display: EXTRA_NAMES.get(index).map_or_else(|| format!("Member {}", index + TEAM.len() + 1), |name| name.to_string()),
            relay: "A".into(),
            headless: true,
        })
        .collect();
    let rooms: Vec<String> = std::iter::once(GENERAL.to_string())
        .chain((0..sizes.channels as usize - 1).map(|index| EXTRA_CHANNELS.get(index).map_or_else(|| format!("channel-{}", index + 2), |name| name.to_string())))
        .collect();
    let everyone: Vec<String> = TEAM.iter().map(|name| name.to_string()).chain(extras.iter().map(|p| p.name.clone())).collect();
    let others: Vec<&str> = everyone[1..].iter().map(String::as_str).collect();
    let authors: Vec<&str> = everyone.iter().map(String::as_str).collect();

    let mut plan = vec![profiles(&TEAM, "A")];
    if !extras.is_empty() {
        plan.push(Step::Accounts(extras));
    }
    plan.push(server("alice", "busy"));
    plan.extend(rooms[1..].iter().map(|room| channel("alice", "busy", room, ChannelKind::Text)));
    plan.push(join("alice", "busy", &others));
    // Spread the messages over the channels, most in #general as in a real server.
    let messages = sizes.messages as usize;
    let per_room = messages / (rooms.len() + 1);
    for (index, room) in rooms.iter().enumerate() {
        let count = if index == 0 { messages - per_room * (rooms.len() - 1) } else { per_room };
        plan.push(chat("busy", room, &authors, count));
    }
    plan
}
