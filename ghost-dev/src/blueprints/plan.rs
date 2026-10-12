//! A built-in blueprint's plan: the ordered steps that build its world. The world builder
//! runs them through the real relays, and the page's preview is worked out from them, so
//! the two always agree.

use ghost_core::storage::ChannelKind;

/// The channel every server starts with.
pub const GENERAL: &str = "general";

/// Someone a plan gives an account: a launcher profile, or a headless person who only
/// fills the world.
#[derive(Debug, Clone)]
pub struct Person {
    pub name: String,
    pub display: String,
    pub relay: String,
    pub headless: bool,
}

#[derive(Debug, Clone)]
pub enum Step {
    Accounts(Vec<Person>),
    /// `owner` creates server `name`, with #general, on their home relay.
    Server { owner: String, name: String },
    Channel { owner: String, server: String, name: String, kind: ChannelKind },
    /// `owner` invites each of `members`, who joins through the relay hosting the server.
    Join { owner: String, server: String, members: Vec<String> },
    Role { owner: String, server: String, name: String, permissions: u32, holders: Vec<String> },
    /// A text channel only holders of `roles` may enter.
    PrivateChannel { owner: String, server: String, name: String, roles: Vec<String> },
    /// `count` messages in `channel`, each from one of `authors`.
    Chat { server: String, channel: String, authors: Vec<String>, count: usize },
    /// A DM between `owner` and `member`, with `count` messages between them.
    Dm { owner: String, member: String, count: usize },
    /// Someone stops, so what follows reaches them only when their window opens.
    GoOffline { name: String },
    Kick { owner: String, server: String, member: String },
    /// `owner` links a second device, opened as profile `profile`.
    Link { owner: String, profile: String, label: String },
}

/// A display name for a profile name: capitalised.
pub fn display(name: &str) -> String {
    let mut chars = name.chars();
    chars.next().map(|first| first.to_uppercase().chain(chars).collect()).unwrap_or_default()
}

/// Accounts for launcher profiles `names`, at home on `relay`.
pub fn profiles(names: &[&str], relay: &str) -> Step {
    Step::Accounts(
        names.iter().map(|name| Person { name: name.to_string(), display: display(name), relay: relay.into(), headless: false }).collect(),
    )
}

pub fn server(owner: &str, name: &str) -> Step {
    Step::Server { owner: owner.into(), name: name.into() }
}

pub fn channel(owner: &str, server: &str, name: &str, kind: ChannelKind) -> Step {
    Step::Channel { owner: owner.into(), server: server.into(), name: name.into(), kind }
}

pub fn join(owner: &str, server: &str, members: &[&str]) -> Step {
    Step::Join { owner: owner.into(), server: server.into(), members: members.iter().map(|m| m.to_string()).collect() }
}

pub fn role(owner: &str, server: &str, name: &str, permissions: u32, holders: &[&str]) -> Step {
    Step::Role { owner: owner.into(), server: server.into(), name: name.into(), permissions, holders: holders.iter().map(|h| h.to_string()).collect() }
}

pub fn private_channel(owner: &str, server: &str, name: &str, roles: &[&str]) -> Step {
    Step::PrivateChannel { owner: owner.into(), server: server.into(), name: name.into(), roles: roles.iter().map(|r| r.to_string()).collect() }
}

pub fn chat(server: &str, channel: &str, authors: &[&str], count: usize) -> Step {
    Step::Chat { server: server.into(), channel: channel.into(), authors: authors.iter().map(|a| a.to_string()).collect(), count }
}

pub fn dm(owner: &str, member: &str, count: usize) -> Step {
    Step::Dm { owner: owner.into(), member: member.into(), count }
}

pub fn go_offline(name: &str) -> Step {
    Step::GoOffline { name: name.into() }
}

pub fn kick(owner: &str, server: &str, member: &str) -> Step {
    Step::Kick { owner: owner.into(), server: server.into(), member: member.into() }
}

pub fn link(owner: &str, profile: &str, label: &str) -> Step {
    Step::Link { owner: owner.into(), profile: profile.into(), label: label.into() }
}

/// Every launcher profile a plan opens, with its home relay, in the order it makes them.
pub fn plan_profiles(plan: &[Step]) -> Vec<(String, String)> {
    let mut found: Vec<(String, String)> = Vec::new();
    for step in plan {
        match step {
            Step::Accounts(people) => found.extend(people.iter().filter(|p| !p.headless).map(|p| (p.name.clone(), p.relay.clone()))),
            Step::Link { owner, profile, .. } => {
                if let Some(relay) = found.iter().find(|(name, _)| name == owner).map(|(_, relay)| relay.clone()) {
                    found.push((profile.clone(), relay));
                }
            }
            _ => {}
        }
    }
    found
}

/// Every relay a plan gives someone a home on, in the order it first does.
pub fn plan_relays(plan: &[Step]) -> Vec<String> {
    let mut relays: Vec<String> = Vec::new();
    for step in plan {
        if let Step::Accounts(people) = step {
            for person in people {
                if !relays.contains(&person.relay) {
                    relays.push(person.relay.clone());
                }
            }
        }
    }
    relays
}
