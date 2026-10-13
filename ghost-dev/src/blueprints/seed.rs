//! Building a built-in blueprint's world by running its plan: people with accounts in their
//! profile folders, servers, channels, roles and history, all made through the real relays
//! by the same code the app runs (headless devices on the profiles' folders). Everyone has
//! read what they had when they last were online. Last, each profile gets the app settings
//! it needs to open straight into that world rather than a setup screen.

use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ghost_core::account_keys::RecoveryKey;
use ghost_core::storage::ChannelKind;
use ghost_core::wire::derive_default_channel_id;
use ghost_node::Device;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::Serialize;

use super::plan::{Step, GENERAL};
use crate::paths::{EXTRAS, PROFILES};

/// How long a step may wait on another device (an owner taking in a join, a member
/// entering a private channel) before building fails.
const WAIT: Duration = Duration::from_secs(30);
const POLL: Duration = Duration::from_millis(200);
/// Messages between progress lines in the blueprint log.
const PROGRESS_EVERY: usize = 100;
/// Each account's recovery key, beside its device, so a tester can recover it in the app.
const RECOVERY_KEY_FILE: &str = "recovery-key.txt";

/// Ordinary chat, so history reads like a team's rather than filler.
const LINES: &[&str] = &[
    "morning all",
    "anyone up for a call later?",
    "pushed the fix, mind taking a look?",
    "lunch in ten?",
    "the build is green again",
    "I'll be offline for an hour",
    "ha, classic",
    "can someone read over my notes before tomorrow?",
    "sounds good to me",
    "on it",
    "sent you the doc",
    "what time works tomorrow?",
    "nice work on the release",
    "brb",
    "did the invite reach you?",
    "testing voice in the lounge in five",
    "notes from today: ship friday, docs next week",
    "who has the projector?",
    "running late, start without me",
    "that was quicker than I expected",
    "can we move standup to 10?",
    "I'll pick that one up",
    "thanks, that fixed it",
    "the new channel layout is much easier to scan",
    "back now",
    "has anyone tried it on the old laptop?",
    "coffee?",
    "yes, merged",
    "let's keep that for next week",
    "I wrote it up in the doc",
    "agreed",
    "not sure, let me check",
    "found it: it was the config, not the code",
    "weekend plans?",
    "the relay came back after the restart",
    "good call",
    "two minutes",
    "I can take notes",
    "makes sense",
    "see you tomorrow",
];

/// The app settings a profile opens with: a name means set up, and its home relay.
#[derive(Serialize)]
struct AppConfig<'a> {
    display_name: &'a str,
    relay_url: &'a str,
}

/// Someone in the world, by their profile or headless name.
struct Person {
    display: String,
    relay: String,
    /// Whether the person is a launcher profile the app will open, or exists only to fill
    /// the world (a busy server's extra members).
    profile: bool,
    folder: PathBuf,
    device: Device,
    online: bool,
}

/// A server or DM, by its id and its #general.
#[derive(Clone, Copy)]
struct Server {
    id: [u8; 32],
    general: [u8; 32],
}

pub struct World {
    root: PathBuf,
    relays: HashMap<String, String>,
    log: Box<dyn Fn(String) + Send + Sync>,
    people: HashMap<String, Person>,
    /// What the plan has made so far, by the names it uses.
    servers: HashMap<String, Server>,
    channels: HashMap<(String, String), [u8; 32]>,
    /// Each role's id and holders, by server and role name.
    roles: HashMap<(String, String), (u8, Vec<String>)>,
    rng: StdRng,
}

/// Wait until `check` holds, or fail naming `what`. `check` makes an owned future each
/// time: one borrowing the closure would keep the building future from being `Send`.
async fn until<F: Future<Output = bool>>(what: &str, mut check: impl FnMut() -> F) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + WAIT;
    while tokio::time::Instant::now() < deadline {
        if check().await {
            return Ok(());
        }
        tokio::time::sleep(POLL).await;
    }
    Err(format!("timed out waiting for {what}"))
}

fn failed(what: &str) -> impl Fn(ghost_core::error::GhostError) -> String + '_ {
    move |e| format!("{what}: {e}")
}

impl World {
    /// A world kept under `root` (profiles in `profiles/`, headless people in `extras/`),
    /// on the relays named in `relays` (name to URL). `seed` makes its history repeatable.
    pub fn new(root: &Path, relays: HashMap<String, String>, seed: u64, log: impl Fn(String) + Send + Sync + 'static) -> Self {
        Self {
            root: root.to_path_buf(),
            relays,
            log: Box::new(log),
            people: HashMap::new(),
            servers: HashMap::new(),
            channels: HashMap::new(),
            roles: HashMap::new(),
            rng: StdRng::seed_from_u64(seed),
        }
    }

    fn log(&self, line: impl Into<String>) {
        (self.log)(line.into());
    }

    fn relay_url(&self, relay: &str) -> Result<String, String> {
        self.relays.get(relay).cloned().ok_or_else(|| format!("relay {relay} is not running"))
    }

    fn person(&self, name: &str) -> Result<&Person, String> {
        self.people.get(name).ok_or_else(|| format!("{name} is not in this world"))
    }

    fn server(&self, name: &str) -> Result<Server, String> {
        self.servers.get(name).copied().ok_or_else(|| format!("no server {name} in this plan"))
    }

    fn channel(&self, server: &str, name: &str) -> Result<[u8; 32], String> {
        if name == GENERAL {
            return Ok(self.server(server)?.general);
        }
        self.channels.get(&(server.to_string(), name.to_string())).copied().ok_or_else(|| format!("no #{name} in {server}"))
    }

    /// Run `plan`, step by step.
    pub async fn run(&mut self, plan: &[Step]) -> Result<(), String> {
        for step in plan {
            self.step(step).await?;
        }
        Ok(())
    }

    async fn step(&mut self, step: &Step) -> Result<(), String> {
        match step {
            Step::Accounts(people) => {
                for person in people {
                    self.create(&person.name, &person.display, &person.relay, !person.headless).await?;
                }
            }
            Step::Server { owner, name } => {
                let id = self.person(owner)?.device.create_server(name).await.map_err(failed(&format!("create {name}")))?;
                self.servers.insert(name.clone(), Server { id, general: derive_default_channel_id(&id) });
                self.log(format!("{} made the server {name}", self.person(owner)?.display));
            }
            Step::Channel { owner, server, name, kind } => {
                let server_id = self.server(server)?.id;
                let id = self.person(owner)?.device.create_channel(&server_id, name, *kind).await.map_err(failed(&format!("create #{name}")))?;
                self.channels.insert((server.clone(), name.clone()), id);
                self.log(match kind {
                    ChannelKind::Text => format!("made #{name}"),
                    ChannelKind::Voice => format!("made the {name} voice channel"),
                });
            }
            Step::Join { owner, server, members } => {
                let server = self.server(server)?;
                for member in members {
                    self.join(owner, server, member).await?;
                }
            }
            Step::Role { owner, server, name, permissions, holders } => {
                let server_id = self.server(server)?.id;
                let mut accounts = Vec::new();
                for holder in holders {
                    accounts.push(self.person(holder)?.device.fingerprint().await);
                }
                let id = self.person(owner)?.device.add_role(&server_id, name, *permissions, &accounts).await.map_err(failed(&format!("add the {name} role")))?;
                self.roles.insert((server.clone(), name.clone()), (id, holders.clone()));
                self.log(format!("{} hold the {name} role", holders.join(" and ")));
            }
            Step::PrivateChannel { owner, server, name, roles } => {
                let server_id = self.server(server)?.id;
                let (mut role_ids, mut holders) = (Vec::new(), Vec::new());
                for role in roles {
                    let (id, held_by) = self.roles.get(&(server.clone(), role.clone())).ok_or_else(|| format!("no {role} role in {server}"))?;
                    role_ids.push(*id);
                    holders.extend(held_by.iter().cloned());
                }
                let id = self.person(owner)?.device.create_private_channel(&server_id, name, role_ids, Vec::new()).await.map_err(failed(&format!("create #{name}")))?;
                self.channels.insert((server.clone(), name.clone()), id);
                // Everyone who may enter is in before anything is posted there.
                for holder in holders {
                    let client = self.person(&holder)?.device.client.clone();
                    let entered = || {
                        let client = client.clone();
                        async move { client.lock().await.store().get_channel(&id).is_ok() }
                    };
                    until(&format!("{holder} to enter #{name}"), entered).await?;
                }
                self.log(format!("made the private #{name}"));
            }
            Step::Chat { server, channel, authors, count } => {
                let server_id = self.server(server)?.id;
                let channel_id = self.channel(server, channel)?;
                self.chat(server_id, channel_id, authors, *count).await?;
            }
            Step::Dm { owner, member, count } => {
                let name = self.person(member)?.display.clone();
                let id = self.person(owner)?.device.create_dm(&name).await.map_err(failed("create the DM"))?;
                let dm = Server { id, general: derive_default_channel_id(&id) };
                self.join(owner, dm, member).await?;
                self.chat(dm.id, dm.general, &[owner.clone(), member.clone()], *count).await?;
            }
            Step::GoOffline { name } => self.go_offline(name).await?,
            Step::Kick { owner, server, member } => {
                let server_id = self.server(server)?.id;
                let account = self.person(member)?.device.fingerprint().await;
                self.person(owner)?.device.kick(&server_id, &account).await.map_err(failed(&format!("kick {member}")))?;
                self.log(format!("{} was kicked", self.person(member)?.display));
            }
            Step::Link { owner, profile, label } => self.link(owner, profile, label).await?,
        }
        Ok(())
    }

    async fn create(&mut self, name: &str, display: &str, relay: &str, profile: bool) -> Result<(), String> {
        let folder = self.root.join(if profile { PROFILES } else { EXTRAS }).join(name);
        let _ = std::fs::remove_dir_all(&folder);
        let recovery_key = RecoveryKey::generate();
        let mut device =
            Device::create(&folder, &self.relay_url(relay)?, display, &recovery_key).await.map_err(failed(&format!("create {name}")))?;
        std::fs::write(folder.join(RECOVERY_KEY_FILE), recovery_key.encode()).map_err(|e| format!("save {name}'s recovery key: {e}"))?;
        device.start();
        self.people.insert(name.to_string(), Person { display: display.to_string(), relay: relay.to_string(), profile, folder, device, online: true });
        self.log(format!("{display} has an account, at home on relay {relay}"));
        Ok(())
    }

    /// Bring `member` into `owner`'s server by an invite, through the relay hosting it
    /// when that is not the member's home, and wait for the owner to take the join in.
    async fn join(&self, owner: &str, server: Server, member: &str) -> Result<(), String> {
        let (owner_person, member_person) = (self.person(owner)?, self.person(member)?);
        let (token, key) = owner_person.device.invite(&server.id).await.map_err(failed("make an invite"))?;
        let joined = if member_person.relay == owner_person.relay {
            member_person.device.join(&token, &key).await
        } else {
            member_person.device.join_at(&self.relay_url(&owner_person.relay)?, &token, &key).await
        };
        joined.map_err(failed(&format!("{member} joining")))?;
        // The member's name follows its join commit in a message of its own, and the next
        // invite gives the newcomer the members by the names the owner knows, so the join
        // is in once the owner knows the member by name.
        let client = owner_person.device.client.clone();
        let (account, display) = (member_person.device.fingerprint().await, member_person.display.clone());
        let named = || {
            let (client, display) = (client.clone(), display.clone());
            async move {
                let c = client.lock().await;
                c.store().list_members(&server.id).is_ok_and(|members| members.iter().any(|m| m.fingerprint == account && m.display_name == display))
            }
        };
        until(&format!("{owner} to take in {member}'s join"), named).await?;
        self.log(format!("{} joined", member_person.display));
        Ok(())
    }

    /// `count` messages in `channel`, each from one of `authors`.
    async fn chat(&mut self, server: [u8; 32], channel: [u8; 32], authors: &[String], count: usize) -> Result<(), String> {
        for sent in 0..count {
            let author = &authors[self.rng.gen_range(0..authors.len())];
            let line = LINES[self.rng.gen_range(0..LINES.len())];
            self.person(author)?.device.say(&server, &channel, line).await.map_err(failed(&format!("{author} posting")))?;
            if (sent + 1) % PROGRESS_EVERY == 0 {
                self.log(format!("{} of {count} messages", sent + 1));
            }
        }
        Ok(())
    }

    /// Link a new device, as profile `profile`, to `owner`'s account.
    async fn link(&mut self, owner: &str, profile: &str, label: &str) -> Result<(), String> {
        let folder = self.root.join(PROFILES).join(profile);
        let _ = std::fs::remove_dir_all(&folder);
        let (relay, display) = {
            let person = self.person(owner)?;
            (person.relay.clone(), person.display.clone())
        };
        let mut device =
            self.person(owner)?.device.link_device(&folder, &self.relay_url(&relay)?, label).await.map_err(failed("link the device"))?;
        device.start();
        // Its session enters the private channels the relays list for the account, as the
        // app's does on start, and a member tells it each one's name after. The link is
        // done once it shows every channel as the owner's does.
        let channels: Vec<([u8; 32], String)> = {
            let owner_client = self.person(owner)?.device.client.lock().await;
            let store = owner_client.store();
            let servers = store.list_servers().map_err(failed(&format!("list {owner}'s servers")))?;
            let mut channels = Vec::new();
            for server in servers {
                channels.extend(store.list_channels(&server.server_id).map_err(failed("list channels"))?.into_iter().map(|c| (c.channel_id, c.name)));
            }
            channels
        };
        let client = device.client.clone();
        let entered = || {
            let (client, channels) = (client.clone(), channels.clone());
            async move {
                let c = client.lock().await;
                channels.iter().all(|(id, name)| c.store().get_channel(id).is_ok_and(|channel| channel.name == *name))
            }
        };
        until(&format!("{profile} to enter {owner}'s channels"), entered).await?;
        self.people.insert(profile.to_string(), Person { display: display.clone(), relay, profile: true, folder, device, online: true });
        self.log(format!("{display} linked a second device ({label})"));
        Ok(())
    }

    /// Stop `name`'s device, having read everything it has, so whatever happens next
    /// reaches it only when its window opens.
    async fn go_offline(&mut self, name: &str) -> Result<(), String> {
        let person = self.people.get_mut(name).ok_or_else(|| format!("{name} is not in this world"))?;
        person.device.mark_all_read().await.map_err(failed(&format!("{name} reading")))?;
        person.device.stop().await;
        person.online = false;
        let display = person.display.clone();
        self.log(format!("{display} went offline"));
        Ok(())
    }

    /// Let everyone still online read what they have, stop every device and give each
    /// profile its app settings. Headless people's folders go: they only ever existed to
    /// fill the world.
    pub async fn finish(self) -> Result<(), String> {
        for (name, person) in self.people {
            let Person { display, relay, profile, folder, mut device, online } = person;
            if profile && online {
                device.mark_all_read().await.map_err(failed(&format!("{name} reading")))?;
            }
            device.stop().await;
            drop(device);
            if !profile {
                let _ = std::fs::remove_dir_all(&folder);
                continue;
            }
            let relay_url = self.relays.get(&relay).cloned().unwrap_or_default();
            let config = toml::to_string(&AppConfig { display_name: &display, relay_url: &relay_url }).map_err(|e| e.to_string())?;
            std::fs::write(folder.join("config.toml"), config).map_err(|e| format!("write {display}'s settings: {e}"))?;
        }
        Ok(())
    }
}
