//! Built-in blueprints built against real relays in-process, then the profiles' folders
//! read back the way a saved blueprint's preview is read: each plan's preview must match
//! what it actually built.

use std::collections::HashMap;
use std::path::Path;

use ghost_relay::config::Config;
use ghost_relay::server::RunningRelay;
use ghost_relay::storage::Storage;

use super::built_in::{self, Sizes};
use super::plan::{plan_profiles, Step};
use super::preview::{self, Preview, ProfileData, WindowPreview};
use super::seed::World;
use crate::paths::PROFILES;

async fn relay() -> RunningRelay {
    let config = Config {
        port: 0,
        max_blob_size: 10 * 1024 * 1024,
        voice_port: 0,
        voice_public_port: None,
        max_voice_participants: 25,
        db_path: None,
        log_retention_hours: 72,
        log_min_entries: 100,
        public_url: None,
        mirror_refresh_secs: 1,
        ws_ping_secs: 1,
        presence_grace_secs: 2,
        skip_policy_checks_for_tests: false,
        revoked_devices_for_tests: Default::default(),
        trusted_proxies: Vec::new(),
    };
    ghost_relay::server::start(config, Storage::open_ephemeral().unwrap(), ([127, 0, 0, 1], 0).into()).await.unwrap()
}

/// Build built-in blueprint `id` at `sizes` on `relays` (name to URL).
async fn build(id: &str, relays: &HashMap<String, String>, sizes: Sizes) -> (tempfile::TempDir, Vec<Step>) {
    let root = tempfile::tempdir().unwrap();
    let plan = (built_in::find(id).unwrap().plan)(sizes);
    let mut world = World::new(root.path(), relays.clone(), 7, |_| {});
    world.run(&plan).await.unwrap();
    world.finish().await.unwrap();
    (root, plan)
}

/// What the built profiles hold, read as a saved blueprint's preview is.
async fn read_back(root: &Path, plan: &[Step], relays: &HashMap<String, String>) -> Preview {
    let profiles: Vec<ProfileData> = plan_profiles(plan)
        .into_iter()
        .map(|(name, relay)| ProfileData { folder: root.join(PROFILES).join(&name), relay_url: relays[&relay].clone(), name })
        .collect();
    let names: HashMap<String, String> = relays.iter().map(|(name, url)| (url.clone(), name.clone())).collect();
    preview::of_profiles(&profiles, &names, relays.len() as u32).await.unwrap()
}

/// A window as a profile's own data can show it: which private channels it cannot see is
/// not in its data.
fn as_stored(window: &WindowPreview) -> WindowPreview {
    let mut window = window.clone();
    for server in &mut window.servers {
        server.hidden_private = None;
    }
    window
}

/// Build `id` and check its plan's preview against what was built. Windows of profiles
/// offline at the end are left out: what they missed only reaches them when they open.
async fn plan_matches_build(id: &str, relay_names: &[&str], sizes: Sizes, offline_at_end: &[&str]) -> (tempfile::TempDir, Preview) {
    let mut running = Vec::new();
    let mut relays = HashMap::new();
    for name in relay_names {
        let relay = relay().await;
        relays.insert(name.to_string(), relay.url());
        running.push(relay);
    }
    let (root, plan) = build(id, &relays, sizes).await;
    let planned = preview::of_plan(&plan);
    let built = read_back(root.path(), &plan, &relays).await;
    assert_eq!(planned.counts, built.counts, "{id}: counts");
    for window in planned.windows.iter().filter(|w| !offline_at_end.contains(&w.profile.as_str())) {
        let stored = built.windows.iter().find(|w| w.profile == window.profile).unwrap_or_else(|| panic!("{id}: no window {}", window.profile));
        assert_eq!(as_stored(window), *stored, "{id}: {}'s window", window.profile);
    }
    (root, planned)
}

#[tokio::test(flavor = "multi_thread")]
async fn the_team_opens_set_up_with_bob_moderating_and_carol_outside_mods() {
    let (root, planned) = plan_matches_build("team", &["A"], Sizes::default(), &[]).await;
    let config = std::fs::read_to_string(root.path().join(PROFILES).join("alice").join("config.toml")).unwrap();
    assert!(config.contains("display_name = \"Alice\""), "set up, so no setup screen: {config}");
    let carol = planned.windows.iter().find(|w| w.profile == "carol").unwrap();
    assert!(!carol.servers[0].channels.iter().any(|c| c.name == "mods"), "carol is outside #mods");
    assert_eq!(carol.servers[0].hidden_private, Some(1));
}

#[tokio::test(flavor = "multi_thread")]
async fn across_relays_shows_dave_from_relay_b_in_club() {
    let (_root, planned) = plan_matches_build("across-relays", &["A", "B"], Sizes::default(), &[]).await;
    let alice = planned.windows.iter().find(|w| w.profile == "alice").unwrap();
    let dave = alice.servers[0].members.iter().find(|m| m.display == "Dave").unwrap();
    assert_eq!(dave.home_relay.as_deref(), Some("B"));
}

#[tokio::test(flavor = "multi_thread")]
async fn catch_up_leaves_only_carol_with_messages_to_catch_up_on() {
    let (_root, planned) = plan_matches_build("catch-up", &["A"], Sizes::default(), &["carol"]).await;
    let carol = planned.windows.iter().find(|w| w.profile == "carol").unwrap();
    assert_eq!(carol.servers[0].channels[0].unread, 300);
    assert!(planned.windows.iter().filter(|w| w.profile != "carol").all(|w| w.servers.iter().flat_map(|s| &s.channels).all(|c| c.unread == 0)));
}

#[tokio::test(flavor = "multi_thread")]
async fn linked_devices_open_the_same_account_twice() {
    plan_matches_build("linked-devices", &["A"], Sizes::default(), &[]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn kicked_shows_club_read_only_to_eve_once_she_opens() {
    let (_root, planned) = plan_matches_build("kicked", &["A"], Sizes::default(), &["eve"]).await;
    let eve = planned.windows.iter().find(|w| w.profile == "eve").unwrap();
    assert!(eve.servers.iter().all(|s| s.removed), "club stays, read-only");
    assert_eq!(eve.notes[0].label, "kicked while offline");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_small_busy_server_matches_its_plan() {
    plan_matches_build("busy", &["A"], Sizes { members: 5, channels: 3, messages: 12 }, &[]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn fresh_accounts_have_nothing() {
    let (_root, planned) = plan_matches_build("fresh", &["A"], Sizes::default(), &[]).await;
    assert!(planned.windows.iter().all(|w| w.servers.is_empty() && w.dms.is_empty()));
}
