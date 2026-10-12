//! Saved blueprints: whatever was set up by hand (every profile's data, every relay's
//! database and the launcher's settings) copied under a name, to use again later, with a
//! preview read from the profiles' data. Everything stops while it is copied, so databases
//! are whole; saving reopens what was running where it was, and using one starts what was
//! running when it was saved.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::launcher::{launcher, profile_process, relay_process};
use crate::paths::{self, PROFILES, RELAYS};
use crate::process::Status;
use crate::settings::Settings;
use crate::windows::{self, Bounds};
use crate::{callers, profiles, relays};

use super::log;
use super::preview::{self, Preview, ProfileData};

const META_FILE: &str = "blueprint.json";
const MAX_NAME: usize = 60;

#[derive(Serialize, Deserialize)]
pub struct Meta {
    pub name: String,
    pub saved_at_ms: u64,
    pub settings: Settings,
    pub preview: Preview,
    running_relays: Vec<String>,
    running_profiles: Vec<String>,
}

pub struct Saved {
    pub id: String,
    pub meta: Meta,
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |since| since.as_millis() as u64)
}

/// A folder name for `name`: its letters and digits, dashed, then the time, so two
/// blueprints of one name never collide.
fn id_for(name: &str, at_ms: u64) -> String {
    let slug: String = name.to_lowercase().chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).collect();
    let slug = slug.split('-').filter(|part| !part.is_empty()).collect::<Vec<_>>().join("-");
    format!("{}-{at_ms}", if slug.is_empty() { "blueprint" } else { &slug })
}

/// Saved blueprint `id`'s folder, refusing ids that would reach outside the blueprints.
fn folder(id: &str) -> Result<PathBuf, String> {
    if id.is_empty() || id.starts_with('.') || id.contains(['/', '\\']) {
        return Err(format!("no blueprint {id}"));
    }
    Ok(paths::blueprints().join(id))
}

fn read_meta(folder: &Path) -> Option<Meta> {
    serde_json::from_slice(&std::fs::read(folder.join(META_FILE)).ok()?).ok()
}

pub fn exists(id: &str) -> bool {
    folder(id).is_ok_and(|folder| folder.join(META_FILE).exists())
}

/// Every saved blueprint, newest first.
pub fn list() -> Vec<Saved> {
    let Ok(entries) = std::fs::read_dir(paths::blueprints()) else { return Vec::new() };
    let mut saved: Vec<Saved> = entries
        .flatten()
        .filter_map(|entry| Some(Saved { meta: read_meta(&entry.path())?, id: entry.file_name().to_str()?.to_string() }))
        .collect();
    saved.sort_by(|a, b| b.meta.saved_at_ms.cmp(&a.meta.saved_at_ms));
    saved
}

fn copy_dir(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

/// Copy the profiles' and relays' folders from `from` into `to`, where they exist.
fn copy_world(from: &Path, to: &Path) -> Result<(), String> {
    for kind in [PROFILES, RELAYS] {
        if from.join(kind).exists() {
            copy_dir(&from.join(kind), &to.join(kind)).map_err(|e| format!("copy {kind}: {e}"))?;
        }
    }
    Ok(())
}

/// What every profile with data holds, read while nothing runs.
async fn read_preview(settings: &Settings) -> Result<Preview, String> {
    let relay_names: HashMap<String, String> = settings.relays.iter().map(|r| (r.url(), r.name.clone())).collect();
    let mut held = Vec::new();
    for profile in &settings.profiles {
        let folder = paths::profile(&profile.name);
        if folder.exists() {
            held.push(ProfileData { name: profile.name.clone(), folder, relay_url: settings.relay(&profile.relay)?.url() });
        }
    }
    let relays = settings.relays.iter().filter(|r| paths::relay(&r.name).exists()).count() as u32;
    preview::of_profiles(&held, &relay_names, relays).await
}

/// Start `relays`, trying every one and keeping the first failure.
async fn start_relays(relays: &[String], first_error: &mut Option<String>) {
    for relay in relays {
        if let Err(e) = relays::start(relay).await {
            first_error.get_or_insert(format!("start relay {relay}: {e}"));
        }
    }
}

/// Save everything as blueprint `name`. Test callers end, since the calls they were in do.
pub async fn save(name: &str) -> Result<(), String> {
    let name = name.trim();
    if name.is_empty() || name.len() > MAX_NAME {
        return Err(format!("a blueprint name is 1 to {MAX_NAME} characters"));
    }
    let launcher = launcher();
    let settings = launcher.settings.lock().unwrap().clone();
    let running = |process: String| launcher.processes.status(&process) == Status::Running;
    let running_relays: Vec<String> = settings.relays.iter().map(|r| r.name.clone()).filter(|name| running(relay_process(name))).collect();
    let running_profiles: Vec<String> = settings.profiles.iter().map(|p| p.name.clone()).filter(|name| running(profile_process(name))).collect();
    let mut open: Vec<(String, Option<Bounds>)> = Vec::new();
    for profile in &running_profiles {
        open.push((profile.clone(), windows::window(profile).await));
    }

    log("stopping everything");
    let callers: Vec<u32> = launcher.callers.lock().unwrap().keys().copied().collect();
    for id in callers {
        callers::remove(id).await;
    }
    for profile in &settings.profiles {
        profiles::stop(&profile.name).await;
    }
    for relay in &settings.relays {
        relays::stop(&relay.name).await;
    }

    log(format!("copying every profile and relay as {name}"));
    let saved_at_ms = now_ms();
    let target = paths::blueprints().join(id_for(name, saved_at_ms));
    let saved = match read_preview(&settings).await {
        Ok(preview) => {
            let meta = Meta { name: name.to_string(), saved_at_ms, settings, preview, running_relays: running_relays.clone(), running_profiles };
            copy_world(&paths::home(), &target).and_then(|()| {
                let json = serde_json::to_vec_pretty(&meta).map_err(|e| e.to_string())?;
                std::fs::write(target.join(META_FILE), json).map_err(|e| format!("write {META_FILE}: {e}"))
            })
        }
        Err(e) => Err(format!("read what the profiles hold: {e}")),
    };
    if saved.is_err() {
        let _ = std::fs::remove_dir_all(&target);
    }

    log("starting what was running again");
    let mut first_error = None;
    start_relays(&running_relays, &mut first_error).await;
    for (profile, bounds) in open {
        if let Err(e) = profiles::start_at(&profile, bounds).await {
            first_error.get_or_insert(format!("start {profile}: {e}"));
        }
    }
    saved.and(first_error.map_or(Ok(()), Err))
}

/// Replace everything with saved blueprint `id`, its settings included, and start what
/// was running when it was saved. The world must already be cleared.
pub async fn apply(id: &str) -> Result<(), String> {
    let source = folder(id)?;
    let meta = read_meta(&source).ok_or_else(|| format!("no blueprint {id}"))?;
    log(format!("copying in {}", meta.name));
    copy_world(&source, &paths::home())?;
    meta.settings.save()?;
    *launcher().settings.lock().unwrap() = meta.settings;
    log("starting what was running when it was saved");
    let mut first_error = None;
    start_relays(&meta.running_relays, &mut first_error).await;
    if let Err(e) = profiles::start_all(&meta.running_profiles).await {
        first_error.get_or_insert(e);
    }
    first_error.map_or(Ok(()), Err)
}

pub fn delete(id: &str) -> Result<(), String> {
    std::fs::remove_dir_all(folder(id)?).map_err(|e| format!("delete blueprint {id}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folders_are_named_from_the_name_and_time() {
        assert_eq!(id_for("Before the kick test!", 42), "before-the-kick-test-42");
        assert_eq!(id_for("  ", 7), "blueprint-7");
    }

    #[test]
    fn ids_cannot_reach_outside_the_blueprints() {
        assert!(folder("../profiles").is_err());
        assert!(folder("..").is_err());
        assert!(folder("").is_err());
        assert!(folder("team-42").is_ok());
    }

    #[test]
    fn a_world_copies_whole_folders() {
        let (from, to) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        std::fs::create_dir_all(from.path().join(PROFILES).join("alice")).unwrap();
        std::fs::write(from.path().join(PROFILES).join("alice").join("ghost.db"), b"db").unwrap();
        std::fs::create_dir_all(from.path().join(RELAYS).join("A")).unwrap();
        std::fs::write(from.path().join(RELAYS).join("A").join("relay.db"), b"relay").unwrap();
        copy_world(from.path(), to.path()).unwrap();
        assert_eq!(std::fs::read(to.path().join(PROFILES).join("alice").join("ghost.db")).unwrap(), b"db");
        assert_eq!(std::fs::read(to.path().join(RELAYS).join("A").join("relay.db")).unwrap(), b"relay");
    }
}
