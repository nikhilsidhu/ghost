//! Blueprints: worlds to start from. Built-in ones are made in code through the real
//! relays; saved ones are whatever was set up by hand, copied whole. Using one replaces
//! every profile's data and every relay's, then starts its profiles, their windows tiled.

mod built_in;
mod plan;
pub(crate) mod preview;
mod saved;
mod seed;

use std::collections::HashMap;
use std::future::Future;

use serde::Serialize;

pub use built_in::Sizes;
use built_in::{BUILT_IN, MAX_SIZES, MIN_SIZES};
pub use preview::Preview;

use crate::launcher::{hold_world, launcher};
use crate::paths;
use crate::settings::ProfileSettings;
use crate::{callers, profiles, relays, workspace};

/// The log of using or saving a blueprint.
pub const BLUEPRINT_PROCESS: &str = "blueprint";
/// History comes out the same each time a built-in blueprint is used.
const SEED: u64 = 7;

/// The sizes a built-in blueprint takes, with the bounds the page's inputs keep to.
#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
pub struct SizeLimits {
    default: Sizes,
    min: Sizes,
    max: Sizes,
}

#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BlueprintSource {
    /// Made by a plan; `sizes` when it takes them (the busy server).
    BuiltIn { purpose: String, sizes: Option<SizeLimits> },
    /// Saved from what was set up by hand.
    Saved { saved_at_ms: u64 },
}

#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
pub struct BlueprintView {
    id: String,
    name: String,
    source: BlueprintSource,
    /// What it opens; for a built-in one that takes sizes, at its default sizes.
    preview: Preview,
}

/// The built-in blueprints, then the saved ones, newest first.
pub fn views() -> Vec<BlueprintView> {
    let built_in = BUILT_IN.iter().map(|b| BlueprintView {
        id: b.id.into(),
        name: b.name.into(),
        source: BlueprintSource::BuiltIn {
            purpose: b.purpose.into(),
            sizes: b.sized.then(|| SizeLimits { default: Sizes::default(), min: MIN_SIZES, max: MAX_SIZES }),
        },
        preview: preview::of_plan(&(b.plan)(Sizes::default())),
    });
    let saved = saved::list().into_iter().map(|s| BlueprintView {
        id: s.id,
        name: s.meta.name,
        source: BlueprintSource::Saved { saved_at_ms: s.meta.saved_at_ms },
        preview: s.meta.preview,
    });
    built_in.chain(saved).collect()
}

/// What built-in blueprint `id` opens at `sizes`.
pub fn preview_at(id: &str, sizes: Sizes) -> Result<Preview, String> {
    let blueprint = built_in::find(id).ok_or_else(|| format!("no built-in blueprint {id}"))?;
    Ok(preview::of_plan(&(blueprint.plan)(sizes)))
}

fn remove(folder: &std::path::Path) -> Result<(), String> {
    match std::fs::remove_dir_all(folder) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(format!("remove {}: {e}", folder.display())),
        _ => Ok(()),
    }
}

/// Stop everything the launcher runs and delete every profile's and relay's data, folders
/// of profiles no longer in the settings included.
async fn clear_world() -> Result<(), String> {
    let launcher = launcher();
    let callers: Vec<u32> = launcher.callers.lock().unwrap().keys().copied().collect();
    for id in callers {
        callers::remove(id).await;
    }
    let settings = launcher.settings.lock().unwrap().clone();
    for profile in &settings.profiles {
        profiles::reset(&profile.name).await?;
    }
    for relay in &settings.relays {
        relays::reset(&relay.name).await?;
    }
    for folder in [paths::PROFILES, paths::RELAYS, paths::EXTRAS] {
        remove(&paths::home().join(folder))?;
    }
    Ok(())
}

/// A line of progress in the blueprint log.
fn log(line: impl Into<String>) {
    launcher().processes.line(BLUEPRINT_PROCESS, line);
}

/// Run `work` as the blueprint task, shown with its log as the blueprint process.
async fn task(work: impl Future<Output = Result<(), String>>) -> Result<(), String> {
    let _world = hold_world()?;
    let processes = &launcher().processes;
    processes.begin_task(BLUEPRINT_PROCESS);
    let result = work.await;
    processes.end_task(BLUEPRINT_PROCESS, &result);
    result
}

/// Use blueprint `id`, built-in or saved: replace the world with it and start its profiles.
/// `sizes` are for a built-in blueprint that takes them.
pub async fn apply(id: &str, sizes: Sizes) -> Result<(), String> {
    task(async {
        log(format!("{id}: clearing every profile and relay"));
        clear_world().await?;
        if let Some(blueprint) = built_in::find(id) {
            build(&(blueprint.plan)(sizes)).await?;
        } else if saved::exists(id) {
            saved::apply(id).await?;
        } else {
            return Err(format!("no blueprint {id}"));
        }
        log("ready");
        Ok(())
    })
    .await
}

/// Save everything as a blueprint named `name`.
pub async fn save(name: &str) -> Result<(), String> {
    task(saved::save(name)).await
}

pub fn delete(id: &str) -> Result<(), String> {
    if built_in::find(id).is_some() {
        return Err(format!("{id} comes with the launcher and cannot be deleted"));
    }
    saved::delete(id)
}

/// Build the world `plan` makes through the real relays, then start its profiles.
async fn build(plan: &[plan::Step]) -> Result<(), String> {
    let launcher = launcher();
    let plan_profiles = plan::plan_profiles(plan);
    {
        let mut settings = launcher.settings.lock().unwrap();
        for (name, relay) in &plan_profiles {
            match settings.profiles.iter_mut().find(|p| p.name == *name) {
                Some(profile) => profile.relay = relay.clone(),
                None => settings.profiles.push(ProfileSettings { name: name.clone(), relay: relay.clone() }),
            }
        }
        settings.save()?;
    }
    workspace::build().await?;
    let mut urls = HashMap::new();
    for relay in plan::plan_relays(plan) {
        relays::start(&relay).await?;
        let url = launcher.settings.lock().unwrap().relay(&relay)?.url();
        urls.insert(relay, url);
    }
    let mut world = seed::World::new(&paths::home(), urls, SEED, |line: String| log(line));
    world.run(plan).await?;
    world.finish().await?;
    log("starting its profiles");
    let names: Vec<String> = plan_profiles.into_iter().map(|(name, _)| name).collect();
    profiles::start_all(&names).await
}

#[cfg(test)]
mod tests;
