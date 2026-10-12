//! Where the launcher finds the workspace and keeps its data: a `.ghost-dev` folder at the
//! repository root, ignored by git, with the launcher's settings, each profile's data,
//! each relay's database and the test callers' folders. Each checkout has its own.

use std::path::{Path, PathBuf};

/// The folders under the launcher's home: what a blueprint sets up (profiles and relays),
/// a busy server's extra members, test callers, and saved blueprints.
pub const PROFILES: &str = "profiles";
pub const RELAYS: &str = "relays";
pub const EXTRAS: &str = "extras";
const CALLERS: &str = "callers";
const BLUEPRINTS: &str = "blueprints";

/// The repository root, which holds this crate's folder.
pub fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().expect("ghost-dev sits in the repository").to_path_buf()
}

pub fn home() -> PathBuf {
    repo().join(".ghost-dev")
}

pub fn settings() -> PathBuf {
    home().join("launcher.json")
}

pub fn profile(name: &str) -> PathBuf {
    home().join(PROFILES).join(name)
}

pub fn relay(name: &str) -> PathBuf {
    home().join(RELAYS).join(name)
}

pub fn caller(id: u32) -> PathBuf {
    home().join(CALLERS).join(id.to_string())
}

pub fn blueprints() -> PathBuf {
    home().join(BLUEPRINTS)
}

/// The app's front-end project, whose dev server serves the launcher page too.
pub fn app() -> PathBuf {
    repo().join("ghost-app")
}

/// A workspace binary as `cargo build` leaves it.
pub fn binary(name: &str) -> PathBuf {
    let target = std::env::var_os("CARGO_TARGET_DIR").map(PathBuf::from).unwrap_or_else(|| repo().join("target"));
    target.join("debug").join(format!("{name}{}", std::env::consts::EXE_SUFFIX))
}
