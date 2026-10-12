//! The launcher's state, shared by its commands: settings, the processes it runs, each
//! relay's forwarder, each instance's control port and account, and the test callers.

use std::collections::HashMap;
use std::sync::atomic::AtomicU32;
use std::sync::{Arc, Mutex, OnceLock};

use ghost_media::netem::Forwarder;
use tauri::AppHandle;

use crate::callers::Caller;
use crate::process::Processes;
use crate::settings::Settings;
use crate::view::CallPlace;

pub struct Launcher {
    /// The launcher app, for its window and display.
    pub app: AppHandle,
    pub processes: Processes,
    pub settings: Mutex<Settings>,
    /// The forwarder in front of each running relay's voice port.
    pub forwarders: Mutex<HashMap<String, Arc<Forwarder>>>,
    /// The loopback port each running instance answers on.
    pub control_ports: Mutex<HashMap<String, u16>>,
    /// Each profile's account fingerprint, once its instance has said.
    pub fingerprints: Mutex<HashMap<String, String>>,
    /// Where each running profile is in a call, as its instance last said.
    pub calls: Mutex<HashMap<String, CallPlace>>,
    pub callers: Mutex<HashMap<u32, Arc<Caller>>>,
    pub next_caller: AtomicU32,
    /// Held while a build runs, so builds never overlap.
    pub building: tokio::sync::Mutex<()>,
    /// Held while a blueprint replaces every profile's and relay's data, or they are saved
    /// as one, so two never interleave.
    pub world: tokio::sync::Mutex<()>,
}

static LAUNCHER: OnceLock<Launcher> = OnceLock::new();

/// Set up the launcher's state. Called once, as the app starts.
pub fn init(app: AppHandle) {
    let launcher = Launcher {
        processes: Processes::new(app.clone()),
        app,
        settings: Mutex::new(Settings::load()),
        forwarders: Mutex::default(),
        control_ports: Mutex::default(),
        fingerprints: Mutex::default(),
        calls: Mutex::default(),
        callers: Mutex::default(),
        next_caller: AtomicU32::new(1),
        building: tokio::sync::Mutex::new(()),
        world: tokio::sync::Mutex::new(()),
    };
    if LAUNCHER.set(launcher).is_err() {
        panic!("the launcher is set up once");
    }
}

pub fn launcher() -> &'static Launcher {
    LAUNCHER.get().expect("the launcher is set up at startup")
}

/// The world, for a blueprint to replace or save; refused while one already is.
pub fn hold_world() -> Result<tokio::sync::MutexGuard<'static, ()>, String> {
    launcher().world.try_lock().map_err(|_| "a blueprint is already being used or saved".to_string())
}

/// Process names, as the logs view lists them.
pub const DEV_SERVER: &str = "dev server";
pub const BUILD: &str = "build";

pub fn relay_process(name: &str) -> String {
    format!("relay {name}")
}

pub fn profile_process(name: &str) -> String {
    format!("profile {name}")
}

pub fn caller_process(id: u32) -> String {
    format!("caller {id}")
}
