use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use ghost_core::client::GhostClient;
use ghost_core::identity::keyring_store::StoredDevice;
use ghost_core::identity::Identity;
use ghost_core::relay::{RelayClient, RelayEvent};
use ghost_core::voice::{Voice, VoiceLoop};
use tokio::sync::{mpsc, Mutex};

use ghost_audio::VoiceAudio;
use ghost_core::flows::now_millis;

use crate::audio::CpalDevices;
use crate::config::{self, GhostConfig};
use ghost_core::flows::presence::PresenceInfo;
use crate::state::{AccountPhase, AppState, AuthMaterial};

pub(crate) fn ghost_dir() -> PathBuf {
    match std::env::var("GHOST_DATA_DIR") {
        Ok(dir) => PathBuf::from(dir),
        Err(_) => dirs::home_dir().expect("no home directory").join(".ghost"),
    }
}

pub(crate) fn db_path() -> PathBuf {
    ghost_dir().join("ghost.db")
}

/// Remove the local databases, for a device about to hold another account's data.
pub(crate) fn wipe_local_databases() {
    fn try_remove(path: &std::path::Path) {
        if let Err(e) = std::fs::remove_file(path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!("wipe: failed to remove {}: {e}", path.display());
            }
        }
    }
    let db = db_path();
    // Where MLS state was kept before it moved into the database, should the file of an
    // install not opened since still be there.
    let mls_db = db.with_extension("mls.db");
    for path in [&db, &mls_db] {
        try_remove(path);
        try_remove(&std::path::PathBuf::from(format!("{}-wal", path.display())));
        try_remove(&std::path::PathBuf::from(format!("{}-shm", path.display())));
    }
}

/// Remove the files the account left beside its databases: the members' avatars and its
/// own sealed one.
pub(crate) fn wipe_account_files() {
    let avatars = ghost_dir().join(ghost_core::session::AVATARS_DIR);
    if let Err(e) = std::fs::remove_dir_all(&avatars) {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!("wipe: failed to remove {}: {e}", avatars.display());
        }
    }
}

/// What this device is called in the account's device list unless the user picks
/// another name: the machine's name, or the OS when the machine has none.
pub(crate) fn device_label() -> String {
    let hostname = gethostname::gethostname().to_string_lossy().trim().to_string();
    if !hostname.is_empty() {
        return hostname;
    }
    match std::env::consts::OS {
        "macos" => "macOS",
        "windows" => "Windows",
        "linux" => "Linux",
        other => other,
    }
    .to_string()
}

/// Debug builds keep the device record in a file, to avoid keychain prompts on every
/// recompile; release builds keep it in the OS keyring, with the fingerprint it is
/// filed under in `identity.txt`.
/// The device record's file in a debug build.
#[cfg(debug_assertions)]
const DEVICE_FILE: &str = "device.key";

#[cfg(debug_assertions)]
fn device_file() -> PathBuf {
    ghost_dir().join(DEVICE_FILE)
}

#[cfg(debug_assertions)]
pub(crate) fn load_device() -> Option<StoredDevice> {
    let bytes = fs::read(device_file()).ok()?;
    Some(StoredDevice::from_bytes(&bytes).expect("device.key is corrupt or from an older Ghost build; delete it to start over"))
}

#[cfg(debug_assertions)]
pub(crate) fn save_device(device: &StoredDevice) -> std::io::Result<()> {
    fs::write(device_file(), device.to_bytes())
}

#[cfg(debug_assertions)]
pub(crate) fn delete_device() {
    let _ = fs::remove_file(device_file());
}

/// The file naming a release build's device record in the keyring.
#[cfg(not(debug_assertions))]
const IDENTITY_FILE: &str = "identity.txt";

#[cfg(not(debug_assertions))]
fn identity_file() -> PathBuf {
    ghost_dir().join(IDENTITY_FILE)
}

#[cfg(not(debug_assertions))]
pub(crate) fn load_device() -> Option<StoredDevice> {
    use ghost_core::identity::keyring_store;
    let fp_short = fs::read_to_string(identity_file()).ok()?;
    Some(keyring_store::retrieve(fp_short.trim()).expect("device in keyring not found — delete ~/.ghost/identity.txt to reset"))
}

#[cfg(not(debug_assertions))]
pub(crate) fn save_device(device: &StoredDevice) -> std::io::Result<()> {
    use ghost_core::crypto::FINGERPRINT_SHORT_BYTES;
    use ghost_core::identity::keyring_store;
    let fp_short = hex::encode(&device.fingerprint[..FINGERPRINT_SHORT_BYTES]);
    keyring_store::store(&fp_short, device).map_err(|e| std::io::Error::other(format!("keyring: {e}")))?;
    fs::write(identity_file(), &fp_short)
}

#[cfg(not(debug_assertions))]
pub(crate) fn delete_device() {
    use ghost_core::identity::keyring_store;
    if let Ok(fp_short) = fs::read_to_string(identity_file()) {
        let _ = keyring_store::delete(fp_short.trim());
    }
    let _ = fs::remove_file(identity_file());
}

/// An account whose batch goes to the relay before this device keeps its record: the
/// record is filed as unfinished first, with where the account was made, so a crash
/// between the two leaves something the next start can finish from once the relay says
/// it holds the account.
pub(crate) struct UnfinishedAccount {
    pub device: StoredDevice,
    pub relay_url: String,
    pub display_name: String,
}

/// Where an unfinished account was made, beside its device record.
#[derive(serde::Serialize, serde::Deserialize)]
struct UnfinishedPlace {
    relay_url: String,
    display_name: String,
}

fn unfinished_place_file(dir: &Path) -> PathBuf {
    dir.join("unfinished-account.json")
}

/// File the device record of an account about to be posted.
pub(crate) fn save_unfinished(account: &UnfinishedAccount) -> std::io::Result<()> {
    save_unfinished_in(&ghost_dir(), account)
}

/// The account filed as unfinished, if one is.
pub(crate) fn load_unfinished() -> Option<UnfinishedAccount> {
    load_unfinished_in(&ghost_dir())
}

/// The relay holds the unfinished account: its record becomes this device's.
pub(crate) fn finish_unfinished(device: &StoredDevice) -> std::io::Result<()> {
    finish_unfinished_in(&ghost_dir(), device)
}

/// The relay does not hold the unfinished account: nothing of it stays.
pub(crate) fn discard_unfinished() {
    discard_unfinished_in(&ghost_dir())
}

fn save_unfinished_in(dir: &Path, account: &UnfinishedAccount) -> std::io::Result<()> {
    keep_unfinished_device(dir, &account.device)?;
    let place = UnfinishedPlace { relay_url: account.relay_url.clone(), display_name: account.display_name.clone() };
    fs::write(unfinished_place_file(dir), serde_json::to_vec(&place).map_err(std::io::Error::other)?)
}

fn load_unfinished_in(dir: &Path) -> Option<UnfinishedAccount> {
    let place: UnfinishedPlace = serde_json::from_slice(&fs::read(unfinished_place_file(dir)).ok()?).ok()?;
    let device = unfinished_device(dir)?;
    Some(UnfinishedAccount { device, relay_url: place.relay_url, display_name: place.display_name })
}

fn finish_unfinished_in(dir: &Path, device: &StoredDevice) -> std::io::Result<()> {
    promote_unfinished_device(dir, device)?;
    let _ = fs::remove_file(unfinished_place_file(dir));
    Ok(())
}

fn discard_unfinished_in(dir: &Path) {
    forget_unfinished_device(dir);
    let _ = fs::remove_file(unfinished_place_file(dir));
}

#[cfg(debug_assertions)]
fn unfinished_device_file(dir: &Path) -> PathBuf {
    dir.join("device.key.unfinished")
}

#[cfg(debug_assertions)]
fn keep_unfinished_device(dir: &Path, device: &StoredDevice) -> std::io::Result<()> {
    fs::write(unfinished_device_file(dir), device.to_bytes())
}

#[cfg(debug_assertions)]
fn unfinished_device(dir: &Path) -> Option<StoredDevice> {
    StoredDevice::from_bytes(&fs::read(unfinished_device_file(dir)).ok()?).ok()
}

#[cfg(debug_assertions)]
fn promote_unfinished_device(dir: &Path, _device: &StoredDevice) -> std::io::Result<()> {
    fs::rename(unfinished_device_file(dir), dir.join(DEVICE_FILE))
}

#[cfg(debug_assertions)]
fn forget_unfinished_device(dir: &Path) {
    let _ = fs::remove_file(unfinished_device_file(dir));
}

/// The fingerprint a release build files a device record under in the keyring.
#[cfg(not(debug_assertions))]
fn keyring_name(fingerprint: &[u8; 32]) -> String {
    hex::encode(&fingerprint[..ghost_core::crypto::FINGERPRINT_SHORT_BYTES])
}

#[cfg(not(debug_assertions))]
fn unfinished_identity_file(dir: &Path) -> PathBuf {
    dir.join("identity.unfinished.txt")
}

#[cfg(not(debug_assertions))]
fn keep_unfinished_device(dir: &Path, device: &StoredDevice) -> std::io::Result<()> {
    use ghost_core::identity::keyring_store;
    let name = keyring_name(&device.fingerprint);
    keyring_store::store(&name, device).map_err(|e| std::io::Error::other(format!("keyring: {e}")))?;
    fs::write(unfinished_identity_file(dir), &name)
}

#[cfg(not(debug_assertions))]
fn unfinished_device(dir: &Path) -> Option<StoredDevice> {
    let name = fs::read_to_string(unfinished_identity_file(dir)).ok()?;
    ghost_core::identity::keyring_store::retrieve(name.trim()).ok()
}

/// The keyring holds the record under its final name already; the pointer to it moves.
#[cfg(not(debug_assertions))]
fn promote_unfinished_device(dir: &Path, device: &StoredDevice) -> std::io::Result<()> {
    fs::write(dir.join(IDENTITY_FILE), keyring_name(&device.fingerprint))?;
    let _ = fs::remove_file(unfinished_identity_file(dir));
    Ok(())
}

#[cfg(not(debug_assertions))]
fn forget_unfinished_device(dir: &Path) {
    if let Ok(name) = fs::read_to_string(unfinished_identity_file(dir)) {
        let _ = ghost_core::identity::keyring_store::delete(name.trim());
    }
    let _ = fs::remove_file(unfinished_identity_file(dir));
}

pub struct SetupResult {
    pub state: AppState,
    pub inbox_rx: mpsc::Receiver<RelayEvent>,
    /// Serves `state.voice`; spawned once the app can receive its events.
    pub voice_loop: VoiceLoop,
    /// Whether the device has an account to run; without one the session is not started.
    pub phase: AccountPhase,
}

pub fn initialize() -> SetupResult {
    let dir = ghost_dir();
    fs::create_dir_all(&dir).expect("failed to create ~/.ghost");

    let cfg_path = config::config_path(&dir);
    let mut cfg = GhostConfig::load(&cfg_path);

    // Without an account the client runs a provisional identity in memory, so the app
    // has something to show its setup screens against; creation, linking or recovery
    // replaces it.
    let (mut client, phase) = match load_device() {
        Some(device) => {
            let client = GhostClient::open(device.identity(), device.db_key, device.mls_db_key, &db_path()).expect("failed to open database");
            (client, AccountPhase::Ready)
        }
        None => {
            let identity = Identity::generate().expect("failed to make a provisional identity");
            let mut db_key = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut db_key);
            (GhostClient::open_in_memory(identity, db_key).expect("failed to open an in-memory database"), AccountPhase::None)
        }
    };

    if let Some(name) = &cfg.display_name {
        client.set_display_name(name.clone());
    }

    // Config file takes priority, then env var, then default
    let relay_url = cfg
        .relay_url
        .as_deref()
        .filter(|u| !u.is_empty())
        .map(String::from)
        .or_else(|| std::env::var("GHOST_RELAY_URL").ok())
        .unwrap_or_else(|| "http://localhost:7700".into());

    let (relay, inbox_rx) = RelayClient::new(&relay_url);
    relay.set_auth(
        *client.fingerprint(),
        client.verifying_key_bytes(),
        client.signing_key_clone(),
    );

    // A status message that expired while the app was closed goes.
    if cfg.status_expiry.is_some_and(|expiry| now_millis() >= expiry) {
        cfg.status_message = None;
        cfg.status_expiry = None;
        if let Err(e) = cfg.save(&cfg_path) {
            tracing::warn!("expired status message not cleared from the config: {e}");
        }
    }

    let initial_presence = PresenceInfo {
        status: cfg.status().into(),
        status_message: cfg.status_message.clone(),
        status_expiry: cfg.status_expiry,
        avatar: ghost_core::flows::presence::own_avatar(&client),
    };

    let auth = AuthMaterial {
        account_fp: *client.fingerprint(),
        device_vk: client.verifying_key_bytes(),
        signing_key: client.signing_key_clone(),
    };

    let client = Arc::new(Mutex::new(client));
    let relay = Arc::new(relay);
    let devices = Arc::new(CpalDevices::default());
    devices.choose(cfg.device_choice());
    let audio = Arc::new(VoiceAudio::new(devices.clone()));
    cfg.apply_audio(&audio);
    let (voice, voice_loop) = Voice::new(client.clone(), relay.clone(), audio.clone());

    let state = AppState {
        client,
        relay,
        config_path: cfg_path,
        config: Arc::new(Mutex::new(cfg)),
        voice,
        audio,
        devices,
        presence: Arc::new(Mutex::new(initial_presence)),
        phase: Arc::new(Mutex::new(phase)),
        pending_creation: Arc::new(Mutex::new(None)),
        pending_pairing: Arc::new(Mutex::new(None)),
        pending_recovery: Arc::new(Mutex::new(None)),
        pending_new_key: Arc::new(Mutex::new(None)),
        relay_task_handle: Arc::new(Mutex::new(None)),
        auth: Arc::new(RwLock::new(auth)),
        live: Arc::default(),
        idle_mute: Arc::default(),
    };

    keep_learned_gains(&state);

    SetupResult {
        state,
        inbox_rx,
        voice_loop,
        phase,
    }
}

/// Keep in the config each gain the volume normalizer settles on, by microphone, so the
/// next start begins at the right loudness.
fn keep_learned_gains(state: &AppState) {
    let (config, config_path) = (state.config.clone(), state.config_path.clone());
    state.audio.on_gain_learned(move |input, gain_db| {
        let (config, config_path, input) = (config.clone(), config_path.clone(), input.to_string());
        tauri::async_runtime::spawn(async move {
            let mut cfg = config.lock().await;
            cfg.input_gains.get_or_insert_with(Default::default).insert(input, gain_db);
            if let Err(e) = cfg.save(&config_path) {
                tracing::warn!("learned microphone gain not saved: {e}");
            }
        });
    });
}

#[cfg(all(test, debug_assertions))]
mod tests {
    use super::*;

    fn unfinished() -> UnfinishedAccount {
        let identity = Identity::generate().unwrap();
        let device = StoredDevice {
            fingerprint: identity.fingerprint,
            signing_key: identity.signing_key.clone(),
            encryption_key: identity.encryption_key.clone(),
            db_key: [1; 32],
            mls_db_key: [2; 32],
            added_at: identity.added_at,
        };
        UnfinishedAccount { device, relay_url: "http://relay".into(), display_name: "alice".into() }
    }

    #[test]
    fn an_unfinished_account_becomes_the_device_record_or_goes() {
        let dir = std::env::temp_dir().join(format!("ghost-unfinished-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let account = unfinished();
        save_unfinished_in(&dir, &account).unwrap();
        let loaded = load_unfinished_in(&dir).expect("filed");
        assert_eq!((loaded.relay_url.as_str(), loaded.display_name.as_str()), ("http://relay", "alice"));
        assert_eq!(loaded.device.to_bytes(), account.device.to_bytes());
        assert!(!dir.join(DEVICE_FILE).exists(), "not the device's record until the relay holds it");

        finish_unfinished_in(&dir, &loaded.device).unwrap();
        assert!(load_unfinished_in(&dir).is_none());
        assert_eq!(fs::read(dir.join(DEVICE_FILE)).unwrap(), account.device.to_bytes());

        fs::remove_file(dir.join(DEVICE_FILE)).unwrap();
        save_unfinished_in(&dir, &account).unwrap();
        discard_unfinished_in(&dir);
        assert!(load_unfinished_in(&dir).is_none());
        assert!(!dir.join(DEVICE_FILE).exists());
        fs::remove_dir_all(&dir).unwrap();
    }
}
