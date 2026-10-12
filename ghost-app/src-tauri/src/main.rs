// A release build on Windows opens no console window beside the app's.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::Arc;

mod audio;
mod audio_test;
#[cfg(test)]
mod bindings;
mod commands;
mod config;
mod constants;
#[cfg(debug_assertions)]
mod dev;
mod device_watcher;
#[cfg(feature = "devtools")]
mod devtools;
mod dto;
mod error;
mod idle_task;
mod relay_task;
mod setup;
mod state;
mod sync_utils;

// The profiler is for development: it must never reach a release build.
#[cfg(all(feature = "devtools", not(debug_assertions)))]
compile_error!("the devtools feature is for debug builds only");

/// Daily log files, inside the data directory.
const LOG_DIR: &str = "logs";

/// The main window, from its entry in the app config. A data directory given in the
/// environment (a launcher profile, or a second install) gets webview storage of its own
/// too, so settings kept there stay apart.
fn main_window(app: &tauri::App) -> tauri::Result<tauri::WebviewWindow> {
    let config = app.config().app.windows.iter().find(|w| w.label == "main").expect("a main window in the app config");
    let builder = tauri::WebviewWindowBuilder::from_config(app.handle(), config)?;
    #[cfg(debug_assertions)]
    let builder = match dev::profile() {
        Some(profile) => builder.title(format!("{} · {profile}", config.title)),
        None => builder,
    };
    #[cfg(debug_assertions)]
    let builder = match dev::window_bounds() {
        Some(bounds) => builder.position(bounds.x, bounds.y).inner_size(bounds.width, bounds.height),
        None => builder,
    };
    if std::env::var_os("GHOST_DATA_DIR").is_none() {
        return builder.build();
    }
    let data_dir = setup::ghost_dir();
    // WKWebView keeps storage by identifier, not by folder (macOS 14 and later).
    #[cfg(target_os = "macos")]
    let builder = {
        let digest: [u8; 32] = blake3::hash(data_dir.as_os_str().as_encoded_bytes()).into();
        builder.data_store_identifier(digest[..16].try_into().expect("16 bytes"))
    };
    #[cfg(not(target_os = "macos"))]
    let builder = builder.data_directory(data_dir.join("webview"));
    builder.build()
}

fn main() {
    // Before anything is logged or traced, so every line and span is seen.
    let log_file = ghost_log::LogFile { dir: setup::ghost_dir().join(LOG_DIR), stem: "ghost" };
    #[cfg(feature = "devtools")]
    let (devtools_state, devtools_layer) = devtools::prepare();
    #[cfg(feature = "devtools")]
    let _log = ghost_log::init_with(Some(log_file), devtools_layer);
    #[cfg(not(feature = "devtools"))]
    let _log = ghost_log::init(Some(log_file));
    let setup::SetupResult {
        state: app_state,
        inbox_rx,
        voice_loop,
        phase,
    } = setup::initialize();
    let handles = app_state.handles();
    let relay_task_handle = app_state.relay_task_handle.clone();
    let relay_for_exit = app_state.relay.clone();

    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_global_shortcut::Builder::new().build())
        .manage(app_state);
    #[cfg(feature = "devtools")]
    let builder = builder.manage(devtools_state);
    builder
        .setup(move |app| {
            #[cfg_attr(not(target_os = "macos"), allow(unused_variables))]
            let window = main_window(app)?;
            #[cfg(target_os = "macos")]
            {
                use objc2_app_kit::{NSColor, NSWindow};

                let ns_window = unsafe { &*(window.ns_window().unwrap() as *mut NSWindow) };
                // pure black — matches --neutral-950
                let color = NSColor::colorWithSRGBRed_green_blue_alpha(0.0, 0.0, 0.0, 1.0);
                ns_window.setBackgroundColor(Some(&color));
            }

            #[cfg(debug_assertions)]
            dev::serve(app.handle());

            let handle = app.handle().clone();
            // Without an account there is nothing to run a session for; the command that
            // makes, links or recovers one starts it.
            if phase != state::AccountPhase::None {
                let jh = tauri::async_runtime::spawn(relay_task::run(handle.clone(), handles.clone(), inbox_rx));
                *relay_task_handle.blocking_lock() = Some(jh);
            }
            let voice_sink = Arc::new(relay_task::TauriSink::new(handle.clone(), handles.clone()));
            tauri::async_runtime::spawn(voice_loop.run(voice_sink));
            tauri::async_runtime::spawn(idle_task::run(handle, handles));

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_identity,
            commands::live_state,
            commands::note_activity,
            commands::dismiss_alert,
            commands::set_auto_mute_on_idle,
            commands::list_servers,
            commands::create_server,
            commands::create_dm,
            commands::list_channels,
            commands::list_members,
            commands::save_server_order,
            commands::get_server_order,
            commands::list_messages,
            commands::send_message,
            commands::retry_message,
            commands::create_channel,
            commands::rename_channel,
            commands::delete_channel,
            commands::reorder_channels,
            commands::create_private_channel,
            commands::get_channel_access,
            commands::set_channel_access,
            commands::get_server_roles,
            commands::set_server_roles,
            commands::kick_member,
            commands::mark_channel_read,
            commands::create_invite,
            commands::join_by_invite,
            commands::kept_out,
            commands::let_back_in,
            commands::forget_server,
            commands::accept_relay_state,
            commands::move_server,
            commands::follow_server_move,
            commands::get_config,
            commands::set_display_name,
            commands::set_relay_url,
            commands::join_voice,
            commands::leave_voice,
            commands::set_muted,
            commands::set_deafened,
            commands::list_audio_devices,
            commands::set_input_device,
            commands::set_output_device,
            commands::set_noise_suppression,
            commands::set_agc,
            commands::set_input_mode,
            commands::set_ptt_active,
            commands::set_vad_threshold,
            commands::set_input_gain,
            commands::start_mic_test,
            commands::stop_mic_test,
            commands::play_test_tone,
            commands::get_keybinds,
            commands::set_keybind,
            commands::set_status,
            commands::set_status_message,
            commands::upload_avatar,
            commands::clear_avatar,
            commands::get_cached_avatar,
            commands::get_devices,
            commands::revoke_device,
            commands::rename_device,
            commands::get_account_status,
            commands::begin_create_account,
            commands::confirm_new_account,
            commands::cancel_create_account,
            commands::start_pairing,
            commands::check_pairing,
            commands::confirm_pairing,
            commands::cancel_pairing,
            commands::join_as_new_device,
            commands::begin_recovery,
            commands::confirm_recovery,
            commands::recover_through_relay,
            commands::cancel_recovery,
            commands::check_recovery_key,
            commands::begin_replace_recovery_key,
            commands::confirm_new_recovery_key,
            commands::cancel_new_recovery_key,
            commands::move_home,
            commands::reset_device,
            commands::resume_unfinished_account,
            commands::exit_app,
            #[cfg(debug_assertions)]
            dev::dev_profile,
            #[cfg(feature = "devtools")]
            devtools::devtools_limits,
            #[cfg(feature = "devtools")]
            devtools::devtools_snapshot,
            #[cfg(feature = "devtools")]
            devtools::devtools_reset,
            #[cfg(feature = "devtools")]
            devtools::devtools_capture,
            #[cfg(feature = "devtools")]
            devtools::devtools_open_profiler,
        ])
        .build(tauri::generate_context!())
        .expect("error while building ghost")
        .run(move |_app, event| {
            // Quitting closes every relay connection, so relays show this device
            // offline at once.
            if let tauri::RunEvent::Exit = event {
                tauri::async_runtime::block_on(relay_for_exit.close_all(constants::EXIT_CLOSE_WAIT));
            }
        });
}
