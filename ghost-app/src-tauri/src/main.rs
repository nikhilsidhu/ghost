use tauri::Manager;

mod audio;
mod audio_test;
mod commands;
mod config;
mod constants;
mod device_watcher;
mod dto;
mod idle_task;
mod presence;
mod relay_task;
mod setup;
mod state;
mod sync_utils;
mod udp_transport;
mod voice_task;

#[cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
fn main() {
    let setup::SetupResult {
        state: app_state,
        inbox_rx,
        voice_cmd_rx,
        voice_state_tx,
    } = setup::initialize();
    let client = app_state.client.clone();
    let idle_client = app_state.client.clone();
    let voice_client = app_state.client.clone();
    let relay = app_state.relay.clone();
    let idle_relay = app_state.relay.clone();
    let voice_relay = app_state.relay.clone();
    let presence = app_state.presence.clone();
    let idle_presence = app_state.presence.clone();
    let idle_voice_tx = app_state.voice.cmd_tx.clone();
    let idle_config = app_state.config.clone();
    let idle_config_path = app_state.config_path.clone();
    let relay_task_handle = app_state.relay_task_handle.clone();
    let data_dir = app_state.config_path.parent().unwrap().to_path_buf();

    tauri::Builder::default()
        .plugin(tauri_plugin_global_shortcut::Builder::new().build())
        .manage(app_state)
        .setup(move |app| {
            #[cfg(target_os = "macos")]
            {
                use objc2_app_kit::{NSColor, NSWindow};

                let window = app.get_webview_window("main").unwrap();
                let ns_window = unsafe { &*(window.ns_window().unwrap() as *mut NSWindow) };
                // pure black — matches --neutral-950
                let color = NSColor::colorWithSRGBRed_green_blue_alpha(0.0, 0.0, 0.0, 1.0);
                ns_window.setBackgroundColor(Some(&color));
            }

            let handle = app.handle().clone();
            let relay_config = idle_config.clone();
            let relay_config_path = idle_config_path.clone();
            let relay_voice_tx = idle_voice_tx.clone();
            let relay_task_handle = relay_task_handle.clone();
            let jh = tauri::async_runtime::spawn(relay_task::run(
                handle.clone(),
                client,
                relay,
                inbox_rx,
                presence,
                data_dir,
                relay_config,
                relay_config_path,
                relay_voice_tx,
            ));
            *relay_task_handle.blocking_lock() = Some(jh);
            tauri::async_runtime::spawn(voice_task::run(
                handle.clone(),
                voice_client,
                voice_relay,
                voice_cmd_rx,
                voice_state_tx,
            ));
            tauri::async_runtime::spawn(idle_task::run(
                handle,
                idle_client,
                idle_relay,
                idle_presence,
                idle_voice_tx,
                idle_config,
                idle_config_path,
            ));

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_identity,
            commands::list_servers,
            commands::create_server,
            commands::create_dm,
            commands::list_channels,
            commands::list_members,
            commands::save_server_order,
            commands::get_server_order,
            commands::list_messages,
            commands::send_message,
            commands::create_channel,
            commands::rename_channel,
            commands::delete_channel,
            commands::kick_member,
            commands::mark_channel_read,
            commands::create_invite,
            commands::join_by_invite,
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
            commands::start_pairing,
            commands::check_pairing,
            commands::cancel_pairing,
            commands::join_as_new_device,
            commands::set_recovery_passphrase,
            commands::skip_recovery_setup,
            commands::get_recovery_code,
            commands::change_recovery_passphrase,
            commands::has_recovery_blob,
            commands::recover_account,
            commands::exit_app,
            commands::spawn_dev_instance,
        ])
        .run(tauri::generate_context!())
        .expect("error while running ghost");
}
