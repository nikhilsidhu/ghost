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
            tauri::async_runtime::spawn(relay_task::run(
                handle.clone(),
                client,
                relay,
                inbox_rx,
                presence,
            ));
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
            commands::pin_server,
            commands::unpin_server,
            commands::list_pinned_servers,
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
            commands::seed_test_data,
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
            commands::create_dev_session,
            commands::read_dev_session,
            commands::get_keybinds,
            commands::set_keybind,
            commands::set_status,
            commands::set_status_message,
        ])
        .run(tauri::generate_context!())
        .expect("error while running ghost");
}
