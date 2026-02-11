mod setup;
mod state;

#[cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
fn main() {
    let app_state = setup::initialize();

    tauri::Builder::default()
        .manage(app_state)
        .run(tauri::generate_context!())
        .expect("error while running ghost");
}
