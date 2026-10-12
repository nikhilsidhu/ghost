//! Where profiles' windows go: a grid over the launcher's display, beside the launcher when
//! that leaves room, each window sized to its cell but never below the app's minimum, so on
//! a display too small for all of them they overlap evenly. Windows opening together take
//! the grid in order; a window opening on its own takes the place its neighbours cover least.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tauri::Manager;

use crate::launcher::{launcher, profile_process};
use crate::paths;
use crate::process::Status;
use crate::profiles;

/// Between neighbouring windows, where the grid fits.
const GAP: f64 = 8.0;
/// Tauri's label for a window the config does not name.
const DEFAULT_LABEL: &str = "main";

/// A window's place on its display, in logical pixels.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Bounds {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

impl Bounds {
    /// The value an app instance reads from its environment to open its window here.
    pub fn env_value(&self) -> String {
        format!("{},{},{},{}", self.x, self.y, self.width, self.height)
    }

    fn overlap(&self, other: &Bounds) -> f64 {
        let width = (self.x + self.width).min(other.x + other.width) - self.x.max(other.x);
        let height = (self.y + self.height).min(other.y + other.height) - self.y.max(other.y);
        width.max(0.0) * height.max(0.0)
    }
}

/// The app window's size and smallest size, as the app's own config sets them.
#[derive(Debug, Clone, Copy)]
struct AppWindow {
    width: f64,
    height: f64,
    min_width: f64,
    min_height: f64,
}

fn app_window() -> Result<AppWindow, String> {
    let path = paths::app().join("src-tauri").join("tauri.conf.json");
    let bytes = std::fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let config: Value = serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    let main = config["app"]["windows"]
        .as_array()
        .and_then(|windows| windows.iter().find(|window| window["label"].as_str().unwrap_or(DEFAULT_LABEL) == DEFAULT_LABEL))
        .ok_or("no main window in the app config")?;
    let size = |key: &str| main[key].as_f64().ok_or_else(|| format!("no {key} for the app's window"));
    Ok(AppWindow { width: size("width")?, height: size("height")?, min_width: size("minWidth")?, min_height: size("minHeight")? })
}

/// The part of the launcher's display windows go in: beside the launcher when that leaves
/// room for an app window, else all of it.
fn region(app: &AppWindow) -> Result<Bounds, String> {
    let handle = &launcher().app;
    let window = handle.webview_windows().into_values().next().ok_or("the launcher has no window")?;
    let monitor = window
        .current_monitor()
        .ok()
        .flatten()
        .or_else(|| handle.primary_monitor().ok().flatten())
        .ok_or("no display to put windows on")?;
    let scale = monitor.scale_factor();
    let area = monitor.work_area();
    let display = Bounds {
        x: f64::from(area.position.x) / scale,
        y: f64::from(area.position.y) / scale,
        width: f64::from(area.size.width) / scale,
        height: f64::from(area.size.height) / scale,
    };
    let own_scale = window.scale_factor().map_err(|e| e.to_string())?;
    let (position, size) = (window.outer_position().map_err(|e| e.to_string())?, window.outer_size().map_err(|e| e.to_string())?);
    let (left_edge, right_edge) = (f64::from(position.x) / own_scale, (f64::from(position.x) + f64::from(size.width)) / own_scale);
    let left = left_edge - display.x;
    let right = display.x + display.width - right_edge;
    Ok(if left.max(right) < app.min_width {
        display
    } else if right >= left {
        Bounds { x: right_edge, width: right, ..display }
    } else {
        Bounds { width: left, ..display }
    })
}

/// `count` places in `region`, row by row, in the arrangement whose cells come nearest the
/// app window's own shape.
fn grid(region: Bounds, count: usize, app: &AppWindow) -> Vec<Bounds> {
    if count == 0 {
        return Vec::new();
    }
    let cell = |columns: usize| {
        let rows = count.div_ceil(columns);
        let width = (region.width - GAP * (columns - 1) as f64) / columns as f64;
        let height = (region.height - GAP * (rows - 1) as f64) / rows as f64;
        (width, height)
    };
    let fit = |columns: usize| {
        let (width, height) = cell(columns);
        (width / app.width).min(height / app.height)
    };
    let columns = (1..=count).max_by(|a, b| fit(*a).total_cmp(&fit(*b))).unwrap_or(1);
    let rows = count.div_ceil(columns);
    let (cell_width, cell_height) = cell(columns);
    let (width, height) = (cell_width.max(app.min_width), cell_height.max(app.min_height));
    // Where windows fit their cells this steps a cell and a gap; where they are bigger, it
    // spreads them evenly across the region, overlapping.
    let step = |span: f64, size: f64, cells: usize| if cells > 1 { ((span - size) / (cells - 1) as f64).max(0.0) } else { 0.0 };
    let (step_x, step_y) = (step(region.width, width, columns), step(region.height, height, rows));
    (0..count)
        .map(|index| Bounds {
            x: region.x + (index % columns) as f64 * step_x,
            y: region.y + (index / columns) as f64 * step_y,
            width,
            height,
        })
        .collect()
}

/// The place among `places` that `windows` cover least, the first of any tie.
fn least_covered(places: &[Bounds], windows: &[Bounds]) -> Option<Bounds> {
    let covered = |place: &Bounds| windows.iter().map(|window| place.overlap(window)).sum::<f64>();
    places.iter().copied().min_by(|a, b| covered(a).total_cmp(&covered(b)))
}

/// Places for `count` windows opening together.
pub fn places(count: usize) -> Result<Vec<Bounds>, String> {
    let app = app_window()?;
    Ok(grid(region(&app)?, count, &app))
}

/// Running profiles in settings order, `except` left out.
fn running_profiles(except: Option<&str>) -> Vec<String> {
    let launcher = launcher();
    let names: Vec<String> = launcher.settings.lock().unwrap().profiles.iter().map(|profile| profile.name.clone()).collect();
    names
        .into_iter()
        .filter(|name| Some(name.as_str()) != except && launcher.processes.status(&profile_process(name)) == Status::Running)
        .collect()
}

/// Where profile `name`'s window is, when its instance answers.
pub async fn window(name: &str) -> Option<Bounds> {
    let reply = profiles::request(name, json!({ "cmd": "window" })).await.ok()?;
    serde_json::from_value(reply).ok()
}

/// Where profile `starting`'s window opens, among the windows already open.
pub async fn next_place(starting: &str) -> Result<Bounds, String> {
    let mut open = Vec::new();
    for name in running_profiles(Some(starting)) {
        // An instance still starting has no window yet to avoid.
        if let Some(bounds) = window(&name).await {
            open.push(bounds);
        }
    }
    least_covered(&places(open.len() + 1)?, &open).ok_or_else(|| "no place for the window".to_string())
}

/// Arrange every running profile's window afresh.
pub async fn tile() -> Result<(), String> {
    let names = running_profiles(None);
    for (name, place) in names.iter().zip(places(names.len())?) {
        let mut request = serde_json::to_value(place).map_err(|e| e.to_string())?;
        request["cmd"] = json!("place");
        profiles::request(name, request).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP: AppWindow = AppWindow { width: 1000.0, height: 700.0, min_width: 800.0, min_height: 600.0 };

    fn region(width: f64, height: f64) -> Bounds {
        Bounds { x: 0.0, y: 25.0, width, height }
    }

    #[test]
    fn a_big_display_tiles_four_windows_two_by_two_without_overlap() {
        let places = grid(region(2560.0, 1415.0), 4, &APP);
        assert_eq!(places.len(), 4);
        assert_eq!((places[0].width, places[0].height), (1276.0, 703.5));
        assert_eq!((places[1].x, places[2].y), (1284.0, 25.0 + 711.5));
        for (i, a) in places.iter().enumerate() {
            for b in &places[i + 1..] {
                assert_eq!(a.overlap(b), 0.0, "{a:?} and {b:?}");
            }
        }
    }

    #[test]
    fn a_laptop_display_keeps_windows_at_their_smallest_and_spreads_them() {
        let places = grid(region(1512.0, 944.0), 3, &APP);
        assert!(places.iter().all(|place| (place.width, place.height) == (800.0, 600.0)), "{places:?}");
        assert_eq!((places[0].x, places[1].x, places[2].x), (0.0, 712.0, 0.0));
        assert_eq!((places[0].y, places[2].y), (25.0, 25.0 + 344.0));
        let right_edge = places[1].x + places[1].width;
        assert_eq!(right_edge, 1512.0, "spread to the region's edge, not past it");
    }

    #[test]
    fn one_window_fills_the_region() {
        assert_eq!(grid(region(1600.0, 1000.0), 1, &APP), vec![region(1600.0, 1000.0)]);
    }

    #[test]
    fn a_window_opening_alone_takes_the_least_covered_place() {
        let places = grid(region(2560.0, 1415.0), 3, &APP);
        let open = [places[0], places[2]];
        assert_eq!(least_covered(&places, &open), Some(places[1]));
    }

    #[test]
    fn the_app_config_gives_the_window_sizes() {
        let app = app_window().unwrap();
        assert!(app.min_width > 0.0 && app.min_width <= app.width, "{app:?}");
        assert!(app.min_height > 0.0 && app.min_height <= app.height, "{app:?}");
    }
}
