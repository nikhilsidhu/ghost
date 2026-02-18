use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct GhostConfig {
    pub display_name: Option<String>,
    pub relay_url: Option<String>,
    pub input_device: Option<String>,
    pub output_device: Option<String>,
}

impl GhostConfig {
    pub fn load(path: &Path) -> Self {
        fs::read_to_string(path)
            .ok()
            .and_then(|s| toml::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        let content = toml::to_string_pretty(self).map_err(|e| e.to_string())?;
        fs::write(path, content).map_err(|e| e.to_string())
    }
}

pub fn config_path(ghost_dir: &Path) -> PathBuf {
    ghost_dir.join("config.toml")
}
