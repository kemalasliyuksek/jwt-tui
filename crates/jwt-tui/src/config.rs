//! User config (`~/.config/jwt-tui/config.toml`).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::theme::ThemeColors;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub theme: Option<String>,
    #[serde(default)]
    pub colors: Option<ThemeColors>,
    #[serde(default)]
    pub jwks_cache_ttl_secs: Option<u64>,
}

impl Config {
    pub fn load() -> Self {
        let Some(path) = config_path() else {
            return Self::default();
        };
        let Ok(s) = std::fs::read_to_string(&path) else {
            return Self::default();
        };
        toml::from_str::<Self>(&s).unwrap_or_default()
    }
}

pub fn config_path() -> Option<PathBuf> {
    directories::ProjectDirs::from("dev", "jwt-tui", "jwt-tui")
        .map(|p| p.config_dir().join("config.toml"))
}
