//! App preferences, kept as JSON in `$XDG_CONFIG_HOME/cosmic-authenticator/settings.json`.
//! Nothing secret lives here.

use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::store::xdg_dir;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AppTheme {
    #[default]
    System,
    Dark,
    Light,
}

impl AppTheme {
    pub const ALL: [AppTheme; 3] = [AppTheme::System, AppTheme::Dark, AppTheme::Light];

    pub fn label(self) -> &'static str {
        match self {
            AppTheme::System => "Match desktop",
            AppTheme::Dark => "Dark",
            AppTheme::Light => "Light",
        }
    }

    pub fn theme(self) -> cosmic::Theme {
        match self {
            AppTheme::System => cosmic::theme::system_preference(),
            AppTheme::Dark => cosmic::theme::system_dark(),
            AppTheme::Light => cosmic::theme::system_light(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub hide_codes: bool,
    /// Downloads each service's logo from the address in Proton's issuer list.
    pub show_logos: bool,
    pub theme: AppTheme,
}

impl Default for Settings {
    fn default() -> Self {
        Settings { hide_codes: false, show_logos: true, theme: AppTheme::System }
    }
}

fn settings_path() -> PathBuf {
    xdg_dir("XDG_CONFIG_HOME", ".config").join("settings.json")
}

/// A missing or unreadable file gives the defaults, so a bad edit never
/// keeps the app from starting.
pub fn load() -> Settings {
    fs::read_to_string(settings_path())
        .ok()
        .and_then(|contents| serde_json::from_str(&contents).ok())
        .unwrap_or_default()
}

pub fn save(settings: &Settings) -> Result<(), String> {
    let path = settings_path();
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|error| format!("Cannot create {}: {error}", dir.display()))?;
    }
    let json = serde_json::to_string_pretty(settings).map_err(|error| error.to_string())?;
    fs::write(&path, json).map_err(|error| format!("Cannot write {}: {error}", path.display()))
}
