// SPDX-License-Identifier: GPL-3.0-only

mod app;
mod form;
mod import;
mod lock;
mod logos;
mod proton;
mod ring;
mod secret;
mod settings;
mod store;

use std::path::{Path, PathBuf};

/// `--import FILE` adds the codes from an export or QR code image and exits.
/// Password-protected exports read the password from `AUTHENTICATOR_EXPORT_PASSWORD`.
fn import_from_command_line(path: &str) -> Result<String, String> {
    let contents = std::fs::read(path).map_err(|error| format!("Cannot read {path}: {error}"))?;
    let password = std::env::var("AUTHENTICATOR_EXPORT_PASSWORD").ok();
    let imported = import::import_bytes(&contents, password.as_deref())
        .map_err(|error| format!("Cannot import {path}: {}", error.message()))?;
    if lock::load()?.is_some() {
        return Err(String::from("Authenticator has an app lock password; import from within the app instead"));
    }
    let mut entries = store::load()?;
    let before = entries.len();
    for entry in imported.entries {
        let uri = entry.uri();
        if !entries.iter().any(|existing| existing.uri() == uri) {
            entries.push(entry);
        }
    }
    store::save(&entries)?;
    Ok(format!("Imported {} codes into {}", entries.len() - before, store::vault_path().display()))
}

/// Reads `key` from `[section]` of an INI-style file such as `kdeglobals`.
fn ini_value(path: &Path, section: &str, key: &str) -> Option<String> {
    let contents = std::fs::read_to_string(path).ok()?;
    let mut in_section = false;
    for line in contents.lines().map(str::trim) {
        if line.starts_with('[') {
            in_section = line == format!("[{section}]");
        } else if in_section
            && let Some((name, value)) = line.split_once('=')
            && name.trim() == key
        {
            return Some(value.trim().to_string());
        }
    }
    None
}

/// libcosmic looks icons up in the COSMIC icon theme. Outside COSMIC that
/// theme is usually not installed and symbolic icons come out blank, so use
/// the desktop's own theme instead: KDE's, then GTK's, then Breeze or Adwaita.
fn fallback_icon_theme() -> Option<String> {
    let home = PathBuf::from(std::env::var_os("HOME")?);
    let data_home = std::env::var_os("XDG_DATA_HOME").map_or_else(|| home.join(".local/share"), PathBuf::from);
    let config_home = std::env::var_os("XDG_CONFIG_HOME").map_or_else(|| home.join(".config"), PathBuf::from);
    let data_dirs = std::env::var("XDG_DATA_DIRS").unwrap_or_else(|_| String::from("/usr/local/share:/usr/share"));

    let mut icon_dirs = vec![data_home.join("icons"), home.join(".icons")];
    icon_dirs.extend(data_dirs.split(':').filter(|dir| !dir.is_empty()).map(|dir| Path::new(dir).join("icons")));
    let installed = |name: &str| icon_dirs.iter().any(|dir| dir.join(name).join("index.theme").is_file());

    if installed("Cosmic") {
        return None;
    }
    [
        ini_value(&config_home.join("kdeglobals"), "Icons", "Theme"),
        ini_value(&config_home.join("gtk-3.0/settings.ini"), "Settings", "gtk-icon-theme-name"),
        Some(String::from("breeze")),
        Some(String::from("Adwaita")),
    ]
    .into_iter()
    .flatten()
    .find(|name| installed(name))
}

fn main() -> cosmic::iced::Result {
    let args: Vec<String> = std::env::args().collect();
    if let [_, flag, path] = args.as_slice()
        && flag == "--import"
    {
        match import_from_command_line(path) {
            Ok(message) => {
                println!("{message}");
                std::process::exit(0);
            }
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(1);
            }
        }
    }

    let mut settings = cosmic::app::Settings::default()
        .size(cosmic::iced::Size::new(1100.0, 720.0))
        .size_limits(cosmic::iced::Limits::NONE.min_width(380.0).min_height(300.0));
    if let Some(theme) = fallback_icon_theme() {
        settings = settings.default_icon_theme(theme);
    }

    cosmic::app::run::<app::AppModel>(settings, ())
}
