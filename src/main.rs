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
mod ui_icons;
mod wayland_activation;
mod window_icons;

pub const APP_ID: &str = "dev.nilltadios.CosmicAuthenticator";

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

    // Prepare the compiled-in private icon theme for libcosmic's own widgets
    // before any worker thread starts (window_icons::prepare updates XDG_DATA_DIRS
    // momentarily while libcosmic's icon lookup cache initializes).
    let icons = window_icons::prepare();
    if args.get(1).map(String::as_str) == Some("--check-icons") {
        let report = serde_json::json!({
            "icon_theme": icons.theme,
            "icons_checked": icons.icons_checked,
            "icons_missing": icons.icons_missing,
            "summary": icons.summary,
        });
        println!("{report}");
        std::process::exit(if icons.ok() { 0 } else { 1 });
    }

    let mut settings = cosmic::app::Settings::default()
        .size(cosmic::iced::Size::new(1100.0, 720.0))
        .size_limits(cosmic::iced::Limits::NONE.min_width(380.0).min_height(300.0));
    if let Some(theme) = icons.theme {
        settings = settings.default_icon_theme(theme);
    }

    cosmic::app::run::<app::AppModel>(settings, ())
}
