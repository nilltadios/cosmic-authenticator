// SPDX-License-Identifier: GPL-3.0-only

//! App UI icons compiled directly into the binary from
//! `resources/icons/CosmicAuthenticator/` (System76 COSMIC Icons, CC-BY-SA-4.0).
//!
//! Never looked up by name from system icon themes, so the app renders
//! identically on every desktop and inside `org.freedesktop.Platform` (which
//! ships no symbolic icon theme). Icons that `libcosmic`'s own widgets look up
//! by name are handled in `src/window_icons.rs`.

use cosmic::widget::icon;

pub const ADD: &[u8] = include_bytes!("../resources/icons/CosmicAuthenticator/scalable/actions/list-add-symbolic.svg");
pub const COPY: &[u8] = include_bytes!("../resources/icons/CosmicAuthenticator/scalable/actions/edit-copy-symbolic.svg");
pub const DELETE: &[u8] = include_bytes!("../resources/icons/CosmicAuthenticator/scalable/places/user-trash-symbolic.svg");
pub const DROPDOWN: &[u8] = include_bytes!("../resources/icons/CosmicAuthenticator/scalable/actions/pan-down-symbolic.svg");
pub const EDIT: &[u8] = include_bytes!("../resources/icons/CosmicAuthenticator/scalable/actions/document-edit-symbolic.svg");
pub const IMPORT: &[u8] = include_bytes!("../resources/icons/CosmicAuthenticator/scalable/actions/document-open-symbolic.svg");
pub const LOCK: &[u8] = include_bytes!("../resources/icons/CosmicAuthenticator/scalable/actions/system-lock-screen-symbolic.svg");
pub const PASTE: &[u8] = include_bytes!("../resources/icons/CosmicAuthenticator/scalable/actions/edit-paste-symbolic.svg");
pub const QR_IMAGE: &[u8] = include_bytes!("../resources/icons/CosmicAuthenticator/scalable/mimetypes/image-x-generic-symbolic.svg");
pub const SETTINGS: &[u8] = include_bytes!("../resources/icons/CosmicAuthenticator/scalable/categories/preferences-system-symbolic.svg");
pub const WARNING: &[u8] = include_bytes!("../resources/icons/CosmicAuthenticator/scalable/status/dialog-warning-symbolic.svg");
pub const WINDOW_CLOSE: &[u8] = include_bytes!("../resources/icons/CosmicAuthenticator/scalable/actions/window-close-symbolic.svg");

/// A symbolic icon handle drawn from compiled-in SVG bytes.
pub fn handle(svg: &'static [u8]) -> icon::Handle {
    icon::from_svg_bytes(svg).symbolic(true)
}

/// A sized symbolic icon widget drawn from compiled-in SVG bytes.
pub fn sized(svg: &'static [u8], size: u16) -> icon::Icon {
    icon::icon(handle(svg)).size(size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    const ALL: [(&str, &[u8]); 12] = [
        ("ADD", ADD),
        ("COPY", COPY),
        ("DELETE", DELETE),
        ("DROPDOWN", DROPDOWN),
        ("EDIT", EDIT),
        ("IMPORT", IMPORT),
        ("LOCK", LOCK),
        ("PASTE", PASTE),
        ("QR_IMAGE", QR_IMAGE),
        ("SETTINGS", SETTINGS),
        ("WARNING", WARNING),
        ("WINDOW_CLOSE", WINDOW_CLOSE),
    ];

    #[test]
    fn every_bundled_app_ui_icon_is_valid_svg() {
        for (name, bytes) in ALL {
            let text = std::str::from_utf8(bytes).unwrap_or_else(|e| panic!("{name} is not UTF-8: {e}"));
            assert!(text.contains("<svg"), "{name} does not contain <svg");
        }
    }

    fn collect_rs_files(dir: &Path, root: &Path, out: &mut Vec<(String, std::path::PathBuf)>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                collect_rs_files(&path, root, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                let rel = path.strip_prefix(root).unwrap().to_string_lossy().into_owned();
                out.push((rel, path));
            }
        }
    }

    /// The window stays self-contained on every desktop and inside
    /// `org.freedesktop.Platform` only while every app icon is compiled in.
    /// Fails if any source file looks up an icon by theme name or system path.
    #[test]
    fn no_icon_comes_from_the_system() {
        // Split so this test's own source does not match.
        let forbidden: Vec<String> = [
            ("from", "_name("),
            ("from", "_path("),
            ("Named", "::new("),
            ("freedesktop", "_icons"),
            ("-symbol", "ic\""),
            ("share/", "icons"),
            ("pix", "maps"),
            ("join(\"", "icons\")"),
            ("default_icon", "_theme("),
        ]
        .iter()
        .map(|(a, b)| format!("{a}{b}"))
        .collect();

        // Only exception: `window_icons.rs` writes the compiled-in libcosmic
        // widget icons as a private theme and probes them once via `from_name`,
        // and `main.rs` hands that prepared theme name to libcosmic.
        let allowed = |rel: &str, pattern: &str| match rel {
            "main.rs" => pattern.starts_with("default_icon"),
            "window_icons.rs" => pattern.starts_with("join(") || pattern.starts_with("from_name"),
            _ => false,
        };

        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        collect_rs_files(&src, &src, &mut files);
        files.sort_by(|a, b| a.0.cmp(&b.0));

        let mut found = Vec::new();
        for (rel, path) in files {
            let text = std::fs::read_to_string(&path).unwrap();
            for (n, line) in text.lines().enumerate() {
                for p in forbidden.iter().filter(|p| line.contains(p.as_str()) && !allowed(&rel, p)) {
                    found.push(format!("src/{rel}:{}: {p}", n + 1));
                }
            }
            if rel == "window_icons.rs" {
                let by_name = text.matches(&forbidden[0][..]).count();
                if by_name != 1 {
                    found.push(format!("src/{rel}: {} appears {by_name} times, expected 1", forbidden[0]));
                }
            }
        }

        assert!(
            found.is_empty(),
            "icons looked up from system themes instead of compiled-in SVGs:\n{}\n\
             Add the SVG to resources/icons/CosmicAuthenticator/ and expose it via src/ui_icons.rs \
             (or src/window_icons.rs if looked up internally by libcosmic).",
            found.join("\n")
        );
    }
}
