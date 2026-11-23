// SPDX-License-Identifier: GPL-3.0-only

//! Compiled-in icons for the symbolic names `libcosmic`'s own widgets look up
//! by name in the icon theme (header bar window buttons, toast/warning close
//! buttons, search input magnifying glass and clear button, password lock and
//! visibility icons, dropdown chevrons, context drawer arrows, menus).
//!
//! Because `org.freedesktop.Platform` ships no symbolic icon theme (only
//! `hicolor`), relying on host or runtime themes leaves those buttons blank
//! whenever the host lacks matching symbolic icons. Instead, the SVGs are
//! compiled into the binary and written at startup to a private icon theme
//! under `$XDG_DATA_HOME/dev.nilltadios.CosmicAuthenticator/icons/`, which is
//! temporarily prepended to `XDG_DATA_DIRS` while `libcosmic`'s `LazyLock`
//! icon-theme cache initializes and verifies every single icon resolves.

use std::ffi::{OsStr, OsString};
use std::io;
use std::path::{Path, PathBuf};

/// The private theme's name and folder name: the app ID, so no installed theme collides.
const THEME: &str = crate::APP_ID;

/// The single icon directory inside the private theme.
const DIR: &str = "scalable/actions";

/// Every symbolic icon name that `libcosmic`'s own widgets look up by name.
const ICONS: [(&str, &[u8]); 21] = [
    ("window-minimize-symbolic.svg", include_bytes!("../resources/icons/CosmicAuthenticator/scalable/actions/window-minimize-symbolic.svg")),
    ("window-maximize-symbolic.svg", include_bytes!("../resources/icons/CosmicAuthenticator/scalable/actions/window-maximize-symbolic.svg")),
    ("window-restore-symbolic.svg", include_bytes!("../resources/icons/CosmicAuthenticator/scalable/actions/window-restore-symbolic.svg")),
    ("window-close-symbolic.svg", include_bytes!("../resources/icons/CosmicAuthenticator/scalable/actions/window-close-symbolic.svg")),
    ("system-search-symbolic.svg", include_bytes!("../resources/icons/CosmicAuthenticator/scalable/actions/system-search-symbolic.svg")),
    ("edit-clear-symbolic.svg", include_bytes!("../resources/icons/CosmicAuthenticator/scalable/actions/edit-clear-symbolic.svg")),
    ("system-lock-screen-symbolic.svg", include_bytes!("../resources/icons/CosmicAuthenticator/scalable/actions/system-lock-screen-symbolic.svg")),
    ("document-properties-symbolic.svg", include_bytes!("../resources/icons/CosmicAuthenticator/scalable/actions/document-properties-symbolic.svg")),
    ("image-red-eye-symbolic.svg", include_bytes!("../resources/icons/CosmicAuthenticator/scalable/actions/image-red-eye-symbolic.svg")),
    ("edit-symbolic.svg", include_bytes!("../resources/icons/CosmicAuthenticator/scalable/actions/edit-symbolic.svg")),
    ("pan-down-symbolic.svg", include_bytes!("../resources/icons/CosmicAuthenticator/scalable/actions/pan-down-symbolic.svg")),
    ("pan-up-symbolic.svg", include_bytes!("../resources/icons/CosmicAuthenticator/scalable/actions/pan-up-symbolic.svg")),
    ("pan-end-symbolic.svg", include_bytes!("../resources/icons/CosmicAuthenticator/scalable/actions/pan-end-symbolic.svg")),
    ("go-next-symbolic.svg", include_bytes!("../resources/icons/CosmicAuthenticator/scalable/actions/go-next-symbolic.svg")),
    ("go-previous-symbolic.svg", include_bytes!("../resources/icons/CosmicAuthenticator/scalable/actions/go-previous-symbolic.svg")),
    ("object-select-symbolic.svg", include_bytes!("../resources/icons/CosmicAuthenticator/scalable/actions/object-select-symbolic.svg")),
    ("open-menu-symbolic.svg", include_bytes!("../resources/icons/CosmicAuthenticator/scalable/actions/open-menu-symbolic.svg")),
    ("list-add-symbolic.svg", include_bytes!("../resources/icons/CosmicAuthenticator/scalable/actions/list-add-symbolic.svg")),
    ("list-remove-symbolic.svg", include_bytes!("../resources/icons/CosmicAuthenticator/scalable/actions/list-remove-symbolic.svg")),
    ("navbar-open-symbolic.svg", include_bytes!("../resources/icons/CosmicAuthenticator/scalable/actions/navbar-open-symbolic.svg")),
    ("navbar-closed-symbolic.svg", include_bytes!("../resources/icons/CosmicAuthenticator/scalable/actions/navbar-closed-symbolic.svg")),
];

/// Result of preparing the private libcosmic icon theme.
pub struct Prepared {
    pub theme: Option<String>,
    pub icons_checked: usize,
    pub icons_missing: Vec<String>,
    pub summary: String,
}

impl Prepared {
    pub fn ok(&self) -> bool {
        self.theme.as_deref() == Some(THEME) && self.icons_missing.is_empty()
    }
}

/// Writes the private theme and verifies `libcosmic`'s lookup resolves every
/// bundled widget icon from it. Must run before any thread is started, because
/// it temporarily prepends the private theme root to `XDG_DATA_DIRS`.
pub fn prepare() -> Prepared {
    let fallback = fallback_icon_theme();
    let all_names = || ICONS.iter().map(|(f, _)| f.trim_end_matches(".svg").to_string()).collect();
    let fall_back = |why: String, missing: Vec<String>| Prepared {
        theme: fallback.clone(),
        icons_checked: ICONS.len(),
        icons_missing: missing,
        summary: format!("fallback ({}): {why}", fallback.as_deref().unwrap_or("libcosmic default")),
    };

    let Some(base) = private_base() else {
        return fall_back(String::from("no absolute XDG_DATA_HOME or HOME"), all_names());
    };
    let theme_dir = base.join("icons").join(THEME);
    let desktop = fallback.clone().unwrap_or_else(cosmic::icon_theme::default);
    let inherits = inherits(&desktop, &theme_bases());
    if let Err(error) = write_theme(&theme_dir, &theme_files(&inherits)) {
        return fall_back(format!("cannot write {}: {error}", theme_dir.display()), all_names());
    }
    let threads = std::fs::read_dir("/proc/self/task").map(Iterator::count).unwrap_or(0);
    if threads != 1 {
        return fall_back(format!("{threads} threads running at start"), all_names());
    }

    cosmic::icon_theme::set_default(THEME);
    let mut missing = Vec::new();
    for (name, path) in with_data_dir(&base, probe) {
        if !path.as_deref().is_some_and(|p| p.starts_with(&theme_dir)) && !missing.contains(&name) {
            missing.push(name);
        }
    }
    if !missing.is_empty() {
        return fall_back(
            format!("lookup did not resolve from {}: {}", theme_dir.display(), missing.join(", ")),
            missing,
        );
    }

    Prepared {
        theme: Some(THEME.to_string()),
        icons_checked: ICONS.len(),
        icons_missing: Vec::new(),
        summary: format!("{} (inherits: {})", theme_dir.display(), inherits.join(", ")),
    }
}

/// Probes every compiled-in libcosmic widget icon at both unsized and 16 px.
fn probe() -> Vec<(String, Option<PathBuf>)> {
    let mut found = Vec::new();
    for (file, _) in ICONS {
        let name = file.trim_end_matches(".svg");
        for size in [None, Some(16)] {
            let mut named = cosmic::widget::icon::from_name(name);
            if let Some(size) = size {
                named = named.size(size);
            }
            found.push((name.to_string(), named.path()));
        }
    }
    found
}

/// Runs `f` with `base` prepended to `XDG_DATA_DIRS`, restoring the original
/// value on return or unwind. Caller must ensure the process is single-threaded.
fn with_data_dir<T>(base: &Path, f: impl FnOnce() -> T) -> T {
    struct Restore(Option<OsString>);
    impl Drop for Restore {
        fn drop(&mut self) {
            // SAFETY: prepare() verified this process has only one thread.
            unsafe {
                match &self.0 {
                    Some(value) => std::env::set_var("XDG_DATA_DIRS", value),
                    None => std::env::remove_var("XDG_DATA_DIRS"),
                }
            }
        }
    }
    let original = std::env::var_os("XDG_DATA_DIRS");
    let mut dirs = vec![base.to_path_buf()];
    dirs.extend(data_dirs(original.as_deref()));
    let Ok(joined) = std::env::join_paths(dirs) else {
        return f();
    };
    let _restore = Restore(original);
    // SAFETY: prepare() verified this process has only one thread, and `_restore`
    // restores `XDG_DATA_DIRS` before this function returns.
    unsafe { std::env::set_var("XDG_DATA_DIRS", &joined) };
    f()
}

fn data_dirs(value: Option<&OsStr>) -> Vec<PathBuf> {
    let dirs: Vec<PathBuf> = value.map(|v| std::env::split_paths(v).filter(|p| p.is_absolute()).collect()).unwrap_or_default();
    if dirs.is_empty() { vec![PathBuf::from("/usr/local/share"), PathBuf::from("/usr/share")] } else { dirs }
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from).filter(|p| p.is_absolute())
}

fn private_base() -> Option<PathBuf> {
    let data_home = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| home_dir().map(|h| h.join(".local/share")))?;
    Some(data_home.join(crate::APP_ID))
}

fn theme_bases() -> Vec<PathBuf> {
    let mut bases: Vec<PathBuf> = data_dirs(std::env::var_os("XDG_DATA_DIRS").as_deref()).iter().map(|d| d.join("icons")).collect();
    if let Some(data_home) = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| home_dir().map(|h| h.join(".local/share")))
    {
        bases.push(data_home.join("icons"));
    }
    if let Some(home) = home_dir() {
        bases.push(home.join(".icons"));
    }
    bases
}

fn ini_value(text: &str, section: &str, key: &str) -> Option<String> {
    let mut in_section = false;
    for line in text.lines().map(str::trim) {
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

fn inherits(desktop: &str, bases: &[PathBuf]) -> Vec<String> {
    let usable = |n: &str| !n.is_empty() && n != THEME && !n.contains([',', '/', '\n', '\r']);
    let mut list: Vec<String> = Vec::new();
    if usable(desktop) {
        list.push(desktop.to_string());
    }
    let parents = bases
        .iter()
        .find_map(|b| std::fs::read_to_string(b.join(desktop).join("index.theme")).ok())
        .and_then(|text| ini_value(&text, "Icon Theme", "Inherits"))
        .unwrap_or_default();
    for parent in parents.split(',').map(str::trim) {
        if usable(parent) && !list.iter().any(|n| n == parent) {
            list.push(parent.to_string());
        }
    }
    list
}

fn theme_files(inherits: &[String]) -> Vec<(String, Vec<u8>)> {
    let index = format!(
        "[Icon Theme]\nName=COSMIC Authenticator window icons\nComment=Written by COSMIC Authenticator at startup\n\
         Inherits={}\nDirectories={DIR}\nHidden=true\n\n[{DIR}]\nContext=Actions\nSize=16\nMinSize=8\nMaxSize=512\nType=Scalable\n",
        inherits.join(",")
    );
    let mut files = vec![(String::from("index.theme"), index.into_bytes())];
    files.extend(ICONS.iter().map(|(name, svg)| (format!("{DIR}/{name}"), svg.to_vec())));
    files
}

fn write_theme(dir: &Path, files: &[(String, Vec<u8>)]) -> io::Result<bool> {
    let mut changed = false;
    for (rel, data) in files {
        let path = dir.join(rel);
        if std::fs::read(&path).is_ok_and(|old| old == *data) {
            continue;
        }
        std::fs::create_dir_all(path.parent().unwrap_or(dir))?;
        let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
        std::fs::write(&tmp, data)?;
        std::fs::rename(&tmp, &path)?;
        changed = true;
    }
    changed |= remove_others(dir, Path::new(""), files)?;
    Ok(changed)
}

fn remove_others(dir: &Path, rel: &Path, files: &[(String, Vec<u8>)]) -> io::Result<bool> {
    let mut changed = false;
    for entry in std::fs::read_dir(dir.join(rel))? {
        let entry = entry?;
        let rel = rel.join(entry.file_name());
        let wanted_file = files.iter().any(|(f, _)| Path::new(f) == rel);
        let wanted_dir = files.iter().any(|(f, _)| Path::new(f).starts_with(&rel) && Path::new(f) != rel);
        let is_dir = entry.path().symlink_metadata()?.is_dir();
        if is_dir && wanted_dir {
            changed |= remove_others(dir, &rel, files)?;
        } else if !(wanted_file && !is_dir) {
            if is_dir { std::fs::remove_dir_all(entry.path())? } else { std::fs::remove_file(entry.path())? }
            changed = true;
        }
    }
    Ok(changed)
}

fn fallback_icon_theme() -> Option<String> {
    let bases = theme_bases();
    let installed = |name: &str| bases.iter().any(|d| d.join(name).join("index.theme").is_file());
    if installed("Cosmic") {
        return None;
    }
    let config_home = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| home_dir().map(|h| h.join(".config")));
    let read = |rel: &str, section: &str, key: &str| {
        let file = config_home.as_ref()?.join(rel);
        std::fs::read_to_string(file).ok().and_then(|t| ini_value(&t, section, key))
    };
    [
        Some(String::from("CosmicAuthenticator")),
        read("kdeglobals", "Icons", "Theme"),
        read("gtk-3.0/settings.ini", "Settings", "gtk-icon-theme-name"),
        Some(String::from("breeze")),
        Some(String::from("Adwaita")),
    ]
    .into_iter()
    .flatten()
    .find(|n| installed(n))
}

#[cfg(test)]
mod tests {
    use super::{DIR, ICONS, THEME, data_dirs, inherits, ini_value, theme_files, write_theme};
    use std::path::{Path, PathBuf};

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("cosmic-auth-window-icons-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn listing(dir: &Path) -> Vec<String> {
        fn walk(dir: &Path, rel: &Path, out: &mut Vec<String>) {
            for e in std::fs::read_dir(dir.join(rel)).unwrap() {
                let rel = rel.join(e.unwrap().file_name());
                if dir.join(&rel).is_dir() { walk(dir, &rel, out) } else { out.push(rel.to_string_lossy().into_owned()) }
            }
        }
        let mut out = Vec::new();
        walk(dir, Path::new(""), &mut out);
        out.sort();
        out
    }

    #[test]
    fn the_theme_holds_every_libcosmic_icon_and_index_the_lookup_reads() {
        let files = theme_files(&[String::from("breeze-dark"), String::from("breeze")]);
        assert_eq!(files.len(), ICONS.len() + 1);
        for (name, svg) in ICONS {
            let text = std::str::from_utf8(svg).unwrap();
            assert!(text.contains("<svg"), "{name} is not an SVG");
        }
        let index = String::from_utf8(files[0].1.clone()).unwrap();
        assert!(index.starts_with("[Icon Theme]\n") && index.ends_with('\n'));
        assert_eq!(ini_value(&index, "Icon Theme", "Inherits").as_deref(), Some("breeze-dark,breeze"));
        assert_eq!(ini_value(&index, "Icon Theme", "Directories").as_deref(), Some(DIR));
        assert_eq!(ini_value(&index, DIR, "Size").as_deref(), Some("16"));
        assert_eq!(ini_value(&index, DIR, "Type").as_deref(), Some("Scalable"));
    }

    #[test]
    fn writing_twice_changes_nothing() {
        let dir = scratch("twice").join(THEME);
        let files = theme_files(&[String::from("breeze")]);
        assert!(write_theme(&dir, &files).unwrap());
        let stamp = |p: &str| std::fs::metadata(dir.join(p)).unwrap().modified().unwrap();
        let before: Vec<_> = files.iter().map(|(f, _)| stamp(f)).collect();
        assert!(!write_theme(&dir, &files).unwrap());
        let after: Vec<_> = files.iter().map(|(f, _)| stamp(f)).collect();
        assert_eq!(before, after);
        std::fs::remove_dir_all(dir.parent().unwrap()).unwrap();
    }

    #[test]
    fn a_newer_set_replaces_an_older_one() {
        let dir = scratch("newer").join(THEME);
        let mut old = theme_files(&[String::from("Adwaita")]);
        old[1].1 = b"<svg/>".to_vec();
        old.push((format!("{DIR}/gone-symbolic.svg"), b"<svg/>".to_vec()));
        old.push((String::from("16x16/actions/gone-symbolic.svg"), b"<svg/>".to_vec()));
        old.push((String::from("index.tmp-1"), Vec::new()));
        write_theme(&dir, &old).unwrap();

        let new = theme_files(&[String::from("breeze")]);
        assert!(write_theme(&dir, &new).unwrap());
        let mut expected: Vec<String> = new.iter().map(|(f, _)| f.clone()).collect();
        expected.sort();
        assert_eq!(listing(&dir), expected);
        for (f, data) in &new {
            assert_eq!(&std::fs::read(dir.join(f)).unwrap(), data);
        }
        std::fs::remove_dir_all(dir.parent().unwrap()).unwrap();
    }

    #[test]
    fn an_unwritable_folder_is_an_error_not_a_panic() {
        let root = scratch("unwritable");
        std::fs::write(root.join(THEME), b"").unwrap();
        assert!(write_theme(&root.join(THEME), &theme_files(&[])).is_err());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn the_desktop_theme_and_its_own_parents_are_inherited() {
        let root = scratch("inherits");
        let (first, second) = (root.join("a"), root.join("b"));
        for (base, inh) in [(&first, "breeze,hicolor"), (&second, "Adwaita")] {
            std::fs::create_dir_all(base.join("breeze-dark")).unwrap();
            std::fs::write(base.join("breeze-dark/index.theme"), format!("[Icon Theme]\nName=x\nInherits={inh}\n")).unwrap();
        }
        assert_eq!(inherits("breeze-dark", &[first.clone(), second.clone()]), ["breeze-dark", "breeze", "hicolor"]);
        assert_eq!(inherits("breeze-dark", &[root.join("none"), second]), ["breeze-dark", "Adwaita"]);
        assert_eq!(inherits("Cosmic", &[first]), ["Cosmic"]);
        assert_eq!(inherits(THEME, &[]), Vec::<String>::new());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn data_dirs_are_read_as_the_lookup_reads_them() {
        let default = [PathBuf::from("/usr/local/share"), PathBuf::from("/usr/share")];
        assert_eq!(data_dirs(None), default);
        assert_eq!(data_dirs(Some("".as_ref())), default);
        assert_eq!(data_dirs(Some("relative:also/relative".as_ref())), default);
        assert_eq!(data_dirs(Some("/a:rel:/b".as_ref())), [PathBuf::from("/a"), PathBuf::from("/b")]);
    }
}
