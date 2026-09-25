//! Encrypted on-disk vault.
//!
//! Entries are encrypted one by one with Proton's `encrypt_entries` (AES-GCM)
//! and written as a JSON array of Base64 strings. The 32-byte key comes from
//! the Secret Service keyring, stored as Base64 text (KDE's implementation
//! rejects binary secrets labelled as text, which is how `keyring` 3.x stores
//! raw bytes), or, with the app lock on, from the password (see lock.rs).

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use proton_authenticator::crypto::generate_encryption_key;
use proton_authenticator::{AuthenticatorEntry, decrypt_entries, encrypt_entries};

const KEYRING_SERVICE: &str = "dev.nilltadios.CosmicAuthenticator";
const KEYRING_USER: &str = "vault-key";

/// The keyring service holding the vault key and the Proton session. Every
/// copy of the app shares it, so test runs set `AUTHENTICATOR_KEYRING_SERVICE`
/// to keep away from the real keys: turning the app lock on deletes the vault key.
pub fn keyring_service() -> String {
    std::env::var("AUTHENTICATOR_KEYRING_SERVICE")
        .ok()
        .filter(|service| !service.is_empty())
        .unwrap_or_else(|| String::from(KEYRING_SERVICE))
}
const KEY_LENGTH: usize = 32;

/// This app's folder under an XDG base directory, such as `XDG_DATA_HOME`,
/// falling back to `fallback` under `$HOME` as the spec says.
pub fn xdg_dir(variable: &str, fallback: &str) -> PathBuf {
    let base = std::env::var_os(variable)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .unwrap_or_else(|| {
            let home = std::env::var_os("HOME").expect("HOME is not set");
            PathBuf::from(home).join(fallback)
        });
    base.join("cosmic-authenticator")
}

pub fn data_dir() -> PathBuf {
    xdg_dir("XDG_DATA_HOME", ".local/share")
}

pub fn vault_path() -> PathBuf {
    data_dir().join("vault.json")
}

fn keyring_entry() -> Result<keyring::Entry, String> {
    keyring::Entry::new(&keyring_service(), KEYRING_USER)
        .map_err(|error| format!("Cannot open the keyring: {error}"))
}

fn decode_key(encoded: &str) -> Result<Vec<u8>, String> {
    let key = STANDARD
        .decode(encoded)
        .map_err(|_| String::from("The vault key in the keyring is not valid Base64"))?;
    if key.len() != KEY_LENGTH {
        return Err(format!("The vault key must be {KEY_LENGTH} bytes"));
    }
    Ok(key)
}

/// The keyring's vault key, if there is one.
pub fn keyring_key() -> Result<Option<Vec<u8>>, String> {
    match keyring_entry()?.get_password() {
        Ok(password) => decode_key(&password).map(Some),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => Err(format!("Cannot read the vault key from the keyring: {error}")),
    }
}

/// Removes the keyring's vault key, once the app lock's key has replaced it.
pub fn delete_keyring_key() -> Result<(), String> {
    match keyring_entry()?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(error) => Err(format!("Cannot remove the vault key from the keyring: {error}")),
    }
}

pub fn keyring_key_or_new() -> Result<Vec<u8>, String> {
    let entry = keyring_entry()?;
    match entry.get_password() {
        Ok(password) => decode_key(&password),
        Err(keyring::Error::NoEntry) => {
            let key = generate_encryption_key();
            entry
                .set_password(&STANDARD.encode(&key))
                .map_err(|error| format!("Cannot store the vault key in the keyring: {error}"))?;
            Ok(key)
        }
        Err(error) => Err(format!("Cannot read the vault key from the keyring: {error}")),
    }
}

/// Loads the vault with the keyring's key. A missing vault is an empty one,
/// and the keyring is not touched until there is something to decrypt.
pub fn load() -> Result<Vec<AuthenticatorEntry>, String> {
    if !vault_path().exists() {
        return Ok(Vec::new());
    }
    let key = keyring_key()?.ok_or("The vault key is missing from the keyring")?;
    load_with(&key)
}

pub fn save(entries: &[AuthenticatorEntry]) -> Result<(), String> {
    save_with(entries, &keyring_key_or_new()?)
}

pub fn load_with(key: &[u8]) -> Result<Vec<AuthenticatorEntry>, String> {
    let path = vault_path();
    let contents = match fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(format!("Cannot read {}: {error}", path.display())),
    };

    let encoded: Vec<String> =
        serde_json::from_str(&contents).map_err(|error| format!("The vault file is damaged: {error}"))?;
    let encrypted = encoded
        .iter()
        .map(|item| STANDARD.decode(item))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| String::from("The vault file is damaged: invalid Base64"))?;

    decrypt_entries(encrypted, key.to_vec()).map_err(|error| format!("Cannot decrypt the vault: {error:?}"))
}

pub fn save_with(entries: &[AuthenticatorEntry], key: &[u8]) -> Result<(), String> {
    let encrypted = encrypt_entries(entries.to_vec(), key.to_vec())
        .map_err(|error| format!("Cannot encrypt the vault: {error:?}"))?;
    let encoded: Vec<String> = encrypted.iter().map(|item| STANDARD.encode(item)).collect();
    let json = serde_json::to_string(&encoded).map_err(|error| error.to_string())?;

    let dir = data_dir();
    fs::create_dir_all(&dir).map_err(|error| format!("Cannot create {}: {error}", dir.display()))?;
    let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    write_private(&vault_path(), json.as_bytes())
}

/// Writes a file only its owner can read. The data goes to a file beside the
/// target first and is renamed over it, so a crash never leaves half a file.
pub fn write_private(path: &Path, contents: &[u8]) -> Result<(), String> {
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(".tmp");
    let temporary = PathBuf::from(temporary);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|error| format!("Cannot write {}: {error}", temporary.display()))?;
    file.write_all(contents)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("Cannot write {}: {error}", temporary.display()))?;
    fs::rename(&temporary, path).map_err(|error| format!("Cannot replace {}: {error}", path.display()))
}

fn links_path() -> PathBuf {
    data_dir().join("sync.json")
}

/// Which local entries are linked to which Proton entries. Only ids, revisions
/// and times, nothing secret; a missing file means nothing is synced.
pub fn load_links() -> Result<crate::proton::sync::Links, String> {
    match fs::read_to_string(links_path()) {
        Ok(contents) => serde_json::from_str(&contents).map_err(|error| format!("The sync state file is damaged: {error}")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Default::default()),
        Err(error) => Err(format!("Cannot read {}: {error}", links_path().display())),
    }
}

pub fn save_links(links: &crate::proton::sync::Links) -> Result<(), String> {
    let dir = data_dir();
    fs::create_dir_all(&dir).map_err(|error| format!("Cannot create {}: {error}", dir.display()))?;
    let json = serde_json::to_string(links).map_err(|error| error.to_string())?;
    write_private(&links_path(), json.as_bytes())
}

/// Removes the vault and the sync links: what the app lock erases after too
/// many wrong passwords. Settings and the logo cache stay.
pub fn erase() -> Result<(), String> {
    for path in [vault_path(), links_path()] {
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("Cannot remove {}: {error}", path.display())),
        }
    }
    Ok(())
}
