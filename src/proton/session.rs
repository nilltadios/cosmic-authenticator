//! The signed-in session, kept in the Secret Service keyring next to the vault
//! key. It holds the tokens and the key password, which unlocks the account's
//! OpenPGP keys, so it never goes to disk in the clear. With the app lock on it
//! is also encrypted with the password's key, so the keyring alone is not enough.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};

use super::api::Tokens;
use crate::lock::Key;
use zeroize::Zeroizing;

const KEYRING_USER: &str = "proton-session";

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Session {
    pub tokens: Tokens,
    pub key_password: Zeroizing<String>,
    pub email: String,
}

/// Shows the account but never the key password or tokens, in case a
/// message holding a session is ever logged.
impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session").field("email", &self.email).finish_non_exhaustive()
    }
}

fn entry() -> Result<keyring::Entry, String> {
    keyring::Entry::new(&crate::store::keyring_service(), KEYRING_USER).map_err(|error| format!("Cannot open the keyring: {error}"))
}

const SEALED_PREFIX: &str = "sealed:";
const SEALED_TAG: &[u8] = b"cosmic-authenticator;session";

/// `lock_key` is the app lock's key, or `None` when the lock is off.
pub fn load(lock_key: Option<&Key>) -> Result<Option<Session>, String> {
    let stored = match entry()?.get_password() {
        Ok(stored) => stored,
        Err(keyring::Error::NoEntry) => return Ok(None),
        Err(error) => return Err(format!("Cannot read the Proton session from the keyring: {error}")),
    };
    let json = match (stored.strip_prefix(SEALED_PREFIX), lock_key) {
        (Some(sealed), Some(key)) => STANDARD
            .decode(sealed)
            .ok()
            .and_then(|bytes| crate::lock::open(key, SEALED_TAG, &bytes))
            .and_then(|plain| String::from_utf8(plain).ok())
            .ok_or("The saved Proton session does not match the app lock; sign in again")?,
        (Some(_), None) => return Err(String::from("The saved Proton session is locked; sign in again")),
        (None, _) => stored,
    };
    serde_json::from_str(&json)
        .map(Some)
        .map_err(|_| String::from("The saved Proton session is damaged; sign in again"))
}

pub fn save(session: &Session, lock_key: Option<&Key>) -> Result<(), String> {
    let json = serde_json::to_string(session).map_err(|error| error.to_string())?;
    let stored = match lock_key {
        Some(key) => format!("{SEALED_PREFIX}{}", STANDARD.encode(crate::lock::seal(key, SEALED_TAG, json.as_bytes()))),
        None => json,
    };
    entry()?
        .set_password(&stored)
        .map_err(|error| format!("Cannot store the Proton session in the keyring: {error}"))
}

pub fn delete() -> Result<(), String> {
    match entry()?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(error) => Err(format!("Cannot remove the Proton session from the keyring: {error}")),
    }
}
