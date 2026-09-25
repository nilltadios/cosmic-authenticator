//! App lock with a password, as the official app's `lib/locks/password`:
//! Argon2id of the password, with Proton's recommended parameters and a random
//! salt, becomes the key that encrypts the vault and the Proton session, in
//! place of the keyring key. A random value encrypted with that key (the
//! verifier) tells whether a password is right. After `MAX_FAILURES` wrong
//! passwords in a row the local data is erased, as the official app does.

use aes_gcm::aead::{Aead, KeyInit, OsRng, Payload, rand_core::RngCore};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use zeroize::Zeroizing;

pub const MAX_FAILURES: u32 = 10;
/// The official verifier tag (`AuthenticatorEncryptionTag.OfflineVerifier`).
const VERIFIER_TAG: &[u8] = b"authenticator;offline_verifier";
const IV_LENGTH: usize = 12;

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct Params {
    pub passes: u32,
    pub parallelism: u32,
    /// Memory is 2^memory_exponent KiB.
    pub memory_exponent: u32,
}

/// `ARGON2_PARAMS.RECOMMENDED` from Proton's crypto library (RFC 9106): one
/// pass, four lanes, 512 MiB.
pub const RECOMMENDED: Params = Params { passes: 1, parallelism: 4, memory_exponent: 19 };

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LockConfig {
    pub salt: String,
    pub params: Params,
    pub verifier: String,
    pub failed_attempts: u32,
}

impl LockConfig {
    pub fn attempts_left(&self) -> u32 {
        MAX_FAILURES.saturating_sub(self.failed_attempts)
    }
}

/// A 32-byte key derived from the password. Wiped when dropped; never printed.
#[derive(Clone, PartialEq)]
pub struct Key(Zeroizing<[u8; 32]>);

impl Key {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Key> {
        Some(Key(Zeroizing::new(<[u8; 32]>::try_from(bytes).ok()?)))
    }
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key(…)")
    }
}

fn lock_path() -> PathBuf {
    crate::store::data_dir().join("lock.json")
}

pub fn load() -> Result<Option<LockConfig>, String> {
    match std::fs::read_to_string(lock_path()) {
        Ok(json) => serde_json::from_str(&json)
            .map(Some)
            .map_err(|error| format!("The app lock settings are damaged: {error}")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("Cannot read {}: {error}", lock_path().display())),
    }
}

pub fn save(config: &LockConfig) -> Result<(), String> {
    let dir = crate::store::data_dir();
    std::fs::create_dir_all(&dir).map_err(|error| format!("Cannot create {}: {error}", dir.display()))?;
    let json = serde_json::to_string(config).map_err(|error| error.to_string())?;
    crate::store::write_private(&lock_path(), json.as_bytes())
}

pub fn delete() -> Result<(), String> {
    match std::fs::remove_file(lock_path()) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("Cannot remove {}: {error}", lock_path().display())),
    }
}

fn derive(password: &str, salt: &[u8], params: Params) -> Result<Key, String> {
    let argon_params = argon2::Params::new(1 << params.memory_exponent, params.passes, params.parallelism, Some(32))
        .map_err(|error| format!("Invalid Argon2 parameters: {error}"))?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, argon_params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|error| format!("Cannot derive the key from the password: {error}"))?;
    Ok(Key(key))
}

/// Encrypts with AES-256-GCM: a random 12-byte IV, then ciphertext and tag.
pub fn seal(key: &Key, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut iv = [0u8; IV_LENGTH];
    OsRng.fill_bytes(&mut iv);
    let ciphertext = Aes256Gcm::new(key.as_bytes().into())
        .encrypt(Nonce::from_slice(&iv), Payload { msg: plaintext, aad })
        .expect("AES-GCM encryption does not fail for in-memory data");
    [iv.as_slice(), &ciphertext].concat()
}

pub fn open(key: &Key, aad: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
    if sealed.len() <= IV_LENGTH {
        return None;
    }
    let (iv, ciphertext) = sealed.split_at(IV_LENGTH);
    Aes256Gcm::new(key.as_bytes().into()).decrypt(Nonce::from_slice(iv), Payload { msg: ciphertext, aad }).ok()
}

/// Sets up a new password: its key, and the config to store. Slow (Argon2).
pub fn create(password: &str, params: Params) -> Result<(LockConfig, Key), String> {
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);
    let key = derive(password, &salt, params)?;
    let mut verifier = [0u8; 32];
    OsRng.fill_bytes(&mut verifier);
    let config = LockConfig {
        salt: STANDARD.encode(salt),
        params,
        verifier: STANDARD.encode(seal(&key, VERIFIER_TAG, &verifier)),
        failed_attempts: 0,
    };
    Ok((config, key))
}

/// The key for this password, or `None` if the password is wrong. Slow (Argon2).
pub fn verify(config: &LockConfig, password: &str) -> Result<Option<Key>, String> {
    let salt = STANDARD.decode(&config.salt).map_err(|_| "The app lock settings are damaged")?;
    let verifier = STANDARD.decode(&config.verifier).map_err(|_| "The app lock settings are damaged")?;
    let key = derive(password, &salt, config.params)?;
    Ok(open(&key, VERIFIER_TAG, &verifier).map(|_| key))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Small parameters, so the tests do not need 512 MiB each.
    const FAST: Params = Params { passes: 1, parallelism: 1, memory_exponent: 8 };

    #[test]
    fn the_right_password_gives_back_the_same_key() {
        let (config, key) = create("correct horse", FAST).unwrap();
        assert_eq!(verify(&config, "correct horse").unwrap(), Some(key));
        assert_eq!(verify(&config, "wrong horse").unwrap(), None);
    }

    #[test]
    fn each_setup_gets_its_own_salt_and_key() {
        let (first, first_key) = create("same", FAST).unwrap();
        let (second, second_key) = create("same", FAST).unwrap();
        assert_ne!(first.salt, second.salt);
        assert_ne!(first_key, second_key);
    }

    #[test]
    fn sealed_data_needs_the_key_and_the_tag() {
        let key = Key::from_bytes(&[3u8; 32]).unwrap();
        let sealed = seal(&key, b"tag", b"secret");
        assert_eq!(open(&key, b"tag", &sealed).as_deref(), Some(b"secret".as_slice()));
        assert_eq!(open(&key, b"other", &sealed), None);
        assert_eq!(open(&Key::from_bytes(&[4u8; 32]).unwrap(), b"tag", &sealed), None);
    }

    #[test]
    fn keys_never_print() {
        let (_, key) = create("x", FAST).unwrap();
        assert_eq!(format!("{key:?}"), "Key(…)");
    }

    #[test]
    fn counts_attempts_left() {
        let (mut config, _) = create("x", FAST).unwrap();
        assert_eq!(config.attempts_left(), 10);
        config.failed_attempts = 9;
        assert_eq!(config.attempts_left(), 1);
    }
}
