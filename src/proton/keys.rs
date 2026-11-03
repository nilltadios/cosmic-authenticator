//! Account keys (OpenPGP) and the Authenticator key they protect.
//!
//! The account's private keys come from `core/v4/users`, locked with the key
//! password from the sign-in payload. Each Authenticator key from
//! `authenticator/v1/key` is 32 bytes, encrypted to one account key and signed
//! by it; the official app requires the signature (`expectSigned: true`).
//! When the account has no Authenticator key, the official app makes one and
//! uploads it the same way (`serializeKey` in `src/lib/entries/sync.ts`).

use std::io::BufReader;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rand_core::OsRng;
use pgp::composed::{Deserializable, Message, MessageBuilder, SignedPublicKey, SignedSecretKey};
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::types::{KeyDetails, Password};
use serde_json::Value;

pub struct UserKey {
    pub id: String,
    pub secret: SignedSecretKey,
    pub public: SignedPublicKey,
    pub primary: bool,
}

/// Reads and unlocks the active account keys from a `core/v4/users` reply,
/// primary key first, as the official code expects. Keys that do not unlock
/// with this password are skipped, as the official app does.
pub fn unlock_user_keys(user: &Value, key_password: &str) -> Result<Vec<UserKey>, String> {
    let keys = user
        .pointer("/User/Keys")
        .and_then(Value::as_array)
        .ok_or("The account reply has no keys")?;
    let password = Password::from(key_password);
    let mut unlocked: Vec<UserKey> = keys
        .iter()
        .filter(|key| key.get("Active").and_then(Value::as_i64) != Some(0))
        .filter_map(|key| {
            let armored = key.get("PrivateKey")?.as_str()?;
            let (secret, _) = SignedSecretKey::from_string(armored).ok()?;
            secret.primary_key.unlock(&password, |_, _| Ok(())).ok()?.ok()?;
            Some(UserKey {
                id: key.get("ID")?.as_str()?.to_string(),
                public: secret.to_public_key(),
                secret,
                primary: key.get("Primary").and_then(Value::as_i64) == Some(1),
            })
        })
        .collect();
    if unlocked.is_empty() {
        return Err(String::from("None of the account keys unlock with the key password from sign-in"));
    }
    unlocked.sort_by_key(|key| !key.primary);
    Ok(unlocked)
}

/// Decrypts a binary OpenPGP message with `key` and checks that `key` signed it.
pub fn decrypt_signed(message: &[u8], key: &UserKey, key_password: &str) -> Result<Vec<u8>, String> {
    let parsed = Message::from_bytes(BufReader::new(message)).map_err(|e| format!("Not an OpenPGP message: {e}"))?;
    let mut decrypted = parsed
        .decrypt(&Password::from(key_password), &key.secret)
        .map_err(|e| format!("Cannot decrypt: {e}"))?;
    // GnuPG compresses before signing; Proton's library normally does not.
    if decrypted.is_compressed() {
        decrypted = decrypted.decompress().map_err(|e| format!("Cannot decompress: {e}"))?;
    }
    let data = decrypted.as_data_vec().map_err(|e| format!("Cannot read the message: {e}"))?;
    if !decrypted.is_signed() {
        return Err(String::from("The message is not signed"));
    }
    decrypted.verify(&key.public).map_err(|_| String::from("The signature does not match the account key"))?;
    Ok(data)
}

/// Decrypts an Authenticator key (`Key` from `authenticator/v1/key`, base64).
pub fn decrypt_authenticator_key(key_b64: &str, user_key: &UserKey, key_password: &str) -> Result<Vec<u8>, String> {
    let message = STANDARD.decode(key_b64.trim()).map_err(|_| "The Authenticator key is not valid Base64")?;
    let key = decrypt_signed(&message, user_key, key_password)?;
    if key.len() != 32 {
        return Err(format!("The Authenticator key is {} bytes, not 32", key.len()));
    }
    Ok(key)
}

/// Encrypts an Authenticator key to `user_key` and signs it with it, as the
/// official app does before uploading a new key. Returns base64, as the API takes it.
pub fn encrypt_authenticator_key(key: &[u8], user_key: &UserKey, key_password: &str) -> Result<String, String> {
    let mut builder = MessageBuilder::from_bytes("", key.to_vec()).seipd_v1(OsRng, SymmetricKeyAlgorithm::AES256);
    // The subkey made for encryption, as OpenPGP.js picks it; older RSA
    // accounts may encrypt with the primary key.
    let subkey = user_key.public.public_subkeys.iter().find(|subkey| {
        subkey.key.algorithm().can_encrypt()
            && subkey.signatures.iter().any(|sig| sig.key_flags().encrypt_comms() || sig.key_flags().encrypt_storage())
    });
    match subkey {
        Some(subkey) => builder.encrypt_to_key(OsRng, subkey),
        None if user_key.public.primary_key.algorithm().can_encrypt() => {
            builder.encrypt_to_key(OsRng, &user_key.public.primary_key)
        }
        None => return Err(String::from("The account key has no encryption key")),
    }
    .map_err(|e| format!("Cannot encrypt the Authenticator key: {e}"))?;
    builder.sign(&user_key.secret.primary_key, Password::from(key_password), HashAlgorithm::Sha512);
    let message = builder.to_vec(OsRng).map_err(|e| format!("Cannot encrypt the Authenticator key: {e}"))?;
    Ok(STANDARD.encode(message))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Made by tests/fixtures/make-pgp-fixtures.sh with GnuPG; throwaway keys.
    const USER_KEY: &str = include_str!("../../tests/fixtures/user-key.asc");
    const PASSWORD: &str = include_str!("../../tests/fixtures/user-key.password");
    const KEY_BIN: &[u8] = include_bytes!("../../tests/fixtures/authenticator-key.bin");
    const KEY_PGP: &[u8] = include_bytes!("../../tests/fixtures/authenticator-key.pgp");
    const WRONG_SIGNER: &[u8] = include_bytes!("../../tests/fixtures/authenticator-key-wrong-signer.pgp");

    fn user(password_ok: bool) -> Result<Vec<UserKey>, String> {
        let reply = json!({"User": {"Keys": [{"ID": "key-1", "PrivateKey": USER_KEY, "Primary": 1, "Active": 1}]}});
        unlock_user_keys(&reply, if password_ok { PASSWORD } else { "wrong" })
    }

    #[test]
    fn unlocks_the_account_key_only_with_its_password() {
        assert_eq!(user(true).unwrap()[0].id, "key-1");
        assert!(user(false).is_err());
    }

    #[test]
    fn decrypts_a_signed_authenticator_key() {
        let keys = user(true).unwrap();
        let key = decrypt_authenticator_key(&STANDARD.encode(KEY_PGP), &keys[0], PASSWORD).unwrap();
        assert_eq!(key, KEY_BIN);
    }

    #[test]
    fn a_new_key_reads_back_as_proton_would_read_it() {
        let keys = user(true).unwrap();
        let new_key = [7u8; 32];
        let encrypted = encrypt_authenticator_key(&new_key, &keys[0], PASSWORD).unwrap();
        assert_eq!(decrypt_authenticator_key(&encrypted, &keys[0], PASSWORD).unwrap(), new_key);
    }

    #[test]
    fn rejects_a_key_signed_by_someone_else() {
        let keys = user(true).unwrap();
        // It decrypts fine; only the signature gives it away.
        let error = decrypt_authenticator_key(&STANDARD.encode(WRONG_SIGNER), &keys[0], PASSWORD).unwrap_err();
        assert_eq!(error, "The signature does not match the account key");
    }
}
