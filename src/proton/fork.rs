//! Desktop browser session fork (docs/proton-sync.md).
//!
//! Instead of embedding a web view, the app requests a fork selector and user
//! code from Proton (`GET auth/v4/sessions/forks`), generates a one-time
//! 32-byte AES-256-GCM key, and opens `https://account.proton.me/desktop/login`
//! in the user's system browser with `0:<userCode>:<base64(key)>:linux-authenticator`
//! in the URL fragment (`#payload=...`). Proton's account page handles the
//! password, 2FA, passkeys and CAPTCHA, encrypts the key password with our
//! one-time key, and pushes the fork; the app polls `GET auth/v4/sessions/forks/{selector}`
//! until the session is ready and decrypts the payload locally.

use aes_gcm::aead::consts::U16;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::aes::Aes256;
use aes_gcm::{Aes256Gcm, AesGcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use zeroize::Zeroizing;

use super::api::{APP_NAME, CLIENT_ID, SSO_URL};

/// AES-256-GCM with the 16-byte IV that payload versions 1 and 2 use.
type Aes256Gcm16 = AesGcm<Aes256, U16>;

/// Payload version requested in `/desktop/login?pv=...` (12-byte IV, AAD `fork`, UTF-8).
pub const DESKTOP_PAYLOAD_VERSION: u8 = 3;

/// Payload schema version expected by Proton's `deserializeQrCodePayload`.
const DESKTOP_FORK_SCHEMA_VERSION: u8 = 0;

/// One-time 32-byte AES-256-GCM key for a desktop browser fork: wiped on drop
/// and never printed by `Debug`.
#[derive(Clone)]
pub struct ForkKey(Zeroizing<[u8; 32]>);

impl ForkKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for ForkKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ForkKey(…)")
    }
}

pub struct DesktopFork {
    pub selector: String,
    pub key: ForkKey,
    pub url: Zeroizing<String>,
}

impl std::fmt::Debug for DesktopFork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DesktopFork").field("selector", &self.selector).finish_non_exhaustive()
    }
}

/// Builds the `/desktop/login` address for a fork created by `GET auth/v4/sessions/forks`.
pub fn desktop_request(selector: String, user_code: &str, sign_up: bool) -> Result<DesktopFork, String> {
    if selector.is_empty() || user_code.is_empty() || user_code.contains(':') {
        return Err(String::from("Proton returned an invalid sign-in code"));
    }
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    Ok(desktop_request_with_key(selector, user_code, sign_up, key))
}

fn desktop_request_with_key(selector: String, user_code: &str, sign_up: bool, key: [u8; 32]) -> DesktopFork {
    let key = Zeroizing::new(key);
    // Proton's `signInWithAnotherDevicePush.ts` decodes `encodedBytes` with
    // `Uint8Array.fromBase64` (standard alphabet).
    let encoded_key = Zeroizing::new(STANDARD.encode(*key));
    let raw_payload =
        Zeroizing::new(format!("{DESKTOP_FORK_SCHEMA_VERSION}:{user_code}:{}:{CLIENT_ID}", encoded_key.as_str()));
    // Proton's `handleDesktopFork.ts` reads `#payload=...` with `URLSearchParams`,
    // which treats `+` as a space unless percent-encoded.
    let fragment = Zeroizing::new(
        url::form_urlencoded::Serializer::new(String::new()).append_pair("payload", raw_payload.as_str()).finish(),
    );
    let pv = DESKTOP_PAYLOAD_VERSION.to_string();
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair("app", APP_NAME).append_pair("pv", &pv);
    if sign_up {
        query.append_pair("t", "2").append_pair("plan", "free");
    }
    let url = Zeroizing::new(format!("{SSO_URL}/desktop/login?{}#{}", query.finish(), fragment.as_str()));
    DesktopFork { selector, key: ForkKey(key), url }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForkBlob {
    pub key_password: Zeroizing<String>,
}

/// Decrypts a desktop fork payload: tries the requested version (`pv=3`),
/// falling back to Proton's default (`pv=1`) if the page ignored `pv`.
pub fn decrypt_desktop_payload(key: &[u8; 32], payload: &str) -> Result<ForkBlob, String> {
    decrypt_payload(key, payload, DESKTOP_PAYLOAD_VERSION).or_else(|_| decrypt_payload(key, payload, 1))
}

/// Decrypts the fork payload: base64 of IV, ciphertext and tag.
pub fn decrypt_payload(key: &[u8; 32], payload: &str, version: u8) -> Result<ForkBlob, String> {
    let bytes = STANDARD.decode(payload.trim()).map_err(|_| "The sign-in payload is not valid Base64")?;
    let iv_length = if version == 3 { 12 } else { 16 };
    if bytes.len() <= iv_length {
        return Err(String::from("The sign-in payload is too short"));
    }
    let (iv, ciphertext) = bytes.split_at(iv_length);
    let aad: &[u8] = if version >= 2 { b"fork" } else { b"" };
    let message = Payload { msg: ciphertext, aad };

    let plaintext: Zeroizing<Vec<u8>> = Zeroizing::new(if version == 3 {
        Aes256Gcm::new(key.into()).decrypt(&Nonce::try_from(iv).expect("12-byte IV"), message)
    } else {
        Aes256Gcm16::new(key.into()).decrypt(&aes_gcm::Nonce::<U16>::try_from(iv).expect("16-byte IV"), message)
    }
    .map_err(|_| "Cannot decrypt the sign-in payload")?);

    // Versions 1 and 2 encode the JSON as a binary string, one byte per
    // character; the JSON itself is ASCII, so both read as UTF-8.
    let text: Zeroizing<String> = Zeroizing::new(if version == 3 {
        String::from_utf8(plaintext.to_vec()).map_err(|_| "The sign-in payload is not text")?
    } else {
        plaintext.iter().map(|&b| char::from(b)).collect()
    });
    serde_json::from_str(&text).map_err(|_| String::from("The sign-in payload is not the expected JSON"))
}

#[cfg(test)]
pub(crate) fn encrypt_for_test(key: &[u8; 32], version: u8, json: &str) -> String {
    let aad: &[u8] = if version >= 2 { b"fork" } else { b"" };
    let payload = Payload { msg: json.as_bytes(), aad };
    let (iv, ciphertext) = if version == 3 {
        let iv = [7u8; 12];
        (iv.to_vec(), Aes256Gcm::new(key.into()).encrypt(&Nonce::from(iv), payload).unwrap())
    } else {
        let iv = [7u8; 16];
        (iv.to_vec(), Aes256Gcm16::new(key.into()).encrypt(&aes_gcm::Nonce::<U16>::from(iv), payload).unwrap())
    };
    STANDARD.encode([iv, ciphertext].concat())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decrypts_every_payload_version() {
        let key = [42u8; 32];
        let json = r#"{"type":"default","keyPassword":"abc/123.xyz"}"#;
        for version in 1..=3 {
            let blob = decrypt_payload(&key, &encrypt_for_test(&key, version, json), version).unwrap();
            assert_eq!(blob.key_password.as_str(), "abc/123.xyz", "version {version}");
        }
        // The associated data differs between versions 1 and 2.
        assert!(decrypt_payload(&key, &encrypt_for_test(&key, 2, json), 1).is_err());
        assert!(decrypt_payload(&[1u8; 32], &encrypt_for_test(&key, 3, json), 3).is_err());
        // Desktop decrypt accepts both pv=3 and Proton's QR default pv=1.
        assert_eq!(decrypt_desktop_payload(&key, &encrypt_for_test(&key, 3, json)).unwrap().key_password.as_str(), "abc/123.xyz");
        assert_eq!(decrypt_desktop_payload(&key, &encrypt_for_test(&key, 1, json)).unwrap().key_password.as_str(), "abc/123.xyz");
    }

    #[test]
    fn builds_desktop_login_url_and_encodes_base64_safely() {
        // Key bytes chosen so standard Base64 includes `+`, `/` and `=`.
        let key = [0xfb, 0xff, 0xfe, 0xfb, 0xff, 0xfe, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                   11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26];
        let encoded = STANDARD.encode(key);
        assert!(encoded.contains('+') && encoded.contains('/') && encoded.contains('='));

        let fork = desktop_request_with_key("sel-1".into(), "4PDQ78S3", false, key);
        let parsed = url::Url::parse(fork.url.as_str()).unwrap();
        assert_eq!(parsed.origin().ascii_serialization(), "https://account.proton.me");
        assert_eq!(parsed.path(), "/desktop/login");
        let query: Vec<(String, String)> = parsed.query_pairs().into_owned().collect();
        assert_eq!(query, vec![("app".into(), "proton-authenticator".into()), ("pv".into(), "3".into())]);

        // Simulate Proton's `new URLSearchParams(window.location.hash.slice(1)).get('payload')`.
        let fragment = parsed.fragment().unwrap();
        assert!(!fragment.contains('+'), "literal '+' would become a space in URLSearchParams");
        let payload = url::form_urlencoded::parse(fragment.as_bytes())
            .find_map(|(k, v)| (k == "payload").then(|| v.into_owned()))
            .unwrap();
        let parts: Vec<&str> = payload.split(':').collect();
        assert_eq!(parts, vec!["0", "4PDQ78S3", encoded.as_str(), "linux-authenticator"]);
        assert_eq!(STANDARD.decode(parts[2]).unwrap(), key);

        // Sign-up requests ForkType.SIGNUP (`t=2`) with the free plan.
        let sign_up = desktop_request_with_key("sel-2".into(), "ABCD1234", true, key);
        let parsed = url::Url::parse(sign_up.url.as_str()).unwrap();
        let query: Vec<(String, String)> = parsed.query_pairs().into_owned().collect();
        assert_eq!(
            query,
            vec![
                ("app".into(), "proton-authenticator".into()),
                ("pv".into(), "3".into()),
                ("t".into(), "2".into()),
                ("plan".into(), "free".into()),
            ]
        );
    }

    #[test]
    fn rejects_invalid_fork_reply_and_redacts_debug() {
        assert!(desktop_request(String::new(), "ABCD1234", false).is_err());
        assert!(desktop_request("sel".into(), "", false).is_err());
        assert!(desktop_request("sel".into(), "BAD:CODE", false).is_err());

        let fork = desktop_request_with_key("sel-debug".into(), "4PDQ78S3", false, [9u8; 32]);
        let shown = format!("{fork:?}");
        assert!(shown.contains("sel-debug"));
        assert!(!shown.contains("4PDQ78S3"));
        assert!(!shown.contains(&STANDARD.encode([9u8; 32])));
        assert_eq!(format!("{:?}", fork.key), "ForkKey(…)");
    }

    /// Payloads encrypted by an earlier build (aes-gcm 0.10): crate upgrades
    /// must still decrypt every version.
    #[test]
    fn decrypts_payloads_made_by_an_earlier_build() {
        let payloads = [
            "BwcHBwcHBwcHBwcHBwcHB3pH6/UFmZvKhD09fSsootUIXHsfa6FDgN4mI74HO9aSWOgUoj817KVaGKhRbS2V7XfslU6+w/JhVhfvobFYlC5cWUQHcV29ORh3dEBLLJymvCqdAwvBc0GNZTuhRm53zcGG/siQ9/yn7cPbsA==",
            "BwcHBwcHBwcHBwcHBwcHB3pH6/UFmZvKhD09fSsootUIXHsfa6FDgN4mI74HO9aSWOgUoj817KVaGKhRbS2V7XfslU6+w/JhVhfvobFYlC5cWUQHcV29ORh3dEBLLJymvCqdAwvBc0GNZTuh6KdNdAaPopGroB9BvrS7mg==",
            "BwcHBwcHBwcHBwcHRN2L3CXxBwvbJRbG5pXZXhiqTxj7RDBU2Un1+C5YICjczZZ4Uey8zN73iCDoK8SuFeTFMIuN2H/I3y4bpPX/EIj0UzMOeEd5S3NuRl1tnSiRWTYCyYA5peNCh9W6ZU0DywaY/V/SF8SiQfLR",
        ];
        for (version, payload) in (1..=3).zip(payloads) {
            let blob = decrypt_payload(&[42u8; 32], payload, version).unwrap();
            assert_eq!(blob.key_password.as_str(), "abc/123.xyz", "version {version}");
        }
    }
}
