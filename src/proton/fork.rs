//! Session fork: how the official app signs in (docs/proton-sync.md).
//! Proton's account site does the sign-in and hands back a selector and a
//! one-time key; the session is pulled with the selector, and the key decrypts
//! the payload holding the key password.

use aes_gcm::aead::consts::U16;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::aes::Aes256;
use aes_gcm::{Aes256Gcm, AesGcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use zeroize::Zeroizing;

use super::api::{APP_NAME, SSO_URL};

/// AES-256-GCM with the 16-byte IV that payload versions 1 and 2 use.
type Aes256Gcm16 = AesGcm<Aes256, U16>;

pub struct ForkRequest {
    pub url: String,
    pub state: String,
}

/// The sign-in address, with the parameters in the official app's order.
pub fn request(sign_up: bool) -> ForkRequest {
    let mut random = [0u8; 32];
    OsRng.fill_bytes(&mut random);
    let state = URL_SAFE_NO_PAD.encode(random);
    let mut params = vec![
        ("app", APP_NAME),
        ("state", state.as_str()),
        ("independent", "0"),
        ("prompt", "login"),
        ("promptBypass", "sso"),
        ("promptType", "offline"),
        ("pt", "offline"),
        ("t", if sign_up { "2" } else { "3" }),
    ];
    if sign_up {
        params.push(("plan", "free"));
    }
    let query: Vec<String> = params.iter().map(|(key, value)| format!("{key}={value}")).collect();
    ForkRequest { url: format!("{SSO_URL}/authorize?{}", query.join("&")), state }
}

#[derive(Debug, PartialEq)]
pub struct Callback {
    pub selector: String,
    pub key: [u8; 32],
    pub payload_version: u8,
}

/// Reads the fragment of the sign-in callback, and checks that it answers
/// this app's own request.
pub fn parse_callback(fragment: &str, expected_state: &str) -> Result<Callback, String> {
    let params: Vec<(String, String)> =
        url::form_urlencoded::parse(fragment.trim_start_matches('#').as_bytes()).into_owned().collect();
    let get = |name: &str| params.iter().find(|(key, _)| key == name).map(|(_, value)| value.as_str());

    let selector = get("selector").filter(|s| !s.is_empty()).ok_or("The sign-in reply has no selector")?;
    if get("state").map(|state| &state[..state.len().min(100)]) != Some(expected_state) {
        return Err(String::from("The sign-in reply does not match this sign-in"));
    }
    let raw_key = get("sk").ok_or("The sign-in reply has no key")?;
    let key = URL_SAFE_NO_PAD
        .decode(raw_key.trim_end_matches('='))
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or("The sign-in reply has an invalid key")?;
    let payload_version = match get("pv").and_then(|v| v.parse::<u8>().ok()) {
        Some(version @ 1..=3) => version,
        _ => 1,
    };
    Ok(Callback { selector: selector.to_string(), key, payload_version })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForkBlob {
    pub key_password: Zeroizing<String>,
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
mod tests {
    use super::*;

    fn encrypt(key: &[u8; 32], version: u8, json: &str) -> String {
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

    #[test]
    fn decrypts_every_payload_version() {
        let key = [42u8; 32];
        let json = r#"{"type":"offline","keyPassword":"abc/123.xyz","offlineKeyPassword":"p","offlineKeySalt":"s"}"#;
        for version in 1..=3 {
            let blob = decrypt_payload(&key, &encrypt(&key, version, json), version).unwrap();
            assert_eq!(blob.key_password.as_str(), "abc/123.xyz", "version {version}");
        }
        // The associated data differs between versions 1 and 2.
        assert!(decrypt_payload(&key, &encrypt(&key, 2, json), 1).is_err());
        assert!(decrypt_payload(&[1u8; 32], &encrypt(&key, 3, json), 3).is_err());
    }

    #[test]
    fn builds_the_official_sign_in_address() {
        let sign_in = request(false);
        assert!(sign_in.url.starts_with(
            "https://account.proton.me/authorize?app=proton-authenticator&state="
        ));
        assert!(sign_in.url.ends_with("&independent=0&prompt=login&promptBypass=sso&promptType=offline&pt=offline&t=3"));
        assert_eq!(sign_in.state.len(), 43);
        assert!(request(true).url.ends_with("&t=2&plan=free"));
    }

    #[test]
    fn reads_the_callback_and_checks_its_state() {
        let key = URL_SAFE_NO_PAD.encode([9u8; 32]);
        let fragment = format!("selector=sel123&state=abc&sk={key}&pv=3&pt=offline&p=1");
        let callback = parse_callback(&fragment, "abc").unwrap();
        assert_eq!(callback, Callback { selector: String::from("sel123"), key: [9u8; 32], payload_version: 3 });
        assert!(parse_callback(&fragment, "other").is_err());
        assert!(parse_callback("state=abc", "abc").is_err());
        let no_version = format!("selector=s&state=abc&sk={key}");
        assert_eq!(parse_callback(&no_version, "abc").unwrap().payload_version, 1);
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
