//! Blocking client for Proton's API. It identifies as the official Linux app,
//! as the owner decided (see docs/proton-sync.md), and refreshes the session
//! once when a request is refused as unauthorised.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const API_URL: &str = "https://authenticator.proton.me/api";
pub const SSO_URL: &str = "https://account.proton.me";
pub const APP_NAME: &str = "proton-authenticator";
/// The official Linux app's client ID and version.
pub const APP_VERSION: &str = "linux-authenticator@1.1.6";
/// The official sign-in window's user agent (`src-tauri/src/auth.rs`).
pub const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) ProtonAuthenticator/1.1.6 Electron/1.0.0";

/// Proton's reply when it no longer accepts `APP_VERSION` (`APP_VERSION_BAD`
/// in `packages/shared/lib/errors.ts`).
const APP_VERSION_BAD: i64 = 5003;

/// Largest response read; entry pages are far smaller.
const MAX_RESPONSE: u64 = 32 << 20;

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Tokens {
    pub uid: String,
    pub access_token: String,
    pub refresh_token: String,
}

impl std::fmt::Debug for Tokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tokens").field("uid", &self.uid).finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ApiError {
    /// No connection, DNS failure or timeout. Local codes keep working.
    Offline(String),
    /// The session is no longer valid, even after a refresh; sign in again.
    SignedOut,
    Proton { status: u16, code: i64, message: String },
    Invalid(String),
}

impl ApiError {
    pub fn message(&self) -> String {
        match self {
            ApiError::Offline(detail) => format!("Cannot reach Proton ({detail})"),
            ApiError::SignedOut => String::from("The Proton session has ended. Sign in again to sync."),
            ApiError::Proton { code: APP_VERSION_BAD, .. } => String::from(
                "Proton no longer accepts this version of Authenticator, so sync is paused. Update the app; \
                 your codes still work here.",
            ),
            ApiError::Proton { message, code, .. } if !message.is_empty() => format!("{message} (Proton error {code})"),
            ApiError::Proton { status, code, .. } => format!("Proton refused the request (HTTP {status}, error {code})"),
            ApiError::Invalid(detail) => format!("Unexpected reply from Proton: {detail}"),
        }
    }
}

#[derive(Clone, Copy)]
pub enum Method {
    Get,
    Post,
    Put,
    Delete,
}

pub struct Client {
    agent: ureq::Agent,
    pub tokens: Option<Tokens>,
    /// Set when a refresh replaced the tokens, so the caller can store them.
    pub tokens_changed: bool,
}

impl Client {
    pub fn new(tokens: Option<Tokens>) -> Self {
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(30)))
            .http_status_as_error(false)
            .user_agent(USER_AGENT)
            .build()
            .into();
        Client { agent, tokens, tokens_changed: false }
    }

    fn send(&self, method: Method, path: &str, body: Option<&Value>, auth: bool) -> Result<(u16, Value), ApiError> {
        let url = format!("{API_URL}/{path}");
        let mut headers = vec![
            ("x-pm-appversion", APP_VERSION.to_string()),
            ("Accept", String::from("application/vnd.protonmail.v1+json")),
        ];
        if let Some(tokens) = &self.tokens {
            headers.push(("x-pm-uid", tokens.uid.clone()));
            if auth {
                headers.push(("Authorization", format!("Bearer {}", tokens.access_token)));
            }
        }

        let result = match (method, body) {
            (Method::Get, _) => headers.iter().fold(self.agent.get(&url), |r, (k, v)| r.header(*k, v)).call(),
            (Method::Delete, None) => headers.iter().fold(self.agent.delete(&url), |r, (k, v)| r.header(*k, v)).call(),
            (method, body) => {
                let builder = match method {
                    Method::Post => self.agent.post(&url),
                    Method::Put => self.agent.put(&url),
                    _ => self.agent.delete(&url).force_send_body(),
                };
                let text = body.map(Value::to_string).unwrap_or_else(|| String::from("{}"));
                headers
                    .iter()
                    .fold(builder, |r, (k, v)| r.header(*k, v))
                    .content_type("application/json")
                    .send(text)
            }
        };

        let mut response = result.map_err(|error| ApiError::Offline(error.to_string()))?;
        let status = response.status().as_u16();
        let text = response
            .body_mut()
            .with_config()
            .limit(MAX_RESPONSE)
            .read_to_string()
            .map_err(|error| ApiError::Offline(error.to_string()))?;
        let value = if text.trim().is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&text).map_err(|error| ApiError::Invalid(format!("HTTP {status}: {error}")))?
        };
        Ok((status, value))
    }

    fn check(status: u16, value: Value) -> Result<Value, ApiError> {
        let code = value.get("Code").and_then(Value::as_i64);
        let accepted = matches!(code, None | Some(1000) | Some(1001));
        if (200..300).contains(&status) && accepted {
            return Ok(value);
        }
        if status == 401 {
            return Err(ApiError::SignedOut);
        }
        Err(ApiError::Proton {
            status,
            code: code.unwrap_or(0),
            message: value.get("Error").and_then(Value::as_str).unwrap_or_default().to_string(),
        })
    }

    /// Sends a request with the session, refreshing it once if it has expired.
    pub fn request(&mut self, method: Method, path: &str, body: Option<&Value>) -> Result<Value, ApiError> {
        let (status, value) = self.send(method, path, body, true)?;
        if status == 401 && self.tokens.is_some() {
            self.refresh()?;
            let (status, value) = self.send(method, path, body, true)?;
            return Self::check(status, value);
        }
        Self::check(status, value)
    }

    /// Sends a request without session headers, as the fork pull needs.
    pub fn request_anonymous(&self, method: Method, path: &str) -> Result<Value, ApiError> {
        let client = Client { agent: self.agent.clone(), tokens: None, tokens_changed: false };
        let (status, value) = client.send(method, path, None, false)?;
        Self::check(status, value)
    }

    /// Token refresh, as clients without a browser cookie jar do it.
    pub fn refresh(&mut self) -> Result<(), ApiError> {
        let Some(tokens) = self.tokens.clone() else {
            return Err(ApiError::SignedOut);
        };
        let body = json!({
            "UID": tokens.uid,
            "RefreshToken": tokens.refresh_token,
            "ResponseType": "token",
            "GrantType": "refresh_token",
            "RedirectURI": "https://protonmail.com",
        });
        let (status, value) = self.send(Method::Post, "auth/v4/refresh", Some(&body), false)?;
        // A refused refresh token means the session was revoked or expired,
        // unless Proton refused the app version, which signing in again won't fix.
        let version_bad = value.get("Code").and_then(Value::as_i64) == Some(APP_VERSION_BAD);
        if (400..500).contains(&status) && !version_bad {
            return Err(ApiError::SignedOut);
        }
        let value = Self::check(status, value)?;
        let field = |name: &str| value.get(name).and_then(Value::as_str).map(str::to_string);
        let (Some(access_token), Some(refresh_token)) = (field("AccessToken"), field("RefreshToken")) else {
            return Err(ApiError::Invalid(String::from("the refresh reply has no tokens")));
        };
        self.tokens = Some(Tokens { uid: field("UID").unwrap_or(tokens.uid), access_token, refresh_token });
        self.tokens_changed = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outdated_version_is_reported_as_such() {
        let value = json!({ "Code": APP_VERSION_BAD, "Error": "Please update" });
        let error = Client::check(400, value).unwrap_err();
        assert!(error.message().contains("no longer accepts this version"), "{}", error.message());
    }
}
