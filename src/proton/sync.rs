//! Sign-in and read-only sync (docs/proton-sync.md). Blocking: run it off the
//! UI thread.
//!
//! Read-only means this module never writes to Proton, apart from ending the
//! session on sign-out. Merges use Proton's own rules
//! (`calculate_operations_to_perform`), but only their local side is applied;
//! uploads and remote deletions are counted and held back until two-way sync.

use std::collections::{HashMap, HashSet};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use proton_authenticator::operations::{
    AuthenticatorEntryState, AuthenticatorOperation, LocalEntry, RemoteEntry, calculate_operations_to_perform,
};
use proton_authenticator::{AuthenticatorEntry, decrypt_entries};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::api::{ApiError, Client, Method, Tokens};
use super::keys::{UserKey, decrypt_authenticator_key, unlock_user_keys};
use super::session::Session;
use super::fork;

#[derive(Debug, Clone, PartialEq)]
pub enum SyncError {
    Offline(String),
    SignedOut,
    /// The account has no Authenticator key yet. The official app would create
    /// and upload one; read-only sync does not write.
    NoKey,
    Failed(String),
}

impl SyncError {
    pub fn message(&self) -> String {
        match self {
            SyncError::Offline(detail) => ApiError::Offline(detail.clone()).message(),
            SyncError::SignedOut => ApiError::SignedOut.message(),
            SyncError::NoKey => String::from(
                "This Proton account has no Authenticator codes yet. Add a code in Proton Authenticator on \
                 another device first; this app does not upload yet.",
            ),
            SyncError::Failed(message) => message.clone(),
        }
    }
}

impl From<ApiError> for SyncError {
    fn from(error: ApiError) -> Self {
        match error {
            ApiError::Offline(detail) => SyncError::Offline(detail),
            ApiError::SignedOut => SyncError::SignedOut,
            other => SyncError::Failed(other.message()),
        }
    }
}

/// How a local entry is linked to its copy on Proton.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Link {
    pub remote_id: String,
    pub revision: u32,
    pub key_id: String,
    pub modify_time: i64,
}

/// Local entry id to its Proton link, for entries in sync.
pub type Links = HashMap<String, Link>;

#[derive(Clone, Debug)]
pub struct Remote {
    pub link: Link,
    pub entry: AuthenticatorEntry,
}

#[derive(Clone, Debug)]
pub struct Fetched {
    pub entries: Vec<Remote>,
    /// Entries Proton returned that could not be decrypted.
    pub unreadable: usize,
}

fn string(value: &Value, pointer: &str) -> Option<String> {
    value.pointer(pointer).and_then(Value::as_str).map(str::to_string)
}

/// Finishes a sign-in from the login window's callback fragment.
pub fn sign_in(fragment: &str, state: &str) -> Result<Session, SyncError> {
    let callback = fork::parse_callback(fragment, state).map_err(SyncError::Failed)?;
    let mut client = Client::new(None);
    let pulled = client.request_anonymous(Method::Get, &format!("auth/v4/sessions/forks/{}", callback.selector))?;

    let tokens = match (string(&pulled, "/UID"), string(&pulled, "/AccessToken"), string(&pulled, "/RefreshToken")) {
        (Some(uid), Some(access_token), Some(refresh_token)) => Tokens { uid, access_token, refresh_token },
        _ => return Err(SyncError::Failed(String::from("The sign-in reply has no session"))),
    };
    let payload = string(&pulled, "/Payload")
        .ok_or_else(|| SyncError::Failed(String::from("The sign-in reply has no key password")))?;
    let key_password =
        fork::decrypt_payload(&callback.key, &payload, callback.payload_version).map_err(SyncError::Failed)?.key_password;

    client.tokens = Some(tokens);
    let user = client.request(Method::Get, "core/v4/users", None)?;
    unlock_user_keys(&user, &key_password).map_err(SyncError::Failed)?;
    let email = string(&user, "/User/Email").or_else(|| string(&user, "/User/Name")).unwrap_or_default();

    Ok(Session { tokens: client.tokens.expect("set above"), key_password, email })
}

/// Downloads and decrypts every entry. Updates `session.tokens` if the
/// session was refreshed; the caller stores the session again then.
pub fn fetch(session: &mut Session) -> Result<Fetched, SyncError> {
    let mut client = Client::new(Some(session.tokens.clone()));
    let result = fetch_with(&mut client, session);
    if client.tokens_changed
        && let Some(tokens) = client.tokens
    {
        session.tokens = tokens;
    }
    result
}

fn fetch_with(client: &mut Client, session: &Session) -> Result<Fetched, SyncError> {
    let user = client.request(Method::Get, "core/v4/users", None)?;
    let user_keys = unlock_user_keys(&user, &session.key_password).map_err(SyncError::Failed)?;
    let keys = authenticator_keys(client, &user_keys, &session.key_password)?;

    let mut entries = Vec::new();
    let mut unreadable = 0;
    let mut since: Option<String> = None;
    loop {
        let path = match &since {
            Some(last) => format!("authenticator/v1/entry?Since={last}"),
            None => String::from("authenticator/v1/entry"),
        };
        let page = client.request(Method::Get, &path, None)?;
        let items = page.pointer("/Entries/Entries").and_then(Value::as_array).cloned().unwrap_or_default();
        for item in &items {
            match decrypt_remote(item, &keys) {
                Some(remote) => entries.push(remote),
                None => unreadable += 1,
            }
        }
        match string(&page, "/Entries/LastID") {
            Some(last) if !items.is_empty() && since.as_deref() != Some(last.as_str()) => since = Some(last),
            _ => break,
        }
    }
    Ok(Fetched { entries, unreadable })
}

/// Authenticator key id to key bytes, for keys protected by one of our keys.
fn authenticator_keys(client: &mut Client, user_keys: &[UserKey], password: &str) -> Result<HashMap<String, Vec<u8>>, SyncError> {
    let reply = client.request(Method::Get, "authenticator/v1/key", None)?;
    let listed = reply.pointer("/Keys/Keys").and_then(Value::as_array).cloned().unwrap_or_default();
    let mut keys = HashMap::new();
    let mut ours = 0;
    for item in &listed {
        let (Some(key_id), Some(user_key_id), Some(key)) =
            (string(item, "/KeyID"), string(item, "/UserKeyID"), string(item, "/Key"))
        else {
            continue;
        };
        let Some(user_key) = user_keys.iter().find(|k| k.id == user_key_id) else {
            continue;
        };
        ours += 1;
        if let Ok(bytes) = decrypt_authenticator_key(&key, user_key, password) {
            keys.insert(key_id, bytes);
        }
    }
    if keys.is_empty() {
        return Err(if ours == 0 {
            SyncError::NoKey
        } else {
            SyncError::Failed(String::from(
                "Proton has Authenticator keys for this account, but none of them decrypt. \
                 This can happen after an account password reset.",
            ))
        });
    }
    Ok(keys)
}

fn decrypt_remote(item: &Value, keys: &HashMap<String, Vec<u8>>) -> Option<Remote> {
    let key_id = string(item, "/AuthenticatorKeyID")?;
    let key = keys.get(&key_id)?;
    let content = STANDARD.decode(string(item, "/Content")?).ok()?;
    let entry = decrypt_entries(vec![content], key.clone()).ok()?.into_iter().next()?;
    Some(Remote {
        link: Link {
            remote_id: string(item, "/EntryID")?,
            revision: item.get("Revision").and_then(Value::as_u64)? as u32,
            key_id,
            modify_time: item.get("ModifyTime").and_then(Value::as_i64).unwrap_or(0),
        },
        entry,
    })
}

#[derive(Debug, Default, PartialEq)]
pub struct Merged {
    pub added: usize,
    pub updated: usize,
    pub removed: usize,
    /// Local changes that two-way sync would upload or delete on Proton.
    pub held_back: usize,
}

/// Applies the local side of Proton's merge rules to `entries` and `links`.
/// Local entries without a link count as not yet uploaded. When some remote
/// entries could not be read, nothing is removed locally, since a missing
/// entry might only be an unreadable one.
pub fn merge(entries: &mut Vec<AuthenticatorEntry>, links: &mut Links, fetched: Fetched) -> Merged {
    let local = entries
        .iter()
        .map(|entry| LocalEntry {
            entry: entry.clone(),
            state: if links.contains_key(&entry.id) {
                AuthenticatorEntryState::Synced
            } else {
                AuthenticatorEntryState::PendingSync
            },
            modify_time: links.get(&entry.id).map_or(0, |link| link.modify_time),
            local_modify_time: None,
        })
        .collect();
    let remote_links: HashMap<String, Link> =
        fetched.entries.iter().map(|remote| (remote.link.remote_id.clone(), remote.link.clone())).collect();
    let remote = fetched
        .entries
        .into_iter()
        .map(|remote| RemoteEntry {
            remote_id: remote.link.remote_id,
            revision: remote.link.revision,
            entry: remote.entry,
            modify_time: remote.link.modify_time,
        })
        .collect();

    let mut merged = Merged::default();
    let mut removed_ids = HashSet::new();
    for operation in calculate_operations_to_perform(remote, local) {
        match operation.operation {
            AuthenticatorOperation::Upsert => {
                let Some(link) = operation.remote_id.as_ref().and_then(|id| remote_links.get(id)) else {
                    continue;
                };
                let id = operation.entry.id.clone();
                match entries.iter().position(|entry| entry.id == id) {
                    Some(index) => {
                        if entries[index] != operation.entry {
                            merged.updated += 1;
                        }
                        entries[index] = operation.entry;
                    }
                    None => {
                        entries.push(operation.entry);
                        merged.added += 1;
                    }
                }
                links.insert(id, link.clone());
            }
            AuthenticatorOperation::DeleteLocal if fetched.unreadable == 0 => {
                removed_ids.insert(operation.entry.id.clone());
            }
            AuthenticatorOperation::DeleteLocal => {}
            AuthenticatorOperation::Push | AuthenticatorOperation::DeleteLocalAndRemote => merged.held_back += 1,
        }
    }
    if !removed_ids.is_empty() {
        entries.retain(|entry| !removed_ids.contains(&entry.id));
        links.retain(|id, _| !removed_ids.contains(id));
        merged.removed = removed_ids.len();
    }
    merged
}

/// Ends the session on Proton. Local codes stay; their links are dropped by the caller.
pub fn sign_out(session: &Session) -> Result<(), SyncError> {
    let mut client = Client::new(Some(session.tokens.clone()));
    client.request(Method::Delete, "core/v4/auth", None)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(issuer: &str) -> AuthenticatorEntry {
        AuthenticatorEntry::from_uri(&format!("otpauth://totp/{issuer}:me?secret=JBSWY3DPEHPK3PXP&issuer={issuer}"), None)
            .unwrap()
    }

    fn remote(entry: &AuthenticatorEntry, remote_id: &str, modify_time: i64) -> Remote {
        Remote {
            link: Link { remote_id: remote_id.into(), revision: 1, key_id: "k".into(), modify_time },
            entry: entry.clone(),
        }
    }

    #[test]
    fn adds_remote_codes_and_keeps_local_only_ones() {
        let local_only = entry("Local");
        let from_phone = entry("Phone");
        let mut entries = vec![local_only.clone()];
        let mut links = Links::new();
        let fetched = Fetched { entries: vec![remote(&from_phone, "r1", 10)], unreadable: 0 };

        let merged = merge(&mut entries, &mut links, fetched);
        assert_eq!(merged, Merged { added: 1, updated: 0, removed: 0, held_back: 1 });
        assert_eq!(entries, vec![local_only, from_phone.clone()]);
        assert_eq!(links[&from_phone.id].remote_id, "r1");
    }

    #[test]
    fn remote_edits_replace_synced_copies() {
        let original = entry("Old");
        let mut edited = entry("New");
        edited.id = original.id.clone();
        let mut entries = vec![original.clone()];
        let mut links = Links::from([(original.id.clone(), remote(&original, "r1", 10).link)]);

        let merged = merge(&mut entries, &mut links, Fetched { entries: vec![remote(&edited, "r1", 20)], unreadable: 0 });
        assert_eq!(merged.updated, 1);
        assert_eq!(entries[0].issuer(), "New");
        assert_eq!(links[&original.id].modify_time, 20);
    }

    #[test]
    fn removes_codes_deleted_elsewhere_unless_something_was_unreadable() {
        let synced = entry("Gone");
        let links = Links::from([(synced.id.clone(), remote(&synced, "r1", 10).link)]);

        let (mut entries, mut kept_links) = (vec![synced.clone()], links.clone());
        let merged = merge(&mut entries, &mut kept_links, Fetched { entries: vec![], unreadable: 1 });
        assert_eq!((merged.removed, entries.len()), (0, 1));

        let (mut entries, mut links) = (vec![synced], links);
        let merged = merge(&mut entries, &mut links, Fetched { entries: vec![], unreadable: 0 });
        assert_eq!((merged.removed, entries.len(), links.len()), (1, 0, 0));
    }
}
