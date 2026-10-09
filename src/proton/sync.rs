//! Sign-in and two-way sync (docs/proton-sync.md), ported from the official
//! app's `src/lib/entries/sync.ts` and `src/store/entries.ts`. Blocking: run
//! it off the UI thread.
//!
//! A sync takes a snapshot of the local codes, works out what to do with
//! Proton's own rules (`calculate_operations_to_perform`), makes the changes on
//! Proton, and returns an `Outcome`. The UI thread then applies the outcome
//! with `apply`, entry by entry, leaving alone any code changed meanwhile.
//!
//! Local state lives in `Links` (entry id to Proton entry), like the official
//! `syncMetadata`: an edited code is `PendingSync` until uploaded, and a deleted
//! one leaves a `PendingToDelete` link (a tombstone, without the secret) until
//! Proton has deleted it too.

use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use proton_authenticator::crypto::generate_encryption_key;
use proton_authenticator::operations::{
    AuthenticatorEntryState, AuthenticatorOperation, LocalEntry, RemoteEntry, calculate_operations_to_perform,
};
use proton_authenticator::{AuthenticatorEntry, decrypt_entries, encrypt_entries};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::api::{ApiError, Client, Method, Tokens};
use super::fork;
use super::keys::{UserKey, decrypt_authenticator_key, encrypt_authenticator_key, unlock_user_keys};
use super::session::Session;

/// Entries per request, as the official app sends them.
const BATCH_SIZE: usize = 100;

#[derive(Debug, Clone, PartialEq)]
pub enum SyncError {
    Offline(String),
    SignedOut,
    Failed(String),
}

impl SyncError {
    pub fn message(&self) -> String {
        match self {
            SyncError::Offline(detail) => ApiError::Offline(detail.clone()).message(),
            SyncError::SignedOut => ApiError::SignedOut.message(),
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

/// The official `WasmLocalEntryState`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum State {
    /// Same as on Proton. Links saved by read-only sync had no state and were all this.
    #[default]
    Synced,
    /// Changed here and not yet uploaded.
    PendingSync,
    /// Deleted here and not yet on Proton. The code itself is gone from the vault.
    PendingToDelete,
}

/// How a local entry is linked to its copy on Proton.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Link {
    pub remote_id: String,
    pub revision: u32,
    pub key_id: String,
    /// Proton's modify time, or the time of the local change while pending.
    pub modify_time: i64,
    #[serde(default)]
    pub state: State,
}

/// Local entry id to its Proton link.
pub type Links = HashMap<String, Link>;

/// Seconds since 1970, as the official `getNowRustTimestamp`.
pub fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |time| time.as_secs() as i64)
}

/// Marks a code as changed here, as the official `editEntry` does. Codes that
/// were never on Proton have no link and are uploaded as new.
pub fn mark_edited(links: &mut Links, id: &str) {
    if let Some(link) = links.get_mut(id) {
        link.modify_time = now();
        link.state = State::PendingSync;
    }
}

/// Leaves a tombstone for a code deleted here, as the official `removeEntry`
/// does, so the next sync deletes it on Proton.
pub fn mark_deleted(links: &mut Links, id: &str) {
    if let Some(link) = links.get_mut(id) {
        link.modify_time = now();
        link.state = State::PendingToDelete;
    }
}

#[derive(Clone, Debug)]
pub struct Remote {
    pub link: Link,
    pub entry: AuthenticatorEntry,
}

/// The local codes and links when a sync starts.
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub entries: Vec<AuthenticatorEntry>,
    pub links: Links,
}

/// What a sync found and did on Proton, for `apply`.
#[derive(Clone, Debug, Default)]
pub struct Outcome {
    /// Entry ids in Proton's order.
    pub remote_order: Vec<String>,
    /// Codes from Proton to add or replace here.
    pub upserts: Vec<(AuthenticatorEntry, Link)>,
    /// Codes deleted on another device.
    pub local_deletes: Vec<String>,
    /// Codes uploaded, created or updated, with their new links.
    pub written: Vec<(String, Link)>,
    pub created: usize,
    pub updated: usize,
    /// Tombstones whose code is gone from Proton.
    pub cleared: Vec<String>,
    /// Entries Proton returned that could not be decrypted.
    pub unreadable: usize,
    /// Uploads or deletions that failed; they are tried again next time.
    pub errors: Vec<String>,
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

/// Runs `work` with a client for `session`, and keeps tokens a refresh
/// replaced; the caller stores the session again then.
fn with_client<T>(session: &mut Session, work: impl FnOnce(&mut Client, &Session) -> T) -> T {
    let mut client = Client::new(Some(session.tokens.clone()));
    let result = work(&mut client, session);
    if client.tokens_changed
        && let Some(tokens) = client.tokens
    {
        session.tokens = tokens;
    }
    result
}

/// Syncs `snapshot` with Proton both ways and returns what to apply here.
pub fn run(session: &mut Session, snapshot: Snapshot) -> Result<Outcome, SyncError> {
    with_client(session, |client, session| {
        let user = client.request(Method::Get, "core/v4/users", None)?;
        let user_keys = unlock_user_keys(&user, &session.key_password).map_err(SyncError::Failed)?;
        let keys = authenticator_keys(client, &user_keys, &session.key_password)?;
        let (remote, unreadable) = fetch_entries(client, &keys)?;
        let plan = plan(&snapshot, remote, unreadable, now());
        Ok(execute(client, &keys, plan))
    })
}

/// Moves a code on Proton to just after `after` (a Proton entry id), or to
/// the top, as the official `reorderRemoteEntry`.
pub fn reorder(session: &mut Session, remote_id: &str, after: Option<&str>) -> Result<(), SyncError> {
    with_client(session, |client, _| {
        client.request(Method::Put, &format!("authenticator/v1/entry/{remote_id}/order"), Some(&json!({ "AfterID": after })))?;
        Ok(())
    })
}

/// The Authenticator keys this account can read.
struct Keys {
    by_id: HashMap<String, Zeroizing<Vec<u8>>>,
    /// The key new codes are encrypted with: the first user key's, primary first.
    for_new: String,
}

/// Reads the account's Authenticator keys, as the official `fetchRemoteKeys`:
/// when the primary account key has none, a new key is made and uploaded.
fn authenticator_keys(client: &mut Client, user_keys: &[UserKey], password: &str) -> Result<Keys, SyncError> {
    let reply = client.request(Method::Get, "authenticator/v1/key", None)?;
    let listed = reply.pointer("/Keys/Keys").and_then(Value::as_array).cloned().unwrap_or_default();
    // (key id, user key id, key), in the server's order.
    let mut readable: Vec<(String, String, Zeroizing<Vec<u8>>)> = Vec::new();
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
            readable.push((key_id, user_key_id, Zeroizing::new(bytes)));
        }
    }

    // Keys exist for every account key but none decrypt: making a new one would
    // hide the codes behind the old ones, so stop, as the official app does.
    if user_keys.len() <= ours && readable.is_empty() {
        return Err(SyncError::Failed(String::from(
            "Proton has Authenticator keys for this account, but none of them decrypt. \
             This can happen after an account password reset.",
        )));
    }

    let primary = &user_keys[0];
    if !readable.iter().any(|(_, user_key_id, _)| *user_key_id == primary.id) {
        let key = Zeroizing::new(generate_encryption_key());
        let encrypted = encrypt_authenticator_key(&key, primary, password).map_err(SyncError::Failed)?;
        let reply = client.request(Method::Post, "authenticator/v1/key", Some(&json!({ "Key": encrypted })))?;
        let key_id = string(&reply, "/Key/KeyID")
            .ok_or_else(|| SyncError::Failed(String::from("Proton did not return the new Authenticator key")))?;
        readable.insert(0, (key_id, primary.id.clone(), key));
    }

    let for_new = user_keys
        .iter()
        .find_map(|user_key| readable.iter().find(|(_, owner, _)| *owner == user_key.id))
        .map(|(key_id, _, _)| key_id.clone())
        .expect("the primary key has an Authenticator key by now");
    let by_id = readable.into_iter().map(|(key_id, _, key)| (key_id, key)).collect();
    Ok(Keys { by_id, for_new })
}

/// Downloads and decrypts every entry, in Proton's order.
fn fetch_entries(client: &mut Client, keys: &Keys) -> Result<(Vec<Remote>, usize), SyncError> {
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
            match decrypt_remote(item, keys) {
                Some(remote) => entries.push(remote),
                None => unreadable += 1,
            }
        }
        match string(&page, "/Entries/LastID") {
            Some(last) if !items.is_empty() && since.as_deref() != Some(last.as_str()) => since = Some(last),
            _ => break,
        }
    }
    Ok((entries, unreadable))
}

fn decrypt_remote(item: &Value, keys: &Keys) -> Option<Remote> {
    let key_id = string(item, "/AuthenticatorKeyID")?;
    let key = keys.by_id.get(&key_id)?;
    let content = STANDARD.decode(string(item, "/Content")?).ok()?;
    let entry = decrypt_entries(vec![content], key.to_vec()).ok()?.into_iter().next()?;
    Some(Remote {
        link: Link {
            remote_id: string(item, "/EntryID")?,
            revision: item.get("Revision").and_then(Value::as_u64)? as u32,
            key_id,
            modify_time: item.get("ModifyTime").and_then(Value::as_i64).unwrap_or(0),
            state: State::Synced,
        },
        entry,
    })
}

/// What a sync will do, worked out before anything is sent.
#[derive(Debug, Default)]
struct Plan {
    remote_order: Vec<String>,
    upserts: Vec<(AuthenticatorEntry, Link)>,
    local_deletes: Vec<String>,
    creates: Vec<AuthenticatorEntry>,
    /// Local codes to upload over their Proton copy, with that copy's link.
    updates: Vec<(AuthenticatorEntry, Link)>,
    /// (entry id, Proton entry id) of tombstones still on Proton.
    remote_deletes: Vec<(String, String)>,
    cleared: Vec<String>,
    unreadable: usize,
}

/// Proton's merge rules applied to a snapshot, as the official
/// `syncRemoteEntries` does. When some remote entries could not be read,
/// nothing is removed here, since a missing entry might only be an unreadable one.
fn plan(snapshot: &Snapshot, remote: Vec<Remote>, unreadable: usize, now: i64) -> Plan {
    let tombstones: HashSet<&str> = snapshot
        .links
        .iter()
        .filter(|(_, link)| link.state == State::PendingToDelete)
        .map(|(id, _)| id.as_str())
        .collect();
    let mut plan = Plan { unreadable, ..Plan::default() };

    let mut still_remote = HashSet::new();
    let mut remote_links = HashMap::new();
    let mut remote_entries = Vec::new();
    for remote in remote {
        if tombstones.contains(remote.entry.id.as_str()) {
            still_remote.insert(remote.entry.id.clone());
            plan.remote_deletes.push((remote.entry.id.clone(), remote.link.remote_id.clone()));
            continue;
        }
        plan.remote_order.push(remote.entry.id.clone());
        remote_links.insert(remote.link.remote_id.clone(), remote.link.clone());
        remote_entries.push(RemoteEntry {
            remote_id: remote.link.remote_id,
            revision: remote.link.revision,
            entry: remote.entry,
            modify_time: remote.link.modify_time,
        });
    }
    if unreadable == 0 {
        plan.cleared = tombstones.iter().filter(|id| !still_remote.contains(**id)).map(|id| id.to_string()).collect();
    }

    let local = snapshot
        .entries
        .iter()
        .filter(|entry| !tombstones.contains(entry.id.as_str()))
        .map(|entry| {
            let link = snapshot.links.get(&entry.id);
            // As `toLocalWasmEntry`: codes never synced are pending, timed now.
            let modify_time = link.map_or(now, |link| link.modify_time);
            LocalEntry {
                entry: entry.clone(),
                state: match link.map(|link| link.state) {
                    Some(State::Synced) => AuthenticatorEntryState::Synced,
                    Some(State::PendingToDelete) => AuthenticatorEntryState::PendingToDelete,
                    Some(State::PendingSync) | None => AuthenticatorEntryState::PendingSync,
                },
                modify_time,
                local_modify_time: Some(modify_time),
            }
        })
        .collect();

    for operation in calculate_operations_to_perform(remote_entries, local) {
        let link = operation.remote_id.as_ref().and_then(|id| remote_links.get(id)).cloned();
        match (operation.operation, link) {
            (AuthenticatorOperation::Upsert, Some(link)) => plan.upserts.push((operation.entry, link)),
            (AuthenticatorOperation::Upsert, None) => {}
            (AuthenticatorOperation::DeleteLocal, _) if unreadable == 0 => plan.local_deletes.push(operation.entry.id),
            (AuthenticatorOperation::DeleteLocal, _) => {}
            // A Push of a code Proton already has is the official "Update".
            (AuthenticatorOperation::Push, Some(link)) => plan.updates.push((operation.entry, link)),
            (AuthenticatorOperation::Push, None) => plan.creates.push(operation.entry),
            (AuthenticatorOperation::DeleteLocalAndRemote, Some(link)) => {
                plan.remote_deletes.push((operation.entry.id, link.remote_id))
            }
            (AuthenticatorOperation::DeleteLocalAndRemote, None) => {}
        }
    }
    plan
}

/// Makes the planned changes on Proton. Failures are collected rather than
/// returned, as the official app carries on with the rest; what failed stays
/// pending and is tried again on the next sync.
fn execute(client: &mut Client, keys: &Keys, plan: Plan) -> Outcome {
    let mut outcome = Outcome {
        remote_order: plan.remote_order,
        upserts: plan.upserts,
        local_deletes: plan.local_deletes,
        cleared: plan.cleared,
        unreadable: plan.unreadable,
        ..Outcome::default()
    };

    // Deletions first, so a code is only dropped here once Proton has dropped it.
    for batch in plan.remote_deletes.chunks(BATCH_SIZE) {
        let ids: Vec<&str> = batch.iter().map(|(_, remote_id)| remote_id.as_str()).collect();
        match client.request(Method::Delete, "authenticator/v1/entry/bulk", Some(&json!({ "EntryIDs": ids }))) {
            Ok(_) => outcome.cleared.extend(batch.iter().map(|(id, _)| id.clone())),
            Err(error) => outcome.errors.push(format!("Could not delete codes on Proton: {}", error.message())),
        }
    }

    for batch in plan.creates.chunks(BATCH_SIZE) {
        let key = &keys.by_id[&keys.for_new];
        let encrypted = match encrypt_entries(batch.to_vec(), key.to_vec()) {
            Ok(encrypted) => encrypted,
            Err(error) => {
                outcome.errors.push(format!("Could not encrypt codes for Proton: {error:?}"));
                continue;
            }
        };
        let entries: Vec<Value> = encrypted
            .iter()
            .map(|content| {
                json!({
                    "AuthenticatorKeyID": keys.for_new,
                    "Content": STANDARD.encode(content),
                    "ContentFormatVersion": 1,
                })
            })
            .collect();
        match client.request(Method::Post, "authenticator/v1/entry/bulk", Some(&json!({ "Entries": entries }))) {
            Ok(reply) => outcome.created += read_written(&reply, keys, &mut outcome.written),
            Err(error) => outcome.errors.push(format!("Could not upload codes to Proton: {}", error.message())),
        }
    }

    for batch in plan.updates.chunks(BATCH_SIZE) {
        let mut entries = Vec::new();
        for (entry, link) in batch {
            let Some(key) = keys.by_id.get(&link.key_id) else {
                outcome.errors.push(format!("Could not update {} on Proton: its key is missing", entry.issuer()));
                continue;
            };
            match encrypt_entries(vec![entry.clone()], key.to_vec()) {
                Ok(encrypted) => entries.push(json!({
                    "EntryID": link.remote_id,
                    "AuthenticatorKeyID": link.key_id,
                    "Content": STANDARD.encode(&encrypted[0]),
                    "ContentFormatVersion": 1,
                    "LastRevision": link.revision,
                })),
                Err(error) => outcome.errors.push(format!("Could not encrypt {} for Proton: {error:?}", entry.issuer())),
            }
        }
        if entries.is_empty() {
            continue;
        }
        match client.request(Method::Put, "authenticator/v1/entry/bulk", Some(&json!({ "Entries": entries }))) {
            Ok(reply) => outcome.updated += read_written(&reply, keys, &mut outcome.written),
            Err(error) => outcome.errors.push(format!("Could not update codes on Proton: {}", error.message())),
        }
    }
    outcome
}

/// Reads the entries Proton returns after an upload, as `mergeRemoteEntries`.
fn read_written(reply: &Value, keys: &Keys, written: &mut Vec<(String, Link)>) -> usize {
    let items = reply.get("Entries").and_then(Value::as_array).cloned().unwrap_or_default();
    let before = written.len();
    written.extend(items.iter().filter_map(|item| decrypt_remote(item, keys)).map(|remote| (remote.entry.id, remote.link)));
    written.len() - before
}

#[derive(Debug, Default, PartialEq)]
pub struct Merged {
    pub added: usize,
    pub updated: usize,
    pub removed: usize,
    pub uploaded: usize,
    pub deleted_remote: usize,
}

/// Applies a sync's outcome to the current codes and links. A code changed
/// since `snapshot` keeps its change, which the next sync uploads; what Proton
/// returned for it is still recorded, so nothing is uploaded twice.
pub fn apply(entries: &mut Vec<AuthenticatorEntry>, links: &mut Links, snapshot: &Snapshot, outcome: Outcome) -> Merged {
    let before: HashMap<&str, &AuthenticatorEntry> = snapshot.entries.iter().map(|entry| (entry.id.as_str(), entry)).collect();
    let unchanged = |entries: &[AuthenticatorEntry], links: &Links, id: &str| {
        entries.iter().find(|entry| entry.id == id) == before.get(id).copied() && links.get(id) == snapshot.links.get(id)
    };
    let mut merged = Merged::default();

    for (entry, link) in outcome.upserts {
        let id = entry.id.clone();
        if !unchanged(entries, links, &id) {
            continue;
        }
        match entries.iter().position(|existing| existing.id == id) {
            Some(index) => {
                if entries[index] != entry {
                    merged.updated += 1;
                }
                entries[index] = entry;
            }
            None => {
                entries.push(entry);
                merged.added += 1;
            }
        }
        links.insert(id, Link { state: State::Synced, ..link });
    }

    let mut removed = HashSet::new();
    for id in outcome.local_deletes {
        if unchanged(entries, links, &id) {
            links.remove(&id);
            removed.insert(id);
        }
    }
    if !removed.is_empty() {
        let count = entries.len();
        entries.retain(|entry| !removed.contains(&entry.id));
        merged.removed = count - entries.len();
    }

    merged.uploaded = outcome.written.len();
    for (id, link) in outcome.written {
        let changed = !unchanged(entries, links, &id);
        let present = entries.iter().any(|entry| entry.id == id);
        let current = links.get(&id).cloned();
        let link = match (present, changed, current) {
            (true, false, _) => Link { state: State::Synced, ..link },
            // Edited again meanwhile: keep the edit pending, on the new revision.
            (true, true, current) => Link {
                state: State::PendingSync,
                modify_time: current.map_or_else(now, |current| current.modify_time),
                ..link
            },
            // Deleted meanwhile: leave a tombstone, so Proton's copy goes too.
            (false, _, _) => Link { state: State::PendingToDelete, modify_time: now(), ..link },
        };
        links.insert(id, link);
    }

    for id in outcome.cleared {
        if links.get(&id).is_some_and(|link| link.state == State::PendingToDelete) {
            links.remove(&id);
            merged.deleted_remote += 1;
        }
    }

    // Two tiers, as `itemSyncSortWithOrdering`: synced codes first in Proton's
    // order, then the rest in their local order.
    let position: HashMap<&str, usize> =
        outcome.remote_order.iter().enumerate().map(|(index, id)| (id.as_str(), index)).collect();
    let mut keyed: Vec<_> = std::mem::take(entries)
        .into_iter()
        .enumerate()
        .map(|(local, entry)| {
            let synced = links.get(&entry.id).is_some_and(|link| link.state == State::Synced);
            let remote = if synced { position.get(entry.id.as_str()).copied().unwrap_or(usize::MAX) } else { usize::MAX };
            ((!synced, remote, local), entry)
        })
        .collect();
    keyed.sort_by_key(|(key, _)| *key);
    *entries = keyed.into_iter().map(|(_, entry)| entry).collect();
    merged
}

/// After a drag, the code that moved and the Proton entry it now follows, for
/// `reorder`. `None` when it moved more than one code or a code not on Proton.
pub fn moved(previous: &[AuthenticatorEntry], order: &[usize], links: &Links) -> Option<(String, Option<String>)> {
    let first = (0..order.len()).find(|&i| order[i] != i)?;
    let last = (0..order.len()).rfind(|&i| order[i] != i)?;
    // Moved up: it now sits at `first`. Moved down: it now sits at `last`.
    let position = [first, last].into_iter().find(|&at| {
        let rest: Vec<usize> = order.iter().copied().filter(|&index| index != order[at]).collect();
        rest.iter().enumerate().all(|(i, &index)| index == i + usize::from(i >= order[at]))
    })?;
    let link = links.get(&previous[order[position]].id).filter(|link| link.state != State::PendingToDelete)?;
    // The nearest code above it that is on Proton; the official app takes the
    // one right above, which is the same while synced codes come first.
    let after = order[..position]
        .iter()
        .rev()
        .find_map(|&index| links.get(&previous[index].id).filter(|link| link.state != State::PendingToDelete))
        .map(|link| link.remote_id.clone());
    Some((link.remote_id.clone(), after))
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

    fn link(remote_id: &str, modify_time: i64) -> Link {
        Link { remote_id: remote_id.into(), revision: 1, key_id: "k".into(), modify_time, state: State::Synced }
    }

    fn remote(entry: &AuthenticatorEntry, remote_id: &str, modify_time: i64) -> Remote {
        Remote { link: link(remote_id, modify_time), entry: entry.clone() }
    }

    /// A sync whose uploads all succeed, as Proton would answer them.
    fn sync(entries: &mut Vec<AuthenticatorEntry>, links: &mut Links, remote: Vec<Remote>) -> (Merged, Plan) {
        let snapshot = Snapshot { entries: entries.clone(), links: links.clone() };
        let plan = plan(&snapshot, remote, 0, 1000);
        let mut written = Vec::new();
        for (i, created) in plan.creates.iter().enumerate() {
            written.push((created.id.clone(), link(&format!("new{i}"), 1000)));
        }
        for (updated, old) in &plan.updates {
            written.push((updated.id.clone(), Link { revision: old.revision + 1, modify_time: 1000, ..old.clone() }));
        }
        let outcome = Outcome {
            remote_order: plan.remote_order.clone(),
            upserts: plan.upserts.clone(),
            local_deletes: plan.local_deletes.clone(),
            cleared: plan.cleared.iter().cloned().chain(plan.remote_deletes.iter().map(|(id, _)| id.clone())).collect(),
            written,
            ..Outcome::default()
        };
        (apply(entries, links, &snapshot, outcome), plan)
    }

    #[test]
    fn uploads_local_codes_and_adds_remote_ones() {
        let local_only = entry("Local");
        let from_phone = entry("Phone");
        let mut entries = vec![local_only.clone()];
        let mut links = Links::new();

        let (merged, plan) = sync(&mut entries, &mut links, vec![remote(&from_phone, "r1", 10)]);
        assert_eq!(plan.creates.len(), 1);
        assert_eq!((merged.added, merged.uploaded), (1, 1));
        // Synced codes come first in Proton's order; the new upload is synced too.
        assert_eq!(entries, vec![from_phone.clone(), local_only.clone()]);
        assert_eq!(links[&from_phone.id].remote_id, "r1");
        assert_eq!(links[&local_only.id].state, State::Synced);
    }

    #[test]
    fn remote_edits_replace_synced_copies() {
        let original = entry("Old");
        let mut edited = entry("New");
        edited.id = original.id.clone();
        let mut entries = vec![original.clone()];
        let mut links = Links::from([(original.id.clone(), link("r1", 10))]);

        let (merged, _) = sync(&mut entries, &mut links, vec![remote(&edited, "r1", 20)]);
        assert_eq!(merged.updated, 1);
        assert_eq!(entries[0].issuer(), "New");
        assert_eq!(links[&original.id].modify_time, 20);
    }

    #[test]
    fn local_edits_are_uploaded_over_the_remote_copy() {
        let original = entry("Old");
        let mut edited = entry("New");
        edited.id = original.id.clone();
        let mut entries = vec![edited.clone()];
        let mut links = Links::from([(original.id.clone(), link("r1", 10))]);
        mark_edited(&mut links, &original.id);

        let (_, plan) = sync(&mut entries, &mut links, vec![remote(&original, "r1", 10)]);
        assert_eq!(plan.updates.len(), 1);
        assert_eq!(plan.updates[0].1.revision, 1, "LastRevision is the one Proton has");
        assert_eq!(entries[0].issuer(), "New");
        assert_eq!((links[&original.id].state, links[&original.id].revision), (State::Synced, 2));
    }

    #[test]
    fn local_deletions_reach_proton_and_then_leave_no_trace() {
        let code = entry("Gone");
        let mut entries = vec![];
        let mut links = Links::from([(code.id.clone(), link("r1", 10))]);
        mark_deleted(&mut links, &code.id);

        let (merged, plan) = sync(&mut entries, &mut links, vec![remote(&code, "r1", 10)]);
        assert_eq!(plan.remote_deletes, vec![(code.id.clone(), String::from("r1"))]);
        assert!(plan.upserts.is_empty(), "a deleted code must not come back");
        assert_eq!(merged.deleted_remote, 1);
        assert!(entries.is_empty() && links.is_empty());
    }

    #[test]
    fn a_failed_remote_deletion_keeps_the_tombstone() {
        let code = entry("Gone");
        let mut links = Links::from([(code.id.clone(), link("r1", 10))]);
        mark_deleted(&mut links, &code.id);
        let snapshot = Snapshot { entries: vec![], links: links.clone() };
        let outcome = Outcome { errors: vec![String::from("offline")], ..Outcome::default() };
        apply(&mut vec![], &mut links, &snapshot, outcome);
        assert_eq!(links[&code.id].state, State::PendingToDelete);
    }

    #[test]
    fn removes_codes_deleted_elsewhere_unless_something_was_unreadable() {
        let synced = entry("Gone");
        let links = Links::from([(synced.id.clone(), link("r1", 10))]);
        let snapshot = Snapshot { entries: vec![synced.clone()], links: links.clone() };

        assert!(plan(&snapshot, vec![], 1, 1000).local_deletes.is_empty());

        let (mut entries, mut links) = (vec![synced], links);
        let (merged, _) = sync(&mut entries, &mut links, vec![]);
        assert_eq!((merged.removed, entries.len(), links.len()), (1, 0, 0));
    }

    #[test]
    fn changes_made_during_a_sync_are_kept_and_uploaded_next_time() {
        let original = entry("Old");
        let snapshot = Snapshot { entries: vec![original.clone()], links: Links::new() };
        // The sync uploads the code; meanwhile it is edited here.
        let mut edited = entry("New");
        edited.id = original.id.clone();
        let mut entries = vec![edited.clone()];
        let mut links = Links::new();
        let outcome = Outcome { written: vec![(original.id.clone(), link("r1", 10))], ..Outcome::default() };
        apply(&mut entries, &mut links, &snapshot, outcome);
        assert_eq!(entries, vec![edited]);
        assert_eq!((links[&original.id].remote_id.as_str(), links[&original.id].state), ("r1", State::PendingSync));

        // Deleted meanwhile instead: Proton's new copy gets a tombstone.
        let outcome = Outcome { written: vec![(original.id.clone(), link("r1", 10))], ..Outcome::default() };
        let mut links = Links::new();
        apply(&mut vec![], &mut links, &snapshot, outcome);
        assert_eq!(links[&original.id].state, State::PendingToDelete);
    }

    #[test]
    fn links_from_read_only_sync_read_as_synced() {
        let old: Link = serde_json::from_str(r#"{"remote_id":"r","revision":3,"key_id":"k","modify_time":5}"#).unwrap();
        assert_eq!(old.state, State::Synced);
    }

    #[test]
    fn finds_the_moved_code_and_what_it_follows() {
        let codes: Vec<_> = ["A", "B", "C", "D"].into_iter().map(entry).collect();
        let links: Links = codes.iter().enumerate().map(|(i, code)| (code.id.clone(), link(&format!("r{i}"), 1))).collect();
        // D to the top.
        assert_eq!(moved(&codes, &[3, 0, 1, 2], &links), Some((String::from("r3"), None)));
        // A below C.
        assert_eq!(moved(&codes, &[1, 2, 0, 3], &links), Some((String::from("r0"), Some(String::from("r2")))));
        // B and C swapped: either reading is one move.
        assert!(moved(&codes, &[0, 2, 1, 3], &links).is_some());
        assert_eq!(moved(&codes, &[0, 1, 2, 3], &links), None);
    }
}
