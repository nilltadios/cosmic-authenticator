# How the official app signs in and syncs

Worked out on 2026-09-25 from Proton's WebClients source
(`Proton-WebClients/applications/authenticator` and `packages/shared`) and
from the official app 1.1.6's WebKit cache. Paths below are in that repository
unless they say otherwise. Recheck them when Proton releases a new version.

## Identity

| What | Value | Source |
|---|---|---|
| API | `https://authenticator.proton.me/api` | `applications/authenticator/webpack.options.ts` (`api: https://authenticator.${API_ENV}/api`, `API_ENV=proton.me`) |
| Sign-in site | `https://account.proton.me` | same file (`sso`); the cache shows `account.proton.me/authorize` |
| App name (fork `app`) | `proton-authenticator` | `packages/shared/lib/constants.ts` (`APPS.PROTONAUTHENTICATOR`) |
| Client ID | `linux-authenticator` | same file (`linuxClientID`) |
| Version header | `x-pm-appversion: linux-authenticator@1.1.6` | `packages/shared/lib/fetch/headers.ts` (`clientID@version`); the version is in `src-tauri/Cargo.toml` |
| Sign-in window user agent | `Mozilla/5.0 (X11; Linux x86_64) ProtonAuthenticator/1.1.6 Electron/1.0.0` | `src-tauri/src/auth.rs` (`get_user_agent`) |
| Client type | 10 | `applications/authenticator/appConfig.ts` |

The owner decided on 2026-09-25 that this app presents itself with these values.

## Sign-in (session fork)

1. **Request.** `packages/pass/lib/auth/fork.ts` (`requestFork`) builds
   `https://account.proton.me/authorize?` with, in order: `app=proton-authenticator`,
   `state=<32 random bytes, base64url, no padding>`, `independent=0`, `prompt=login`,
   `promptBypass=sso`, `promptType=offline`, `pt=offline`, `t=3` (log in) or `t=2`
   (sign up, plus `plan=free`). The fork type values come from
   `packages/shared/lib/authentication/fork/constants.ts`.
2. **Window.** `src-tauri/src/auth.rs` opens a 400x600 web view at that address.
   On every navigation, if the path contains `/login`, it blocks the navigation
   and sends the URL fragment to the app. Proton's page handles the password,
   2FA and CAPTCHA, so the app never sees the password.
3. **Callback fragment** (`packages/shared/lib/authentication/fork/getConsumeForkParameters.ts`):
   `selector`, `state` (check that it matches the request), `sk` (32-byte key,
   base64url), `pv` (payload version 1 to 3; missing or invalid means 1),
   `pt`, `p` (persistent), `tr` (trusted), `t`.
4. **Pull.** `GET auth/v4/sessions/forks/{selector}`, with no session headers,
   returns `UID`, `AccessToken`, `RefreshToken`, `LocalID`, `Payload` and more.
5. **Payload** (`fork/blob.ts`, `authentication/sessionBlobCryptoHelper.ts`,
   `node_modules/@protontech/crypto/src/subtle/aesGcm.ts`): base64 (standard
   alphabet) of IV || ciphertext || tag, AES-256-GCM with the `sk` key.
   - v1: 16-byte IV, no associated data, plaintext as a binary string
   - v2: 16-byte IV, associated data `fork`
   - v3: 12-byte IV, associated data `fork`, UTF-8
   The plaintext is JSON: `{type: "default" | "offline", keyPassword,
   offlineKeyPassword?, offlineKeySalt?}`.
6. **User and keys.** `GET core/v4/users` with session headers. `User.Keys[]`
   holds armored OpenPGP private keys (`ID`, `PrivateKey`, `Primary`, `Active`),
   unlocked with `keyPassword`. The official code expects the primary key first.

Session headers: `x-pm-uid: UID` and `Authorization: Bearer AccessToken`, plus
`x-pm-appversion` on every request.

The official app then moves the session into browser cookies (`setCookies`,
`core/v4/auth/cookies`). A native app has no cookie jar, so it keeps the tokens
itself and refreshes with `POST auth/v4/refresh`
`{UID, RefreshToken, ResponseType: "token", GrantType: "refresh_token", RedirectURI: "https://protonmail.com"}`.
Sign-out is `DELETE core/v4/auth` (`packages/shared/lib/api/auth.ts`, `revoke`).

## Sync

Code: `src/lib/entries/sync.ts`, `src/lib/api/requests.ts`, `src/lib/api/types.ts`,
`src/store/auth.ts` (`setupSession`, `logout`).

- **Keys.** `GET authenticator/v1/key` returns `Keys[]` of `{KeyID, UserKeyID, Key}`.
  `Key` is base64 of a binary OpenPGP message: the 32-byte Authenticator key,
  encrypted to the user key and signed by it (`expectSigned: true`). Keys whose
  `UserKeyID` is not one of the user's keys are skipped.
  If no key exists for the primary user key, the official app generates one
  (core `generate_key`), encrypts and signs it to the primary user key, and
  uploads it with `POST authenticator/v1/key {Key}`. **That is a write.**
- **Entries.** `GET authenticator/v1/entry?Since=<LastID>` pages through
  `Entries: {Entries[], Total, LastID}`. Each entry has `EntryID`,
  `AuthenticatorKeyID`, `Revision`, `ContentFormatVersion` (1), `Content`
  (base64), `Flags`, `CreateTime` and `ModifyTime`. Decrypt `Content` with the
  core's `decrypt_entries([content], keyBytes)`. The entry `id` inside the
  content is the same on every device.
- **Merge.** The core's `operations.rs` (`calculate_operations_to_perform`)
  compares remote entries with local ones by entry `id`, using each local
  entry's state (`Synced`, `PendingSync`, `PendingToDelete`), the server
  `modify_time` last seen, and any offline edit time. It returns `Upsert`,
  `DeleteLocal`, `DeleteLocalAndRemote` or `Push` per entry.
- **Writes** (two-way sync): `POST authenticator/v1/entry/bulk` (create, batches
  of 100), `PUT authenticator/v1/entry/bulk` (update, needs `LastRevision`),
  `DELETE authenticator/v1/entry/bulk {EntryIDs}`, and
  `PUT authenticator/v1/entry/{id}/order {AfterID}`.
- **When.** On session resume, after sign-in, and before sign-out. No timer
  was found (`grep setInterval` in `src` finds nothing).

## How this app syncs

`src/proton/sync.rs` follows the official code; differences are listed below.

- **State.** `sync.json` maps each local entry id to its Proton entry
  (`remote_id`, `revision`, `key_id`, `modify_time`, `state`), like the
  official `syncMetadata`. Links saved by read-only sync had no `state` and
  read as `Synced`.
- **Local changes** (`src/store/entries.ts`). Edit: `PendingSync` with
  `modify_time` now. Delete: the code leaves the vault, and its link stays as a
  `PendingToDelete` tombstone. The official app keeps the whole item hidden in
  its database; this app keeps only the ids, so a deleted secret is not left on
  disk. Codes never synced have no link and count as `PendingSync`, timed now.
- **A sync** (`run`): account keys, Authenticator keys (making and uploading
  one when the primary account key has none, and stopping if keys exist but
  none decrypt), every entry, then `calculate_operations_to_perform` on the
  snapshot. Tombstones still on Proton are deleted there (`DELETE entry/bulk`)
  and then dropped; their remote copies are left out of the merge so they do not
  come back. `Push` without a remote id is a create (`POST entry/bulk`, with the
  first account key's Authenticator key); with one it is an update (`PUT
  entry/bulk`, `LastRevision` = Proton's revision). A failed request is
  reported and the change stays pending for the next sync.
- **Applying** (`apply`) runs on the UI thread, by entry id. A code changed
  since the snapshot keeps its change; what Proton returned for it is still
  recorded, so a create is never sent twice. Then the two-tier order: synced
  codes first in Proton's order, the rest in local order.
- **When.** At startup and after sign-in, as the official app; also after every
  add, edit, delete and import (the official app sends each change on its own
  request and imports at the next start). One sync runs at a time; changes made
  meanwhile start another. Sign-out syncs once more, then ends the session.
- **Reorder.** As the official app, only the moved code's place goes to Proton
  (`PUT entry/{id}/order {AfterID}`). `AfterID` is the nearest synced code above
  it; the official app takes the code right above, which is the same while
  synced codes come first.
- **Unreadable entries.** When some entries do not decrypt, no local code is
  removed and no tombstone is dropped, since a missing entry might only be an
  unreadable one. The official app has no such guard.
