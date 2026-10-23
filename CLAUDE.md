# cosmic-authenticator: notes for Claude

## Goal (from the user, 2026-09-25)

The user wants **the official Proton Authenticator desktop app with a lighter UI**,
and nothing else changed: **every official feature stays the same**, including
sign-in and sync with their Proton account and phone. This app is meant to
replace the official one day to day. It is not a separate local-only authenticator.

Why: on 2026-09-24 the official app (1.1.6, Flatpak) idled at about 25% CPU and
1.3 GB of memory. Almost all of that was its WebKit front end redrawing the
countdown rings; its Rust side was idle. So the plan was a native libcosmic UI on
Proton's own Rust core.

When choosing what to work on, feature parity with the official app comes first.
Extras (QR images, pasted links, Base32 checks) are fine, but never ahead of a
missing official feature. Sync was left out of the first build, and that was the
wrong priority.

## Where the official features live

Full details of sign-in and sync (identity values, the fork flow, payload
encryption, endpoints, merge rules) are in `docs/proton-sync.md`.

The official app's source is in `../Proton-WebClients/applications/authenticator`.

- Its Rust side (`src-tauri/src`, about 800 lines) is only helpers: keyring
  storage key, theme, the sign-in window, and biometrics (Linux:
  `biometrics/linux.rs` reports it unavailable).
- Almost every feature is TypeScript in the web UI, so "only replace the UI"
  means porting that logic to Rust:
  - Sign-in: `src/lib/auth/service.ts`, `src/app/components/Settings/Sync/ProtonSyncModal.tsx`
    (`requestFork(ForkType.LOGIN | SIGNUP)`), and `src-tauri/src/auth.rs`, which
    opens a 400x600 login webview at the SSO fork URL and takes the URL fragment
    when navigation reaches a path containing `/login`. Proton's page handles
    password, 2FA and CAPTCHA, so the app never sees the password.
  - Sync: `src/lib/entries/sync.ts` and `src/lib/api/requests.ts`. Endpoints:
    `authenticator/v1/key` (GET and POST; the key is OpenPGP-encrypted to a user
    key), `authenticator/v1/entry` (GET with `Since`), `authenticator/v1/entry/bulk`
    (POST create, PUT update with `LastRevision`, DELETE), and
    `authenticator/v1/entry/{id}/order` (PUT). `ContentFormatVersion: 1`.
  - Local database, app lock, backups and the storage key: `src/lib/db`,
    `src/lib/locks`, `src/lib/backup` and `src/lib/storage-key`.
  - Settings screen: `src/app/views/SettingsScreen.tsx`.
- Proton's Rust core (`proton-authenticator` in protonpass/proton-pass-common,
  checked out at `vendor-ref/proton-pass-common`) already has entries, codes,
  entry encryption, import/export and the sync merge logic
  (`operations.rs`: `calculate_operations_to_perform`; `ordering.rs`). It has no
  sign-in, account-key or API client.

## Parity status (2026-09-25, version 0.2.0)

Done: code grid, copy, search, countdown rings; add manually, edit, delete, drag
to reorder; import from every official provider; export with or without a
password; hide codes; theme; service logos. App lock (None or Password, as on
Linux in the official app), in `src/lock.rs`: Argon2id with Proton's
RECOMMENDED parameters (1 pass, 4 lanes, 512 MiB); the derived key replaces the
keyring key for the vault and seals the Proton session; 10 wrong passwords in a
row erase the local data. Tested end to end by `demo/lock-test.sh`. The user
asked (2026-09-25) that the password never be exposed in plain text: passwords
live in `secret::Secret`, keys in `lock::Key` and `Zeroizing` buffers (wiped on
drop, redacted `Debug`); `demo/secret-test.py` scans process memory (with
positive controls), files and keyring. Keep new password or key fields in those
types. The app sets up no logger, so nothing is logged today.

Sync status: the user signed in and read-only sync worked with their account
on 2026-09-25. Two-way sync was built on 2026-10-09 (`src/proton/sync.rs`,
how it works in `docs/proton-sync.md`) and is **not yet tried with the real
account**. Tested the same day by unit tests, by GnuPG reading a key upload,
and end to end by `demo/sync-test.sh` against a fake Proton (all passing). The
first two-way sync uploads the local codes that read-only sync held back.

Renderer: GPU (`wgpu`) is the default since 2026-09-25, at the user's request
after they tried both: smooth scrolling and resizing, and 0.2% idle CPU against
6.1% for the software renderer on their 2560x1440 monitor. The software
renderer stays built in as a startup fallback (`ICED_BACKEND=tiny-skia` forces it).

GPU choice (checked 2026-09-25 with DP-2 attached): the laptop has a discrete
Radeon RX 7600M XT (`03:00.0`, renderD128) and an integrated Radeon 680M
(`78:00.0`, renderD129). iced asks wgpu for `HighPerformance`, and the app drew
on the discrete GPU, which was already active before it started (it drives the
external monitor or KWin composites on it). `WGPU_POWER_PREF=low` did not move
it to the integrated GPU. Cost: a few ms of GPU time per 8 s. **Not yet checked:
the laptop screen alone**, where the discrete GPU may otherwise sleep and the
app could wake it; check `/sys/bus/pci/devices/0000:03:00.0/power/runtime_status`
and `/proc/<pid>/fdinfo` (`drm-pdev`, `drm-engine-gfx`) with no monitor attached.

Built on 2026-09-25, **not yet tried with a real account** (only the user can
sign in). Checked the same day: the installed Flatpak's sign-in window opens
and Proton's page loads as "Sign in — To continue to Proton Authenticator".
Built: sign-in and account creation through `login/` (the WebKit helper,
`cosmic-authenticator-login`), and sync (`src/proton/`). The session (tokens and
key password) is in the keyring as `proton-session`; links between local and
Proton entries are in `$XDG_DATA_HOME/cosmic-authenticator/sync.json`.

Missing, in planned order:
1. Automatic backups (daily, chosen folder, last 5
   kept, password), digit style (plain or boxed), animated code changes, the
   warning when the storage key is not in the keyring, and help links.
   The in-app update bar is not needed: `flatpak update` delivers new builds
   through the local `cosmicauthenticator` remote (see Releasing).

**Decided by the user on 2026-09-25 ("yes"):** to Proton's API, sign-in and sync
present this app as the official Proton Authenticator client (`x-pm-appversion`,
fork app name). The accepted risk is that Proton blocks the client or questions
the account.

Two-way sync can delete codes on Proton and on the user's phone; change it with
care. Claude never signs in to the user's account; the user does the sign-in tests.

## Machine and project facts

The project folder is on the `realcachy` home, which two installs on the same
laptop use. Check which one is running (`/etc/os-release`, `$XDG_CURRENT_DESKTOP`)
before following a machine-specific note.

**CachyOS with COSMIC on Wayland** (checked 2026-09-25):
- `~` is `/home/realcachy`; cargo home `~/.cargo`.
- Screens: eDP-1 (built in, 1920x1200 at 125%) and DP-1 (external, 2560x1440
  at 150%). The KWin placement script (`demo/on-screen.sh`) does not work here;
  COSMIC opens test windows on the screen in use (eDP-1).
- `flatpak-builder` exists only as the Flathub app `org.flatpak.Builder`;
  `flatpak/build.sh` falls back to it.
- Git has no name or email set. Commit with `git -c user.name=… -c user.email=…`,
  using the author of the first commit (`git log --format='%an <%ae>' f3656e0`).
- `gio trash` works.
- Screenshots: `cosmic-screenshot --interactive=false --modal=false --notify=false -s <dir>`
  captures both screens side by side (logical size, eDP-1 first). Crop with
  ImageMagick (`magick in.png -crop WxH+X+Y out.png`); PIL is not installed.
  The image shows the whole desktop, so keep it in a scratch folder and delete it after.
  The user lets Claude open test windows and check them this way without asking (2026-09-25).

**Fedora 44 with KDE Plasma on Wayland:**
- `~` is `/home/nilllinux22`; this folder is at `.../@home/realcachy`, with that
  install's cargo home at `.../@home/realcachy/.cargo` and Fedora's at `~/.cargo`.
- The COSMIC icon theme is not installed; `main.rs` falls back to the desktop's
  icon theme (Breeze).
- `gio trash` fails on this mount ("system internal mounts"); say so before
  falling back to `rm`.
- Test windows go on the external monitor, DP-2 (see Building and testing).

Both:
- The COSMIC theme is read from `~/.config/cosmic` (the
  `com.system76.CosmicTheme.*` folders; the user's accent is red). Never test
  with `XDG_CONFIG_HOME` pointed elsewhere unless `cosmic` is linked in, or the
  app shows default teal, which looks like a theming bug.
- Local git repository since 2026-09-25 (first commit that day), no remote.
  "Commit" means a local commit; push only when asked. The user's Gitea
  (git.nillsite.com) is retired; do not offer it as a remote.

## Building and testing

- **One large build at a time.** On 2026-09-25 a background Flatpak build plus a
  `cargo clippy --release` ran 32 rustc jobs at once and ran this 14 GB laptop
  out of memory; the OOM killer hit the user's desktop session. Wait for a
  background build to finish before any other compile. `flatpak/build.sh` caps
  its own memory and jobs; cap ad-hoc builds the same way
  (`systemd-run --user --scope -p MemoryMax=6G -p MemorySwapMax=2G nice -n 10 …`,
  `CARGO_BUILD_JOBS=6`).

- `cargo build --release`, `cargo test --release` (38 tests, 3 more ignored ones run by `demo/sync-test.sh`), `cargo clippy --release`.
  The sign-in helper (`login/`, `cargo build -p cosmic-authenticator-login`)
  needs WebKitGTK 6.0 development files, which this host lacks
  (`webkitgtk6.0-devel`); it builds in the Flatpak (GNOME 51 SDK). A native
  build without it shows an error when signing in. To check the helper alone
  (about a minute, instead of a full Flatpak build):
  `systemd-run --user --scope -p MemoryMax=4G flatpak run --filesystem="$PWD" --filesystem=home/.cargo --command=sh org.gnome.Sdk//51 -c 'export PATH=/usr/lib/sdk/rust-stable/bin:$PATH; cargo --offline test --release -j 4 -p cosmic-authenticator-login --target-dir target/sdk'`.
  `login/Cargo.toml` turns on gtk4's `v4_10` because webkit6 0.6.1 needs it
  but does not ask for it.
- Sync end to end: `demo/sync-test.sh [screenshot dir]` starts
  `demo/mock-proton.py` (a fake Proton API on 127.0.0.1 with the fixture account
  key) and points the app at it with `AUTHENTICATOR_API_URL`, which only accepts
  loopback addresses. It runs two devices through the server, then the app
  itself (preview steps `sync-add`, `sync-edit`, `sync-delete`, `sync-reorder`,
  `sync-off`) with a "phone" changing codes, and checks the server after each.
  Windows open on the screen in use. It builds with the `preview` feature, so
  rebuild normally afterwards before measuring.
- OpenPGP test fixtures: `tests/fixtures/make-pgp-fixtures.sh` (GnuPG, all calls
  non-interactive).
- Flatpak: `flatpak/build.sh`, which writes `flatpak/dev.nilltadios.CosmicAuthenticator.flatpak`.
  It is installed for the user (`flatpak install --user …`); its vault is in
  `~/.var/app/dev.nilltadios.CosmicAuthenticator`, separate from the native build's.
- Measure on the user's real desktop: `demo/measure.sh 60` and
  `demo/measure.sh 60 --flatpak`. The user asked for their real session, not
  headless. Windows open on their screen, so say so first.
- `demo/screenshots.sh` runs headless sway (with no pointer) and uses the
  `preview` feature (`AUTHENTICATOR_PREVIEW=<view>`), so re-shooting does not
  steal focus. It cannot test clicks: right-click menus, dragging and the file
  dialogs are still untested by hand.
- On Fedora/KDE: the user works on the built-in screen (eDP-1) and asked for test windows on
  the external monitor, **DP-2** (2026-09-25). Launch every desktop test through
  `demo/on-screen.sh DP-2 …` (`--fullscreen` to fill it), which places the window
  there without taking focus. The general how-to is the user's skill
  `kde-desktop-app-testing` (`~/.claude/skills/kde-desktop-app-testing`), which
  also has `capture-screen.sh` for a one-monitor screenshot. Never use
  `spectacle --activewindow`; it captured the user's Claude window once.
- The vault key and Proton session live in the keyring under service
  `dev.nilltadios.CosmicAuthenticator`, **shared by every copy of the app,
  including the user's real Flatpak**. Turning the app lock on deletes the
  vault key, so a test that did that on the real service would make the real
  vault unreadable. Every test run sets
  `AUTHENTICATOR_KEYRING_SERVICE=dev.nilltadios.CosmicAuthenticator.test` (the
  demo scripts do). Never run the app against the real service with test data.
- To give the Flatpak a test data folder, set the variables inside the sandbox:
  `flatpak run --command=sh <app id> -c "XDG_DATA_HOME=… AUTHENTICATOR_KEYRING_SERVICE=….test exec cosmic-authenticator"`.
  `flatpak run --env=XDG_DATA_HOME=…` is silently overridden, so the app would
  open the real vault and app lock (happened 2026-09-25, no harm). Check
  `/proc/<pid>/environ` of the running app.

## Releasing

- `flatpak/release.sh X.Y.Z` releases to the installed Flatpak: raises the
  version (both Cargo.toml files, Cargo.lock, metainfo), runs the tests,
  builds, commits "Release X.Y.Z", then `flatpak update`s the app from the local
  `cosmicauthenticator` remote (`file://…/flatpak/repo`, added 2026-09-27 on
  CachyOS). It needs a clean tree, because the Flatpak builds the working tree.
  It updates the user's real app, so ask before running it.
- The installed app now comes from the `cosmicauthenticator` remote (the user
  reinstalled it from there on 2026-09-27; data kept). It was first installed
  from the bundle, whose origin `flatpak update` never updates; release.sh
  prints the reinstall command if an install is still on the bundle.
- `./check-upstream.sh` reads the official app's version from Proton's update
  feed (`proton.me/download/authenticator/linux/latest.json`, still 1.1.6 on
  2026-09-27) and compares it with `APP_VERSION`, and compares the Proton core
  and libcosmic pins with upstream. Run it at the start of parity work. On a new
  official version: diff `../Proton-WebClients/applications/authenticator`
  between the versions, port the changes, then raise `APP_VERSION` and
  `USER_AGENT` (`src/proton/api.rs`) and `docs/proton-sync.md`. Proton refuses
  outdated versions with error 5003; the app shows "sync is paused" for it.
- Update the Proton core or libcosmic (`cargo update -p …`) in their own
  commits, not mixed with sync changes, so a regression points at one cause.
  If an update breaks the build or the app, fix our code for the new API; do
  not revert the update or pin back (the user, 2026-10-02).
