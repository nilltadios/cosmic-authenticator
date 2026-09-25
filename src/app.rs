use std::borrow::Cow;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cosmic::app::context_drawer::{self, ContextDrawer};
use cosmic::dialog::file_chooser::{self, FileFilter};
use cosmic::iced::futures::SinkExt;
use cosmic::iced::futures::channel::oneshot;
use cosmic::iced::keyboard::{self, Key, Modifiers};
use cosmic::iced::{Alignment, Background, Border, Color, Length, Point, Subscription};
use cosmic::Application;
use cosmic::prelude::*;
use cosmic::widget::{self, canvas, container, icon, menu, popover, settings};
use proton_authenticator::{AuthenticatorClient, AuthenticatorEntry};

use crate::form::{self, EntryForm, Field};
use crate::import::{self, ImportError, Imported};
use crate::lock::{self, LockConfig};
use crate::secret::Secret;
use zeroize::Zeroizing;
use crate::logos::{self, Logos};
use crate::proton::api::USER_AGENT;
use crate::proton::session::{self, Session};
use crate::proton::sync::{self as proton_sync, Fetched, Links, SyncError};
use crate::proton::fork;
use crate::ring::Countdown;
use crate::settings::{AppTheme, Settings};
use crate::store;

const CARD_MIN_WIDTH: f32 = 340.0;
const TILE_SIZE: f32 = 36.0;
/// Proton's mask character for hidden codes.
const HIDDEN: char = '·';

/// Proton sync, as the official settings show it.
#[derive(Clone, Debug, PartialEq)]
enum SyncStatus {
    Off,
    SigningIn,
    Syncing,
    On,
    Error(String),
}

enum Drawer {
    Form(EntryForm),
    Settings,
}

/// The unlock screen shown at startup while the app lock is on.
#[derive(Default)]
struct Locked {
    password: Secret,
    error: Option<String>,
    checking: bool,
}

/// The official wording for a wrong app lock password.
fn wrong_password_message(attempts_left: u32) -> String {
    let attempts = if attempts_left == 1 { "attempt" } else { "attempts" };
    format!("Wrong password. You have {attempts_left} {attempts} left, after that, your data will be erased.")
}

enum Dialog {
    Delete { id: String },
    ImportPassword { contents: Vec<u8>, password: Secret, wrong: bool },
    Export { password: Secret, confirm: Secret, error: Option<&'static str> },
    CreateLock { password: Secret, confirm: Secret, error: Option<String>, working: bool },
    RemoveLock { password: Secret, error: Option<String>, working: bool },
}

pub struct AppModel {
    core: cosmic::Core,
    client: AuthenticatorClient,
    entries: Vec<AuthenticatorEntry>,
    /// Current and next code for each entry, refreshed every tick.
    codes: Vec<(String, String)>,
    now: u64,
    query: String,
    settings: Settings,
    logos: Logos,
    toasts: widget::Toasts<Message>,
    /// A failure that needs attention, such as a vault that cannot be read.
    error: Option<String>,
    drawer: Option<Drawer>,
    dialog: Option<Dialog>,
    add_menu_open: bool,
    /// Set while the save dialog for an export is open. The inner value is the
    /// export password, if one was given.
    pending_export: Option<Option<Secret>>,
    session: Option<Session>,
    /// Local entry id to Proton entry, for codes that came from Proton.
    links: Links,
    sync: SyncStatus,
    /// The `state` of the sign-in in progress, checked against the reply.
    sign_in_state: Option<String>,
    /// The key the vault is saved with: the keyring's, or the app lock's.
    vault_key: Option<Zeroizing<Vec<u8>>>,
    /// Set while the app lock is on.
    lock: Option<LockConfig>,
    /// Set until the app lock password has been entered.
    locked: Option<Locked>,
    /// Messages to run once unlocked (used by the preview steps).
    after_unlock: Vec<Message>,
    search_id: widget::Id,
    password_id: widget::Id,
}

#[derive(Debug, Clone)]
pub enum Message {
    Tick,
    Key(Key, Modifiers),
    Search(String),
    Copy(usize),
    CopyNext(usize),
    CloseToast(widget::ToastId),
    DismissError,

    ToggleAddMenu,
    CloseAddMenu,
    AddManually,
    ScanQrImage,
    PasteLink,
    Pasted(Option<String>),
    ImportFile,
    FileOpened(Result<Vec<u8>, String>),
    ImportPassword(Secret),
    SubmitImportPassword,

    Form(Field),
    SaveForm,
    Edit(usize),
    RequestDelete(usize),
    ConfirmDelete,
    Reorder(Vec<usize>),

    OpenSettings,
    CloseDrawer,
    CloseDialog,
    HideCodes(bool),
    ShowLogos(bool),
    Theme(usize),
    LogoLoaded(String, Option<widget::image::Handle>),

    RequestExport,
    ExportPassword(Secret),
    ExportConfirm(Secret),
    Export,
    ExportPath(Result<PathBuf, String>),

    SyncToggle(bool),
    SignUp,
    LoginWindowClosed(Result<String, String>),
    SignedIn(Result<Session, SyncError>),
    SyncNow,
    Synced(Box<(Session, Result<Fetched, SyncError>)>),
    SignedOut,

    LockInput(Secret),
    Unlock,
    Unlocked(Result<Option<lock::Key>, String>),
    AppLock(usize),
    LockPassword(Secret),
    LockConfirm(Secret),
    CreateLock,
    LockCreated(Result<(LockConfig, lock::Key), String>),
    RemoveLock,
    LockRemoveChecked(Result<Option<lock::Key>, String>),
    AfterUnlock(Vec<Message>),
}

/// Runs blocking work on its own thread and delivers its result as a message.
fn background<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
    message: impl FnOnce(T) -> Message + Send + 'static,
) -> Task<cosmic::Action<Message>> {
    cosmic::task::future(async move {
        let (sender, receiver) = oneshot::channel();
        std::thread::spawn(move || {
            let _ = sender.send(work());
        });
        match receiver.await {
            Ok(value) => message(value),
            Err(_) => Message::DismissError,
        }
    })
}

/// The sign-in helper sits next to this binary (and in /app/bin in the Flatpak).
fn login_helper() -> Option<PathBuf> {
    let beside = std::env::current_exe().ok()?.with_file_name("cosmic-authenticator-login");
    beside.is_file().then_some(beside)
}

/// Opens the sign-in window and waits for it: the callback fragment, or an
/// error when the window was closed or could not start.
fn run_login_window(url: &str, title: &str) -> Result<String, String> {
    let helper = login_helper().ok_or_else(|| {
        String::from(
            "The sign-in window (cosmic-authenticator-login) is missing. It is part of the Flatpak; \
             for a native build, build it with `cargo build -p cosmic-authenticator-login`.",
        )
    })?;
    let output = std::process::Command::new(helper)
        .args([url, title, USER_AGENT])
        .stderr(std::process::Stdio::inherit())
        .output()
        .map_err(|error| format!("Cannot open the sign-in window: {error}"))?;
    let fragment = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if output.status.success() && !fragment.is_empty() { Ok(fragment) } else { Err(String::new()) }
}

/// Actions in a card's right-click menu.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CardAction {
    CopyNext(usize),
    Edit(usize),
    Delete(usize),
}

impl menu::Action for CardAction {
    type Message = Message;

    fn message(&self) -> Message {
        match *self {
            CardAction::CopyNext(index) => Message::CopyNext(index),
            CardAction::Edit(index) => Message::Edit(index),
            CardAction::Delete(index) => Message::RequestDelete(index),
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// `YYYY-MM-DD` in UTC, for export file names.
fn iso_date(unix: u64) -> String {
    // Howard Hinnant's days-to-civil algorithm.
    let days = (unix / 86_400) as i64 + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days.rem_euclid(146_097);
    let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 { month_index + 3 } else { month_index - 9 };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

/// Groups characters the way Proton does: fours when the length allows,
/// otherwise threes, so `658812` becomes `658 812`. Hidden codes keep the
/// grouping with every character masked.
fn format_code(code: &str, hidden: bool) -> String {
    let chars: Vec<char> = code.chars().map(|c| if hidden { HIDDEN } else { c }).collect();
    let size = match chars.len() {
        n if n > 4 && n % 4 == 0 => 4,
        n if n % 3 == 0 => 3,
        n => n.max(1),
    };
    chars.chunks(size).map(|group| group.iter().collect::<String>()).collect::<Vec<_>>().join(" ")
}

/// Stable tile colour per issuer, so a service keeps its colour between runs.
fn tile_color(issuer: &str) -> Color {
    const PALETTE: [(u8, u8, u8); 8] = [
        (0x6d, 0x4a, 0xff),
        (0x1f, 0x83, 0x8a),
        (0xb8, 0x4a, 0x62),
        (0x3a, 0x7d, 0xd6),
        (0xc2, 0x7c, 0x0e),
        (0x2f, 0x8f, 0x4e),
        (0x8e, 0x44, 0xad),
        (0x5c, 0x6b, 0x7a),
    ];
    let hash = issuer.bytes().fold(0u32, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u32));
    let (r, g, b) = PALETTE[hash as usize % PALETTE.len()];
    Color::from_rgb8(r, g, b)
}

#[derive(Clone, Copy)]
enum CardState {
    Idle,
    Hovered,
    Pressed,
}

/// A card that is also a button: the COSMIC card colour, with the usual
/// component hover and press shades and an accent outline under keyboard focus.
fn card_style(theme: &cosmic::Theme, focused: bool, state: CardState) -> widget::button::Style {
    let cosmic = theme.cosmic();
    let component = &cosmic.background(false).component;
    let background = match state {
        CardState::Idle => component.base,
        CardState::Hovered => component.hover,
        CardState::Pressed => component.pressed,
    };
    let mut style = widget::button::Style::new();
    style.background = Some(Background::Color(background.into()));
    style.border_radius = cosmic.corner_radii.radius_s.into();
    style.text_color = Some(component.on.into());
    style.icon_color = Some(component.on.into());
    if focused {
        style.outline_width = 2.0;
        style.outline_color = cosmic.accent_color().into();
    }
    style
}

fn card_class() -> cosmic::theme::Button {
    cosmic::theme::Button::Custom {
        active: Box::new(|focused, theme| card_style(theme, focused, CardState::Idle)),
        disabled: Box::new(|theme| card_style(theme, false, CardState::Idle)),
        hovered: Box::new(|focused, theme| card_style(theme, focused, CardState::Hovered)),
        pressed: Box::new(|focused, theme| card_style(theme, focused, CardState::Pressed)),
    }
}

fn open_file(title: &'static str, filter: Option<FileFilter>) -> Task<cosmic::Action<Message>> {
    cosmic::task::future(async move {
        let mut dialog = file_chooser::open::Dialog::new().title(title);
        if let Some(filter) = filter {
            dialog = dialog.filter(filter);
        }
        let result = match dialog.open_file().await {
            Ok(response) => response
                .url()
                .to_file_path()
                .map_err(|()| String::from("The selected file is not a local file"))
                .and_then(|path| std::fs::read(&path).map_err(|error| format!("Cannot read {}: {error}", path.display()))),
            Err(error) => Err(error.to_string()),
        };
        Message::FileOpened(result)
    })
}

/// Portal dialogs report a closed dialog as an error. It is not worth showing.
fn is_cancelled(error: &str) -> bool {
    error.to_lowercase().contains("cancel")
}

impl AppModel {
    fn refresh_codes(&mut self) {
        self.now = unix_now();
        // One entry at a time, so a single bad secret cannot blank every card.
        self.codes = self
            .entries
            .iter()
            .map(|entry| match self.client.generate_codes(std::slice::from_ref(entry), self.now) {
                Ok(mut codes) if !codes.is_empty() => {
                    let code = codes.swap_remove(0);
                    (code.current_code, code.next_code)
                }
                _ => (String::from("------"), String::from("------")),
            })
            .collect();
    }

    fn toast(&mut self, text: impl Into<String>) -> Task<cosmic::Action<Message>> {
        self.toasts.push(widget::Toast::new(text)).map(cosmic::Action::App)
    }

    /// The app lock's key, when the lock is on.
    fn lock_key(&self) -> Option<lock::Key> {
        self.lock.as_ref()?;
        self.vault_key.as_deref().and_then(|key| lock::Key::from_bytes(key))
    }

    fn save_vault(&mut self) -> Result<(), String> {
        // While locked nothing is loaded, so saving would overwrite the vault
        // with an empty list.
        if self.locked.is_some() {
            return Err(String::from("Unlock Authenticator first"));
        }
        let key = match &self.vault_key {
            Some(key) => key.clone(),
            None => {
                let key = Zeroizing::new(store::keyring_key_or_new()?);
                self.vault_key = Some(key.clone());
                key
            }
        };
        store::save_with(&self.entries, &key)
    }

    /// Loads the vault, the Proton session and the sync links, with the app
    /// lock's key or else the keyring's, then starts logos and sync.
    fn open_data(&mut self, lock_key: Option<lock::Key>) -> Task<cosmic::Action<Message>> {
        let loaded = match lock_key {
            Some(ref key) => self.load_locked_vault(key),
            None => store::keyring_key().and_then(|key| match key {
                Some(key) => {
                    let key = Zeroizing::new(key);
                    self.vault_key = Some(key.clone());
                    store::load_with(&key)
                }
                None if store::vault_path().exists() => Err(String::from("The vault key is missing from the keyring")),
                None => Ok(Vec::new()),
            }),
        };
        match loaded {
            Ok(entries) => self.entries = entries,
            Err(error) => self.error = Some(error),
        }
        match (session::load(lock_key.as_ref()), store::load_links()) {
            (Ok(saved), Ok(links)) => {
                self.session = saved;
                self.links = links;
            }
            (Err(error), _) | (_, Err(error)) => self.error = Some(error),
        }
        self.refresh_codes();
        Task::batch([self.request_logos(), self.start_sync()])
    }

    fn load_locked_vault(&mut self, key: &lock::Key) -> Result<Vec<AuthenticatorEntry>, String> {
        self.vault_key = Some(Zeroizing::new(key.as_bytes().to_vec()));
        if !store::vault_path().exists() {
            return Ok(Vec::new());
        }
        match store::load_with(key.as_bytes()) {
            Ok(entries) => Ok(entries),
            // Turning the lock on or off was interrupted while the vault still
            // used the keyring key. Finish with the lock on.
            Err(error) => match store::keyring_key()? {
                Some(old) => {
                    let entries = store::load_with(&old)?;
                    store::save_with(&entries, key.as_bytes())?;
                    store::delete_keyring_key()?;
                    Ok(entries)
                }
                None => Err(error),
            },
        }
    }

    /// Counts a wrong app lock password. After the tenth in a row the local
    /// data is erased, as the official app does. Returns the attempts left.
    fn record_wrong_password(&mut self) -> u32 {
        let Some(config) = self.lock.as_mut() else {
            return 0;
        };
        config.failed_attempts += 1;
        let left = config.attempts_left();
        if left == 0 {
            self.erase_local_data();
        } else if let Err(error) = lock::save(config) {
            self.error = Some(error);
        }
        left
    }

    fn erase_local_data(&mut self) {
        let results = [store::erase(), session::delete(), lock::delete(), store::delete_keyring_key()];
        if let Some(Err(error)) = results.into_iter().find(Result::is_err) {
            self.error = Some(error);
        }
        self.entries.clear();
        self.links.clear();
        self.session = None;
        self.lock = None;
        self.vault_key = None;
        self.locked = None;
        self.dialog = None;
        self.sync = SyncStatus::Off;
        self.refresh_codes();
    }

    /// The lock file goes first and the keyring key last, so an interrupted
    /// switch is finished at the next unlock (see `load_locked_vault`).
    fn enable_lock(&mut self, config: LockConfig, key: lock::Key) -> Result<(), String> {
        lock::save(&config)?;
        store::save_with(&self.entries, key.as_bytes())?;
        if let Some(session) = &self.session {
            session::save(session, Some(&key))?;
        }
        store::delete_keyring_key()?;
        self.vault_key = Some(Zeroizing::new(key.as_bytes().to_vec()));
        self.lock = Some(config);
        Ok(())
    }

    fn disable_lock(&mut self) -> Result<(), String> {
        let key = store::keyring_key_or_new()?;
        store::save_with(&self.entries, &key)?;
        if let Some(session) = &self.session {
            session::save(session, None)?;
        }
        lock::delete()?;
        self.vault_key = Some(Zeroizing::new(key));
        self.lock = None;
        Ok(())
    }

    fn unlock_view<'a>(&'a self, locked: &'a Locked) -> Element<'a, Message> {
        let spacing = cosmic::theme::spacing();
        let unlock = if locked.checking {
            widget::button::suggested("Checking…")
        } else {
            widget::button::suggested("Unlock").on_press(Message::Unlock)
        };
        let mut column = widget::column::with_capacity(6)
            .push(icon::from_name("system-lock-screen-symbolic").size(64))
            .push(widget::text::title3("Unlock Authenticator"))
            .push(widget::text::body("Enter your password:"))
            .push(
                widget::secure_input("Password", locked.password.as_str(), None, true)
                    .id(self.password_id.clone())
                    .on_input(|text| Message::LockInput(Secret::from(text)))
                    .on_submit(|_| Message::Unlock)
                    .width(320),
            )
            .push(unlock)
            .spacing(spacing.space_s)
            .align_x(Alignment::Center);
        if let Some(error) = &locked.error {
            column = column.push(widget::text::body(error.clone()).align_x(Alignment::Center));
        }
        container(column.max_width(420)).center(Length::Fill).into()
    }

    fn persist(&mut self) -> bool {
        match self.save_vault() {
            Ok(()) => true,
            Err(error) => {
                self.error = Some(error);
                false
            }
        }
    }

    fn save_settings(&mut self) {
        if let Err(error) = crate::settings::save(&self.settings) {
            self.error = Some(error);
        }
    }

    fn open_drawer(&mut self, drawer: Drawer) {
        self.add_menu_open = false;
        self.drawer = Some(drawer);
        self.core.window.show_context = true;
    }

    fn close_drawer(&mut self) {
        self.drawer = None;
        self.core.window.show_context = false;
    }

    /// Codes that came from Proton are read-only until two-way sync exists:
    /// a local edit would never reach Proton and would be replaced on the next sync.
    fn is_synced(&self, index: usize) -> bool {
        self.entries.get(index).is_some_and(|entry| self.links.contains_key(&entry.id))
    }

    fn start_sync(&mut self) -> Task<cosmic::Action<Message>> {
        let Some(mut session) = self.session.clone() else {
            return Task::none();
        };
        self.sync = SyncStatus::Syncing;
        background(
            move || {
                let result = proton_sync::fetch(&mut session);
                (session, result)
            },
            |result| Message::Synced(Box::new(result)),
        )
    }

    fn apply_sync(&mut self, session: Session, result: Result<Fetched, SyncError>) -> Task<cosmic::Action<Message>> {
        // A refresh during the sync replaced the tokens; keep the new ones.
        if self.session.as_ref().is_some_and(|current| current.tokens != session.tokens) {
            if let Err(error) = session::save(&session, self.lock_key().as_ref()) {
                self.error = Some(error);
            }
            self.session = Some(session);
        }
        let fetched = match result {
            Ok(fetched) => fetched,
            Err(SyncError::SignedOut) => {
                self.forget_session();
                self.sync = SyncStatus::Error(SyncError::SignedOut.message());
                return Task::none();
            }
            Err(error) => {
                self.sync = SyncStatus::Error(error.message());
                return Task::none();
            }
        };

        let unreadable = fetched.unreadable;
        let (previous_entries, previous_links) = (self.entries.clone(), self.links.clone());
        let merged = proton_sync::merge(&mut self.entries, &mut self.links, fetched);
        let saved = self.save_vault().and_then(|()| store::save_links(&self.links));
        if let Err(error) = saved {
            // Keep memory in step with the files on disk.
            (self.entries, self.links) = (previous_entries, previous_links);
            self.sync = SyncStatus::Error(error);
            return Task::none();
        }
        self.refresh_codes();
        self.sync = SyncStatus::On;

        let mut parts = Vec::new();
        if merged.added > 0 {
            parts.push(format!("{} added", merged.added));
        }
        if merged.updated > 0 {
            parts.push(format!("{} updated", merged.updated));
        }
        if merged.removed > 0 {
            parts.push(format!("{} removed", merged.removed));
        }
        if unreadable > 0 {
            parts.push(format!("{unreadable} could not be read"));
        }
        let mut tasks = vec![self.request_logos()];
        if !parts.is_empty() {
            tasks.push(self.toast(format!("Synced with Proton: {}", parts.join(", "))));
        }
        Task::batch(tasks)
    }

    /// Drops the session and the links; the codes themselves stay on this device.
    fn forget_session(&mut self) {
        self.session = None;
        self.links.clear();
        let results = [session::delete(), store::save_links(&self.links)];
        if let Some(Err(error)) = results.into_iter().find(Result::is_err) {
            self.error = Some(error);
        }
    }

    fn sign_in(&mut self, sign_up: bool) -> Task<cosmic::Action<Message>> {
        let request = fork::request(sign_up);
        self.sign_in_state = Some(request.state);
        self.sync = SyncStatus::SigningIn;
        let title = if sign_up { "Sign up" } else { "Log in" };
        background(move || run_login_window(&request.url, title), Message::LoginWindowClosed)
    }

    fn request_logos(&mut self) -> Task<cosmic::Action<Message>> {
        if !self.settings.show_logos {
            return Task::none();
        }
        let issuers: Vec<String> = self.entries.iter().map(AuthenticatorEntry::issuer).collect();
        let fetches = self.logos.request(issuers.iter().map(String::as_str));
        Task::batch(fetches.into_iter().map(|fetch| {
            cosmic::task::future(async move {
                let (sender, receiver) = oneshot::channel();
                let key = fetch.key.clone();
                std::thread::spawn(move || {
                    let _ = sender.send(logos::download(&fetch));
                });
                Message::LogoLoaded(key, receiver.await.ok().flatten())
            })
        }))
    }

    fn add_entries(&mut self, imported: Imported) -> Task<cosmic::Action<Message>> {
        let total = imported.entries.len();
        let mut added = 0;
        for entry in imported.entries {
            let uri = entry.uri();
            if !self.entries.iter().any(|existing| existing.uri() == uri) {
                self.entries.push(entry);
                added += 1;
            }
        }
        if added > 0 && !self.persist() {
            return Task::none();
        }
        self.refresh_codes();

        let mut parts = vec![match added {
            1 => String::from("Added 1 code"),
            n => format!("Added {n} codes"),
        }];
        if total > added {
            parts.push(format!("{} already here", total - added));
        }
        if imported.failed > 0 {
            parts.push(format!("{} not supported", imported.failed));
        }
        let toast = self.toast(parts.join(", "));
        Task::batch([toast, self.request_logos()])
    }

    fn import(&mut self, contents: Vec<u8>, password: Option<Secret>) -> Task<cosmic::Action<Message>> {
        match import::import_bytes(&contents, password.as_ref().map(Secret::as_str)) {
            Ok(imported) => {
                self.dialog = None;
                self.add_entries(imported)
            }
            Err(error @ (ImportError::PasswordRequired | ImportError::WrongPassword)) => {
                self.dialog = Some(Dialog::ImportPassword {
                    contents,
                    password: Secret::default(),
                    wrong: error == ImportError::WrongPassword,
                });
                widget::text_input::focus(self.password_id.clone())
            }
            Err(error) => self.toast(error.message()),
        }
    }

    fn visible(&self) -> Vec<usize> {
        let query = self.query.trim().to_lowercase();
        (0..self.entries.len())
            .filter(|&i| {
                query.is_empty() || {
                    let entry = &self.entries[i];
                    entry.issuer().to_lowercase().contains(&query) || entry.name().to_lowercase().contains(&query)
                }
            })
            .collect()
    }

    fn tile(&self, title: &str, issuer: &str) -> Element<'_, Message> {
        if self.settings.show_logos
            && let Some(handle) = self.logos.get(issuer)
        {
            return widget::image(handle.clone())
                .width(TILE_SIZE)
                .height(TILE_SIZE)
                .border_radius([8.0; 4])
                .into();
        }
        let letter = title.chars().find(|c| c.is_alphanumeric()).map(|c| c.to_uppercase().to_string()).unwrap_or_default();
        let color = tile_color(title);
        container(widget::text::title4(letter))
            .center(Length::Fixed(TILE_SIZE))
            .style(move |_| container::Style {
                background: Some(Background::Color(color)),
                text_color: Some(Color::WHITE),
                border: Border { radius: 8.0.into(), ..Border::default() },
                ..container::Style::default()
            })
            .into()
    }

    fn card(&self, index: usize, width: f32) -> Element<'_, Message> {
        let entry = &self.entries[index];
        let (current, next) = &self.codes[index];
        let issuer = entry.issuer();
        let name = entry.name();
        let (title, subtitle) = if issuer.is_empty() { (name, String::new()) } else { (issuer.clone(), name) };

        let period = u64::from(entry.period().max(1));
        let remaining = period - self.now % period;

        let mut labels = widget::column::with_capacity(2).push(widget::text::heading(title.clone()));
        if !subtitle.is_empty() {
            labels = labels.push(widget::text::caption(subtitle));
        }

        let header = widget::row::with_capacity(3)
            .push(self.tile(&title, &issuer))
            .push(labels.width(Length::Fill))
            .push(canvas(Countdown { remaining, period }).width(32).height(32))
            .spacing(12)
            .align_y(Alignment::Center);

        let hidden = self.settings.hide_codes;
        let codes = widget::row::with_capacity(2)
            .push(
                widget::text(format_code(current, hidden))
                    .size(28)
                    .font(cosmic::font::mono())
                    .width(Length::Fill),
            )
            .push(
                widget::column::with_capacity(2)
                    .push(widget::text::caption("Next"))
                    .push(widget::text(format_code(next, hidden)).size(13).font(cosmic::font::mono()))
                    .align_x(Alignment::End),
            )
            .align_y(Alignment::End);

        let body = widget::column::with_capacity(3)
            .push(header)
            .push(widget::divider::horizontal::light())
            .push(codes)
            .spacing(12);

        let card = widget::button::custom(body)
            .padding(16)
            .width(Length::Fixed(width))
            .class(card_class())
            .on_press(Message::Copy(index));

        let editable = !self.is_synced(index);
        let entry = |label, icon_name: &str, action| {
            let icon = Some(icon::from_name(icon_name).into());
            if editable { menu::Item::Button(label, icon, action) } else { menu::Item::ButtonDisabled(label, icon, action) }
        };
        let actions = vec![
            menu::Item::Button("Copy next code", Some(icon::from_name("edit-copy-symbolic").into()), CardAction::CopyNext(index)),
            entry("Edit", "document-edit-symbolic", CardAction::Edit(index)),
            menu::Item::Divider,
            entry("Delete", "user-trash-symbolic", CardAction::Delete(index)),
        ];
        widget::context_menu(card, Some(menu::items(&HashMap::new(), actions))).into()
    }

    fn grid(&self, width: f32) -> Element<'_, Message> {
        let spacing = cosmic::theme::spacing().space_s as f32;
        let columns = ((width + spacing) / (CARD_MIN_WIDTH + spacing)).floor().max(1.0);
        let card_width = ((width - spacing * (columns - 1.0)) / columns).floor();

        // Dragging reorders the full list, so it only works while every card shows.
        let reorderable = self.query.trim().is_empty();
        let mut row = widget::reorderable_flex_row(Message::Reorder).spacing(spacing).width(Length::Fill);
        for index in self.visible() {
            row = if reorderable {
                row.push(index, self.card(index, card_width))
            } else {
                row.push_locked(index, self.card(index, card_width))
            };
        }
        widget::scrollable(row).height(Length::Fill).into()
    }

    fn empty_state(&self) -> Element<'_, Message> {
        let spacing = cosmic::theme::spacing();
        let mut column = widget::column::with_capacity(3).spacing(spacing.space_s).align_x(Alignment::Center);
        if self.entries.is_empty() {
            column = column
                .push(widget::text::title3("No codes yet"))
                .push(widget::text::body(
                    "Add a code from a QR code image or a setup key, or import an export from \
                     Proton Authenticator, Aegis, 2FAS, Bitwarden, Ente, LastPass or Google Authenticator.",
                ).align_x(Alignment::Center))
                .push(
                    widget::row::with_capacity(2)
                        .push(widget::button::suggested("Add code").on_press(Message::AddManually))
                        .push(widget::button::standard("Import").on_press(Message::ImportFile))
                        .spacing(spacing.space_xs),
                );
        } else {
            column = column
                .push(widget::text::title3("No matches"))
                .push(widget::text::body("No code matches your search."));
        }
        container(column.max_width(520)).center(Length::Fill).into()
    }

    fn add_menu(&self) -> Element<'_, Message> {
        let item = |icon_name: &'static str, label: &'static str, message: Message| -> Element<'_, Message> {
            menu::menu_button(vec![
                icon::from_name(icon_name).size(16).into(),
                widget::space().width(12).into(),
                widget::text::body(label).into(),
            ])
            .on_press(message)
            .into()
        };
        container(
            widget::column::with_capacity(4)
                .push(item("list-add-symbolic", "Enter a setup key", Message::AddManually))
                .push(item("image-x-generic-symbolic", "Scan QR code image…", Message::ScanQrImage))
                .push(item("edit-paste-symbolic", "Paste otpauth:// link", Message::PasteLink))
                .push(item("document-open-symbolic", "Import from another app…", Message::ImportFile)),
        )
        .padding(4)
        .width(280)
        .class(cosmic::theme::Container::Dropdown)
        .into()
    }

    fn toolbar(&self) -> Element<'_, Message> {
        let add_button = widget::button::suggested("Add")
            .leading_icon(icon::from_name("list-add-symbolic"))
            .on_press(Message::ToggleAddMenu);
        let mut add = popover(add_button).position(popover::Position::Point(Point::new(0.0, 40.0)));
        if self.add_menu_open {
            add = add.popup(self.add_menu()).on_close(Message::CloseAddMenu);
        }

        widget::row::with_capacity(3)
            .push(add)
            .push(
                widget::search_input("Search", &self.query)
                    .id(self.search_id.clone())
                    .on_input(Message::Search)
                    .on_clear(Message::Search(String::new()))
                    .width(Length::Fill),
            )
            .push(
                widget::button::icon(icon::from_name("preferences-system-symbolic"))
                    .tooltip("Settings")
                    .on_press(Message::OpenSettings),
            )
            .spacing(cosmic::theme::spacing().space_s)
            .align_y(Alignment::Center)
            .into()
    }

    fn form_drawer<'a>(&'a self, form: &'a EntryForm) -> ContextDrawer<'a, Message> {
        let spacing = cosmic::theme::spacing();
        let field = |label: &'static str, placeholder: &'static str, value: &'a str, to: fn(String) -> Field| {
            widget::text_input(placeholder, value)
                .label(label)
                .on_input(move |text| Message::Form(to(text)))
                .on_submit(|_| Message::SaveForm)
        };

        let mut content = widget::column::with_capacity(6)
            .push(field("Title", "Account, email or label", &form.name, Field::Name))
            .push(field("Secret key", "Setup key, or paste an otpauth:// link", &form.secret, Field::Secret))
            .push(field("Issuer", "Service name, such as GitHub", &form.issuer, Field::Issuer))
            .spacing(spacing.space_s);

        if form.show_advanced {
            let mut section = settings::section().title("Advanced").add(
                settings::item::builder("Type").control(widget::dropdown(
                    &form::TYPE_LABELS[..],
                    Some(usize::from(form.steam)),
                    |index| Message::Form(Field::Steam(index == 1)),
                )),
            );
            if !form.steam {
                let digits: Vec<String> = form.digit_options().iter().map(u8::to_string).collect();
                let selected = form.digit_options().iter().position(|d| *d == form.digits);
                section = section
                    .add(settings::item::builder("Digits").control(widget::dropdown(
                        Cow::Owned(digits),
                        selected,
                        |index| Message::Form(Field::Digits(index)),
                    )))
                    .add(
                        settings::item::builder("Time interval (seconds)").control(
                            widget::text_input("30", &form.period)
                                .on_input(|text| Message::Form(Field::Period(text)))
                                .on_submit(|_| Message::SaveForm)
                                .width(80),
                        ),
                    )
                    .add(settings::item::builder("Algorithm").control(widget::dropdown(
                        &form::ALGORITHM_LABELS[..],
                        Some(form.algorithm),
                        |index| Message::Form(Field::Algorithm(index)),
                    )));
            }
            content = content.push(section);
        } else {
            content = content.push(
                widget::button::text("Advanced options")
                    .trailing_icon(icon::from_name("pan-down-symbolic"))
                    .on_press(Message::Form(Field::ShowAdvanced)),
            );
        }

        if let Some(error) = &form.error {
            content = content.push(widget::warning(error.clone()));
        }

        let mut footer = widget::row::with_capacity(4).spacing(spacing.space_xs).align_y(Alignment::Center);
        if let Some(id) = &form.editing
            && let Some(index) = self.entries.iter().position(|entry| &entry.id == id)
        {
            footer = footer.push(widget::button::destructive("Delete").on_press(Message::RequestDelete(index)));
        }
        footer = footer
            .push(widget::space().width(Length::Fill))
            .push(widget::button::standard("Cancel").on_press(Message::CloseDrawer))
            .push(widget::button::suggested("Save").on_press(Message::SaveForm));

        let title = if form.editing.is_some() { "Edit code" } else { "Add code" };
        context_drawer::context_drawer(content, Message::CloseDrawer).title(title).footer(footer)
    }

    fn settings_drawer(&self) -> ContextDrawer<'_, Message> {
        let theme_labels: Vec<&'static str> = AppTheme::ALL.iter().map(|theme| theme.label()).collect();
        let theme_index = AppTheme::ALL.iter().position(|theme| *theme == self.settings.theme);

        let (sync_on, sync_label) = match (&self.sync, &self.session) {
            (SyncStatus::SigningIn, _) => (true, String::from("Signing in…")),
            (SyncStatus::Syncing, _) => (true, String::from("Syncing…")),
            (SyncStatus::Error(message), Some(session)) => (true, format!("Account: {}. {message}", session.email)),
            (SyncStatus::Error(message), None) => (false, message.clone()),
            (_, Some(session)) => (true, format!("Account: {}", session.email)),
            (_, None) => (false, String::from("Sign in to a Proton account to get the codes from your other devices.")),
        };
        let busy = matches!(self.sync, SyncStatus::SigningIn | SyncStatus::Syncing);
        let mut security = settings::section().title("Security").add(
            settings::item::builder("Sync between devices")
                .description(sync_label)
                .toggler(sync_on, Message::SyncToggle),
        );
        if self.session.is_some() {
            security = security.add(
                settings::item::builder("Codes from Proton are read-only here")
                    .description(
                        "This version downloads your codes but does not upload changes yet. \
                         Codes you add here stay on this device.",
                    )
                    .control(widget::button::standard("Sync now").on_press_maybe((!busy).then_some(Message::SyncNow))),
            );
        } else if !busy {
            security = security.add(
                settings::item::builder("No Proton account?")
                    .control(widget::button::standard("Create one").on_press(Message::SignUp)),
            );
        }

        let security = security
            .add(
                settings::item::builder("App lock")
                    .description("Asks for a password every time Authenticator starts.")
                    .control(widget::dropdown(&["None", "Password"][..], Some(usize::from(self.lock.is_some())), Message::AppLock)),
            )
            .add(
                settings::item::builder("Hide codes")
                    .description("Show dots instead of digits. Clicking a card still copies its code.")
                    .toggler(self.settings.hide_codes, Message::HideCodes),
            );

        let appearance = settings::section()
            .title("Appearance")
            .add(settings::item::builder("Theme").control(widget::dropdown(Cow::Owned(theme_labels), theme_index, Message::Theme)))
            .add(
                settings::item::builder("Service logos")
                    .description(
                        "Downloads each service's logo once, from its website or Google's favicon service, \
                         as Proton Authenticator does.",
                    )
                    .toggler(self.settings.show_logos, Message::ShowLogos),
            );

        let data = settings::section()
            .title("Your data")
            .add(
                settings::item::builder("Import codes")
                    .description("From Proton Authenticator, Proton Pass, Aegis, 2FAS, Bitwarden, Ente, LastPass or a Google Authenticator QR code.")
                    .control(widget::button::standard("Import…").on_press(Message::ImportFile)),
            )
            .add(
                settings::item::builder("Export codes")
                    .description("As a Proton Authenticator export, with or without a password.")
                    .control(widget::button::standard("Export…").on_press(Message::RequestExport)),
            );

        let protection = if self.lock.is_some() { "your app lock password" } else { "a key kept in your keyring" };
        let about = widget::text::caption(format!(
            "Version {}. Codes are stored in {}, encrypted with {protection}. \
             Codes, imports and encryption come from Proton's open-source Rust core. \
             Not an official Proton app.",
            env!("CARGO_PKG_VERSION"),
            store::vault_path().display(),
        ));

        let content = widget::column::with_capacity(4)
            .push(security)
            .push(appearance)
            .push(data)
            .push(about)
            .spacing(cosmic::theme::spacing().space_m);
        context_drawer::context_drawer(content, Message::CloseDrawer).title("Settings")
    }

    fn export(&mut self, path: PathBuf) -> Result<(), String> {
        let password = self.pending_export.take().flatten();
        let contents = match password {
            Some(password) => self.client.export_entries_with_password(self.entries.clone(), password.as_str()),
            None => self.client.export_entries(self.entries.clone()),
        }
        .map_err(|error| format!("Cannot export: {error:?}"))?;
        store::write_private(&path, contents.as_bytes())
    }

    fn handle_key(&mut self, key: Key, modifiers: Modifiers) -> Task<cosmic::Action<Message>> {
        if !modifiers.control() || self.locked.is_some() {
            return Task::none();
        }
        let Key::Character(character) = key else {
            return Task::none();
        };
        match character.as_str() {
            "f" => widget::text_input::focus(self.search_id.clone()),
            "n" => self.update(Message::AddManually),
            "o" | "i" => self.update(Message::ImportFile),
            "v" => self.update(Message::PasteLink),
            "," => self.update(Message::OpenSettings),
            _ => Task::none(),
        }
    }
}

impl cosmic::Application for AppModel {
    type Executor = cosmic::executor::Default;
    type Flags = ();
    type Message = Message;

    const APP_ID: &'static str = "dev.nilltadios.CosmicAuthenticator";

    fn core(&self) -> &cosmic::Core {
        &self.core
    }

    fn core_mut(&mut self) -> &mut cosmic::Core {
        &mut self.core
    }

    fn init(core: cosmic::Core, _flags: ()) -> (Self, Task<cosmic::Action<Message>>) {
        let (lock_config, error) = match lock::load() {
            Ok(config) => (config, None),
            Err(error) => (None, Some(error)),
        };
        let mut app = AppModel {
            core,
            client: AuthenticatorClient::new(),
            entries: Vec::new(),
            codes: Vec::new(),
            now: 0,
            query: String::new(),
            settings: crate::settings::load(),
            logos: Logos::new(),
            toasts: widget::Toasts::new(Message::CloseToast),
            error,
            drawer: None,
            dialog: None,
            add_menu_open: false,
            pending_export: None,
            session: None,
            links: Links::new(),
            sync: SyncStatus::Off,
            sign_in_state: None,
            vault_key: None,
            locked: lock_config.is_some().then(Locked::default),
            after_unlock: Vec::new(),
            lock: lock_config,
            search_id: widget::Id::unique(),
            password_id: widget::Id::unique(),
        };
        app.refresh_codes();
        app.set_header_title(String::from("Authenticator"));

        let mut tasks = vec![if app.locked.is_some() {
            widget::text_input::focus(app.password_id.clone())
        } else {
            app.open_data(None)
        }];
        if let Some(id) = app.core.main_window_id() {
            tasks.push(app.set_window_title(String::from("Authenticator"), id));
        }
        if app.settings.theme != AppTheme::System {
            tasks.push(cosmic::command::set_theme(app.settings.theme.theme()));
        }
        #[cfg(feature = "preview")]
        for message in preview_messages() {
            tasks.push(app.update(message));
        }
        (app, Task::batch(tasks))
    }

    fn context_drawer(&self) -> Option<ContextDrawer<'_, Message>> {
        if !self.core.window.show_context || self.locked.is_some() {
            return None;
        }
        match self.drawer.as_ref()? {
            Drawer::Form(form) => Some(self.form_drawer(form)),
            Drawer::Settings => Some(self.settings_drawer()),
        }
    }

    fn dialog(&self) -> Option<Element<'_, Message>> {
        if self.locked.is_some() {
            return None;
        }
        let dialog = match self.dialog.as_ref()? {
            Dialog::Delete { id } => {
                let entry = self.entries.iter().find(|entry| &entry.id == id)?;
                let label = if entry.issuer().is_empty() { entry.name() } else { entry.issuer() };
                widget::dialog()
                    .title(format!("Delete the {label} code?"))
                    .body(format!(
                        "Make sure you can still sign in to {label}, with another authenticator or a recovery \
                         code, or turn off two-factor authentication there first. This cannot be undone."
                    ))
                    .icon(icon::from_name("dialog-warning-symbolic").size(64))
                    .primary_action(widget::button::destructive("Delete").on_press(Message::ConfirmDelete))
                    .secondary_action(widget::button::standard("Cancel").on_press(Message::CloseDialog))
            }
            Dialog::ImportPassword { password, wrong, .. } => {
                let mut controls = widget::column::with_capacity(2).spacing(8).push(
                    widget::secure_input("Password", password.as_str(), None, true)
                        .id(self.password_id.clone())
                        .on_input(|text| Message::ImportPassword(Secret::from(text)))
                        .on_submit(|_| Message::SubmitImportPassword),
                );
                if *wrong {
                    controls = controls.push(widget::text::caption("Wrong password. Try again."));
                }
                widget::dialog()
                    .title("Password-protected export")
                    .body("Enter the password that was set when this file was exported.")
                    .control(controls)
                    .primary_action(widget::button::suggested("Import").on_press(Message::SubmitImportPassword))
                    .secondary_action(widget::button::standard("Cancel").on_press(Message::CloseDialog))
            }
            Dialog::Export { password, confirm, error } => {
                let mut controls = widget::column::with_capacity(3)
                    .spacing(8)
                    .push(
                        widget::secure_input("Password (optional)", password.as_str(), None, true)
                            .id(self.password_id.clone())
                            .on_input(|text| Message::ExportPassword(Secret::from(text)))
                            .on_submit(|_| Message::Export),
                    )
                    .push(
                        widget::secure_input("Repeat password", confirm.as_str(), None, true)
                            .on_input(|text| Message::ExportConfirm(Secret::from(text)))
                            .on_submit(|_| Message::Export),
                    );
                if let Some(error) = error {
                    controls = controls.push(widget::text::caption(*error));
                }
                widget::dialog()
                    .title("Export codes")
                    .body(
                        "Anyone who gets an export without a password can copy every code in it. \
                         With a password, the file is encrypted and Proton Authenticator can import it.",
                    )
                    .control(controls)
                    .primary_action(widget::button::suggested("Export…").on_press(Message::Export))
                    .secondary_action(widget::button::standard("Cancel").on_press(Message::CloseDialog))
            }
            Dialog::CreateLock { password, confirm, error, working } => {
                let mut controls = widget::column::with_capacity(4)
                    .spacing(8)
                    .push(
                        widget::secure_input("Password", password.as_str(), None, true)
                            .id(self.password_id.clone())
                            .on_input(|text| Message::LockPassword(Secret::from(text)))
                            .on_submit(|_| Message::CreateLock),
                    )
                    .push(
                        widget::secure_input("Confirm password", confirm.as_str(), None, true)
                            .on_input(|text| Message::LockConfirm(Secret::from(text)))
                            .on_submit(|_| Message::CreateLock),
                    )
                    .push(widget::text::caption("Your data will be erased after 10 failed attempts."));
                if let Some(error) = error {
                    controls = controls.push(widget::text::body(error.clone()));
                }
                let create = if *working {
                    widget::button::suggested("Creating…")
                } else {
                    widget::button::suggested("Create").on_press(Message::CreateLock)
                };
                widget::dialog()
                    .title("Create password")
                    .body("You will need this password to unlock Authenticator every time it restarts.")
                    .control(controls)
                    .primary_action(create)
                    .secondary_action(widget::button::standard("Cancel").on_press(Message::CloseDialog))
            }
            Dialog::RemoveLock { password, error, working } => {
                let mut controls = widget::column::with_capacity(2).spacing(8).push(
                    widget::secure_input("Password", password.as_str(), None, true)
                        .id(self.password_id.clone())
                        .on_input(|text| Message::LockPassword(Secret::from(text)))
                        .on_submit(|_| Message::RemoveLock),
                );
                if let Some(error) = error {
                    controls = controls.push(widget::text::body(error.clone()));
                }
                let confirm = if *working {
                    widget::button::suggested("Checking…")
                } else {
                    widget::button::suggested("Confirm").on_press(Message::RemoveLock)
                };
                widget::dialog()
                    .title("Confirm password")
                    .body("Enter your current password to turn off the app lock.")
                    .control(controls)
                    .primary_action(confirm)
                    .secondary_action(widget::button::standard("Cancel").on_press(Message::CloseDialog))
            }
        };
        Some(dialog.into())
    }

    fn view(&self) -> Element<'_, Message> {
        if let Some(locked) = &self.locked {
            return widget::toaster(&self.toasts, self.unlock_view(locked));
        }
        let spacing = cosmic::theme::spacing();
        let mut content = widget::column::with_capacity(3).push(self.toolbar()).spacing(spacing.space_s);

        if let Some(error) = &self.error {
            content = content.push(widget::warning(error.clone()).on_close(Message::DismissError));
        }

        let body: Element<_> = if self.visible().is_empty() {
            self.empty_state()
        } else {
            widget::responsive(move |size| self.grid(size.width)).into()
        };
        content = content.push(body);

        let page = container(content).padding(spacing.space_m).width(Length::Fill).height(Length::Fill);
        widget::toaster(&self.toasts, page)
    }

    /// Ticks on each whole second, so codes roll over when the period does.
    fn subscription(&self) -> Subscription<Message> {
        let ticks = Subscription::run(|| {
            cosmic::iced::stream::channel(1, |mut output: cosmic::iced::futures::channel::mpsc::Sender<Message>| async move {
                loop {
                    let since_epoch = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
                    let to_next_second = Duration::from_secs(1) - Duration::from_nanos(since_epoch.subsec_nanos() as u64);
                    tokio::time::sleep(to_next_second + Duration::from_millis(5)).await;
                    if output.send(Message::Tick).await.is_err() {
                        break;
                    }
                }
            })
        });
        let keys = keyboard::listen().filter_map(|event| match event {
            keyboard::Event::KeyPressed { key, modifiers, .. } => Some(Message::Key(key, modifiers)),
            _ => None,
        });
        Subscription::batch([ticks, keys])
    }

    fn on_escape(&mut self) -> Task<cosmic::Action<Message>> {
        if self.add_menu_open {
            self.add_menu_open = false;
        } else if self.dialog.is_some() {
            self.dialog = None;
        } else if self.drawer.is_some() {
            self.close_drawer();
        } else if !self.query.is_empty() {
            self.query.clear();
        }
        Task::none()
    }

    fn update(&mut self, message: Message) -> Task<cosmic::Action<Message>> {
        match message {
            Message::Tick => self.refresh_codes(),
            Message::Key(key, modifiers) => return self.handle_key(key, modifiers),
            Message::Search(query) => self.query = query,
            Message::Copy(index) | Message::CopyNext(index) if index >= self.codes.len() => {}
            Message::Copy(index) => {
                let code = self.codes[index].0.clone();
                let toast = self.toast(format!("Copied the {} code", self.entries[index].issuer()));
                return Task::batch([cosmic::iced::clipboard::write(code), toast]);
            }
            Message::CopyNext(index) => {
                let code = self.codes[index].1.clone();
                let toast = self.toast(format!("Copied the next {} code", self.entries[index].issuer()));
                return Task::batch([cosmic::iced::clipboard::write(code), toast]);
            }
            Message::CloseToast(id) => self.toasts.remove(id),
            Message::DismissError => self.error = None,

            Message::ToggleAddMenu => self.add_menu_open = !self.add_menu_open,
            Message::CloseAddMenu => self.add_menu_open = false,
            Message::AddManually => self.open_drawer(Drawer::Form(EntryForm::default())),
            Message::ScanQrImage => {
                self.add_menu_open = false;
                let images = ["image/png", "image/jpeg", "image/webp", "image/gif", "image/bmp"]
                    .into_iter()
                    .fold(FileFilter::new("Images"), FileFilter::mimetype);
                return open_file("Choose a QR code image", Some(images));
            }
            Message::PasteLink => {
                self.add_menu_open = false;
                return cosmic::iced::clipboard::read().map(|text| cosmic::Action::App(Message::Pasted(text)));
            }
            Message::Pasted(text) => {
                let text = text.unwrap_or_default();
                let link = text.trim();
                if !(link.starts_with("otpauth://") || link.starts_with("otpauth-migration://") || link.starts_with("steam://")) {
                    return self.toast("The clipboard has no otpauth:// link. Copy the link, then try again.");
                }
                return match import::import_text(link, None) {
                    // A single new code opens in the form, so it can be checked and named first.
                    Ok(imported) if imported.entries.len() == 1 => {
                        let mut form = EntryForm::edit(&imported.entries[0]);
                        form.editing = None;
                        self.open_drawer(Drawer::Form(form));
                        Task::none()
                    }
                    Ok(imported) => self.add_entries(imported),
                    Err(error) => self.toast(error.message()),
                };
            }
            Message::ImportFile => {
                self.add_menu_open = false;
                return open_file("Import codes", None);
            }
            Message::FileOpened(Ok(contents)) => return self.import(contents, None),
            Message::FileOpened(Err(error)) => {
                if !is_cancelled(&error) {
                    return self.toast(error);
                }
            }
            Message::ImportPassword(text) => {
                if let Some(Dialog::ImportPassword { password, .. }) = &mut self.dialog {
                    *password = text;
                }
            }
            Message::SubmitImportPassword => {
                if let Some(Dialog::ImportPassword { contents, password, .. }) = self.dialog.take() {
                    return self.import(contents, Some(password));
                }
            }

            Message::Form(field) => {
                if let Some(Drawer::Form(form)) = &mut self.drawer {
                    form.apply(field);
                }
            }
            Message::SaveForm => {
                let Some(Drawer::Form(form)) = &mut self.drawer else {
                    return Task::none();
                };
                let existing = form.editing.as_ref().and_then(|id| self.entries.iter().position(|entry| &entry.id == id));
                match form.build(existing.map(|index| &self.entries[index])) {
                    Err(error) => form.error = Some(error),
                    Ok(entry) => {
                        let label = entry.issuer();
                        match existing {
                            Some(index) => self.entries[index] = entry,
                            None => {
                                let uri = entry.uri();
                                if self.entries.iter().any(|existing| existing.uri() == uri) {
                                    form.error = Some(String::from("This code is already in your list"));
                                    return Task::none();
                                }
                                self.entries.push(entry);
                            }
                        }
                        if self.persist() {
                            self.close_drawer();
                            self.refresh_codes();
                            let verb = if existing.is_some() { "Saved" } else { "Added" };
                            let toast = self.toast(format!("{verb} the {label} code"));
                            return Task::batch([toast, self.request_logos()]);
                        }
                    }
                }
            }
            Message::Edit(index) | Message::RequestDelete(index) if self.is_synced(index) => {
                return self.toast("Codes from Proton are read-only here until two-way sync is finished");
            }
            Message::Edit(index) => {
                if let Some(entry) = self.entries.get(index) {
                    let form = EntryForm::edit(entry);
                    self.open_drawer(Drawer::Form(form));
                }
            }
            Message::RequestDelete(index) => {
                if let Some(entry) = self.entries.get(index) {
                    self.dialog = Some(Dialog::Delete { id: entry.id.clone() });
                }
            }
            Message::ConfirmDelete => {
                if let Some(Dialog::Delete { id }) = self.dialog.take()
                    && let Some(index) = self.entries.iter().position(|entry| entry.id == id)
                {
                    let removed = self.entries.remove(index);
                    if self.persist() {
                        if matches!(&self.drawer, Some(Drawer::Form(form)) if form.editing.as_ref() == Some(&id)) {
                            self.close_drawer();
                        }
                        self.refresh_codes();
                        let label = removed.issuer();
                        return self.toast(format!("Deleted the {label} code"));
                    }
                    // Keep the list in step with the vault on disk.
                    self.entries.insert(index, removed);
                }
            }
            Message::Reorder(order) => {
                if order.len() == self.entries.len() {
                    let previous = self.entries.clone();
                    self.entries = order.iter().map(|&index| previous[index].clone()).collect();
                    if !self.persist() {
                        self.entries = previous;
                    }
                    self.refresh_codes();
                }
            }

            Message::OpenSettings => self.open_drawer(Drawer::Settings),
            Message::CloseDrawer => self.close_drawer(),
            Message::CloseDialog => {
                self.dialog = None;
            }
            Message::HideCodes(hide) => {
                self.settings.hide_codes = hide;
                self.save_settings();
            }
            Message::ShowLogos(show) => {
                self.settings.show_logos = show;
                self.save_settings();
                return self.request_logos();
            }
            Message::Theme(index) => {
                self.settings.theme = AppTheme::ALL[index];
                self.save_settings();
                return cosmic::command::set_theme(self.settings.theme.theme());
            }
            Message::LogoLoaded(key, handle) => self.logos.finish(key, handle),

            Message::RequestExport => {
                if self.entries.is_empty() {
                    return self.toast("There are no codes to export");
                }
                self.dialog = Some(Dialog::Export { password: Secret::default(), confirm: Secret::default(), error: None });
                return widget::text_input::focus(self.password_id.clone());
            }
            Message::ExportPassword(text) => {
                if let Some(Dialog::Export { password, error, .. }) = &mut self.dialog {
                    *password = text;
                    *error = None;
                }
            }
            Message::ExportConfirm(text) => {
                if let Some(Dialog::Export { confirm, error, .. }) = &mut self.dialog {
                    *confirm = text;
                    *error = None;
                }
            }
            Message::Export => {
                let Some(Dialog::Export { password, confirm, error }) = &mut self.dialog else {
                    return Task::none();
                };
                if password != confirm {
                    *error = Some("The passwords do not match");
                    return Task::none();
                }
                let password = std::mem::take(password);
                self.pending_export = Some(Some(password).filter(|password| !password.is_empty()));
                self.dialog = None;
                let file_name = format!("authenticator-export-{}.json", iso_date(unix_now()));
                return cosmic::task::future(async move {
                    let dialog = file_chooser::save::Dialog::new().title(String::from("Export codes")).file_name(file_name);
                    let result = match dialog.save_file().await {
                        Ok(response) => response
                            .url()
                            .and_then(|url| url.to_file_path().ok())
                            .ok_or_else(|| String::from("Choose a local folder for the export")),
                        Err(error) => Err(error.to_string()),
                    };
                    Message::ExportPath(result)
                });
            }
            Message::ExportPath(Ok(path)) => {
                return match self.export(path.clone()) {
                    Ok(()) => self.toast(format!("Exported {} codes to {}", self.entries.len(), path.display())),
                    Err(error) => {
                        self.error = Some(error);
                        Task::none()
                    }
                };
            }
            Message::SyncToggle(true) => {
                if self.session.is_none() && self.sync != SyncStatus::SigningIn {
                    return self.sign_in(false);
                }
            }
            Message::SyncToggle(false) => {
                let Some(session) = self.session.clone() else {
                    self.sync = SyncStatus::Off;
                    return Task::none();
                };
                self.forget_session();
                self.sync = SyncStatus::Off;
                // Ending the session on Proton is best effort; the local copy is gone either way.
                return background(move || proton_sync::sign_out(&session), |_| Message::SignedOut);
            }
            Message::SignedOut => return self.toast("Sync disabled"),

            Message::AfterUnlock(messages) => self.after_unlock = messages,
            Message::LockInput(text) => {
                if let Some(locked) = &mut self.locked {
                    locked.password = text;
                }
            }
            Message::Unlock => {
                let (Some(config), Some(locked)) = (self.lock.clone(), self.locked.as_mut()) else {
                    return Task::none();
                };
                if locked.checking || locked.password.is_empty() {
                    return Task::none();
                }
                locked.checking = true;
                let password = locked.password.clone();
                return background(move || lock::verify(&config, password.as_str()), Message::Unlocked);
            }
            Message::Unlocked(Ok(Some(key))) => {
                self.locked = None;
                if let Some(config) = self.lock.as_mut().filter(|config| config.failed_attempts > 0) {
                    config.failed_attempts = 0;
                    if let Err(error) = lock::save(config) {
                        self.error = Some(error);
                    }
                }
                let mut tasks = vec![self.open_data(Some(key))];
                for message in std::mem::take(&mut self.after_unlock) {
                    tasks.push(self.update(message));
                }
                return Task::batch(tasks);
            }
            Message::Unlocked(Ok(None)) => {
                let left = self.record_wrong_password();
                if left == 0 {
                    return self.toast("Too many wrong passwords. The data on this device was erased.");
                }
                if let Some(locked) = &mut self.locked {
                    locked.checking = false;
                    locked.password = Secret::default();
                    locked.error = Some(wrong_password_message(left));
                }
            }
            Message::Unlocked(Err(error)) => {
                if let Some(locked) = &mut self.locked {
                    locked.checking = false;
                    locked.error = Some(error);
                }
            }
            Message::AppLock(_) | Message::CreateLock | Message::RemoveLock if self.locked.is_some() => {}
            Message::AppLock(index) => {
                let want_lock = index == 1;
                if want_lock == self.lock.is_some() {
                    return Task::none();
                }
                self.dialog = Some(if want_lock {
                    Dialog::CreateLock { password: Secret::default(), confirm: Secret::default(), error: None, working: false }
                } else {
                    Dialog::RemoveLock { password: Secret::default(), error: None, working: false }
                });
                return widget::text_input::focus(self.password_id.clone());
            }
            Message::LockPassword(text) => match &mut self.dialog {
                Some(Dialog::CreateLock { password, error, .. } | Dialog::RemoveLock { password, error, .. }) => {
                    *password = text;
                    *error = None;
                }
                _ => {}
            },
            Message::LockConfirm(text) => {
                if let Some(Dialog::CreateLock { confirm, error, .. }) = &mut self.dialog {
                    *confirm = text;
                    *error = None;
                }
            }
            Message::CreateLock => {
                let Some(Dialog::CreateLock { password, confirm, error, working }) = &mut self.dialog else {
                    return Task::none();
                };
                if *working {
                    return Task::none();
                }
                if password.is_empty() {
                    *error = Some(String::from("Enter a password"));
                    return Task::none();
                }
                if password != confirm {
                    *error = Some(String::from("Passwords do not match"));
                    return Task::none();
                }
                *working = true;
                let password = password.clone();
                return background(move || lock::create(password.as_str(), lock::RECOMMENDED), Message::LockCreated);
            }
            Message::LockCreated(Ok((config, key))) => match self.enable_lock(config, key) {
                Ok(()) => {
                    self.dialog = None;
                    return self.toast("App lock turned on");
                }
                Err(error) => {
                    if let Some(Dialog::CreateLock { error: shown, working, .. }) = &mut self.dialog {
                        *shown = Some(error);
                        *working = false;
                    }
                }
            },
            Message::LockCreated(Err(error)) => {
                if let Some(Dialog::CreateLock { error: shown, working, .. }) = &mut self.dialog {
                    *shown = Some(error);
                    *working = false;
                }
            }
            Message::RemoveLock => {
                let (Some(config), Some(Dialog::RemoveLock { password, working, .. })) = (self.lock.clone(), &mut self.dialog) else {
                    return Task::none();
                };
                if *working || password.is_empty() {
                    return Task::none();
                }
                *working = true;
                let password = password.clone();
                return background(move || lock::verify(&config, password.as_str()), Message::LockRemoveChecked);
            }
            Message::LockRemoveChecked(result) => {
                let outcome = match result {
                    Ok(Some(_)) => self.disable_lock().map(|()| None),
                    Ok(None) => {
                        let left = self.record_wrong_password();
                        if left == 0 {
                            return self.toast("Too many wrong passwords. The data on this device was erased.");
                        }
                        Ok(Some(wrong_password_message(left)))
                    }
                    Err(error) => Err(error),
                };
                match outcome {
                    Ok(None) => {
                        self.dialog = None;
                        return self.toast("App lock turned off");
                    }
                    Ok(Some(message)) | Err(message) => {
                        if let Some(Dialog::RemoveLock { password, error, working }) = &mut self.dialog {
                            *password = Secret::default();
                            *error = Some(message);
                            *working = false;
                        }
                    }
                }
            }
            Message::SignUp => return self.sign_in(true),
            Message::LoginWindowClosed(Err(error)) => {
                self.sign_in_state = None;
                self.sync = SyncStatus::Off;
                if !error.is_empty() {
                    self.sync = SyncStatus::Error(error);
                }
            }
            Message::LoginWindowClosed(Ok(fragment)) => {
                let Some(state) = self.sign_in_state.take() else {
                    return Task::none();
                };
                return background(move || proton_sync::sign_in(&fragment, &state), Message::SignedIn);
            }
            Message::SignedIn(Err(error)) => self.sync = SyncStatus::Error(error.message()),
            Message::SignedIn(Ok(session)) => {
                if let Err(error) = session::save(&session, self.lock_key().as_ref()) {
                    self.sync = SyncStatus::Error(error);
                    return Task::none();
                }
                self.session = Some(session);
                let toast = self.toast("Sync enabled");
                return Task::batch([toast, self.start_sync()]);
            }
            Message::SyncNow => {
                if self.sync != SyncStatus::Syncing {
                    return self.start_sync();
                }
            }
            Message::Synced(result) => {
                let (session, result) = *result;
                if self.session.is_some() {
                    return self.apply_sync(session, result);
                }
            }
            Message::ExportPath(Err(error)) => {
                self.pending_export = None;
                if !is_cancelled(&error) {
                    return self.toast(error);
                }
            }
        }
        Task::none()
    }
}

/// Opens one view at startup, named by `AUTHENTICATOR_PREVIEW`, so every
/// screen can be screenshotted without driving the mouse. Only in builds with
/// `--features preview`.
#[cfg(feature = "preview")]
const PREVIEW_PASSWORD: &str = "preview password";

#[cfg(feature = "preview")]
fn preview_messages() -> Vec<Message> {
    match std::env::var("AUTHENTICATOR_PREVIEW").unwrap_or_default().as_str() {
        "add-menu" => vec![Message::ToggleAddMenu],
        "add" => vec![Message::AddManually, Message::Form(Field::ShowAdvanced)],
        "add-error" => vec![
            Message::AddManually,
            Message::Form(Field::Name(String::from("me@example.com"))),
            Message::Form(Field::Secret(String::from("JBSW 0000"))),
            Message::SaveForm,
        ],
        "edit" => vec![Message::Edit(0)],
        "settings" => vec![Message::OpenSettings],
        "delete" => vec![Message::RequestDelete(2)],
        "export" => vec![Message::RequestExport],
        "hidden" => vec![Message::HideCodes(true)],
        "search" => vec![Message::Search(String::from("demo-user"))],
        // App lock steps, for demo/lock-test.sh. The password is a test value.
        "lock-create" => vec![
            Message::AppLock(1),
            Message::LockPassword(Secret::from(String::from(PREVIEW_PASSWORD))),
            Message::LockConfirm(Secret::from(String::from(PREVIEW_PASSWORD))),
            Message::CreateLock,
        ],
        "lock-create-form" => vec![Message::OpenSettings, Message::AppLock(1)],
        "lock-typed" => vec![Message::LockInput(Secret::from(String::from(PREVIEW_PASSWORD)))],
        "unlock-wrong" => vec![Message::LockInput(Secret::from(String::from("not the password"))), Message::Unlock],
        "unlock" => vec![Message::LockInput(Secret::from(String::from(PREVIEW_PASSWORD))), Message::Unlock],
        "unlock-then-remove" => vec![
            Message::LockInput(Secret::from(String::from(PREVIEW_PASSWORD))),
            Message::Unlock,
            Message::AfterUnlock(vec![
                Message::AppLock(0),
                Message::LockPassword(Secret::from(String::from(PREVIEW_PASSWORD))),
                Message::RemoveLock,
            ]),
        ],
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_codes_like_proton() {
        assert_eq!(format_code("658812", false), "658 812");
        assert_eq!(format_code("12345678", false), "1234 5678");
        assert_eq!(format_code("1234567", false), "1234567");
        assert_eq!(format_code("5GH2K", false), "5GH2K");
        assert_eq!(format_code("658812", true), "··· ···");
    }

    #[test]
    fn formats_utc_dates() {
        assert_eq!(iso_date(0), "1970-01-01");
        assert_eq!(iso_date(951_782_400), "2000-02-29");
        assert_eq!(iso_date(1_790_294_400), "2026-09-25");
    }
}
