// SPDX-License-Identifier: GPL-3.0-only

//! Wayland `xdg_activation_v1` token helper that tracks the latest input serial
//! across pointer, keyboard, and touch events.
//!
//! `libcosmic`'s bundled `iced_winit` always prefers `last_kbd_press` whenever
//! the window holds keyboard focus, discarding pointer click serials. That
//! makes compositors such as KWin reject the activation token on a mouse click
//! (leaving the target browser minimized or behind the app). Attaching a small
//! Wayland queue to the window's existing `wl_display` lets us observe every
//! seat input event on this connection and mint tokens with the actual click or
//! keypress serial.

use std::collections::{HashMap, VecDeque};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::{Arc, Mutex};

use cosmic::iced::futures::channel::oneshot;
use cosmic::iced::window::raw_window_handle::{RawDisplayHandle, RawWindowHandle};
use wayland_backend::client::{Backend, ObjectId, WaylandError};
use wayland_client::protocol::{
    wl_keyboard, wl_pointer, wl_registry, wl_seat, wl_surface::WlSurface, wl_touch,
};
use wayland_client::{Connection, Dispatch, EventQueue, Proxy, QueueHandle, WEnum};
use wayland_protocols::xdg::activation::v1::client::{xdg_activation_token_v1, xdg_activation_v1};

#[derive(Clone)]
pub struct WaylandActivation {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for WaylandActivation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WaylandActivation")
    }
}

struct Inner {
    requests: Arc<Mutex<RequestQueue>>,
    wake_write: OwnedFd,
}

impl Drop for Inner {
    fn drop(&mut self) {
        if let Ok(mut queue) = self.requests.lock() {
            queue.close();
        }
        // Dropping `wake_write` closes the write end of the pipe, waking the
        // worker thread's `poll` with POLLHUP/EOF so it exits cleanly.
    }
}

#[derive(Default)]
struct RequestQueue {
    closed: bool,
    pending: VecDeque<oneshot::Sender<Option<String>>>,
}

impl RequestQueue {
    fn push(&mut self, sender: oneshot::Sender<Option<String>>) -> bool {
        if self.closed {
            let _ = sender.send(None);
            return false;
        }
        self.pending.push_back(sender);
        true
    }

    fn take_all(&mut self) -> Vec<oneshot::Sender<Option<String>>> {
        self.pending.drain(..).collect()
    }

    fn close(&mut self) {
        self.closed = true;
        for sender in self.pending.drain(..) {
            let _ = sender.send(None);
        }
    }
}

impl WaylandActivation {
    /// Attaches a dedicated Wayland event queue to `window`'s display and
    /// spawns a background thread that tracks seat input serials and services
    /// `xdg_activation_v1` token requests. Returns `None` outside Wayland.
    pub fn attach(window: &dyn cosmic::iced::window::Window) -> Option<Self> {
        let display_handle = window.display_handle().ok()?;
        let window_handle = window.window_handle().ok()?;
        let (RawDisplayHandle::Wayland(dh), RawWindowHandle::Wayland(wh)) =
            (display_handle.as_raw(), window_handle.as_raw())
        else {
            return None;
        };

        // SAFETY: `dh.display` is a live `wl_display*` owned by the windowing
        // loop for the lifetime of the application; `from_foreign_display`
        // creates an independent `wl_event_queue` and never disconnects the
        // display on drop.
        let backend = unsafe { Backend::from_foreign_display(dh.display.as_ptr().cast()) };
        let conn = Connection::from_backend(backend);

        // SAFETY: `wh.surface` is the window's live `wl_surface*` while this
        // callback runs; `ObjectId::from_ptr` checks its Wayland interface and
        // clones its liveness handle if Rust-managed.
        let surface_id =
            unsafe { ObjectId::from_ptr(WlSurface::interface(), wh.surface.as_ptr().cast()) }.ok()?;
        let main_surface = WlSurface::from_id(&conn, surface_id).ok()?;

        let (wake_read, wake_write) = create_wake_pipe().ok()?;
        let requests = Arc::new(Mutex::new(RequestQueue::default()));
        let worker_requests = Arc::clone(&requests);

        std::thread::Builder::new()
            .name(String::from("wayland-activation"))
            .spawn(move || run_loop(conn, main_surface, wake_read, worker_requests))
            .ok()?;

        Some(Self { inner: Arc::new(Inner { requests, wake_write }) })
    }

    /// Requests a fresh `xdg_activation_v1` token tied to the most recent
    /// pointer, keyboard, or touch input serial on this window.
    pub fn request_token(&self) -> oneshot::Receiver<Option<String>> {
        let (sender, receiver) = oneshot::channel();
        let queued = self.inner.requests.lock().map(|mut q| q.push(sender)).unwrap_or(false);
        if queued {
            notify_wake_pipe(&self.inner.wake_write);
        }
        receiver
    }
}

fn create_wake_pipe() -> std::io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `fds` is a valid 2-element array for `pipe2`.
    let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `pipe2` succeeded and returned two newly opened file descriptors.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

fn notify_wake_pipe(fd: &OwnedFd) {
    let byte = [1u8; 1];
    // Non-blocking write: EAGAIN simply means a wakeup byte is already queued.
    // SAFETY: `fd` is a valid open pipe fd and `byte` is readable for 1 byte.
    let _ = unsafe { libc::write(fd.as_raw_fd(), byte.as_ptr().cast(), byte.len()) };
}

/// Drains all queued wakeup bytes. Returns `false` on EOF (pipe closed).
fn drain_wake_pipe(fd: &OwnedFd) -> bool {
    let mut buf = [0u8; 64];
    loop {
        // SAFETY: `fd` is a valid open non-blocking pipe fd and `buf` is writable.
        let n = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        if n > 0 {
            continue;
        }
        if n == 0 {
            return false;
        }
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return err.kind() == std::io::ErrorKind::WouldBlock;
    }
}

/// Tracks the most recent input serial across pointer, keyboard, and touch
/// regardless of which device currently holds focus.
#[derive(Clone, Debug, PartialEq, Eq)]
struct LastInput<Seat, Surface> {
    seat_name: u32,
    seat: Seat,
    serial: u32,
    surface: Option<Surface>,
}

struct SerialTracker<Seat, Surface> {
    last: Option<LastInput<Seat, Surface>>,
}

impl<Seat, Surface> Default for SerialTracker<Seat, Surface> {
    fn default() -> Self {
        Self { last: None }
    }
}

impl<Seat, Surface> SerialTracker<Seat, Surface> {
    fn record(&mut self, seat_name: u32, seat: Seat, serial: u32, surface: Option<Surface>) {
        self.last = Some(LastInput { seat_name, seat, serial, surface });
    }

    fn clear_seat(&mut self, seat_name: u32) {
        if self.last.as_ref().is_some_and(|input| input.seat_name == seat_name) {
            self.last = None;
        }
    }

    fn latest(&self) -> Option<&LastInput<Seat, Surface>> {
        self.last.as_ref()
    }
}

struct SeatState {
    seat: wl_seat::WlSeat,
    pointer: Option<wl_pointer::WlPointer>,
    keyboard: Option<wl_keyboard::WlKeyboard>,
    touch: Option<wl_touch::WlTouch>,
    pointer_surface: Option<WlSurface>,
    keyboard_surface: Option<WlSurface>,
}

impl SeatState {
    fn new(seat: wl_seat::WlSeat) -> Self {
        Self {
            seat,
            pointer: None,
            keyboard: None,
            touch: None,
            pointer_surface: None,
            keyboard_surface: None,
        }
    }

    fn release_all(&mut self) {
        if let Some(pointer) = self.pointer.take()
            && pointer.version() >= 3
        {
            pointer.release();
        }
        if let Some(keyboard) = self.keyboard.take()
            && keyboard.version() >= 3
        {
            keyboard.release();
        }
        if let Some(touch) = self.touch.take()
            && touch.version() >= 3
        {
            touch.release();
        }
        if self.seat.version() >= 5 {
            self.seat.release();
        }
    }
}

struct State {
    main_surface: WlSurface,
    activation: Option<(u32, xdg_activation_v1::XdgActivationV1)>,
    seats: HashMap<u32, SeatState>,
    tracker: SerialTracker<wl_seat::WlSeat, WlSurface>,
    next_token_id: u64,
    in_flight: HashMap<u64, oneshot::Sender<Option<String>>>,
}

impl State {
    fn new(main_surface: WlSurface) -> Self {
        Self {
            main_surface,
            activation: None,
            seats: HashMap::new(),
            tracker: SerialTracker::default(),
            next_token_id: 0,
            in_flight: HashMap::new(),
        }
    }

    fn request_token(
        &mut self,
        qh: &QueueHandle<Self>,
        sender: oneshot::Sender<Option<String>>,
    ) {
        let Some((_, activation)) = &self.activation else {
            let _ = sender.send(None);
            return;
        };

        let token_id = self.next_token_id;
        self.next_token_id = self.next_token_id.wrapping_add(1);
        let token = activation.get_activation_token(qh, token_id);

        let surface = self
            .tracker
            .latest()
            .and_then(|input| input.surface.as_ref())
            .filter(|s| s.is_alive())
            .or_else(|| self.main_surface.is_alive().then_some(&self.main_surface));
        if let Some(surface) = surface {
            token.set_surface(surface);
        }
        if let Some(input) = self.tracker.latest()
            && input.seat.is_alive()
        {
            token.set_serial(input.serial, &input.seat);
        }
        token.commit();
        self.in_flight.insert(token_id, sender);
    }

    fn cleanup(&mut self) {
        for (_, sender) in self.in_flight.drain() {
            let _ = sender.send(None);
        }
        for (_, mut seat) in self.seats.drain() {
            seat.release_all();
        }
        if let Some((_, activation)) = self.activation.take() {
            activation.destroy();
        }
    }
}

impl Dispatch<wl_registry::WlRegistry, ()> for State {
    fn event(
        state: &mut Self,
        registry: &wl_registry::WlRegistry,
        event: wl_registry::Event,
        _: &(),
        _: &Connection,
        qh: &QueueHandle<Self>,
    ) {
        match event {
            wl_registry::Event::Global { name, interface, version } => match interface.as_str() {
                "xdg_activation_v1" if state.activation.is_none() => {
                    let bound = registry.bind::<xdg_activation_v1::XdgActivationV1, _, _>(
                        name,
                        1,
                        qh,
                        (),
                    );
                    state.activation = Some((name, bound));
                }
                "wl_seat" => {
                    let bound = registry.bind::<wl_seat::WlSeat, _, _>(
                        name,
                        version.min(9),
                        qh,
                        name,
                    );
                    state.seats.insert(name, SeatState::new(bound));
                }
                _ => {}
            },
            wl_registry::Event::GlobalRemove { name } => {
                if state.activation.as_ref().is_some_and(|(n, _)| *n == name)
                    && let Some((_, activation)) = state.activation.take()
                {
                    activation.destroy();
                }
                if let Some(mut seat) = state.seats.remove(&name) {
                    seat.release_all();
                }
                state.tracker.clear_seat(name);
            }
            _ => {}
        }
    }
}

impl Dispatch<wl_seat::WlSeat, u32> for State {
    fn event(
        state: &mut Self,
        seat: &wl_seat::WlSeat,
        event: wl_seat::Event,
        seat_name: &u32,
        _: &Connection,
        qh: &QueueHandle<Self>,
    ) {
        let wl_seat::Event::Capabilities { capabilities } = event else {
            return;
        };
        let Some(entry) = state.seats.get_mut(seat_name) else {
            return;
        };
        let caps = wl_seat::Capability::from_bits_truncate(capabilities.into());

        if caps.contains(wl_seat::Capability::Pointer) {
            if entry.pointer.is_none() {
                entry.pointer = Some(seat.get_pointer(qh, *seat_name));
            }
        } else if let Some(pointer) = entry.pointer.take() {
            entry.pointer_surface = None;
            if pointer.version() >= 3 {
                pointer.release();
            }
        }

        if caps.contains(wl_seat::Capability::Keyboard) {
            if entry.keyboard.is_none() {
                entry.keyboard = Some(seat.get_keyboard(qh, *seat_name));
            }
        } else if let Some(keyboard) = entry.keyboard.take() {
            entry.keyboard_surface = None;
            if keyboard.version() >= 3 {
                keyboard.release();
            }
        }

        if caps.contains(wl_seat::Capability::Touch) {
            if entry.touch.is_none() {
                entry.touch = Some(seat.get_touch(qh, *seat_name));
            }
        } else if let Some(touch) = entry.touch.take()
            && touch.version() >= 3
        {
            touch.release();
        }
    }
}

impl Dispatch<wl_pointer::WlPointer, u32> for State {
    fn event(
        state: &mut Self,
        _: &wl_pointer::WlPointer,
        event: wl_pointer::Event,
        seat_name: &u32,
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        let Some(entry) = state.seats.get_mut(seat_name) else {
            return;
        };
        match event {
            wl_pointer::Event::Enter { surface, .. } => {
                entry.pointer_surface = surface.is_alive().then_some(surface);
            }
            wl_pointer::Event::Leave { .. } => {
                entry.pointer_surface = None;
            }
            wl_pointer::Event::Button {
                serial,
                state: WEnum::Value(wl_pointer::ButtonState::Pressed),
                ..
            } => {
                let seat = entry.seat.clone();
                let surface = entry.pointer_surface.clone();
                state.tracker.record(*seat_name, seat, serial, surface);
            }
            _ => {}
        }
    }
}

impl Dispatch<wl_keyboard::WlKeyboard, u32> for State {
    fn event(
        state: &mut Self,
        _: &wl_keyboard::WlKeyboard,
        event: wl_keyboard::Event,
        seat_name: &u32,
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        let Some(entry) = state.seats.get_mut(seat_name) else {
            return;
        };
        match event {
            wl_keyboard::Event::Enter { surface, .. } => {
                entry.keyboard_surface = surface.is_alive().then_some(surface);
            }
            wl_keyboard::Event::Leave { .. } => {
                entry.keyboard_surface = None;
            }
            wl_keyboard::Event::Key {
                serial,
                state: WEnum::Value(wl_keyboard::KeyState::Pressed),
                ..
            } => {
                let seat = entry.seat.clone();
                let surface = entry.keyboard_surface.clone();
                state.tracker.record(*seat_name, seat, serial, surface);
            }
            _ => {}
        }
    }
}

impl Dispatch<wl_touch::WlTouch, u32> for State {
    fn event(
        state: &mut Self,
        _: &wl_touch::WlTouch,
        event: wl_touch::Event,
        seat_name: &u32,
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        if let wl_touch::Event::Down { serial, surface, .. } = event
            && let Some(entry) = state.seats.get(seat_name)
        {
            let seat = entry.seat.clone();
            let surface = surface.is_alive().then_some(surface);
            state.tracker.record(*seat_name, seat, serial, surface);
        }
    }
}

impl Dispatch<xdg_activation_v1::XdgActivationV1, ()> for State {
    fn event(
        _: &mut Self,
        _: &xdg_activation_v1::XdgActivationV1,
        _: xdg_activation_v1::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        // xdg_activation_v1 has no server-to-client events.
    }
}

impl Dispatch<xdg_activation_token_v1::XdgActivationTokenV1, u64> for State {
    fn event(
        state: &mut Self,
        token_obj: &xdg_activation_token_v1::XdgActivationTokenV1,
        event: xdg_activation_token_v1::Event,
        token_id: &u64,
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        if let xdg_activation_token_v1::Event::Done { token } = event {
            token_obj.destroy();
            if let Some(sender) = state.in_flight.remove(token_id) {
                let _ = sender.send((!token.is_empty()).then_some(token));
            }
        }
    }
}

fn flush_ignoring_wouldblock(event_queue: &EventQueue<State>) -> bool {
    match event_queue.flush() {
        Ok(()) => true,
        Err(WaylandError::Io(err)) if err.kind() == std::io::ErrorKind::WouldBlock => true,
        Err(_) => false,
    }
}

/// Reads any Wayland events already sitting in the socket buffer without
/// blocking, then dispatches our queue so the triggering click/key serial is
/// recorded before we mint an activation token.
fn drain_wayland_nonblocking(event_queue: &mut EventQueue<State>, state: &mut State) -> bool {
    if !flush_ignoring_wouldblock(event_queue) {
        return false;
    }
    if let Some(guard) = event_queue.prepare_read() {
        let mut pfd = libc::pollfd {
            fd: guard.connection_fd().as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `pfd` points to 1 valid `pollfd` with an open Wayland fd.
        let ready = unsafe { libc::poll(&mut pfd, 1, 0) };
        if ready > 0 && (pfd.revents & libc::POLLIN) != 0 {
            match guard.read() {
                Ok(_) => {}
                Err(WaylandError::Io(err)) if err.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => return false,
            }
        } else {
            // Cancel read immediately so other threads sharing `wl_display`
            // are never blocked waiting on us.
            drop(guard);
        }
    }
    event_queue.dispatch_pending(state).is_ok()
}

fn run_loop(
    conn: Connection,
    main_surface: WlSurface,
    wake_read: OwnedFd,
    requests: Arc<Mutex<RequestQueue>>,
) {
    let mut event_queue = conn.new_event_queue::<State>();
    let qh = event_queue.handle();
    let _registry = conn.display().get_registry(&qh, ());
    let mut state = State::new(main_surface);

    loop {
        if event_queue.dispatch_pending(&mut state).is_err() {
            break;
        }

        let (closed, pending) = match requests.lock() {
            Ok(mut queue) => (queue.closed, queue.take_all()),
            Err(_) => (true, Vec::new()),
        };

        if !pending.is_empty() {
            if !drain_wayland_nonblocking(&mut event_queue, &mut state) {
                for sender in pending {
                    let _ = sender.send(None);
                }
                break;
            }
            for sender in pending {
                state.request_token(&qh, sender);
            }
        }

        if closed || !flush_ignoring_wouldblock(&event_queue) {
            break;
        }

        let Some(guard) = event_queue.prepare_read() else {
            // More events are already buffered in our queue; dispatch them now.
            continue;
        };

        let mut fds = [
            libc::pollfd {
                fd: guard.connection_fd().as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd { fd: wake_read.as_raw_fd(), events: libc::POLLIN, revents: 0 },
        ];

        // SAFETY: `fds` holds 2 valid open file descriptors for the call.
        let ret = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
        if ret < 0 {
            drop(guard);
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }

        let wl_revents = fds[0].revents;
        let wake_revents = fds[1].revents;

        if (wl_revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL)) != 0 {
            drop(guard);
            break;
        }

        if (wl_revents & libc::POLLIN) != 0 {
            match guard.read() {
                Ok(_) => {}
                Err(WaylandError::Io(err)) if err.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => break,
            }
        } else {
            drop(guard);
        }

        if (wake_revents & libc::POLLIN) != 0 && !drain_wake_pipe(&wake_read) {
            break;
        }
        if (wake_revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL)) != 0 {
            break;
        }
    }

    if let Ok(mut queue) = requests.lock() {
        queue.close();
    }
    state.cleanup();
    let _ = event_queue.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pointer_click_supersedes_prior_keyboard_serial() {
        let mut tracker: SerialTracker<&'static str, &'static str> = SerialTracker::default();
        assert_eq!(tracker.latest(), None);

        // User typed earlier while keyboard focus was on the window.
        tracker.record(1, "seat0", 10, Some("main"));
        assert_eq!(tracker.latest().map(|i| i.serial), Some(10));

        // User then clicked with the mouse while keyboard focus stayed on the
        // same window: the newer pointer serial must win (unlike iced_winit).
        tracker.record(1, "seat0", 42, Some("main"));
        assert_eq!(
            tracker.latest(),
            Some(&LastInput { seat_name: 1, seat: "seat0", serial: 42, surface: Some("main") })
        );

        // Removing an unrelated seat leaves the tracked serial intact.
        tracker.clear_seat(2);
        assert_eq!(tracker.latest().map(|i| i.serial), Some(42));

        // Removing the active seat clears the stale serial.
        tracker.clear_seat(1);
        assert_eq!(tracker.latest(), None);
    }

    #[test]
    fn wake_pipe_signals_and_detects_close() {
        let (read_fd, write_fd) = create_wake_pipe().expect("pipe2");
        notify_wake_pipe(&write_fd);
        notify_wake_pipe(&write_fd);
        assert!(drain_wake_pipe(&read_fd), "open pipe should remain alive after drain");

        drop(write_fd);
        assert!(!drain_wake_pipe(&read_fd), "closed pipe should report EOF");
    }

    #[test]
    fn closed_request_queue_resolves_waiters_with_none() {
        let mut queue = RequestQueue::default();
        let (tx1, mut rx1) = oneshot::channel();
        assert!(queue.push(tx1));

        queue.close();
        assert_eq!(rx1.try_recv(), Ok(Some(None)));

        let (tx2, mut rx2) = oneshot::channel();
        assert!(!queue.push(tx2));
        assert_eq!(rx2.try_recv(), Ok(Some(None)));
    }
}
