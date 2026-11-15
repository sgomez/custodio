//! What a peer of the snap socket may cost: connections, message size, time in the handshake and time idle, and how
//! often a refusal is written to the journal. Every connection runs through [`relay`], which is the only thing that
//! reads the peer's bytes before zbus does; hitting a bound closes that one connection.
//!
//! The values are constants, each with its reason, and `docs/api.md` ("Socket transport") repeats them; a test
//! compares the two.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, poll};
use rustix::fs::Timespec;
use rustix::io::retry_on_intr;

/// Concurrent connections per socket. A browser opens one or two; 32 leaves room for several profiles and keeps the
/// threads and descriptors of a flood small. One peer can use every slot (the bound is not per user).
pub const MAX_CONNECTIONS: usize = 32;
/// Largest message a peer may send, header included. It is the size of the largest message that can carry a legal
/// `Sign` ([`crate::dbus::MAX_SIGN_MESSAGE_LEN`]), so the socket accepts nothing the bus would not for that method.
pub const MAX_MESSAGE_LEN: usize = crate::dbus::MAX_SIGN_MESSAGE_LEN;
/// From accept to the `BEGIN` line. A local handshake takes milliseconds; 10 s tolerates a loaded machine.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Between the end of one message (or of the handshake) and the end of the next. It is measured from the start of a
/// message, so sending it one byte at a time does not hold the connection. It is long because a `Sign` waits for the
/// user to answer a polkit dialog while the peer is silent.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
/// Lines about refused connections per window; the rest are counted and reported in the next line.
pub const REFUSAL_LINES_PER_WINDOW: u32 = 10;
/// The window of the refusal log. 10 lines a minute cannot fill the journal's own rate limit, which would also
/// drop the audit entries of other callers.
pub const REFUSAL_WINDOW: Duration = Duration::from_secs(60);
/// Longest line of the handshake. The longest legitimate one is `AUTH ANONYMOUS <trace>`.
const MAX_HANDSHAKE_LINE: usize = 1024;
const HEADER_LEN: usize = 16;

/// The bounds one socket is served with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub connections: usize,
    pub message: usize,
    pub handshake: Duration,
    pub idle: Duration,
}

impl Limits {
    /// The values the daemon ships.
    pub const SHIPPED: Self = Self {
        connections: MAX_CONNECTIONS,
        message: MAX_MESSAGE_LEN,
        handshake: HANDSHAKE_TIMEOUT,
        idle: IDLE_TIMEOUT,
    };
}

/// The count of open connections. A [`Slot`] frees its place when dropped.
#[derive(Clone, Debug, Default)]
pub struct Slots(Arc<AtomicUsize>);

/// One place among the connections of a socket.
#[derive(Debug)]
pub struct Slot(Arc<AtomicUsize>);

impl Slots {
    /// A place, or `None` when `max` connections are open.
    #[must_use]
    pub fn take(&self, max: usize) -> Option<Slot> {
        self.0
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < max).then_some(n + 1)
            })
            .ok()
            .map(|_| Slot(Arc::clone(&self.0)))
    }

    /// Connections open now.
    #[must_use]
    pub fn open(&self) -> usize {
        self.0.load(Ordering::Acquire)
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// What to do with one refusal line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Line {
    /// Write it; `suppressed` lines before it were dropped.
    Write {
        suppressed: u32,
    },
    Drop,
}

/// At most `max` lines per `window`; later ones are counted.
#[derive(Debug)]
pub struct RateLimit {
    max: u32,
    window: Duration,
    state: Mutex<(Option<Instant>, u32, u32)>,
}

impl RateLimit {
    #[must_use]
    pub fn new(max: u32, window: Duration) -> Self {
        Self {
            max,
            window,
            state: Mutex::new((None, 0, 0)),
        }
    }

    /// The shipped rate.
    #[must_use]
    pub fn shipped() -> Self {
        Self::new(REFUSAL_LINES_PER_WINDOW, REFUSAL_WINDOW)
    }

    /// Whether a line at `now` is written.
    pub fn check(&self, now: Instant) -> Line {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let (start, written, dropped) = &mut *state;
        let fresh = start.is_none_or(|s| now.saturating_duration_since(s) >= self.window);
        if fresh {
            *start = Some(now);
            *written = 0;
        }
        if *written < self.max {
            *written += 1;
            Line::Write {
                suppressed: std::mem::take(dropped),
            }
        } else {
            *dropped = dropped.saturating_add(1);
            Line::Drop
        }
    }
}

/// Why a connection is closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Violation {
    HandshakeLine,
    BadMessage,
    TooLarge,
}

/// What one chunk of bytes did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fed {
    pub handshake_done: bool,
    pub completed: usize,
    /// A message began in this chunk and is not complete.
    pub began_partial: bool,
}

/// Follows the peer's bytes: handshake lines up to `BEGIN`, then the frames of messages.
#[derive(Debug)]
pub struct Framer {
    max: usize,
    state: State,
}

#[derive(Debug)]
enum State {
    Handshake(Vec<u8>),
    Header(Vec<u8>),
    Body(usize),
}

impl Framer {
    #[must_use]
    pub fn new(max: usize) -> Self {
        Self {
            max,
            state: State::Handshake(Vec::new()),
        }
    }

    fn mid_message(&self) -> bool {
        match &self.state {
            State::Handshake(_) => false,
            State::Header(h) => !h.is_empty(),
            State::Body(_) => true,
        }
    }

    /// Accounts for `bytes`.
    ///
    /// # Errors
    /// The bound the bytes broke; the connection must be closed and the bytes not passed on.
    pub fn feed(&mut self, mut bytes: &[u8]) -> Result<Fed, Violation> {
        let mut fed = Fed::default();
        while !bytes.is_empty() {
            let was_mid = self.mid_message();
            match &mut self.state {
                State::Handshake(line) => {
                    let Some((&byte, rest)) = bytes.split_first() else {
                        break;
                    };
                    bytes = rest;
                    if byte == b'\n' {
                        let done = line.strip_suffix(b"\r").unwrap_or(line) == b"BEGIN";
                        line.clear();
                        if done {
                            fed.handshake_done = true;
                            self.state = State::Header(Vec::new());
                        }
                    } else {
                        line.push(byte);
                        if line.len() > MAX_HANDSHAKE_LINE {
                            return Err(Violation::HandshakeLine);
                        }
                    }
                }
                State::Header(header) => {
                    let take = (HEADER_LEN - header.len()).min(bytes.len());
                    let (now, rest) = bytes.split_at(take);
                    header.extend_from_slice(now);
                    bytes = rest;
                    if header.len() == HEADER_LEN {
                        let total = frame_len(header)?;
                        if total > self.max {
                            return Err(Violation::TooLarge);
                        }
                        self.state = State::Body(total - HEADER_LEN);
                    }
                }
                State::Body(left) => {
                    let take = (*left).min(bytes.len());
                    *left -= take;
                    bytes = bytes.split_at(take).1;
                }
            }
            if matches!(self.state, State::Body(0)) {
                self.state = State::Header(Vec::new());
                fed.completed += 1;
            }
            if !was_mid && self.mid_message() {
                fed.began_partial = true;
            }
        }
        // A message that began and finished inside the chunk is not partial.
        fed.began_partial &= self.mid_message();
        Ok(fed)
    }
}

/// The length of the whole message the fixed header announces.
fn frame_len(header: &[u8]) -> Result<usize, Violation> {
    let word = |at: usize| -> Result<u64, Violation> {
        let raw: [u8; 4] = header
            .get(at..at + 4)
            .and_then(|w| w.try_into().ok())
            .ok_or(Violation::BadMessage)?;
        match header.first().copied().unwrap_or(0) {
            b'l' => Ok(u64::from(u32::from_le_bytes(raw))),
            b'B' => Ok(u64::from(u32::from_be_bytes(raw))),
            _ => Err(Violation::BadMessage),
        }
    };
    let body = word(4)?;
    let fields = word(12)?;
    let total = 16 + fields.next_multiple_of(8) + body;
    // Anything past `usize` is far past every bound.
    Ok(usize::try_from(total).unwrap_or(usize::MAX))
}

/// Copies the peer's bytes to `inner` under `limits`, and what `inner` writes back to the peer. Returns when either
/// side is gone or a bound is hit; both sockets are shut down then.
pub fn relay(peer: &UnixStream, inner: &UnixStream, limits: Limits, started: Instant) {
    let Ok(mut from_peer) = peer.try_clone() else {
        return;
    };
    let (Ok(mut to_inner), Ok(mut from_inner), Ok(mut to_peer)) =
        (inner.try_clone(), inner.try_clone(), peer.try_clone())
    else {
        return;
    };
    thread::spawn(move || {
        let _ = io::copy(&mut from_inner, &mut to_peer);
        let _ = to_peer.shutdown(std::net::Shutdown::Both);
    });
    let mut framer = Framer::new(limits.message);
    let mut deadline = started + limits.handshake;
    let mut buf = [0_u8; 4096];
    loop {
        let wait = deadline.saturating_duration_since(Instant::now());
        if wait.is_zero() {
            break;
        }
        let ready = retry_on_intr(|| {
            let mut fds = [PollFd::new(&from_peer, PollFlags::IN)];
            let timeout = Timespec {
                tv_sec: i64::try_from(wait.as_secs()).unwrap_or(i64::MAX),
                tv_nsec: i64::from(wait.subsec_nanos()),
            };
            poll(&mut fds, Some(&timeout))
        });
        if !matches!(ready, Ok(n) if n > 0) {
            break;
        }
        let n = match from_peer.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let chunk = buf.get(..n).unwrap_or_default();
        let Ok(fed) = framer.feed(chunk) else {
            break;
        };
        let now = Instant::now();
        if fed.handshake_done || fed.completed > 0 || fed.began_partial {
            deadline = now + limits.idle;
        }
        if to_inner.write_all(chunk).is_err() {
            break;
        }
    }
    let _ = peer.shutdown(std::net::Shutdown::Both);
    let _ = inner.shutdown(std::net::Shutdown::Both);
}

#[cfg(test)]
mod tests;
