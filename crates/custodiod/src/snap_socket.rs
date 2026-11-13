//! The sockets of confined browsers (snaps): systemd passes one, named for the snap, and this module decides whether
//! it may be served. Each accepted connection is checked first ([`peer`]): a peer that passes gets the interface with
//! `ListKeys` for its own uid ([`keys`]), any other is closed before a byte is read.
//!
//! The name of the descriptor tells which snap it is for, and the directory is derived from the name and nothing
//! else (`snap-firefox` -> `/run/snap.firefox/`). The directory is checked before the socket is served: it must be
//! owned by root and writable by root alone, or the browser's own user could swap the socket.

use std::fmt;
use std::io::Write;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rustix::fs::{CWD, FileType, Mode, OFlags, fstat, openat};
use rustix::io::Errno;

use crate::store::KeyStore;

pub mod keys;
pub mod peer;
mod sign;
pub use sign::Signing;

/// Snaps with a socket. Anything else systemd passes is closed and ignored.
const KNOWN_SNAPS: [&str; 1] = ["firefox"];
/// Descriptor names are `snap-<snap>`.
const NAME_PREFIX: &str = "snap-";
/// Longest snap name snapd accepts.
const MAX_SNAP_NAME: usize = 40;
/// Pause after a failed `accept`, so a persistent failure (no descriptors left) does not spin.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// The name of the descriptor for `snap` (`FileDescriptorName=` in the socket unit).
#[must_use]
pub fn descriptor_name(snap: &str) -> String {
    format!("{NAME_PREFIX}{snap}")
}

/// Whether `name` is a snap name: 1 to 40 of `a-z`, `0-9` and `-`, at least one letter, no leading, trailing or
/// doubled `-`.
fn valid_snap_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_SNAP_NAME
        && name.bytes().any(|b| b.is_ascii_lowercase())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !name.starts_with('-')
        && !name.ends_with('-')
        && !name.contains("--")
}

/// The known snap a descriptor name stands for, if it is one.
#[must_use]
pub fn snap_for_descriptor(name: &str) -> Option<&'static str> {
    let snap = name.strip_prefix(NAME_PREFIX)?;
    if !valid_snap_name(snap) {
        return None;
    }
    KNOWN_SNAPS.iter().copied().find(|known| *known == snap)
}

/// The directory of the socket of `snap`: `/run/snap.<snap>`.
#[must_use]
pub fn socket_dir(snap: &str) -> PathBuf {
    PathBuf::from(format!("/run/snap.{snap}"))
}

/// Why a directory is not good enough. The texts go to the journal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    Missing,
    Symlink,
    NotDirectory,
    NotRootOwned,
    GroupWritable,
    OtherWritable,
    Unreadable,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Missing => "the directory does not exist",
            Self::Symlink => "the directory is a symbolic link",
            Self::NotDirectory => "the directory is not a directory",
            Self::NotRootOwned => "the directory is not owned by root",
            Self::GroupWritable => "the directory is writable by its group",
            Self::OtherWritable => "the directory is writable by others",
            Self::Unreadable => "the directory cannot be inspected",
        })
    }
}

/// Opens `dir` without following a final symbolic link and checks it: a directory, owned by root, no group or other
/// write bit.
///
/// # Errors
/// The [`Refusal`] that says why the socket must not be served.
pub fn check_dir(dir: &Path) -> Result<(), Refusal> {
    let fd = openat(
        CWD,
        dir,
        OFlags::RDONLY
            .union(OFlags::NOFOLLOW)
            .union(OFlags::NONBLOCK)
            .union(OFlags::CLOEXEC),
        Mode::empty(),
    )
    .map_err(|e| match e {
        Errno::NOENT => Refusal::Missing,
        Errno::LOOP => Refusal::Symlink,
        _ => Refusal::Unreadable,
    })?;
    let stat = fstat(&fd).map_err(|_| Refusal::Unreadable)?;
    judge(
        FileType::from_raw_mode(stat.st_mode),
        stat.st_uid,
        stat.st_mode,
    )
}

/// The rule over what `fstat` reported. The write bits come before the owner, so a directory that anyone can write is
/// refused for that whoever owns it.
fn judge(kind: FileType, uid: u32, mode: u32) -> Result<(), Refusal> {
    if kind != FileType::Directory {
        return Err(Refusal::NotDirectory);
    }
    if mode & 0o020 != 0 {
        return Err(Refusal::GroupWritable);
    }
    if mode & 0o002 != 0 {
        return Err(Refusal::OtherWritable);
    }
    if uid != 0 {
        return Err(Refusal::NotRootOwned);
    }
    Ok(())
}

/// The descriptor names systemd announces, in order, or nothing when the environment is not for this process or is
/// malformed. `None` stands for a descriptor without a name.
#[must_use]
pub fn listen_names(
    pid: Option<&str>,
    fds: Option<&str>,
    names: Option<&str>,
    own_pid: u32,
) -> Vec<Option<String>> {
    let (Some(pid), Some(fds)) = (pid, fds) else {
        return Vec::new();
    };
    let (Ok(pid), Ok(count)) = (pid.parse::<u32>(), fds.parse::<usize>()) else {
        return Vec::new();
    };
    if pid != own_pid || count > 4096 {
        return Vec::new();
    }
    let names = names.unwrap_or("");
    if names.is_empty() {
        return vec![None; count];
    }
    let listed: Vec<&str> = names.split(':').collect();
    if listed.len() != count {
        return Vec::new();
    }
    listed.into_iter().map(|n| Some(n.to_owned())).collect()
}

/// From the passed descriptors, those named for a known snap, one per snap (the first). Every other one is dropped,
/// which closes it.
#[must_use]
pub fn select<T>(passed: Vec<(Option<String>, T)>) -> Vec<(&'static str, T)> {
    let mut taken: Vec<(&'static str, T)> = Vec::new();
    for (name, fd) in passed {
        let Some(snap) = name.as_deref().and_then(snap_for_descriptor) else {
            continue;
        };
        if taken.iter().all(|(have, _)| *have != snap) {
            taken.push((snap, fd));
        }
    }
    taken
}

/// The sockets systemd passed to this process that are for a known snap.
#[must_use]
pub fn take_from_environment() -> Vec<(&'static str, UnixListener)> {
    let var = |k| std::env::var(k).ok();
    let names = listen_names(
        var("LISTEN_PID").as_deref(),
        var("LISTEN_FDS").as_deref(),
        var("LISTEN_FDNAMES").as_deref(),
        std::process::id(),
    );
    let fds = sd_listen_fds::get().unwrap_or_default();
    if fds.len() != names.len() {
        return Vec::new();
    }
    let passed = names
        .into_iter()
        .zip(fds)
        .map(|(name, (_, fd))| (name, UnixListener::from(fd.into_std())))
        .collect();
    select(passed)
}

/// The directory to check for `snap`. A debug build with the `test-seam` feature honours `CUSTODIOD_TEST_SNAP_DIR`,
/// so a test run as an ordinary user can name a directory that passes; no other build reads it.
#[must_use]
pub fn dir_to_check(snap: &str) -> PathBuf {
    #[cfg(feature = "test-seam")]
    if let Some(dir) = std::env::var_os("CUSTODIOD_TEST_SNAP_DIR") {
        return PathBuf::from(dir);
    }
    socket_dir(snap)
}

/// Where a line about a refused connection goes. It never receives label bytes or key material.
pub type Log = Arc<dyn Fn(&str) + Send + Sync>;

/// What serving a socket needs besides the socket: the store, the source of peer values and the log.
#[derive(Clone)]
pub struct Service {
    store: Arc<KeyStore>,
    source: peer::Source,
    log: Log,
    signing: Option<Signing>,
}

impl Service {
    /// The kernel is the source of the peer's values.
    #[must_use]
    pub fn new(store: Arc<KeyStore>, log: Log) -> Self {
        Self {
            store,
            source: peer::Source::Kernel,
            log,
            signing: None,
        }
    }

    /// What `Sign` needs. Without it every `Sign` fails closed with `AuthorizationUnavailable`.
    #[must_use]
    pub fn with_signing(mut self, signing: Signing) -> Self {
        self.signing = Some(signing);
        self
    }

    /// Takes the peer's values from `source` instead of the kernel. Only a test build has it.
    #[cfg(feature = "test-seam")]
    #[must_use]
    pub fn with_source(mut self, source: peer::Source) -> Self {
        self.source = source;
        self
    }
}

/// What became of a socket.
pub enum Outcome {
    /// Served by a thread that accepts and checks each connection.
    Serving,
    /// The directory failed its check. The listener is given back and must be kept open: connections wait in its
    /// backlog, unserved, and are not told they were refused.
    Refused(UnixListener, Refusal),
}

/// Checks `dir`; when it passes, serves `listener`: each connection is checked and then served or closed. Otherwise
/// writes a line naming the socket and the reason to `journal`.
pub fn serve(
    name: &str,
    listener: UnixListener,
    dir: &Path,
    journal: &mut dyn Write,
    service: &Service,
) -> Outcome {
    match check_dir(dir) {
        Ok(()) => {
            let service = service.clone();
            thread::spawn(move || accept_loop(&listener, &service));
            Outcome::Serving
        }
        Err(reason) => {
            // A journal that cannot be written changes nothing: the socket is not served either way.
            let _ = writeln!(
                journal,
                "custodiod: socket {name} is not served: {reason} ({})",
                dir.display()
            );
            Outcome::Refused(listener, reason)
        }
    }
}

fn accept_loop(listener: &UnixListener, service: &Service) {
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                let service = service.clone();
                thread::spawn(move || handle(stream, &service));
            }
            Err(_) => thread::sleep(ACCEPT_BACKOFF),
        }
    }
}

/// One connection: the three kernel values are read once, and the connection is closed (dropped) unless they pass.
fn handle(stream: UnixStream, service: &Service) {
    match peer::admit(&stream, &service.source) {
        Ok(accepted) => {
            let peer::Accepted {
                uid,
                pid,
                label,
                pidfd,
            } = accepted;
            // The pidfd lives as long as the connection: every signature asks polkit about that process.
            let session = sign::Session {
                store: Arc::clone(&service.store),
                signing: service.signing.clone(),
                uid,
                pid,
                label,
                pidfd,
            };
            keys::serve_peer(stream, session);
        }
        Err(reason) => (service.log)(&format!("custodiod: peer refused: {reason}")),
    }
}

#[cfg(test)]
mod tests;
