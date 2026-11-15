//! The Firefox snap's copy of the module (SPEC Design 3 and 4): placed, refreshed and removed by `custodio register`.
//!
//! The snap cannot read `/usr/lib/custodio`, so the command keeps a copy at a fixed path under the snap's own
//! directory. The copy is written beside its target and `rename(2)`d over it; a link at the target is replaced, never
//! followed, and the command never deletes a directory.

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::browser_files::LockState;
use crate::cert_text::escape;
use crate::register_discover::{Profile, SNAP_NAME};
use crate::register_native::{Line, Options, Outcome, handle};

/// The copy, relative to the home directory.
pub const COPY_REL: &str = "snap/firefox/common/libcustodio_pkcs11.so";
/// The file the copy is written to before the rename, beside the copy.
pub const TEMP_NAME: &str = "libcustodio_pkcs11.so.tmp";
/// Where journald listens for the native protocol.
pub const DEFAULT_JOURNAL_SOCKET: &str = "/run/systemd/journal/socket";
/// The `SYSLOG_IDENTIFIER` of the entries of refresh-only mode.
pub const JOURNAL_IDENTIFIER: &str = "custodio-register";

/// The copy's path under a home directory.
#[must_use]
pub fn copy_path(home: &Path) -> PathBuf {
    home.join(COPY_REL)
}

/// What a placement or refresh did to the copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyState {
    /// There was none: it was created.
    Placed,
    /// Its bytes differed (or it was a link): it was replaced.
    Refreshed,
    /// Its bytes already equal the module's.
    UpToDate,
    /// There is none, and none was asked for.
    Absent,
}

fn io_why(e: &io::Error) -> String {
    escape(&e.to_string())
}

/// `symlink_metadata`, with a missing path as `None`.
fn stat(path: &Path) -> io::Result<Option<fs::Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(m) => Ok(Some(m)),
        Err(e) => {
            if e.kind() == io::ErrorKind::NotFound {
                Ok(None)
            } else {
                Err(e)
            }
        }
    }
}

/// The bytes of the module being copied.
fn read_module(module: &Path) -> Result<Vec<u8>, String> {
    fs::read(module).map_err(|e| {
        format!(
            "cannot read the module {}: {}",
            module.display(),
            io_why(&e)
        )
    })
}

/// Replace the copy with `bytes` through the temporary file.
fn write_atomic(copy: &Path, bytes: &[u8]) -> Result<(), String> {
    let tmp = copy.with_file_name(TEMP_NAME);
    match stat(&tmp).map_err(|e| format!("cannot look at {}: {}", tmp.display(), io_why(&e)))? {
        Some(m) if m.is_dir() => {
            return Err(format!(
                "{} is a directory, which is not removed here; remove it and run this again",
                tmp.display()
            ));
        }
        Some(_) => fs::remove_file(&tmp).map_err(|e| {
            format!(
                "cannot remove the leftover {}: {}",
                tmp.display(),
                io_why(&e)
            )
        })?,
        None => {}
    }
    let written = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o755)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits().cast_signed())
            .open(&tmp)
            .map_err(|e| format!("cannot create {}: {}", tmp.display(), io_why(&e)))?;
        file.set_permissions(fs::Permissions::from_mode(0o755))
            .and_then(|()| file.write_all(bytes))
            .and_then(|()| file.sync_all())
            .map_err(|e| format!("cannot write {}: {}", tmp.display(), io_why(&e)))?;
        fs::rename(&tmp, copy).map_err(|e| format!("cannot rename it into place: {}", io_why(&e)))
    })();
    if written.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    written
}

/// Bring the copy to the module's bytes. `create`: make it when there is none.
fn bring_up_to_date(copy: &Path, module: &Path, create: bool) -> Result<CopyState, String> {
    let meta = stat(copy).map_err(|e| format!("cannot look at it: {}", io_why(&e)))?;
    if meta.is_none() && !create {
        return Ok(CopyState::Absent);
    }
    if meta.as_ref().is_some_and(fs::Metadata::is_dir) {
        return Err(
            "it is a directory, which is not replaced; remove it and run this again".to_owned(),
        );
    }
    let bytes = read_module(module)?;
    let regular = meta.as_ref().is_some_and(|m| m.file_type().is_file());
    if regular && fs::read(copy).is_ok_and(|current| current == bytes) {
        return Ok(CopyState::UpToDate);
    }
    write_atomic(copy, &bytes)?;
    Ok(if meta.is_some() {
        CopyState::Refreshed
    } else {
        CopyState::Placed
    })
}

/// Make the copy hold the module's bytes, creating it when there is none.
///
/// # Errors
/// The reason the copy could not be replaced; the old copy is then as it was.
pub fn place_copy(copy: &Path, module: &Path) -> Result<CopyState, String> {
    bring_up_to_date(copy, module, true)
}

/// Replace a copy whose bytes differ from the module's. Never creates one.
///
/// # Errors
/// The reason the copy could not be replaced; the old copy is then as it was.
pub fn refresh_copy(copy: &Path, module: &Path) -> Result<CopyState, String> {
    bring_up_to_date(copy, module, false)
}

/// Delete the copy (a link is deleted, not followed). `Ok(false)`: there was none.
///
/// # Errors
/// The reason it could not be deleted, a directory at the path included.
pub fn remove_copy(copy: &Path) -> Result<bool, String> {
    match stat(copy).map_err(|e| format!("cannot look at it: {}", io_why(&e)))? {
        Some(m) if m.is_dir() => {
            Err("it is a directory, which is not removed; remove it yourself".to_owned())
        }
        Some(_) => fs::remove_file(copy)
            .map(|()| true)
            .map_err(|e| format!("cannot delete it: {}", io_why(&e))),
        None => Ok(false),
    }
}

/// What refresh-only mode found and did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refresh {
    Refreshed,
    UpToDate,
    NoCopy,
    /// There is no module to compare with: nothing was touched.
    NoModule(PathBuf),
    Failed(String),
}

impl Refresh {
    /// Whether the outcome is a failure (error priority, non-zero exit).
    #[must_use]
    pub const fn is_failure(&self) -> bool {
        matches!(self, Self::Failed(_))
    }
}

impl fmt::Display for Refresh {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refreshed => f.write_str("refreshed (the copy differed from the module)"),
            Self::UpToDate => f.write_str("up to date"),
            Self::NoCopy => f.write_str("no copy; nothing to refresh"),
            Self::NoModule(m) => write!(
                f,
                "no installed module at {}; the copy was left as it is",
                m.display()
            ),
            Self::Failed(why) => write!(f, "failed, {why}"),
        }
    }
}

/// Refresh-only mode: the copy is replaced if it is there and stale; nothing else is touched.
#[must_use]
pub fn refresh_only(home: &Path, module: &Path) -> Refresh {
    let copy = copy_path(home);
    if !module.exists() {
        return Refresh::NoModule(module.to_owned());
    }
    match refresh_copy(&copy, module) {
        Ok(CopyState::Refreshed | CopyState::Placed) => Refresh::Refreshed,
        Ok(CopyState::UpToDate) => Refresh::UpToDate,
        Ok(CopyState::Absent) => Refresh::NoCopy,
        Err(why) => Refresh::Failed(why),
    }
}

/// One entry of the journal, in the native protocol: `KEY=value` lines, values on one line.
#[must_use]
pub fn journal_datagram(refresh: &Refresh, copy: &Path) -> Vec<u8> {
    let priority = if refresh.is_failure() { 3 } else { 6 };
    let copy = escape(&copy.to_string_lossy());
    let message = escape(&format!("custodio register: {copy}: {refresh}"));
    format!(
        "SYSLOG_IDENTIFIER={JOURNAL_IDENTIFIER}\nPRIORITY={priority}\nCUSTODIO_COPY={copy}\nMESSAGE={message}\n"
    )
    .into_bytes()
}

/// Send one entry to the journal socket at `socket`, without blocking for more than a moment.
///
/// # Errors
/// Why it could not be sent.
pub fn send_to_journal(socket: &Path, datagram: &[u8]) -> io::Result<()> {
    let sock = std::os::unix::net::UnixDatagram::unbound()?;
    sock.set_write_timeout(Some(Duration::from_secs(1)))?;
    let sent = sock.send_to(datagram, socket)?;
    if sent == datagram.len() {
        Ok(())
    } else {
        Err(io::Error::new(io::ErrorKind::WriteZero, "short send"))
    }
}

/// The lines of the snap: its copy of the module and its profiles.
pub(crate) fn snap_lines(snap: &[&Profile], copy: &Path, options: &Options) -> Vec<Line> {
    let line = |path: &Path, outcome| Line {
        browser: SNAP_NAME,
        path: path.to_owned(),
        outcome,
    };
    let held = |p: &Profile| matches!(p.lock, LockState::Held(_));
    let mut lines = Vec::new();
    if options.remove {
        for p in snap {
            lines.push(line(&p.path, handle(p, options, copy, None)));
        }
        if lines.iter().any(|l| l.outcome.is_fixable_skip()) {
            if fs::symlink_metadata(copy).is_ok() {
                lines.push(line(copy, Outcome::CopyKept));
            }
        } else {
            match remove_copy(copy) {
                Ok(true) => lines.push(line(copy, Outcome::CopyRemoved)),
                Ok(false) => {}
                Err(why) => lines.push(line(copy, Outcome::CopyFailed(why))),
            }
        }
        return lines;
    }
    // A copy is placed for a profile that can be registered; one that is there is refreshed whatever the profiles are.
    let placed = if snap.iter().any(|p| !held(p)) {
        place_copy(copy, &options.module)
    } else {
        refresh_copy(copy, &options.module)
    };
    let usable = match placed {
        Ok(CopyState::Placed) => {
            lines.push(line(copy, Outcome::CopyPlaced));
            true
        }
        Ok(CopyState::Refreshed) => {
            lines.push(line(copy, Outcome::CopyRefreshed));
            true
        }
        Ok(CopyState::UpToDate) => {
            lines.push(line(copy, Outcome::CopyUpToDate));
            true
        }
        Ok(CopyState::Absent) => false,
        Err(why) => {
            lines.push(line(copy, Outcome::CopyFailed(why)));
            copy.exists()
        }
    };
    for p in snap {
        let outcome = if !usable && !held(p) {
            Outcome::Skipped(
                "the copy of the module is not there, so there is nothing to register".to_owned(),
            )
        } else {
            handle(p, options, copy, None)
        };
        lines.push(line(&p.path, outcome));
    }
    lines
}
