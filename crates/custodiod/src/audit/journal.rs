//! The production sink: one datagram per entry to the journald native socket.

use std::io;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};

use super::wire::encode;
use super::{AuditError, AuditSink, Entry};

/// Where journald listens for the Native Journal Protocol.
pub const DEFAULT_JOURNAL_SOCKET: &str = "/run/systemd/journal/socket";
/// Largest encoded entry, well below the kernel's datagram limit. Larger ones are an error, not cut.
pub const MAX_DATAGRAM: usize = 16 * 1024;

/// Sends each entry as one datagram, non-blocking, never retried.
#[derive(Debug, Clone)]
pub struct JournalSink {
    path: PathBuf,
    max: usize,
}

impl JournalSink {
    /// A sink that sends to the socket at `path`.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self::with_max(path, MAX_DATAGRAM)
    }

    pub(crate) fn with_max(path: impl Into<PathBuf>, max: usize) -> Self {
        Self {
            path: path.into(),
            max,
        }
    }

    /// The socket path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Default for JournalSink {
    fn default() -> Self {
        Self::new(DEFAULT_JOURNAL_SOCKET)
    }
}

impl AuditSink for JournalSink {
    fn record(&self, entry: &Entry) -> Result<(), AuditError> {
        send_fields(&self.path, self.max, &entry.fields())
    }
}

fn io_err(e: &io::Error) -> AuditError {
    AuditError::Io(e.kind())
}

pub(super) fn check_sent(sent: usize, expected: usize) -> Result<(), AuditError> {
    if sent == expected {
        Ok(())
    } else {
        Err(AuditError::ShortSend { sent, expected })
    }
}

pub(super) fn send_fields(
    path: &Path,
    max: usize,
    fields: &[(&str, String)],
) -> Result<(), AuditError> {
    let datagram = encode(fields);
    if datagram.len() > max {
        return Err(AuditError::TooLarge);
    }
    let socket = UnixDatagram::unbound().map_err(|e| io_err(&e))?;
    socket.set_nonblocking(true).map_err(|e| io_err(&e))?;
    let sent = socket.send_to(&datagram, path).map_err(|e| io_err(&e))?;
    check_sent(sent, datagram.len())
}
