//! Opens and reads a file that may be hostile: a symlink, a FIFO, a device or an endless file must not
//! be followed, block or exhaust memory.

use std::os::fd::{AsFd, OwnedFd};

use rustix::fs::{FileType, Mode, OFlags, fstat, openat};
use rustix::io::Errno;

/// Why a file was not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReadError {
    /// The name does not exist (a scope that ended after it was listed).
    Missing,
    /// Anything else: a symlink, a FIFO, a device, a directory, more than the bound, an I/O error.
    Refused,
}

/// Opens `name` below `dir` for reading without following a symlink and without blocking (`O_NONBLOCK` makes
/// the open of a FIFO return at once), then checks with `fstat` on the open file that it is a regular file.
/// Nothing is read before that check.
pub(super) fn open_regular(
    dir: impl AsFd,
    name: impl rustix::path::Arg,
) -> Result<OwnedFd, ReadError> {
    let flags = OFlags::RDONLY
        .union(OFlags::NOFOLLOW)
        .union(OFlags::NONBLOCK)
        .union(OFlags::NOCTTY)
        .union(OFlags::CLOEXEC);
    let fd = openat(dir, name, flags, Mode::empty()).map_err(|e| match e {
        Errno::NOENT => ReadError::Missing,
        _ => ReadError::Refused,
    })?;
    let stat = fstat(&fd).map_err(|_| ReadError::Refused)?;
    if FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile {
        Ok(fd)
    } else {
        Err(ReadError::Refused)
    }
}

/// Reads an open regular file up to `max` bytes. A file with more than `max` bytes is refused, not truncated.
pub(super) fn read_bounded(fd: impl AsFd, max: usize) -> Result<Vec<u8>, ReadError> {
    let mut out = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = match rustix::io::read(&fd, &mut chunk) {
            Ok(n) => n,
            Err(Errno::INTR) => continue,
            Err(_) => return Err(ReadError::Refused),
        };
        if n == 0 {
            return Ok(out);
        }
        out.extend_from_slice(chunk.get(..n).ok_or(ReadError::Refused)?);
        if out.len() > max {
            return Err(ReadError::Refused);
        }
    }
}
