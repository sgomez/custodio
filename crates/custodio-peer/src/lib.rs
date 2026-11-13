//! The three things the kernel knows about the peer of a connected Unix socket, each read once and each reported on
//! its own: an unreadable one is `None`, never a default.
//!
//! This is the only place of the service that needs `unsafe` (`getsockopt` with a caller-sized buffer, which neither
//! `rustix` nor `nix` offers for `SO_PEERSEC`), so it is a crate of its own and `custodiod` keeps `forbid(unsafe_code)`.
#![deny(unsafe_code)]

use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

/// `SO_PEERSEC` (`asm-generic/socket.h`).
const SO_PEERSEC: libc::c_int = 31;
/// `SO_PEERPIDFD` (`asm-generic/socket.h`, Linux 6.5).
const SO_PEERPIDFD: libc::c_int = 77;
/// Largest label read. A longer one is reported as read, truncated to one byte more than any accepted label may
/// have, so the caller still sees it is too long.
pub const LABEL_BUFFER: usize = 4096;

/// What the kernel said. A value is `None` when its read failed.
pub struct Peer {
    /// `SO_PEERCRED`: the kernel uid of the process that connected.
    pub uid: Option<u32>,
    /// `SO_PEERPIDFD`: a pidfd of that process.
    pub pidfd: Option<OwnedFd>,
    /// `SO_PEERSEC`: the security label, as bytes. Never printed: `Debug` is hand-written below.
    pub label: Option<Vec<u8>>,
}

impl std::fmt::Debug for Peer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Peer")
            .field("uid", &self.uid)
            .field("pidfd", &self.pidfd.is_some())
            .field("label", &self.label.as_ref().map(Vec::len))
            .finish()
    }
}

/// Reads the three values of the peer of `socket`, once each.
#[must_use]
pub fn read(socket: &impl AsRawFd) -> Peer {
    let fd = socket.as_raw_fd();
    Peer {
        uid: peer_uid(fd),
        pidfd: peer_pidfd(fd),
        label: peer_label(fd),
    }
}

#[allow(
    unsafe_code,
    reason = "getsockopt writes into a buffer of the length passed"
)]
fn getsockopt(
    fd: RawFd,
    name: libc::c_int,
    buf: *mut libc::c_void,
    len: &mut libc::socklen_t,
) -> io::Result<()> {
    // SAFETY: `buf` points to `*len` writable bytes (every caller passes a live buffer and its size), and `len` is a
    // valid pointer for the duration of the call.
    let rc = unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, name, buf, len) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn peer_uid(fd: RawFd) -> Option<u32> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = libc::socklen_t::try_from(size_of::<libc::ucred>()).ok()?;
    getsockopt(
        fd,
        libc::SO_PEERCRED,
        std::ptr::from_mut(&mut cred).cast(),
        &mut len,
    )
    .ok()?;
    (usize::try_from(len).ok()? == size_of::<libc::ucred>()).then_some(cred.uid)
}

#[allow(
    unsafe_code,
    reason = "wraps the descriptor the kernel just created for us"
)]
fn peer_pidfd(fd: RawFd) -> Option<OwnedFd> {
    let mut raw: libc::c_int = -1;
    let mut len = libc::socklen_t::try_from(size_of::<libc::c_int>()).ok()?;
    getsockopt(
        fd,
        SO_PEERPIDFD,
        std::ptr::from_mut(&mut raw).cast(),
        &mut len,
    )
    .ok()?;
    if raw < 0 || usize::try_from(len).ok()? != size_of::<libc::c_int>() {
        return None;
    }
    // SAFETY: on success the kernel installed a new descriptor `raw` in this process; nothing else owns it.
    Some(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn peer_label(fd: RawFd) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; LABEL_BUFFER];
    let mut len = libc::socklen_t::try_from(buf.len()).ok()?;
    getsockopt(fd, SO_PEERSEC, buf.as_mut_ptr().cast(), &mut len).ok()?;
    buf.truncate(usize::try_from(len).ok()?);
    Some(buf)
}

#[cfg(test)]
mod tests;
