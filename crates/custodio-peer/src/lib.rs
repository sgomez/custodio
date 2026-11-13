//! The three things the kernel knows about the peer of a connected Unix socket, each read once and each reported on
//! its own: an unreadable one is `None`, never a default.
//!
//! `SO_PEERCRED` is read with `rustix` and `SO_PEERPIDFD` with `nix`, both safe. `SO_PEERSEC` has no safe wrapper in
//! either, so this crate holds the one audited `unsafe` of the service outside the PKCS#11 FFI layer: [`peer_label`],
//! a `getsockopt` with a buffer of the size it is given and nothing else. `custodiod` keeps `forbid(unsafe_code)`.
#![deny(unsafe_code)]

use std::os::fd::{AsFd, AsRawFd, OwnedFd};

use nix::sys::socket::{getsockopt, sockopt::PeerPidfd};

/// `SO_PEERSEC` (`asm-generic/socket.h`).
const SO_PEERSEC: libc::c_int = 31;

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
pub fn read<S: AsFd + AsRawFd>(socket: &S) -> Peer {
    Peer {
        uid: rustix::net::sockopt::socket_peercred(socket)
            .ok()
            .map(|cred| cred.uid.as_raw()),
        pidfd: getsockopt(socket, PeerPidfd).ok(),
        label: peer_label(socket),
    }
}

/// The one `unsafe` read: `getsockopt(SOL_SOCKET, SO_PEERSEC)` into a buffer of `LABEL_BUFFER` bytes.
#[allow(
    unsafe_code,
    reason = "no safe wrapper of SO_PEERSEC exists; docs/decisions.md records this single exception"
)]
fn peer_label(socket: &impl AsRawFd) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; LABEL_BUFFER];
    let mut len = libc::socklen_t::try_from(buf.len()).ok()?;
    // SAFETY: `buf` is live and holds `len` writable bytes, `len` is a valid pointer for the call, and the fd is
    // open for as long as `socket` is borrowed.
    let rc = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            SO_PEERSEC,
            buf.as_mut_ptr().cast(),
            &raw mut len,
        )
    };
    if rc != 0 {
        return None;
    }
    buf.truncate(usize::try_from(len).ok()?);
    Some(buf)
}

#[cfg(test)]
mod tests;
