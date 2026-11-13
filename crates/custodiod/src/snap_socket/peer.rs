//! The check of one accepted connection: the three values the kernel gives about its peer, read once, and the
//! decision over them. Nothing is read from the connection itself.
//!
//! A connection is accepted only if `SO_PEERCRED`, `SO_PEERPIDFD` and `SO_PEERSEC` were all readable, the label
//! passes [`crate::peer_label::check`] and the uid is neither unreadable nor the overflow uid (`docs/findings/F170.md`:
//! 65534 is what a uid outside the service's user namespace looks like, so it is unknown, not a user). Root is not
//! special: it is judged like any other uid.

use std::fmt;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
#[cfg(feature = "test-seam")]
use std::sync::Arc;

pub use custodio_peer::Peer;

use crate::audit::PeerLabel;
use crate::peer_label;

/// The uid the kernel shows for a uid that has no mapping (`/proc/sys/kernel/overflowuid`).
pub const OVERFLOW_UID: u32 = 65534;

/// A peer that passed: its kernel uid, and the pidfd that pins its process (kept for the signing checks).
#[derive(Debug)]
pub struct Accepted {
    pub uid: u32,
    /// The peer's pid from `SO_PEERCRED`, for the journal only.
    pub pid: u32,
    /// The peer's label, which passed [`peer_label::check`].
    pub label: PeerLabel,
    pub pidfd: OwnedFd,
}

/// Why a peer is refused. The texts are fixed and go to the journal; none holds label bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// `SO_PEERCRED` could not be read.
    UnreadableUid,
    /// The uid is the overflow uid: the peer's real uid is not known.
    OverflowUid,
    /// `SO_PEERPIDFD` could not be read.
    NoPidfd,
    /// `SO_PEERSEC` could not be read.
    NoLabel,
    /// The label is not the Firefox snap's.
    Label(peer_label::Refusal),
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnreadableUid => f.write_str("the peer's uid cannot be read"),
            Self::OverflowUid => f.write_str("the peer's uid is the overflow uid"),
            Self::NoPidfd => f.write_str("the peer's pidfd cannot be read"),
            Self::NoLabel => f.write_str("the peer's security label cannot be read"),
            Self::Label(reason) => write!(f, "the peer's label is refused: {reason}"),
        }
    }
}

/// The decision over what was read. The uid is checked first, then the pidfd, then the label.
///
/// # Errors
/// The [`Refusal`] that says why the connection must be closed.
pub fn decide(peer: Peer) -> Result<Accepted, Refusal> {
    let Peer {
        uid,
        pid,
        pidfd,
        label,
    } = peer;
    let uid = uid.ok_or(Refusal::UnreadableUid)?;
    let pid = pid.ok_or(Refusal::UnreadableUid)?;
    if uid == OVERFLOW_UID {
        return Err(Refusal::OverflowUid);
    }
    let pidfd = pidfd.ok_or(Refusal::NoPidfd)?;
    let label = label.ok_or(Refusal::NoLabel)?;
    let label = PeerLabel::new(&label).map_err(Refusal::Label)?;
    Ok(Accepted {
        uid,
        pid,
        label,
        pidfd,
    })
}

/// Where the three values come from: the kernel. Only a test build with the `test-seam` feature has another.
#[derive(Clone, Default)]
pub enum Source {
    #[default]
    Kernel,
    /// A test supplies the values per connection. Never built into a shipped binary
    /// (`scripts/check-test-label.sh`, and `compile_error!` in release builds).
    #[cfg(feature = "test-seam")]
    Injected(Arc<dyn Fn(&UnixStream) -> Peer + Send + Sync>),
}

impl Source {
    /// The values for the peer of `stream`.
    #[must_use]
    pub fn read(&self, stream: &UnixStream) -> Peer {
        match self {
            Self::Kernel => custodio_peer::read(stream),
            #[cfg(feature = "test-seam")]
            Self::Injected(supply) => supply(stream),
        }
    }
}

/// Reads and judges the peer of `stream`.
///
/// # Errors
/// The [`Refusal`] to journal before the connection is closed.
pub fn admit(stream: &UnixStream, source: &Source) -> Result<Accepted, Refusal> {
    decide(source.read(stream))
}
