//! The peer label check for the Firefox socket: turns the `SO_PEERSEC` bytes of a connection into accept or a
//! refusal reason. Nothing here reads a socket; the caller passes the bytes.
//!
//! Accept means exactly `snap.firefox.firefox (enforce)` (`docs/findings/F171.md`: only the browser app of the
//! snap; geckodriver, the four hooks and every other snap are refused). The comparison is exact: no regex, no trim,
//! no case folding. Anything else is classified into one reason, in this order: empty, NUL, not UTF-8, too long,
//! `SELinux` context (any `:`, never parsed as a snap label), stacked (`//&`), child profile (`//`), whitespace or
//! control characters, the profile name, then the mode.
//!
//! Trailing NUL: refused like any other NUL. Probe in the dev container (no `AppArmor` LSM there):
//! `socket.socketpair(AF_UNIX)` then `getsockopt(SOL_SOCKET, SO_PEERSEC, 256)` returned `b'crun (unconfined)'`, whose
//! length is the text's own, with no NUL (with a buffer of 0 or 4 bytes: `ERANGE`). `docs/findings/F171.md` read
//! `b'snap.firefox.firefox (enforce)'` the same way on the VM, and `AppArmor`'s own code leaves the terminating NUL out
//! of the length. Tolerating one would only widen what is accepted, so it is not.
//!
//! A refusal reason carries no label bytes: its display text is fixed, so a peer cannot put text in the journal.

use std::fmt;

/// The snap the socket is for. Only Firefox has a socket.
const SNAP: &str = "firefox";
/// The one accepted label.
const ACCEPTED: &str = "snap.firefox.firefox (enforce)";
/// Longest label looked at (`AppArmor` names are far shorter; the kernel's limit for a peer label is larger).
pub const MAX_LABEL_LEN: usize = 256;

/// Why a peer label is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// No bytes.
    Empty,
    /// A NUL byte anywhere, a trailing one included.
    EmbeddedNul,
    /// Not valid UTF-8.
    NotUtf8,
    /// Longer than [`MAX_LABEL_LEN`].
    TooLong,
    /// An `SELinux` context (or anything with a `:`), not an `AppArmor` snap label.
    NotSnapLabel,
    /// Stacked profiles (`//&`).
    Stacked,
    /// A child profile (`//`).
    ChildProfile,
    /// `unconfined`, with or without a snap name.
    Unconfined,
    /// Complain mode.
    Complain,
    /// A snap profile name with no mode.
    MissingMode,
    /// Any other mode text, or the right one in another case.
    BadMode,
    /// A profile of another snap.
    OtherSnap,
    /// Another app or hook of the right snap.
    OtherApp,
    /// Whitespace, control characters or text around the label.
    ExtraText,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "peer label is empty",
            Self::EmbeddedNul => "peer label contains a NUL byte",
            Self::NotUtf8 => "peer label is not UTF-8",
            Self::TooLong => "peer label is too long",
            Self::NotSnapLabel => "peer label is not a snap label",
            Self::Stacked => "peer label is stacked",
            Self::ChildProfile => "peer label is a child profile",
            Self::Unconfined => "peer is unconfined",
            Self::Complain => "peer profile is in complain mode",
            Self::MissingMode => "peer label has no mode",
            Self::BadMode => "peer label has an unexpected mode",
            Self::OtherSnap => "peer is another snap",
            Self::OtherApp => "peer is another app of the snap",
            Self::ExtraText => "peer label has extra text",
        })
    }
}

/// Decides whether `label` (the `SO_PEERSEC` bytes) is the label of the Firefox snap's browser app.
///
/// # Errors
/// The [`Refusal`] for the first rule the label breaks.
pub fn check(label: &[u8]) -> Result<(), Refusal> {
    if label.is_empty() {
        return Err(Refusal::Empty);
    }
    if label.contains(&0) {
        return Err(Refusal::EmbeddedNul);
    }
    let text = std::str::from_utf8(label).map_err(|_| Refusal::NotUtf8)?;
    if text.len() > MAX_LABEL_LEN {
        return Err(Refusal::TooLong);
    }
    if text.contains(':') {
        return Err(Refusal::NotSnapLabel);
    }
    if text.contains("//&") {
        return Err(Refusal::Stacked);
    }
    if text.contains("//") {
        return Err(Refusal::ChildProfile);
    }
    if text
        .chars()
        .any(|c| c.is_whitespace() && c != ' ' || c.is_control())
        || text.starts_with(' ')
        || text.ends_with(' ')
    {
        return Err(Refusal::ExtraText);
    }
    let (name, mode) = match text.split_once(' ') {
        Some((name, mode)) => (name, Some(mode)),
        None => (text, None),
    };
    check_name(name)?;
    let Some(mode) = mode else {
        return Err(Refusal::MissingMode);
    };
    check_mode(mode)?;
    if text == ACCEPTED {
        Ok(())
    } else {
        Err(Refusal::ExtraText)
    }
}

fn check_name(name: &str) -> Result<(), Refusal> {
    if name == "unconfined" {
        return Err(Refusal::Unconfined);
    }
    let prefix = format!("snap.{SNAP}.");
    match name.strip_prefix(prefix.as_str()) {
        None => Err(Refusal::OtherSnap),
        Some(SNAP) => Ok(()),
        Some(_) => Err(Refusal::OtherApp),
    }
}

fn check_mode(mode: &str) -> Result<(), Refusal> {
    let Some(inner) = mode.strip_prefix('(') else {
        return Err(Refusal::ExtraText);
    };
    let Some((inner, rest)) = inner.split_once(')') else {
        return Err(Refusal::BadMode);
    };
    if !rest.is_empty() {
        return Err(Refusal::ExtraText);
    }
    match inner {
        "enforce" => Ok(()),
        "complain" => Err(Refusal::Complain),
        "unconfined" => Err(Refusal::Unconfined),
        _ => Err(Refusal::BadMode),
    }
}
