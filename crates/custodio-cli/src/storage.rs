//! The warning `custodio import` and `custodio list` print when the service's state directory is not known to be on an
//! encrypted device (SPEC Design 7). It goes to standard error, after the command's own output, and never changes the
//! exit status or what the command printed.

use std::io::Write;

use crate::report::{self, Line, State};

/// What the service reported for its state directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateStorage {
    Encrypted,
    NotEncrypted,
    /// `unknown`, and any value this CLI does not know: never taken as encrypted.
    Unknown,
}

impl StateStorage {
    /// The wire value of the `StateStorage` method.
    #[must_use]
    pub fn from_wire(wire: &str) -> Self {
        match wire {
            "encrypted" => Self::Encrypted,
            "not-encrypted" => Self::NotEncrypted,
            _ => Self::Unknown,
        }
    }
}

/// The service side of `StateStorage`.
pub trait StorageReader {
    /// `None` when the call fails for any reason, including a service that predates the method: no warning then.
    fn state_storage(&self) -> Option<StateStorage>;
}

/// The name of the key storage line, in `doctor`, `import` and `list`.
pub const NAME: &str = "key storage";

/// The state and short text of an answer: the same words in every command.
#[must_use]
pub const fn summary(storage: StateStorage) -> (State, &'static str) {
    match storage {
        StateStorage::Encrypted => (State::Ok, "on an encrypted disk"),
        StateStorage::NotEncrypted => (State::Warn, "not on an encrypted disk"),
        StateStorage::Unknown => (State::Warn, "cannot tell if encrypted"),
    }
}

/// The line `import` and `list` print, or nothing for *encrypted*: the summary, and where the
/// rest is.
#[must_use]
pub fn warning(storage: StateStorage) -> Option<Line> {
    let (state, text) = summary(storage);
    (state != State::Ok).then(|| Line::new(state, NAME, format!("{text} (see custodio doctor)")))
}

/// Asks the service and prints the warning, if any, to `err`, coloured when `on`. A failed write
/// is ignored: the warning blocks nothing.
pub fn warn<R: StorageReader, W: Write>(reader: &R, err: &mut W, on: bool) {
    if let Some(line) = reader.state_storage().and_then(warning) {
        let _ = write!(err, "\n{}", report::render(&[line], on));
    }
}
