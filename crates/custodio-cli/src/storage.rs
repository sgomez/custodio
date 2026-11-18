//! The warning `custodio import` and `custodio list` print when the service's state directory is not known to be on an
//! encrypted device (SPEC Design 7). It goes to standard error, after the command's own output, and never changes the
//! exit status or what the command printed.

use std::io::Write;

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

/// The warning for a result, or nothing for *encrypted*: what it means, then where the fix is, as
/// `custodio doctor` says it.
#[must_use]
pub fn warning(storage: StateStorage) -> Option<String> {
    let what = match storage {
        StateStorage::Encrypted => return None,
        StateStorage::NotEncrypted => {
            "/var/lib/custodio is not on an encrypted disk: whoever takes this machine can use your keys."
        }
        StateStorage::Unknown => {
            "/var/lib/custodio may not be on an encrypted disk: whoever takes this machine could use your keys."
        }
    };
    Some(format!(
        "warn  {what}\n      Run 'custodio doctor' for the fix."
    ))
}

/// Asks the service and prints the warning, if any, to `err`. A failed write is ignored: the warning blocks nothing.
pub fn warn<R: StorageReader, W: Write>(reader: &R, err: &mut W) {
    if let Some(text) = reader.state_storage().and_then(warning) {
        let _ = writeln!(err, "\n{text}");
    }
}
