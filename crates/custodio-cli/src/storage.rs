//! The warning `custodio import` and `custodio list` print when the service's state directory is not known to be on an
//! encrypted device (SPEC Design 7). It goes to standard error, after the command's own output, and never changes the
//! exit status or what the command printed.

use std::io::Write;

/// The README heading the warning points to, as the anchor of its link.
pub const README_ANCHOR: &str = "full-disk-encryption";

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

/// The warning for a result, or nothing for *encrypted*.
#[must_use]
pub fn warning(storage: StateStorage) -> Option<String> {
    let why = match storage {
        StateStorage::Encrypted => return None,
        StateStorage::NotEncrypted => {
            "The service's state directory is not on an encrypted device."
        }
        StateStorage::Unknown => {
            "The service could not tell whether its state directory is on an encrypted device."
        }
    };
    Some(format!(
        "Warning: {why} Without full-disk encryption, whoever takes this machine can use your keys, though they cannot \
copy a tpm key. See README.md#{README_ANCHOR}."
    ))
}

/// Asks the service and prints the warning, if any, to `err`. A failed write is ignored: the warning blocks nothing.
pub fn warn<R: StorageReader, W: Write>(reader: &R, err: &mut W) {
    if let Some(text) = reader.state_storage().and_then(warning) {
        let _ = writeln!(err, "{text}");
    }
}
