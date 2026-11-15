//! The start-up entry that records the storage of the state directory.

use crate::storage::StateStorage;

/// `MESSAGE_ID` of the start-up entry for the state directory's storage.
pub const STATE_STORAGE_MESSAGE_ID: &str = "5b0d7a2e91c34f68b3e4a7d1c09f2e86";
/// The field that carries the verdict: `encrypted`, `not-encrypted` or `unknown`.
pub const STATE_STORAGE_FIELD: &str = "CUSTODIO_STATE_STORAGE";

/// Syslog priority: 6 when proven encrypted, 4 (warning) otherwise.
#[must_use]
pub const fn priority(storage: StateStorage) -> u8 {
    match storage {
        StateStorage::Encrypted => 6,
        StateStorage::NotEncrypted | StateStorage::Unknown => 4,
    }
}

/// The fields in wire order.
#[must_use]
pub fn fields(storage: StateStorage) -> Vec<(&'static str, String)> {
    vec![
        (
            "MESSAGE",
            format!("state directory storage: {}", storage.name()),
        ),
        ("MESSAGE_ID", STATE_STORAGE_MESSAGE_ID.to_owned()),
        ("PRIORITY", priority(storage).to_string()),
        ("SYSLOG_IDENTIFIER", crate::SERVICE_NAME.to_owned()),
        (STATE_STORAGE_FIELD, storage.name().to_owned()),
    ]
}

#[cfg(test)]
mod tests;
