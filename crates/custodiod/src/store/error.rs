//! The errors of the key store.

use std::io;
use std::path::PathBuf;

use super::RecordError;

/// Errors from the key store. Messages never contain key material.
#[derive(Debug)]
pub enum StoreError {
    /// The key id is empty, too long or has characters outside `[A-Za-z0-9_-]`.
    InvalidId,
    /// A key with this id already exists.
    AlreadyExists,
    /// No key with this id.
    NotFound,
    /// The state directory or a key file has a mode other than the required one.
    BadPermissions(PathBuf),
    /// The state path or a key file is not a plain directory/file (symlinks are rejected).
    BadFileType(PathBuf),
    /// The state path or a key file is not owned by the service uid.
    BadOwner(PathBuf),
    /// The record file is larger than any record we store.
    TooLarge,
    /// The file is of the earlier format (no magic). It is recognised, never read.
    Legacy,
    /// The file is not a well-formed record, or the record cannot be written.
    Record(RecordError),
    /// The owner or id inside the record differs from the path it was found at.
    Mismatch(PathBuf),
    /// The key was stored, but syncing the directory failed, so durability is unconfirmed.
    /// Retrying `put` yields `AlreadyExists`; use `get` to check the key.
    SyncFailed(io::Error),
    /// Underlying I/O failure.
    Io(io::Error),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidId => f.write_str("invalid key id"),
            Self::AlreadyExists => f.write_str("key already exists"),
            Self::NotFound => f.write_str("key not found"),
            Self::BadPermissions(p) => write!(f, "unsafe permissions on {}", p.display()),
            Self::BadFileType(p) => write!(f, "unexpected file type at {}", p.display()),
            Self::BadOwner(p) => write!(f, "unexpected owner of {}", p.display()),
            Self::SyncFailed(e) => write!(f, "key stored but directory sync failed: {e}"),
            Self::TooLarge => f.write_str("key file too large"),
            Self::Legacy => f.write_str("key file is of the earlier format"),
            Self::Record(e) => write!(f, "bad key record: {e}"),
            Self::Mismatch(p) => write!(f, "record does not belong to its path {}", p.display()),
            Self::Io(e) => write!(f, "i/o error: {e}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<io::Error> for StoreError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
