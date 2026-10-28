//! Test doubles for [`AuditSink`].

use std::io;
use std::sync::{Mutex, PoisonError};

use super::{AuditError, AuditSink, Entry};

/// Stores every entry it is given.
#[derive(Debug, Default)]
pub struct MemorySink {
    entries: Mutex<Vec<Entry>>,
}

impl MemorySink {
    /// The entries recorded so far, in order.
    #[must_use]
    pub fn entries(&self) -> Vec<Entry> {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl AuditSink for MemorySink {
    fn record(&self, entry: &Entry) -> Result<(), AuditError> {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(entry.clone());
        Ok(())
    }
}

/// Always fails.
#[derive(Debug, Default, Clone, Copy)]
pub struct FailingSink;

impl AuditSink for FailingSink {
    fn record(&self, _entry: &Entry) -> Result<(), AuditError> {
        Err(AuditError::Io(io::ErrorKind::Other))
    }
}
