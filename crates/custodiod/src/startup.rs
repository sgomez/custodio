//! Start-up: purge the keys of the earlier format, then serve, then take the bus name.
//!
//! The order lives here, in one function that `main` calls, so the service cannot answer a call before the purge is
//! complete: the bus connection is opened only after the purge returned, and the name is requested last.

use std::error::Error;
use std::fmt;
use std::future::Future;
use std::sync::Arc;

use zbus::Connection;

use crate::app_id_source::CgroupAppIdSource;
use crate::audit::{AuditError, AuditSink, InvalidKeyId, KeyId, OperationEntry};
use crate::credentials::BusCredentials;
use crate::creds::Credentials;
use crate::dbus::{BUS_NAME, Custodio, OBJECT_PATH};
use crate::polkit::PolkitAuthorizer;
use crate::store::{KeyStore, LegacyEntry, StoreError};
use crate::tpm::TpmAccess;

/// Why the purge stopped. No variant holds a path or file content.
#[derive(Debug)]
pub enum PurgeError {
    /// The store refused: a file broke its rules, or could not be read or removed.
    Store(StoreError),
    /// The entry of a key could not be written, so the key was not removed.
    Audit(AuditError),
}

impl fmt::Display for PurgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(e) => write!(f, "purge of the earlier format refused: {e}"),
            Self::Audit(e) => write!(f, "purge stopped, entry not written: {e}"),
        }
    }
}

impl Error for PurgeError {}

impl From<StoreError> for PurgeError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

impl From<InvalidKeyId> for PurgeError {
    fn from(_: InvalidKeyId) -> Self {
        Self::Store(StoreError::InvalidId)
    }
}

/// Removes every key of the earlier format from `store`. For each key the entry is submitted first, then its files
/// are removed (the store's rules apply, nothing is repaired). Listing happens before the first removal, so a file
/// that breaks a rule stops the purge before anything is touched. Gives back the keys it purged.
///
/// # Errors
/// [`PurgeError::Store`] for a file or area that breaks the rules; [`PurgeError::Audit`] when an entry cannot be
/// written: that key and the ones after it stay.
pub fn purge_legacy(
    store: &KeyStore,
    sink: &dyn AuditSink,
) -> Result<Vec<LegacyEntry>, PurgeError> {
    let found = store.legacy_all()?;
    for entry in &found {
        let key_id = KeyId::new(&entry.id)?;
        sink.record_operation(&OperationEntry::purge(entry.owner, key_id))
            .map_err(PurgeError::Audit)?;
        store.remove_legacy(entry)?;
    }
    Ok(found)
}

/// Why the service did not start.
#[derive(Debug)]
pub enum StartError {
    Purge(PurgeError),
    Bus(zbus::Error),
}

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Purge(e) => e.fmt(f),
            Self::Bus(e) => write!(f, "bus: {e}"),
        }
    }
}

impl Error for StartError {}

/// Purges the earlier format, then connects (`connect` is not polled before), serves the object and takes the bus
/// name. The connection is given back; the service runs for as long as it lives.
///
/// # Errors
/// [`StartError::Purge`] (nothing was served and no connection made); [`StartError::Bus`] otherwise.
pub async fn start<F>(
    store: Arc<KeyStore>,
    connect: F,
    journal: Arc<dyn AuditSink>,
    key_credentials: Arc<dyn Credentials>,
    tpm: Arc<dyn TpmAccess>,
) -> Result<Connection, StartError>
where
    F: Future<Output = zbus::Result<Connection>>,
{
    purge_legacy(&store, journal.as_ref()).map_err(StartError::Purge)?;
    let connection = connect.await.map_err(StartError::Bus)?;
    let service = Custodio::new(
        store,
        PolkitAuthorizer::new(connection.clone()),
        BusCredentials::new(connection.clone()),
        journal,
    )
    .with_app_id_source(CgroupAppIdSource::new())
    .with_key_credentials(key_credentials)
    .with_tpm(tpm);
    connection
        .object_server()
        .at(OBJECT_PATH, service)
        .await
        .map_err(StartError::Bus)?;
    connection
        .request_name(BUS_NAME)
        .await
        .map_err(StartError::Bus)?;
    Ok(connection)
}

#[cfg(test)]
mod tests;
