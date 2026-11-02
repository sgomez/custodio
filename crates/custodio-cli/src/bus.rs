//! `ImportP12` over D-Bus.

use custodio_client::{BUS_NAME, OBJECT_PATH};
use secrecy::{ExposeSecret, SecretString};
use zbus::{Connection, block_on};

use crate::Importer;
use crate::failure::ServiceFailure;

/// Talks to the service on the given connection (the system bus in `main`).
pub struct DbusImporter {
    connection: Connection,
}

impl DbusImporter {
    #[must_use]
    pub fn new(connection: Connection) -> Self {
        Self { connection }
    }

    /// # Errors
    /// If the system bus is not reachable.
    pub fn system() -> zbus::Result<Self> {
        Ok(Self::new(block_on(Connection::system())?))
    }
}

impl Importer for DbusImporter {
    fn import_p12(
        &self,
        id: &str,
        p12: &[u8],
        password: &SecretString,
    ) -> Result<String, ServiceFailure> {
        let reply = block_on(self.connection.call_method(
            Some(BUS_NAME),
            OBJECT_PATH,
            Some(BUS_NAME),
            "ImportP12",
            &(id, p12, password.expose_secret()),
        ))
        .map_err(|e| failure_of(&e))?;
        reply
            .body()
            .deserialize::<String>()
            .map_err(|_| ServiceFailure::Transport)
    }
}

/// The failure for a call that did not return: by error name for method errors, and a transport
/// failure (or "the service is not there") otherwise.
#[must_use]
pub fn failure_of(e: &zbus::Error) -> ServiceFailure {
    match e {
        zbus::Error::MethodError(name, _, _) => ServiceFailure::from_name(name.as_str()),
        zbus::Error::FDO(fdo) => match **fdo {
            zbus::fdo::Error::ServiceUnknown(_) | zbus::fdo::Error::NameHasNoOwner(_) => {
                ServiceFailure::ServiceAbsent
            }
            _ => ServiceFailure::Transport,
        },
        _ => ServiceFailure::Transport,
    }
}

#[cfg(test)]
mod tests;
