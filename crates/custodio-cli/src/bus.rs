//! `ImportP12`, `ListKeys` and `DeleteKey` over D-Bus.

use custodio_client::{BUS_NAME, Kind, OBJECT_PATH};
use secrecy::{ExposeSecret, SecretString};
use zbus::{Connection, block_on};

use crate::Importer;
use crate::delete::KeyDeleter;
use crate::failure::ServiceFailure;
use crate::list::{KeyEntry, KeyLister};

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
    ) -> Result<(String, Kind), ServiceFailure> {
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
            .deserialize::<(String, String)>()
            .map(|(key_type, kind)| (key_type, Kind::from_wire(&kind)))
            .map_err(|_| ServiceFailure::Transport)
    }
}

impl KeyLister for DbusImporter {
    fn list_keys(&self) -> Result<Vec<KeyEntry>, ServiceFailure> {
        let reply = block_on(self.connection.call_method(
            Some(BUS_NAME),
            OBJECT_PATH,
            Some(BUS_NAME),
            "ListKeys",
            &(),
        ))
        .map_err(|e| failure_of(&e))?;
        let keys = reply
            .body()
            .deserialize::<Vec<(String, String, String, Vec<u8>)>>()
            .map_err(|_| ServiceFailure::Transport)?;
        Ok(keys.into_iter().map(key_entry).collect())
    }
}

impl KeyDeleter for DbusImporter {
    fn delete_key(&self, id: &str) -> Result<(), ServiceFailure> {
        block_on(self.connection.call_method(
            Some(BUS_NAME),
            OBJECT_PATH,
            Some(BUS_NAME),
            "DeleteKey",
            &(id,),
        ))
        .map(|_| ())
        .map_err(|e| failure_of(&e))
    }
}

/// One element of the `ListKeys` reply: `(id, key type, kind, certificate)`.
fn key_entry((id, key_type, kind, certificate): (String, String, String, Vec<u8>)) -> KeyEntry {
    KeyEntry {
        id,
        key_type,
        kind: Kind::from_wire(&kind),
        certificate,
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
