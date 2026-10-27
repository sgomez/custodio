//! `ImportP12` over D-Bus.

use custodiod::dbus::{BUS_NAME, OBJECT_PATH};
use secrecy::{ExposeSecret, SecretString};
use zbus::{Connection, block_on};

use crate::Importer;

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
    fn import_p12(&self, id: &str, p12: &[u8], password: &SecretString) -> Result<String, String> {
        let reply = block_on(self.connection.call_method(
            Some(BUS_NAME),
            OBJECT_PATH,
            Some(BUS_NAME),
            "ImportP12",
            &(id, p12, password.expose_secret()),
        ))
        .map_err(|e| match e {
            zbus::Error::MethodError(_, Some(text), _) => text,
            zbus::Error::MethodError(name, None, _) => name.to_string(),
            other => other.to_string(),
        })?;
        reply
            .body()
            .deserialize::<String>()
            .map_err(|e| e.to_string())
    }
}
