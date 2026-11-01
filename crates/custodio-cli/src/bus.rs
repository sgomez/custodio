//! `ImportP12` over D-Bus.

use custodio_client::{
    BUS_NAME, ERROR_AUDIT_UNAVAILABLE, ERROR_AUTHORIZATION_UNAVAILABLE, ERROR_CERTIFICATE_MISMATCH,
    ERROR_INTERNAL, ERROR_INVALID_ARGS, ERROR_KEY_ID_TAKEN, ERROR_NO_SUCH_KEY, ERROR_POLKIT_DENIED,
    ERROR_UNSUPPORTED_KEY_TYPE, ERROR_WRONG_PASSWORD_OR_BAD_P12, OBJECT_PATH,
};
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
        .map_err(|e| error_message(&e))?;
        reply
            .body()
            .deserialize::<String>()
            .map_err(|e| e.to_string())
    }
}

/// What to tell the person for a service error name. The service's own message text is not shown:
/// the name says what happened, and these texts say what to do about it.
#[must_use]
pub fn message_for_name(name: &str) -> String {
    let text = match name {
        ERROR_INVALID_ARGS => {
            "the service rejected the request: the key id, the file or the password is not acceptable"
        }
        ERROR_KEY_ID_TAKEN => "a key with this id already exists; choose another with --id",
        ERROR_WRONG_PASSWORD_OR_BAD_P12 => {
            "wrong password, or the file is not a usable .p12 (it must hold one private key and its certificate)"
        }
        ERROR_UNSUPPORTED_KEY_TYPE => {
            "unsupported key type; only RSA 2048 and ECDSA P-256 are accepted"
        }
        ERROR_CERTIFICATE_MISMATCH => "no certificate in the .p12 file matches its private key",
        ERROR_INTERNAL => "the service could not store the key (see its log)",
        ERROR_AUDIT_UNAVAILABLE => "the service cannot write its audit log (see its log)",
        ERROR_NO_SUCH_KEY => "the service reports that no such key exists",
        ERROR_POLKIT_DENIED => "not authorized",
        ERROR_AUTHORIZATION_UNAVAILABLE => "the service cannot ask for authorization (see its log)",
        other => return format!("the service answered with an unknown error ({other})"),
    };
    text.to_owned()
}

/// The message for a failed call: by error name for the service's own names, and the transport
/// error (the bus refused or could not be reached) otherwise.
#[must_use]
pub fn error_message(e: &zbus::Error) -> String {
    match e {
        zbus::Error::MethodError(name, _, _) => message_for_name(name.as_str()),
        other => format!("cannot talk to the service: {other}"),
    }
}

#[cfg(test)]
mod tests;
