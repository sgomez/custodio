//! The service behind the module: a trait, so the logic can be tested without a bus, and the
//! D-Bus implementation.
#![forbid(unsafe_code)]

use zbus::{Connection, block_on};

/// Name and object path of the service (`custodiod::dbus::BUS_NAME` and `OBJECT_PATH`; the
/// integration test checks they agree, so this crate does not link the service).
const BUS_NAME: &str = "com.rfirma.Custodio1";
const OBJECT_PATH: &str = "/com/rfirma/Custodio1";

/// Why a call to the service failed, reduced to what the PKCS#11 layer needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendError {
    /// The user, or polkit, refused the signature.
    Denied,
    /// The service rejected the request itself.
    Invalid,
    /// The service or the bus could not be reached, or failed.
    Unavailable,
}

/// Mechanism and parameters of one signature, as the service takes them (`CKM_*` numbers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignParams {
    pub mechanism: u32,
    pub hash: u32,
    pub salt_len: u32,
}

pub trait Backend: Send + Sync {
    /// `(key id, DER certificate)` of every key that has a certificate.
    ///
    /// # Errors
    /// If the service cannot be reached.
    fn list_certificates(&self) -> Result<Vec<(String, Vec<u8>)>, BackendError>;

    /// One signature. The service asks polkit on every call.
    ///
    /// # Errors
    /// If the signature was refused, rejected or could not be made.
    fn sign(&self, id: &str, params: SignParams, data: &[u8]) -> Result<Vec<u8>, BackendError>;
}

/// Talks to `custodiod` on the system bus. A connection is opened for every call and dropped
/// after it, so no connection, thread or lock outlives a call and nothing survives `fork` in a
/// state the child could misuse; the cost is a few milliseconds per call.
#[derive(Debug, Default, Clone, Copy)]
pub struct DbusBackend;

fn map_error(e: &zbus::Error) -> BackendError {
    match e {
        zbus::Error::MethodError(name, _, _) => match name.as_str() {
            "org.freedesktop.DBus.Error.AccessDenied" => BackendError::Denied,
            "org.freedesktop.DBus.Error.InvalidArgs" => BackendError::Invalid,
            _ => BackendError::Unavailable,
        },
        zbus::Error::FDO(e) => match **e {
            zbus::fdo::Error::AccessDenied(_) => BackendError::Denied,
            zbus::fdo::Error::InvalidArgs(_) => BackendError::Invalid,
            _ => BackendError::Unavailable,
        },
        _ => BackendError::Unavailable,
    }
}

impl Backend for DbusBackend {
    fn list_certificates(&self) -> Result<Vec<(String, Vec<u8>)>, BackendError> {
        block_on(async {
            let connection = Connection::system().await?;
            let reply = connection
                .call_method(
                    Some(BUS_NAME),
                    OBJECT_PATH,
                    Some(BUS_NAME),
                    "ListCertificates",
                    &(),
                )
                .await?;
            reply.body().deserialize::<Vec<(String, Vec<u8>)>>()
        })
        .map_err(|e| map_error(&e))
    }

    fn sign(&self, id: &str, params: SignParams, data: &[u8]) -> Result<Vec<u8>, BackendError> {
        let body = (id, params.mechanism, params.hash, params.salt_len, data);
        block_on(async {
            let connection = Connection::system().await?;
            let reply = connection
                .call_method(Some(BUS_NAME), OBJECT_PATH, Some(BUS_NAME), "Sign", &body)
                .await?;
            reply.body().deserialize::<Vec<u8>>()
        })
        .map_err(|e| map_error(&e))
    }
}
