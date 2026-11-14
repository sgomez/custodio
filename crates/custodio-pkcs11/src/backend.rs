//! The service behind the module: a trait, so the logic can be tested without a bus, and the
//! D-Bus implementation.
#![forbid(unsafe_code)]

use std::os::unix::net::UnixStream;

use zbus::connection::{AuthMechanism, Builder};
use zbus::{Connection, block_on};

use custodio_client::{
    BUS_NAME, ERROR_AUTHORIZATION_UNAVAILABLE, ERROR_INVALID_ARGS, ERROR_POLKIT_DENIED, OBJECT_PATH,
};

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

mod socket;
#[cfg(feature = "test-socket-dir")]
mod test_dir;

use socket::Transport;
pub use socket::{SNAP_INSTANCE_VAR, SOCKET_PATH_TEMPLATE};

/// Talks to `custodiod` on the system bus, or, inside a snap (`SNAP_INSTANCE_NAME` set), on the snap's socket. A connection is opened for every call and dropped
/// after it, so no connection, thread or lock outlives a call and nothing survives `fork` in a
/// state the child could misuse; the cost is a few milliseconds per call.
#[derive(Debug, Default, Clone, Copy)]
pub struct DbusBackend;

/// The `BackendError` for a failure of the service. The CKR value of each case is the one the module
/// has always returned: polkit's refusal and "authorization unavailable" are `Denied`
/// (`CKR_FUNCTION_FAILED`), a rejected request is `Invalid` (`CKR_DATA_INVALID`), everything else,
/// including a name this version does not know, is `Unavailable` (`CKR_DEVICE_ERROR`).
///
/// The two generic `org.freedesktop.DBus.Error` names keep their old meaning: the bus itself
/// answers `AccessDenied` when its policy refuses the call, and a service older than the project
/// error names answers both.
fn error_for_name(name: &str) -> BackendError {
    match name {
        ERROR_POLKIT_DENIED | ERROR_AUTHORIZATION_UNAVAILABLE | FDO_ACCESS_DENIED => {
            BackendError::Denied
        }
        ERROR_INVALID_ARGS | FDO_INVALID_ARGS => BackendError::Invalid,
        _ => BackendError::Unavailable,
    }
}

const FDO_ACCESS_DENIED: &str = "org.freedesktop.DBus.Error.AccessDenied";
const FDO_INVALID_ARGS: &str = "org.freedesktop.DBus.Error.InvalidArgs";

fn map_error(e: &zbus::Error) -> BackendError {
    match e {
        zbus::Error::MethodError(name, _, _) => error_for_name(name.as_str()),
        zbus::Error::FDO(e) => match **e {
            zbus::fdo::Error::AccessDenied(_) => BackendError::Denied,
            zbus::fdo::Error::InvalidArgs(_) => BackendError::Invalid,
            _ => BackendError::Unavailable,
        },
        _ => BackendError::Unavailable,
    }
}

/// A connection for one call, and the destination to name in it (none on the socket: it is peer to peer).
async fn connect() -> Result<(Connection, Option<&'static str>), zbus::Error> {
    match socket::current() {
        Transport::Bus => Ok((Connection::system().await?, Some(BUS_NAME))),
        Transport::Socket(path) => {
            let stream = UnixStream::connect(path).map_err(zbus::Error::from)?;
            let connection = Builder::unix_stream(stream)
                .p2p()
                .auth_mechanism(AuthMechanism::Anonymous)
                .build()
                .await?;
            Ok((connection, None))
        }
        // Inside a snap with no trustworthy socket: the same as a service that is not there.
        Transport::None => Err(zbus::Error::Unsupported),
    }
}

impl Backend for DbusBackend {
    fn list_certificates(&self) -> Result<Vec<(String, Vec<u8>)>, BackendError> {
        block_on(async {
            let (connection, destination) = connect().await?;
            let reply = connection
                .call_method(destination, OBJECT_PATH, Some(BUS_NAME), "ListKeys", &())
                .await?;
            reply
                .body()
                .deserialize::<Vec<(String, String, String, Vec<u8>)>>()
        })
        // `ListKeys` also gives the key type and the storage kind; the module reads it from the certificate.
        .map(|keys| {
            keys.into_iter()
                .map(|(id, _, _, cert)| (id, cert))
                .collect()
        })
        .map_err(|e| map_error(&e))
    }

    fn sign(&self, id: &str, params: SignParams, data: &[u8]) -> Result<Vec<u8>, BackendError> {
        let body = (id, params.mechanism, params.hash, params.salt_len, data);
        block_on(async {
            let (connection, destination) = connect().await?;
            let reply = connection
                .call_method(destination, OBJECT_PATH, Some(BUS_NAME), "Sign", &body)
                .await?;
            reply.body().deserialize::<Vec<u8>>()
        })
        .map_err(|e| map_error(&e))
    }
}

#[cfg(test)]
mod tests;
