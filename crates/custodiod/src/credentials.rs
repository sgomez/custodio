//! Who is calling, as the bus daemon says. Never taken from method arguments.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::hash::BuildHasher;

use zbus::{Connection, OwnedVariant};

use crate::audit::Caller;

const BUS_NAME: &str = "org.freedesktop.DBus";
const BUS_PATH: &str = "/org/freedesktop/DBus";
const BUS_INTERFACE: &str = "org.freedesktop.DBus";

/// Why the caller's uid and pid are not known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialsError {
    /// The bus answered without a `u32` `UnixUserID` or `ProcessID`.
    Missing,
    /// The bus could not be asked or refused.
    Bus,
}

impl fmt::Display for CredentialsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Missing => "bus credentials incomplete",
            Self::Bus => "bus credentials unavailable",
        })
    }
}

impl std::error::Error for CredentialsError {}

/// Looks up the uid and pid of a bus sender. Tests use fakes.
pub trait CallerCredentials {
    /// The credentials of the connection `sender`, from the bus daemon.
    fn credentials(
        &self,
        sender: &str,
    ) -> impl Future<Output = Result<Caller, CredentialsError>> + Send;
}

/// Reads `UnixUserID` and `ProcessID` from a `GetConnectionCredentials` reply. No default.
///
/// # Errors
/// [`CredentialsError::Missing`] if either is absent or not a `u32`.
pub fn caller_from<S: BuildHasher>(
    map: &HashMap<String, OwnedVariant, S>,
) -> Result<Caller, CredentialsError> {
    let field = |name: &str| {
        map.get(name)
            .and_then(|v| u32::try_from(v).ok())
            .ok_or(CredentialsError::Missing)
    };
    Ok(Caller {
        uid: field("UnixUserID")?,
        pid: field("ProcessID")?,
    })
}

/// Asks the bus daemon (`GetConnectionCredentials`) on the given connection.
#[derive(Debug, Clone)]
pub struct BusCredentials {
    connection: Connection,
}

impl BusCredentials {
    #[must_use]
    pub fn new(connection: Connection) -> Self {
        Self { connection }
    }
}

impl CallerCredentials for BusCredentials {
    async fn credentials(&self, sender: &str) -> Result<Caller, CredentialsError> {
        let reply = self
            .connection
            .call_method(
                Some(BUS_NAME),
                BUS_PATH,
                Some(BUS_INTERFACE),
                "GetConnectionCredentials",
                &(sender,),
            )
            .await
            .map_err(|_| CredentialsError::Bus)?;
        let map: HashMap<String, OwnedVariant> = reply
            .body()
            .deserialize()
            .map_err(|_| CredentialsError::Bus)?;
        caller_from(&map)
    }
}

#[cfg(test)]
mod tests;
