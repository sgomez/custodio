//! Who is calling, as the bus daemon says. Never taken from method arguments.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::hash::BuildHasher;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};

use zbus::{Connection, Fd, OwnedVariant};

use crate::audit::Caller;

const BUS_NAME: &str = "org.freedesktop.DBus";
const BUS_PATH: &str = "/org/freedesktop/DBus";
const BUS_INTERFACE: &str = "org.freedesktop.DBus";

/// Why the caller's uid and pid are not known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialsError {
    /// The bus answered without a `u32` `UnixUserID` or `ProcessID`, without a `ProcessFD`, or
    /// with a `ProcessFD` that is not a pidfd of `ProcessID`.
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

    /// As [`credentials`](Self::credentials), with the pidfd the bus pinned (the one checked against
    /// `ProcessID`), when the implementation has one. The default has none.
    fn pinned_credentials(
        &self,
        sender: &str,
    ) -> impl Future<Output = Result<(Caller, Option<OwnedFd>), CredentialsError>> + Send {
        let found = self.credentials(sender);
        async move { found.await.map(|caller| (caller, None)) }
    }
}

/// Checks the text of `/proc/self/fdinfo/<fd>` of a pidfd: its `Pid:` line must name `pid`.
/// `Pid: -1` (the process has exited), a missing line and garbage are all errors.
///
/// # Errors
/// [`CredentialsError::Missing`] unless the `Pid:` line is a number equal to `pid`.
pub fn check_pidfd_info(info: &str, pid: u32) -> Result<(), CredentialsError> {
    let line = info
        .lines()
        .find_map(|l| l.strip_prefix("Pid:"))
        .ok_or(CredentialsError::Missing)?;
    match line.trim().parse::<u32>() {
        Ok(got) if got == pid => Ok(()),
        _ => Err(CredentialsError::Missing),
    }
}

/// Reads `UnixUserID`, `ProcessID` and `ProcessFD` from a `GetConnectionCredentials` reply. No
/// default. The pidfd is only borrowed from the map and must refer to `ProcessID`.
///
/// # Errors
/// [`CredentialsError::Missing`] if a field is absent or of the wrong type, or if the pidfd cannot
/// be read or does not name `ProcessID`.
pub fn caller_from<S: BuildHasher>(
    map: &HashMap<String, OwnedVariant, S>,
) -> Result<Caller, CredentialsError> {
    pinned_from(map).map(|(caller, _)| caller)
}

/// As [`caller_from`], and the checked pidfd as an owned duplicate of the one in the reply.
///
/// # Errors
/// As [`caller_from`]; also if the pidfd cannot be duplicated.
pub fn pinned_from<S: BuildHasher>(
    map: &HashMap<String, OwnedVariant, S>,
) -> Result<(Caller, OwnedFd), CredentialsError> {
    let field = |name: &str| {
        map.get(name)
            .and_then(|v| u32::try_from(v).ok())
            .ok_or(CredentialsError::Missing)
    };
    let caller = Caller {
        uid: field("UnixUserID")?,
        pid: field("ProcessID")?,
    };
    let fd = map
        .get("ProcessFD")
        .and_then(|v| <&Fd<'_>>::try_from(v).ok())
        .ok_or(CredentialsError::Missing)?;
    let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", fd.as_raw_fd()))
        .map_err(|_| CredentialsError::Missing)?;
    check_pidfd_info(&info, caller.pid)?;
    let pinned = fd
        .as_fd()
        .try_clone_to_owned()
        .map_err(|_| CredentialsError::Missing)?;
    Ok((caller, pinned))
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
        self.pinned_credentials(sender)
            .await
            .map(|(caller, _)| caller)
    }

    async fn pinned_credentials(
        &self,
        sender: &str,
    ) -> Result<(Caller, Option<OwnedFd>), CredentialsError> {
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
        pinned_from(&map).map(|(caller, fd)| (caller, Some(fd)))
    }
}

#[cfg(test)]
mod tests;
