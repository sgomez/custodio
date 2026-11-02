//! Why a call to the service failed, as a value the CLI can tell apart.
//!
//! One case per documented error name, one for "the service is not on the bus", one for any
//! other transport problem, one for a name that is not documented. Each has a fixed message: the
//! service's own text, the password, the file path and key material never reach it.

use std::fmt;

use custodio_client::{
    ERROR_AUDIT_UNAVAILABLE, ERROR_AUTHORIZATION_UNAVAILABLE, ERROR_CERTIFICATE_MISMATCH,
    ERROR_INTERNAL, ERROR_INVALID_ARGS, ERROR_KEY_ID_TAKEN, ERROR_NO_SUCH_KEY, ERROR_POLKIT_DENIED,
    ERROR_UNSUPPORTED_KEY_TYPE, ERROR_WRONG_PASSWORD_OR_BAD_P12,
};

/// Prefix of the names the bus daemon itself uses (`ServiceUnknown`, `AccessDenied`, ...).
const BUS_DAEMON_PREFIX: &str = "org.freedesktop.DBus.Error.";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceFailure {
    InvalidArgs,
    NoSuchKey,
    KeyIdTaken,
    PolkitDenied,
    AuthorizationUnavailable,
    WrongPasswordOrBadP12,
    UnsupportedKeyType,
    CertificateMismatch,
    AuditUnavailable,
    Internal,
    /// Nobody owns the service's bus name.
    ServiceAbsent,
    /// The bus refused or could not carry the call, or the reply was not what the API describes.
    Transport,
    /// An error name that the API does not document (the name is shown, nothing else of it).
    Unknown(String),
}

impl ServiceFailure {
    /// The failure for an error name in a method error reply.
    #[must_use]
    pub fn from_name(name: &str) -> Self {
        match name {
            ERROR_INVALID_ARGS => Self::InvalidArgs,
            ERROR_NO_SUCH_KEY => Self::NoSuchKey,
            ERROR_KEY_ID_TAKEN => Self::KeyIdTaken,
            ERROR_POLKIT_DENIED => Self::PolkitDenied,
            ERROR_AUTHORIZATION_UNAVAILABLE => Self::AuthorizationUnavailable,
            ERROR_WRONG_PASSWORD_OR_BAD_P12 => Self::WrongPasswordOrBadP12,
            ERROR_UNSUPPORTED_KEY_TYPE => Self::UnsupportedKeyType,
            ERROR_CERTIFICATE_MISMATCH => Self::CertificateMismatch,
            ERROR_AUDIT_UNAVAILABLE => Self::AuditUnavailable,
            ERROR_INTERNAL => Self::Internal,
            "org.freedesktop.DBus.Error.ServiceUnknown"
            | "org.freedesktop.DBus.Error.NameHasNoOwner" => Self::ServiceAbsent,
            other if other.starts_with(BUS_DAEMON_PREFIX) => Self::Transport,
            other => Self::Unknown(other.to_owned()),
        }
    }

    /// What to tell the person. Fixed text: it says what happened and what to do about it.
    #[must_use]
    pub fn message(&self) -> String {
        let text = match self {
            Self::InvalidArgs => {
                "the service rejected the request: the key id, the file or the password is not acceptable"
            }
            Self::KeyIdTaken => "a key with this id already exists; choose another with --id",
            Self::WrongPasswordOrBadP12 => {
                "wrong password, or the file is not a usable .p12 (it must hold one private key and its certificate)"
            }
            Self::UnsupportedKeyType => {
                "unsupported key type; only RSA 2048 and ECDSA P-256 are accepted"
            }
            Self::CertificateMismatch => "no certificate in the .p12 file matches its private key",
            Self::Internal => "the service could not store the key (see its log)",
            Self::AuditUnavailable => "the service cannot write its audit log (see its log)",
            Self::NoSuchKey => "the service reports that no such key exists",
            Self::PolkitDenied => "not authorized",
            Self::AuthorizationUnavailable => {
                "the service cannot ask for authorization (see its log)"
            }
            Self::ServiceAbsent => {
                "cannot talk to the service: it is not running on the system bus"
            }
            Self::Transport => "cannot talk to the service: the system bus did not carry the call",
            Self::Unknown(name) => {
                return format!("the service answered with an unknown error ({name})");
            }
        };
        text.to_owned()
    }
}

impl fmt::Display for ServiceFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message())
    }
}

impl std::error::Error for ServiceFailure {}

#[cfg(test)]
mod tests;
