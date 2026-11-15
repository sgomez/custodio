//! Why a call to the service failed, as a value the CLI can tell apart.
//!
//! One case per documented error name, one for "the service is not on the bus", one for any
//! other transport problem, one for a name that is not documented. Each has a fixed message: the
//! service's own text, the password, the file path and key material never reach it.

use std::fmt;

use custodio_client::{
    ERROR_AUDIT_UNAVAILABLE, ERROR_AUTHORIZATION_UNAVAILABLE, ERROR_CERTIFICATE_MISMATCH,
    ERROR_CREDENTIALS_UNAVAILABLE, ERROR_INTERNAL, ERROR_INVALID_ARGS, ERROR_KEY_ID_TAKEN,
    ERROR_KEY_LOST, ERROR_NO_SUCH_KEY, ERROR_POLKIT_DENIED, ERROR_TEMPORARILY_UNAVAILABLE,
    ERROR_TPM_FAILED, ERROR_UNSUPPORTED_KEY_TYPE, ERROR_WRONG_PASSWORD_OR_BAD_P12,
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
    /// The TPM is present but failed or cannot be used; nothing was stored.
    TpmFailed,
    /// The credential service is down or refused; nothing was stored.
    CredentialsUnavailable,
    /// The stored key can no longer be used.
    KeyLost,
    /// The TPM or the credential service cannot be used right now.
    TemporarilyUnavailable,
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
            ERROR_TPM_FAILED => Self::TpmFailed,
            ERROR_CREDENTIALS_UNAVAILABLE => Self::CredentialsUnavailable,
            ERROR_KEY_LOST => Self::KeyLost,
            ERROR_TEMPORARILY_UNAVAILABLE => Self::TemporarilyUnavailable,
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
            Self::TpmFailed => "the TPM failed or cannot be used; nothing was stored",
            Self::CredentialsUnavailable => {
                "the credential service is unavailable; nothing was stored"
            }
            Self::KeyLost => "the stored key can no longer be used",
            Self::TemporarilyUnavailable => "the key cannot be used right now",
            Self::ServiceAbsent => {
                "cannot talk to the service: it is not running on the system bus"
            }
            Self::Transport => "cannot talk to the service: the system bus did not carry the call",
            Self::Unknown(name) => {
                return format!(
                    "the service answered with an unknown error ({})",
                    crate::cert_text::escape(name)
                );
            }
        };
        text.to_owned()
    }
}

impl ServiceFailure {
    /// The next step for the person: a command, a documented section, or where to report a bug.
    #[must_use]
    pub const fn next_step(&self) -> &'static str {
        match self {
            Self::InvalidArgs => {
                "Check the key id (letters, digits, _ and -) and the file, then try again."
            }
            Self::NoSuchKey => "Run 'custodio list' to see your key ids.",
            Self::KeyIdTaken => {
                "Run 'custodio list' to see the ids in use, or pick another with --id."
            }
            Self::PolkitDenied => {
                "Run the command again and approve the authentication dialog; see 'Polkit actions' in docs/api.md."
            }
            Self::AuthorizationUnavailable => {
                "Check that polkit runs (systemctl status polkit) and that a polkit agent is running, then try again."
            }
            Self::WrongPasswordOrBadP12 => {
                "Run the command again and type the password of the .p12 file; see 'ImportP12' in docs/api.md."
            }
            Self::UnsupportedKeyType => {
                "Export the key as RSA 2048 or ECDSA P-256; see 'ImportP12' in docs/api.md."
            }
            Self::CertificateMismatch => {
                "Export the .p12 again with the certificate that belongs to its private key."
            }
            Self::AuditUnavailable => {
                "Read the service log: journalctl -u custodio.service; nothing was changed."
            }
            Self::Internal => {
                "Read the service log: journalctl -u custodio.service; if it shows no cause, report a bug (see README.md)."
            }
            Self::TpmFailed => {
                "Read the service log: journalctl -u custodio.service; see 'TPM capabilities' in docs/api.md."
            }
            Self::CredentialsUnavailable => {
                "Check that systemd-creds works on this machine (see docs/install.md), then run the command again."
            }
            Self::KeyLost => {
                "Delete the key with 'custodio delete <key id>' and import it again; see 'Errors' in docs/api.md."
            }
            Self::TemporarilyUnavailable => {
                "Try again in a moment; if it persists, read the service log: journalctl -u custodio.service."
            }
            Self::ServiceAbsent | Self::Transport => {
                "Check that the service is installed and running: systemctl status custodio.service; see docs/install.md."
            }
            Self::Unknown(_) => {
                "This CLI may be older than the service; update it, or report a bug (see README.md)."
            }
        }
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
