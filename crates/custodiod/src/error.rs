//! The one error type of the D-Bus service. Each variant is one D-Bus error name under
//! `com.rfirma.Custodio1.Error` (the names are defined in `custodio-client`) and one fixed message.
//!
//! The messages are for people and never contain key ids, paths, passwords, `.p12` bytes, parser
//! errors or any input: the variant is all a reply says. Names are only ever added to.
//!
//! A `.p12` with no private key, several private keys, or a key without a certificate is reported
//! as [`ServiceError::WrongPasswordOrBadP12`]: the file cannot be used as an import.

use std::fmt;

use custodio_client::{
    ERROR_AUDIT_UNAVAILABLE, ERROR_AUTHORIZATION_UNAVAILABLE, ERROR_CERTIFICATE_MISMATCH,
    ERROR_CREDENTIALS_UNAVAILABLE, ERROR_INTERNAL, ERROR_INVALID_ARGS, ERROR_KEY_ID_TAKEN,
    ERROR_NO_SUCH_KEY, ERROR_POLKIT_DENIED, ERROR_TPM_FAILED, ERROR_UNSUPPORTED_KEY_TYPE,
    ERROR_WRONG_PASSWORD_OR_BAD_P12,
};
use zbus::message::{Header, Message};
use zbus::names::ErrorName;

use crate::dbus::RequestError;
use crate::import::ImportError;
use crate::polkit::AuthError;
use crate::sign::SignError;
use crate::store::StoreError;

/// Why a call failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceError {
    InvalidArgs,
    NoSuchKey,
    KeyIdTaken,
    PolkitDenied,
    AuthorizationUnavailable,
    WrongPasswordOrBadP12,
    UnsupportedKeyType,
    CertificateMismatch,
    AuditUnavailable,
    /// The TPM failed or cannot be used for an import.
    TpmFailed,
    /// The credential service is unavailable or refused an import.
    CredentialsUnavailable,
    Internal,
}

impl ServiceError {
    /// Every variant.
    pub const ALL: [Self; 12] = [
        Self::InvalidArgs,
        Self::NoSuchKey,
        Self::KeyIdTaken,
        Self::PolkitDenied,
        Self::AuthorizationUnavailable,
        Self::WrongPasswordOrBadP12,
        Self::UnsupportedKeyType,
        Self::CertificateMismatch,
        Self::AuditUnavailable,
        Self::TpmFailed,
        Self::CredentialsUnavailable,
        Self::Internal,
    ];

    /// The D-Bus error name.
    #[must_use]
    pub fn error_name(self) -> &'static str {
        match self {
            Self::InvalidArgs => ERROR_INVALID_ARGS,
            Self::NoSuchKey => ERROR_NO_SUCH_KEY,
            Self::KeyIdTaken => ERROR_KEY_ID_TAKEN,
            Self::PolkitDenied => ERROR_POLKIT_DENIED,
            Self::AuthorizationUnavailable => ERROR_AUTHORIZATION_UNAVAILABLE,
            Self::WrongPasswordOrBadP12 => ERROR_WRONG_PASSWORD_OR_BAD_P12,
            Self::UnsupportedKeyType => ERROR_UNSUPPORTED_KEY_TYPE,
            Self::CertificateMismatch => ERROR_CERTIFICATE_MISMATCH,
            Self::AuditUnavailable => ERROR_AUDIT_UNAVAILABLE,
            Self::TpmFailed => ERROR_TPM_FAILED,
            Self::CredentialsUnavailable => ERROR_CREDENTIALS_UNAVAILABLE,
            Self::Internal => ERROR_INTERNAL,
        }
    }

    /// The fixed message: the same for every input.
    #[must_use]
    pub fn message(self) -> &'static str {
        match self {
            Self::InvalidArgs => "invalid arguments",
            Self::NoSuchKey => "no such key",
            Self::KeyIdTaken => "a key with this id already exists",
            Self::PolkitDenied => "not authorized",
            Self::AuthorizationUnavailable => "authorization unavailable",
            Self::WrongPasswordOrBadP12 => "wrong password or unreadable .p12 file",
            Self::UnsupportedKeyType => "unsupported key type",
            Self::CertificateMismatch => "certificate does not match the key",
            Self::AuditUnavailable => "audit unavailable",
            Self::TpmFailed => "the TPM failed or cannot be used",
            Self::CredentialsUnavailable => "the credential service is unavailable",
            Self::Internal => "internal error",
        }
    }
}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for ServiceError {}

impl zbus::DBusError for ServiceError {
    fn create_reply(&self, call: &Header<'_>) -> zbus::Result<Message> {
        Message::error(call, self.error_name()).build(&self.message())
    }

    fn name(&self) -> ErrorName<'_> {
        ErrorName::from_static_str_unchecked(self.error_name())
    }

    fn description(&self) -> Option<&str> {
        Some(self.message())
    }
}

impl From<&RequestError> for ServiceError {
    fn from(_: &RequestError) -> Self {
        Self::InvalidArgs
    }
}

impl From<&StoreError> for ServiceError {
    fn from(e: &StoreError) -> Self {
        match e {
            StoreError::InvalidId => Self::InvalidArgs,
            StoreError::AlreadyExists => Self::KeyIdTaken,
            StoreError::NotFound => Self::NoSuchKey,
            _ => Self::Internal,
        }
    }
}

impl From<&ImportError> for ServiceError {
    fn from(e: &ImportError) -> Self {
        match e {
            ImportError::TooLarge => Self::InvalidArgs,
            ImportError::Parse(_)
            | ImportError::NoPrivateKey
            | ImportError::MultipleKeys
            | ImportError::NoCertificate => Self::WrongPasswordOrBadP12,
            ImportError::CertificateMismatch => Self::CertificateMismatch,
            ImportError::UnsupportedKey(_) => Self::UnsupportedKeyType,
            ImportError::Tpm(_) => Self::TpmFailed,
            ImportError::Protect(_) | ImportError::BindingMismatch => Self::CredentialsUnavailable,
            ImportError::Store(e) => Self::from(e),
        }
    }
}

impl From<&SignError> for ServiceError {
    fn from(e: &SignError) -> Self {
        match e {
            SignError::BadData | SignError::MechanismMismatch => Self::InvalidArgs,
            SignError::BadKey | SignError::Failed => Self::Internal,
        }
    }
}

impl From<&AuthError> for ServiceError {
    fn from(e: &AuthError) -> Self {
        match e {
            AuthError::Denied => Self::PolkitDenied,
            AuthError::BadSender | AuthError::Unavailable(_) => Self::AuthorizationUnavailable,
        }
    }
}

#[cfg(test)]
mod tests;
