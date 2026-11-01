//! The operations an entry can name, and the entries of the operations other than signing.
//!
//! Every entry has `CUSTODIO_OPERATION`. Each of import, delete and replace certificate has its own
//! outcome type, so an outcome cannot be paired with an operation it does not belong to, and one
//! `MESSAGE_ID` per operation. Like [`super::Entry`], an [`OperationEntry`] is built from typed parts only:
//! a `.p12`, a password, certificate bytes, data and signatures have no place in it.

use super::{Caller, KeyId};

/// What a request asked Custodio to do. Value of `CUSTODIO_OPERATION`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Sign,
    Import,
    Delete,
    ReplaceCertificate,
}

impl Operation {
    /// Every operation; the exhaustive match stops compiling when a variant is added.
    #[must_use]
    pub const fn all() -> [Self; 4] {
        match Self::Sign {
            Self::Sign | Self::Import | Self::Delete | Self::ReplaceCertificate => [
                Self::Sign,
                Self::Import,
                Self::Delete,
                Self::ReplaceCertificate,
            ],
        }
    }

    /// Value of `CUSTODIO_OPERATION`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sign => "sign",
            Self::Import => "import",
            Self::Delete => "delete",
            Self::ReplaceCertificate => "replace_certificate",
        }
    }

    /// `MESSAGE_ID` of the entries of this operation.
    #[must_use]
    pub const fn message_id(self) -> &'static str {
        match self {
            Self::Sign => super::MESSAGE_ID,
            Self::Import => IMPORT_MESSAGE_ID,
            Self::Delete => DELETE_MESSAGE_ID,
            Self::ReplaceCertificate => REPLACE_CERTIFICATE_MESSAGE_ID,
        }
    }
}

/// `MESSAGE_ID` of every import entry.
pub const IMPORT_MESSAGE_ID: &str = "4c7163ce45d0b9faf8e7c38d098bdb22";
/// `MESSAGE_ID` of every delete entry.
pub const DELETE_MESSAGE_ID: &str = "13d1a981ea8f64fc1a6f390bee7fd66c";
/// `MESSAGE_ID` of every replace certificate entry.
pub const REPLACE_CERTIFICATE_MESSAGE_ID: &str = "336e0b53720a735afb179ebc7f779ed6";

/// Type of an imported key, by fixed name only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditKeyType {
    Rsa2048,
    EcdsaP256,
}

impl AuditKeyType {
    /// Every key type; the exhaustive match stops compiling when a variant is added.
    #[must_use]
    pub const fn all() -> [Self; 2] {
        match Self::Rsa2048 {
            Self::Rsa2048 | Self::EcdsaP256 => [Self::Rsa2048, Self::EcdsaP256],
        }
    }

    /// Value of `CUSTODIO_KEY_TYPE`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Rsa2048 => "rsa_2048",
            Self::EcdsaP256 => "ecdsa_p256",
        }
    }
}

/// Result of an import.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportOutcome {
    /// Approved, decoded and stored.
    Stored,
    /// polkit denied the request.
    Denied,
    /// polkit could not decide, or the caller was unknown.
    AuthorizationUnavailable,
    /// Approved, but the password did not open the file.
    WrongPassword,
    /// Approved, but the file holds no key Custodio accepts.
    UnsupportedKey,
    /// Approved, but the key could not be stored.
    StorageFailure,
}

/// Result of a delete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteOutcome {
    /// Approved and removed.
    Deleted,
    /// polkit denied the request.
    Denied,
    /// polkit could not decide, or the caller was unknown.
    AuthorizationUnavailable,
    /// Approved, but the key could not be removed.
    StorageFailure,
}

/// Result of a replace certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplaceOutcome {
    /// Approved and replaced.
    Replaced,
    /// polkit denied the request.
    Denied,
    /// polkit could not decide, or the caller was unknown.
    AuthorizationUnavailable,
    /// Approved, but the certificate does not belong to the key.
    CertificateMismatch,
    /// Approved, but the certificate could not be stored.
    StorageFailure,
}

impl ImportOutcome {
    /// Every outcome; the exhaustive match stops compiling when a variant is added.
    #[must_use]
    pub const fn all() -> [Self; 6] {
        match Self::Stored {
            Self::Stored
            | Self::Denied
            | Self::AuthorizationUnavailable
            | Self::WrongPassword
            | Self::UnsupportedKey
            | Self::StorageFailure => [
                Self::Stored,
                Self::Denied,
                Self::AuthorizationUnavailable,
                Self::WrongPassword,
                Self::UnsupportedKey,
                Self::StorageFailure,
            ],
        }
    }

    /// Value of `CUSTODIO_OUTCOME`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Stored => "stored",
            Self::Denied => "denied",
            Self::AuthorizationUnavailable => "authorization_unavailable",
            Self::WrongPassword => "wrong_password",
            Self::UnsupportedKey => "unsupported_key",
            Self::StorageFailure => "storage_failure",
        }
    }

    /// Syslog priority.
    #[must_use]
    pub const fn priority(self) -> u8 {
        match self {
            Self::Stored => 6,
            Self::Denied => 5,
            Self::AuthorizationUnavailable | Self::WrongPassword | Self::UnsupportedKey => 4,
            Self::StorageFailure => 3,
        }
    }

    const fn phrase(self) -> &'static str {
        match self {
            Self::Stored => "key imported",
            Self::Denied => "import denied",
            Self::AuthorizationUnavailable => "import authorization unavailable, nothing stored",
            Self::WrongPassword => "import failed, wrong password",
            Self::UnsupportedKey => "import failed, unsupported key",
            Self::StorageFailure => "import failed after approval, key not stored",
        }
    }
}

impl DeleteOutcome {
    /// Every outcome; the exhaustive match stops compiling when a variant is added.
    #[must_use]
    pub const fn all() -> [Self; 4] {
        match Self::Deleted {
            Self::Deleted
            | Self::Denied
            | Self::AuthorizationUnavailable
            | Self::StorageFailure => [
                Self::Deleted,
                Self::Denied,
                Self::AuthorizationUnavailable,
                Self::StorageFailure,
            ],
        }
    }

    /// Value of `CUSTODIO_OUTCOME`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Deleted => "deleted",
            Self::Denied => "denied",
            Self::AuthorizationUnavailable => "authorization_unavailable",
            Self::StorageFailure => "storage_failure",
        }
    }

    /// Syslog priority.
    #[must_use]
    pub const fn priority(self) -> u8 {
        match self {
            Self::Deleted => 6,
            Self::Denied => 5,
            Self::AuthorizationUnavailable => 4,
            Self::StorageFailure => 3,
        }
    }

    const fn phrase(self) -> &'static str {
        match self {
            Self::Deleted => "key deleted",
            Self::Denied => "delete denied",
            Self::AuthorizationUnavailable => "delete authorization unavailable, nothing deleted",
            Self::StorageFailure => "delete failed after approval, key not removed",
        }
    }
}

impl ReplaceOutcome {
    /// Every outcome; the exhaustive match stops compiling when a variant is added.
    #[must_use]
    pub const fn all() -> [Self; 5] {
        match Self::Replaced {
            Self::Replaced
            | Self::Denied
            | Self::AuthorizationUnavailable
            | Self::CertificateMismatch
            | Self::StorageFailure => [
                Self::Replaced,
                Self::Denied,
                Self::AuthorizationUnavailable,
                Self::CertificateMismatch,
                Self::StorageFailure,
            ],
        }
    }

    /// Value of `CUSTODIO_OUTCOME`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Replaced => "replaced",
            Self::Denied => "denied",
            Self::AuthorizationUnavailable => "authorization_unavailable",
            Self::CertificateMismatch => "certificate_mismatch",
            Self::StorageFailure => "storage_failure",
        }
    }

    /// Syslog priority.
    #[must_use]
    pub const fn priority(self) -> u8 {
        match self {
            Self::Replaced => 6,
            Self::Denied => 5,
            Self::AuthorizationUnavailable | Self::CertificateMismatch => 4,
            Self::StorageFailure => 3,
        }
    }

    const fn phrase(self) -> &'static str {
        match self {
            Self::Replaced => "certificate replaced",
            Self::Denied => "certificate replacement denied",
            Self::AuthorizationUnavailable => {
                "certificate replacement authorization unavailable, nothing changed"
            }
            Self::CertificateMismatch => {
                "certificate replacement refused, certificate does not match the key"
            }
            Self::StorageFailure => {
                "certificate replacement failed after approval, nothing changed"
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Import(ImportOutcome, Option<AuditKeyType>),
    Delete(DeleteOutcome),
    Replace(ReplaceOutcome),
}

/// One audit entry of an import, delete or replace certificate. Built only by its constructors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationEntry {
    kind: Kind,
    caller: Option<Caller>,
    key_id: KeyId,
}

impl OperationEntry {
    /// An import entry. `key_type` is `None` when the file did not get far enough to have one (an
    /// unreadable file, a wrong password, a refusal before decoding). `caller` is `None` when the
    /// bus named none.
    #[must_use]
    pub const fn import(
        outcome: ImportOutcome,
        caller: Option<Caller>,
        key_id: KeyId,
        key_type: Option<AuditKeyType>,
    ) -> Self {
        Self {
            kind: Kind::Import(outcome, key_type),
            caller,
            key_id,
        }
    }

    /// A delete entry.
    #[must_use]
    pub const fn delete(outcome: DeleteOutcome, caller: Option<Caller>, key_id: KeyId) -> Self {
        Self {
            kind: Kind::Delete(outcome),
            caller,
            key_id,
        }
    }

    /// A replace certificate entry.
    #[must_use]
    pub const fn replace_certificate(
        outcome: ReplaceOutcome,
        caller: Option<Caller>,
        key_id: KeyId,
    ) -> Self {
        Self {
            kind: Kind::Replace(outcome),
            caller,
            key_id,
        }
    }

    /// The operation.
    #[must_use]
    pub const fn operation(&self) -> Operation {
        match self.kind {
            Kind::Import(..) => Operation::Import,
            Kind::Delete(_) => Operation::Delete,
            Kind::Replace(_) => Operation::ReplaceCertificate,
        }
    }

    /// Value of `CUSTODIO_OUTCOME`.
    #[must_use]
    pub const fn outcome_name(&self) -> &'static str {
        match self.kind {
            Kind::Import(o, _) => o.name(),
            Kind::Delete(o) => o.name(),
            Kind::Replace(o) => o.name(),
        }
    }

    /// Syslog priority.
    #[must_use]
    pub const fn priority(&self) -> u8 {
        match self.kind {
            Kind::Import(o, _) => o.priority(),
            Kind::Delete(o) => o.priority(),
            Kind::Replace(o) => o.priority(),
        }
    }

    /// The caller, when the bus named one.
    #[must_use]
    pub const fn caller(&self) -> Option<Caller> {
        self.caller
    }

    /// The key id.
    #[must_use]
    pub const fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    /// The key type of an import, when known.
    #[must_use]
    pub const fn key_type(&self) -> Option<AuditKeyType> {
        match self.kind {
            Kind::Import(_, t) => t,
            _ => None,
        }
    }

    /// The text of `MESSAGE`, built only from typed values.
    #[must_use]
    pub fn message(&self) -> String {
        let phrase = match self.kind {
            Kind::Import(o, _) => o.phrase(),
            Kind::Delete(o) => o.phrase(),
            Kind::Replace(o) => o.phrase(),
        };
        super::message(phrase, self.caller, &self.key_id)
    }

    /// The fields in wire order.
    pub(crate) fn fields(&self) -> Vec<(&'static str, String)> {
        let op = self.operation();
        let mut f = super::base_fields(
            self.message(),
            op,
            self.priority(),
            self.caller,
            &self.key_id,
            self.outcome_name(),
        );
        if let Some(t) = self.key_type() {
            f.push(("CUSTODIO_KEY_TYPE", t.name().to_owned()));
        }
        f
    }
}
