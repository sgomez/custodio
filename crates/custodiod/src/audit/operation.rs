//! The operations an entry can name, and the entries of the operations other than signing.
//!
//! Every entry has `CUSTODIO_OPERATION`. Each of import, delete and replace certificate has its own
//! outcome type, so an outcome cannot be paired with an operation it does not belong to, and one
//! `MESSAGE_ID` per operation. Like [`super::Entry`], an [`OperationEntry`] is built from typed parts only:
//! a `.p12`, a password, certificate bytes, data and signatures have no place in it.

use super::{Caller, ImportCause, KeyId};
use crate::app_id::AppIdOutcome;
use crate::store::Kind as StorageKind;

/// What a request asked Custodio to do. Value of `CUSTODIO_OPERATION`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Sign,
    Import,
    Delete,
    ReplaceCertificate,
    /// The removal of a key of the earlier format at start-up. No request, so no caller.
    Purge,
}

impl Operation {
    /// Every operation; the exhaustive match stops compiling when a variant is added.
    #[must_use]
    pub const fn all() -> [Self; 5] {
        match Self::Sign {
            Self::Sign | Self::Import | Self::Delete | Self::ReplaceCertificate | Self::Purge => [
                Self::Sign,
                Self::Import,
                Self::Delete,
                Self::ReplaceCertificate,
                Self::Purge,
            ],
        }
    }

    /// The operations a caller can ask for: every operation but the purge, which start-up does.
    #[must_use]
    pub const fn requests() -> [Self; 4] {
        [
            Self::Sign,
            Self::Import,
            Self::Delete,
            Self::ReplaceCertificate,
        ]
    }

    /// Value of `CUSTODIO_OPERATION`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sign => "sign",
            Self::Import => "import",
            Self::Delete => "delete",
            Self::ReplaceCertificate => "replace_certificate",
            Self::Purge => "purge",
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
            Self::Purge => PURGE_MESSAGE_ID,
        }
    }
}

/// `MESSAGE_ID` of every import entry.
pub const IMPORT_MESSAGE_ID: &str = "4c7163ce45d0b9faf8e7c38d098bdb22";
/// `MESSAGE_ID` of every delete entry.
pub const DELETE_MESSAGE_ID: &str = "13d1a981ea8f64fc1a6f390bee7fd66c";
/// `MESSAGE_ID` of every replace certificate entry.
pub const REPLACE_CERTIFICATE_MESSAGE_ID: &str = "336e0b53720a735afb179ebc7f779ed6";

/// `MESSAGE_ID` of every purge entry.
pub const PURGE_MESSAGE_ID: &str = "8e1f5a6c0b3d4972a4c6d58f31b7e902";

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
    /// Reserved: delete never emits it. The entry goes out before the files are removed, so a
    /// removal that fails afterwards cannot change what it says.
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

/// Result of a purge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PurgeOutcome {
    /// The key of the earlier format was removed, or is about to be: the entry goes out first.
    Purged,
}

impl PurgeOutcome {
    /// Every outcome; the exhaustive match stops compiling when a variant is added.
    #[must_use]
    pub const fn all() -> [Self; 1] {
        match Self::Purged {
            Self::Purged => [Self::Purged],
        }
    }

    /// Value of `CUSTODIO_OUTCOME`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Purged => "purged",
        }
    }

    /// Syslog priority: a warning, since a key of a user is removed.
    #[must_use]
    pub const fn priority(self) -> u8 {
        match self {
            Self::Purged => 4,
        }
    }

    const fn phrase(self) -> &'static str {
        match self {
            Self::Purged => "key of the earlier format purged",
        }
    }
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
    Purge(PurgeOutcome),
}

/// One audit entry of an import, delete or replace certificate. Built only by its constructors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationEntry {
    kind: Kind,
    caller: Option<Caller>,
    key_id: KeyId,
    app_id: AppIdOutcome,
    storage_kind: Option<StorageKind>,
    cause: Option<ImportCause>,
    /// The owner of a purged key; the entry has no caller.
    owner: Option<u32>,
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
            app_id: AppIdOutcome::Undetermined,
            storage_kind: None,
            cause: None,
            owner: None,
        }
    }

    /// A delete entry.
    #[must_use]
    pub const fn delete(outcome: DeleteOutcome, caller: Option<Caller>, key_id: KeyId) -> Self {
        Self {
            kind: Kind::Delete(outcome),
            caller,
            key_id,
            app_id: AppIdOutcome::Undetermined,
            storage_kind: None,
            cause: None,
            owner: None,
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
            app_id: AppIdOutcome::Undetermined,
            storage_kind: None,
            cause: None,
            owner: None,
        }
    }

    /// A purge entry: the key `key_id` of `owner` (none for the M0–M2 layout), in the earlier format, removed at
    /// start-up. It has no caller and no app-id (the case is `none`: no request was made).
    #[must_use]
    pub const fn purge(owner: Option<u32>, key_id: KeyId) -> Self {
        Self {
            kind: Kind::Purge(PurgeOutcome::Purged),
            caller: None,
            key_id,
            app_id: AppIdOutcome::None,
            storage_kind: None,
            cause: None,
            owner,
        }
    }

    /// The owner of a purged key.
    #[must_use]
    pub const fn owner(&self) -> Option<u32> {
        self.owner
    }

    /// The entry with the app-id case of the caller. Without this the case is `undetermined`.
    #[must_use]
    pub fn with_app_id(mut self, app_id: AppIdOutcome) -> Self {
        self.app_id = app_id;
        self
    }

    /// The import entry with the storage kind of the key that was stored. Other operations ignore it: only an import
    /// chooses a kind.
    #[must_use]
    pub fn with_storage_kind(mut self, kind: StorageKind) -> Self {
        if matches!(self.kind, Kind::Import(..)) {
            self.storage_kind = Some(kind);
        }
        self
    }

    /// The import entry with the cause of a failure. Other operations ignore it.
    #[must_use]
    pub fn with_cause(mut self, cause: ImportCause) -> Self {
        if matches!(self.kind, Kind::Import(..)) {
            self.cause = Some(cause);
        }
        self
    }

    /// The storage kind of an import that stored a key.
    #[must_use]
    pub const fn storage_kind(&self) -> Option<StorageKind> {
        self.storage_kind
    }

    /// The cause of a failed import, when it has one.
    #[must_use]
    pub const fn cause(&self) -> Option<ImportCause> {
        self.cause
    }

    /// The app-id case of the caller.
    #[must_use]
    pub const fn app_id(&self) -> &AppIdOutcome {
        &self.app_id
    }

    /// The operation.
    #[must_use]
    pub const fn operation(&self) -> Operation {
        match self.kind {
            Kind::Import(..) => Operation::Import,
            Kind::Delete(_) => Operation::Delete,
            Kind::Replace(_) => Operation::ReplaceCertificate,
            Kind::Purge(_) => Operation::Purge,
        }
    }

    /// Value of `CUSTODIO_OUTCOME`.
    #[must_use]
    pub const fn outcome_name(&self) -> &'static str {
        match self.kind {
            Kind::Import(o, _) => o.name(),
            Kind::Delete(o) => o.name(),
            Kind::Replace(o) => o.name(),
            Kind::Purge(o) => o.name(),
        }
    }

    /// Syslog priority.
    #[must_use]
    pub const fn priority(&self) -> u8 {
        match self.kind {
            Kind::Import(o, _) => o.priority(),
            Kind::Delete(o) => o.priority(),
            Kind::Replace(o) => o.priority(),
            Kind::Purge(o) => o.priority(),
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
            Kind::Purge(o) => {
                let owner = self
                    .owner
                    .map_or_else(|| "no owner".to_owned(), |u| format!("owner uid {u}"));
                return format!("{}: {owner} key {}", o.phrase(), self.key_id.as_str());
            }
        };
        super::message(phrase, self.caller, &self.key_id)
    }

    /// The fields in wire order.
    #[must_use]
    pub fn fields(&self) -> Vec<(&'static str, String)> {
        let op = self.operation();
        let mut f = super::base_fields(
            self.message(),
            op,
            self.priority(),
            self.caller,
            &self.key_id,
            self.outcome_name(),
        );
        if let Some(owner) = self.owner
            && let Some(at) = f.iter().position(|(n, _)| *n == "CUSTODIO_KEY_ID")
        {
            f.insert(at, ("CUSTODIO_OWNER_UID", owner.to_string()));
        }
        if let Some(t) = self.key_type() {
            f.push(("CUSTODIO_KEY_TYPE", t.name().to_owned()));
        }
        super::push_storage(&mut f, self.storage_kind, self.cause.map(ImportCause::name));
        super::push_app_id(&mut f, &self.app_id);
        f
    }
}
