//! Why an import or a signature failed, as a closed list of names (F120).
//!
//! A cause is chosen from a typed error by an exhaustive match, never copied from a tool's output, a response code, a
//! path or the input, so no secret can reach an entry through it. The value of `CUSTODIO_CAUSE` is one of these names
//! and nothing else. Which list applies depends on the operation of the entry.

/// Why an import failed after approval. Value of `CUSTODIO_CAUSE` of an `import` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportCause {
    /// The TPM device is there and cannot be used: no resource manager, it cannot be opened, or it is gone.
    TpmDevice,
    /// The owner hierarchy cannot be used: it has an authorization value or it is disabled.
    TpmOwner,
    /// The TPM answered with an error, or the connection failed, in a query or in the import.
    TpmError,
    /// The TPM refused the key itself (a type, size or exponent it does not take).
    TpmKey,
    /// The credential service is not available (the socket or the tool is missing, or it cannot encrypt here).
    CredentialsUnavailable,
    /// The credential service refused the request, or made a credential that must not be kept.
    CredentialsRefused,
    /// The credential is bound to something else than the storage kind chosen.
    BindingMismatch,
    /// The key store refused the record.
    Store,
    /// A fault of the service itself: a value that does not fit, or no credential service configured.
    Internal,
}

impl ImportCause {
    /// Every cause; the exhaustive match stops compiling when a variant is added.
    #[must_use]
    pub const fn all() -> [Self; 9] {
        match Self::Internal {
            Self::TpmDevice
            | Self::TpmOwner
            | Self::TpmError
            | Self::TpmKey
            | Self::CredentialsUnavailable
            | Self::CredentialsRefused
            | Self::BindingMismatch
            | Self::Store
            | Self::Internal => [
                Self::TpmDevice,
                Self::TpmOwner,
                Self::TpmError,
                Self::TpmKey,
                Self::CredentialsUnavailable,
                Self::CredentialsRefused,
                Self::BindingMismatch,
                Self::Store,
                Self::Internal,
            ],
        }
    }

    /// Value of `CUSTODIO_CAUSE`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::TpmDevice => "tpm_device",
            Self::TpmOwner => "tpm_owner",
            Self::TpmError => "tpm_error",
            Self::TpmKey => "tpm_key",
            Self::CredentialsUnavailable => "credentials_unavailable",
            Self::CredentialsRefused => "credentials_refused",
            Self::BindingMismatch => "binding_mismatch",
            Self::Store => "store",
            Self::Internal => "internal",
        }
    }
}

/// Why a signature failed after approval, when the failure is one of the two classes a person can act on. Value of
/// `CUSTODIO_CAUSE` of a `sign` entry. Any other failure has no cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignCause {
    /// The key no longer loads or decrypts: it can never sign again here (D-Bus `KeyLost`).
    KeyLost,
    /// The TPM or the credential service cannot be used now; the same request can work later (D-Bus
    /// `TemporarilyUnavailable`).
    TemporarilyUnavailable,
}

impl SignCause {
    /// Every cause; the exhaustive match stops compiling when a variant is added.
    #[must_use]
    pub const fn all() -> [Self; 2] {
        match Self::KeyLost {
            Self::KeyLost | Self::TemporarilyUnavailable => {
                [Self::KeyLost, Self::TemporarilyUnavailable]
            }
        }
    }

    /// Value of `CUSTODIO_CAUSE`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::KeyLost => "key_lost",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
        }
    }
}
