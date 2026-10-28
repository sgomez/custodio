//! Audit trail: one journal entry per signing attempt.
//!
//! [`AuditSink`] is the interface; [`JournalSink`] is the production implementation (Native Journal
//! Protocol, one datagram per call) and [`MemorySink`] / [`FailingSink`] are test doubles. An [`Entry`]
//! is built only from typed parts, so key material, passwords, data, digests, signatures and strings
//! that failed validation cannot be put in it. `record` returns an error the caller must handle.
//!
//! # Fields
//!
//! | Field | Value |
//! |---|---|
//! | `MESSAGE` | fixed text per outcome, with uid, pid and key id |
//! | `MESSAGE_ID` | [`MESSAGE_ID`], 32 lower-case hex digits |
//! | `PRIORITY` | `6` signed, `5` denied, `4` authorization unavailable, `3` signing failed |
//! | `SYSLOG_IDENTIFIER` | `custodiod` |
//! | `CUSTODIO_UID`, `CUSTODIO_PID` | the caller, decimal |
//! | `CUSTODIO_KEY_ID` | the key id |
//! | `CUSTODIO_OUTCOME` | `signed`, `signing_failed`, `denied` or `authorization_unavailable` |
//! | `CUSTODIO_MECHANISM` | only when known: `rsa_pkcs`, `rsa_pkcs_pss_sha256`, `rsa_pkcs_pss_sha384`, `rsa_pkcs_pss_sha512`, `ecdsa` |
//!
//! ```
//! use custodiod::audit::{AuditSink, Caller, Entry, KeyId, MemorySink, Outcome};
//! let key = KeyId::new("my-key").unwrap();
//! let entry = Entry::new(Outcome::Denied, Caller { uid: 1000, pid: 42 }, key, None);
//! let sink = MemorySink::default();
//! sink.record(&entry).unwrap();
//! assert_eq!(sink.entries(), vec![entry]);
//! ```
//!
//! A struct literal from outside the module is refused, but the constructor works:
//!
//! ```compile_fail
//! use custodiod::audit::{Caller, Entry, KeyId, Outcome};
//! let key_id = KeyId::new("k").unwrap();
//! let _ = Entry { outcome: Outcome::Denied, caller: Caller { uid: 1, pid: 2 }, key_id, mechanism: None };
//! ```
//!
//! ```
//! use custodiod::audit::{Caller, Entry, KeyId, Outcome};
//! let _ = Entry::new(Outcome::Denied, Caller { uid: 1, pid: 2 }, KeyId::new("k").unwrap(), None);
//! ```
//!
//! No conversion from a string to an entry part exists, except the validating [`KeyId::new`]:
//!
//! ```compile_fail
//! use custodiod::audit::KeyId;
//! let _ = KeyId::from("x");
//! ```
//!
//! ```compile_fail
//! use custodiod::audit::KeyId;
//! let _: KeyId = "x".into();
//! ```
//!
//! ```compile_fail
//! use custodiod::audit::Entry;
//! let _: Entry = "x".into();
//! ```
//!
//! ```compile_fail
//! use custodiod::audit::{Caller, Entry, Outcome};
//! let _ = Entry::new(Outcome::Denied, Caller { uid: 1, pid: 2 }, String::from("k"), None);
//! ```
//!
//! ```compile_fail
//! use custodiod::audit::{Caller, Entry, KeyId, Outcome};
//! let k = KeyId::new("k").unwrap();
//! let _ = Entry::new(Outcome::Denied, Caller { uid: 1, pid: 2 }, k, Some(vec![1u8, 2]));
//! ```
//!
//! ```compile_fail
//! use custodiod::audit::{Entry, KeyId, Outcome};
//! let k = KeyId::new("k").unwrap();
//! let _ = Entry::new(Outcome::Denied, String::from("1000"), k, None);
//! ```

mod journal;
mod memory;
mod wire;

use std::fmt;
use std::io;

use crate::sign::{Mechanism, PssHash};
use crate::store::valid_key_id;

pub use journal::{DEFAULT_JOURNAL_SOCKET, JournalSink, MAX_DATAGRAM};
pub use memory::{FailingSink, MemorySink};

/// `MESSAGE_ID` of every entry, generated once from a random source.
pub const MESSAGE_ID: &str = "29c3d30e6c4242406c6db3f120d36401";

/// Where audit entries go. Tests replace it with [`MemorySink`] or [`FailingSink`].
pub trait AuditSink: Send + Sync {
    /// Records one entry. The error must be handled: an entry that was not recorded is never silent.
    ///
    /// ```compile_fail
    /// #![deny(unused_must_use)]
    /// use custodiod::audit::{AuditSink, Caller, Entry, KeyId, MemorySink, Outcome};
    /// let e = Entry::new(Outcome::Denied, Caller { uid: 1, pid: 2 }, KeyId::new("k").unwrap(), None);
    /// let sink = MemorySink::default();
    /// sink.record(&e);
    /// ```
    ///
    /// ```
    /// #![deny(unused_must_use)]
    /// use custodiod::audit::{AuditSink, Caller, Entry, KeyId, MemorySink, Outcome};
    /// let e = Entry::new(Outcome::Denied, Caller { uid: 1, pid: 2 }, KeyId::new("k").unwrap(), None);
    /// let sink = MemorySink::default();
    /// let _ = sink.record(&e);
    /// ```
    ///
    /// # Errors
    ///
    /// [`AuditError`] when the entry could not be handed over completely.
    fn record(&self, entry: &Entry) -> Result<(), AuditError>;
}

/// Why an entry was not recorded. Carries no path and no entry content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditError {
    /// The socket refused, was missing, was full or failed otherwise.
    Io(io::ErrorKind),
    /// The encoded entry is larger than the sink allows.
    TooLarge,
    /// The datagram was sent only in part.
    ShortSend { sent: usize, expected: usize },
}

impl fmt::Display for AuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(kind) => write!(f, "audit entry not recorded: {kind}"),
            Self::TooLarge => f.write_str("audit entry too large"),
            Self::ShortSend { sent, expected } => {
                write!(f, "audit entry sent partially: {sent} of {expected} bytes")
            }
        }
    }
}

impl std::error::Error for AuditError {}

/// What happened to a signing request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Approved and signed.
    Signed,
    /// Approved but signing failed.
    SigningFailed,
    /// Denied.
    Denied,
    /// Authorization was not possible.
    AuthorizationUnavailable,
}

impl Outcome {
    /// Syslog priority of the outcome.
    #[must_use]
    pub const fn priority(self) -> u8 {
        match self {
            Self::Signed => 6,
            Self::Denied => 5,
            Self::AuthorizationUnavailable => 4,
            Self::SigningFailed => 3,
        }
    }

    /// Value of `CUSTODIO_OUTCOME`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Signed => "signed",
            Self::SigningFailed => "signing_failed",
            Self::Denied => "denied",
            Self::AuthorizationUnavailable => "authorization_unavailable",
        }
    }

    const fn phrase(self) -> &'static str {
        match self {
            Self::Signed => "signature made",
            Self::SigningFailed => "signing failed after approval",
            Self::Denied => "signature denied",
            Self::AuthorizationUnavailable => "authorization unavailable, no signature",
        }
    }
}

/// The process that asked, as the bus reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caller {
    pub uid: u32,
    pub pid: u32,
}

/// The id of a key, validated by the rule of the key store. Holds no other text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyId(String);

/// A key id that does not follow the rule. Carries no copy of the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidKeyId;

impl fmt::Display for InvalidKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid key id")
    }
}

impl std::error::Error for InvalidKeyId {}

impl KeyId {
    /// Accepts 1 to 64 bytes of `[A-Za-z0-9_-]`, like the key store.
    ///
    /// # Errors
    ///
    /// [`InvalidKeyId`] for anything else.
    pub fn new(id: &str) -> Result<Self, InvalidKeyId> {
        if valid_key_id(id) {
            Ok(Self(id.to_owned()))
        } else {
            Err(InvalidKeyId)
        }
    }

    /// The id.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The mechanism of a request, by fixed name only (no parameters).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditMechanism {
    RsaPkcs,
    RsaPkcsPssSha256,
    RsaPkcsPssSha384,
    RsaPkcsPssSha512,
    Ecdsa,
}

impl AuditMechanism {
    /// Value of `CUSTODIO_MECHANISM`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::RsaPkcs => "rsa_pkcs",
            Self::RsaPkcsPssSha256 => "rsa_pkcs_pss_sha256",
            Self::RsaPkcsPssSha384 => "rsa_pkcs_pss_sha384",
            Self::RsaPkcsPssSha512 => "rsa_pkcs_pss_sha512",
            Self::Ecdsa => "ecdsa",
        }
    }
}

impl From<&Mechanism> for AuditMechanism {
    fn from(m: &Mechanism) -> Self {
        match m {
            Mechanism::RsaPkcs => Self::RsaPkcs,
            Mechanism::RsaPkcsPss { hash, .. } => match hash {
                PssHash::Sha256 => Self::RsaPkcsPssSha256,
                PssHash::Sha384 => Self::RsaPkcsPssSha384,
                PssHash::Sha512 => Self::RsaPkcsPssSha512,
            },
            Mechanism::Ecdsa => Self::Ecdsa,
        }
    }
}

/// One audit entry. Built only by [`Entry::new`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    outcome: Outcome,
    caller: Caller,
    key_id: KeyId,
    mechanism: Option<AuditMechanism>,
}

impl Entry {
    #[must_use]
    pub const fn new(
        outcome: Outcome,
        caller: Caller,
        key_id: KeyId,
        mechanism: Option<AuditMechanism>,
    ) -> Self {
        Self {
            outcome,
            caller,
            key_id,
            mechanism,
        }
    }

    #[must_use]
    pub const fn outcome(&self) -> Outcome {
        self.outcome
    }

    #[must_use]
    pub const fn caller(&self) -> Caller {
        self.caller
    }

    #[must_use]
    pub const fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    #[must_use]
    pub const fn mechanism(&self) -> Option<AuditMechanism> {
        self.mechanism
    }

    /// The text of `MESSAGE`, built only from typed values.
    #[must_use]
    pub fn message(&self) -> String {
        format!(
            "{}: uid {} pid {} key {}",
            self.outcome.phrase(),
            self.caller.uid,
            self.caller.pid,
            self.key_id.as_str()
        )
    }

    /// The fields in wire order.
    pub(crate) fn fields(&self) -> Vec<(&'static str, String)> {
        let mut f = vec![
            ("MESSAGE", self.message()),
            ("MESSAGE_ID", MESSAGE_ID.to_owned()),
            ("PRIORITY", self.outcome.priority().to_string()),
            ("SYSLOG_IDENTIFIER", crate::SERVICE_NAME.to_owned()),
            ("CUSTODIO_UID", self.caller.uid.to_string()),
            ("CUSTODIO_PID", self.caller.pid.to_string()),
            ("CUSTODIO_KEY_ID", self.key_id.as_str().to_owned()),
            ("CUSTODIO_OUTCOME", self.outcome.name().to_owned()),
        ];
        if let Some(m) = self.mechanism {
            f.push(("CUSTODIO_MECHANISM", m.name().to_owned()));
        }
        f
    }
}

#[cfg(test)]
mod tests;
