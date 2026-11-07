//! Encrypted key storage with `systemd-creds` (not to be confused with [`crate::credentials`], the
//! peer credentials of a bus caller).
//!
//! A private key is encrypted by [`Credentials::encrypt`], and the encrypted credential is the only
//! form that is returned or stored. [`Credentials::decrypt`] gives the key back in `secrecy` memory
//! for one signature. The client sits behind the [`Credentials`] trait so tests can inject both
//! failures; [`systemd::SystemdCreds`] is the real one. What `docs/findings/F110.md` decided
//! (scope `user`, no `withKey`, the explicit-device form for a TPM, the read-back of the header)
//! is implemented in [`systemd`] and [`header`].

pub mod header;
pub mod memory;
pub mod systemd;

use std::fmt;

use secrecy::{ExposeSecret, SecretSlice};

pub use header::{Binding, HeaderError};

/// Why a credential could not be made or opened. None of the variants carries key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredsError {
    /// The credential service cannot be used: the socket or `systemd-creds` is missing, or it cannot
    /// encrypt (no host secret, no TPM). Retrying later can work.
    Unavailable,
    /// The credential cannot be decrypted: a TPM that was cleared, a changed host key, another uid or
    /// a corrupted credential. No signature is made.
    CannotDecrypt,
    /// The service made a credential that must not be kept (see [`HeaderError`]).
    Refused(HeaderError),
    /// The request was wrong: a bad credential name, or a reply of `InvalidParameter`.
    BadRequest,
}

impl fmt::Display for CredsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => f.write_str("credential service unavailable"),
            Self::CannotDecrypt => f.write_str("cannot decrypt the credential"),
            Self::Refused(why) => write!(f, "credential refused: {why}"),
            Self::BadRequest => f.write_str("bad credential request"),
        }
    }
}

impl std::error::Error for CredsError {}

/// The replaceable access point to the credential service.
pub trait Credentials: Send + Sync {
    /// Encrypts `plaintext` under the credential `name`; returns the credential, raw bytes. The
    /// plaintext reaches the service through a pipe or a socket, never a file or an argument.
    ///
    /// # Errors
    /// [`CredsError::Unavailable`] when the service cannot encrypt, [`CredsError::BadRequest`] for a
    /// name the service cannot take.
    fn encrypt(&self, name: &str, plaintext: &SecretSlice<u8>) -> Result<Vec<u8>, CredsError>;

    /// Decrypts a credential made by [`Credentials::encrypt`] under the same `name`.
    ///
    /// # Errors
    /// [`CredsError::Unavailable`] when the service cannot be reached, [`CredsError::CannotDecrypt`]
    /// for every other failure.
    fn decrypt(&self, name: &str, credential: &[u8]) -> Result<SecretSlice<u8>, CredsError>;
}

/// An encrypted credential and what the header says it is bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    /// The encrypted credential, raw bytes: the only form of the key to store.
    credential: Vec<u8>,
    /// TPM or host, from the header.
    binding: Binding,
}

impl Sealed {
    /// The credential, raw bytes. A `Sealed` is only built by [`seal`], which read its header, so
    /// plaintext cannot be dressed as one.
    #[must_use]
    pub fn credential(&self) -> &[u8] {
        &self.credential
    }

    /// What the header says the credential is bound to.
    #[must_use]
    pub fn binding(&self) -> Binding {
        self.binding
    }
}

/// Encrypts `plaintext` and checks the header of what came back: a credential that names a PCR, or
/// is not encrypted, is dropped and refused, whatever the default of the installed systemd.
///
/// # Errors
/// What [`Credentials::encrypt`] returns, or [`CredsError::Refused`].
pub fn seal(
    client: &dyn Credentials,
    name: &str,
    plaintext: &SecretSlice<u8>,
) -> Result<Sealed, CredsError> {
    let credential = client.encrypt(name, plaintext)?;
    let binding = header::inspect(&credential).map_err(CredsError::Refused)?;
    Ok(Sealed {
        credential,
        binding,
    })
}

/// Decrypts `credential` and hands the key to `sign` once; the key is zeroized when `sign` returns.
///
/// # Errors
/// What [`Credentials::decrypt`] returns.
pub fn with_key<R>(
    client: &dyn Credentials,
    name: &str,
    credential: &[u8],
    sign: impl FnOnce(&[u8]) -> R,
) -> Result<R, CredsError> {
    let key = client.decrypt(name, credential)?;
    Ok(sign(key.expose_secret()))
}

#[cfg(test)]
mod tests;
