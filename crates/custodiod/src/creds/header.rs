//! The header of an encrypted credential, read back after `Encrypt`.
//!
//! `systemd-creds` cannot be told per call to bind to no PCR through the Varlink interface (the daemon
//! takes the mask from its own command line), and the default of the mask differs between versions of
//! systemd. So the service does not trust the call: it reads the stored policy from the header and
//! refuses a credential that is bound to any PCR, or that is not encrypted at all (the null key).
//! The layout is the one `## F110` of `docs/findings.md` measured: a 16-byte key id first, and, for a
//! TPM-bound credential, the PCR mask as a little-endian `u64` at byte 48.

use std::fmt;

/// Key id of a credential encrypted with the host key, not scoped to a user.
pub(crate) const HOST_ID: [u8; 16] = [
    0x5a, 0x1c, 0x6a, 0x86, 0xdf, 0x9d, 0x40, 0x96, 0xb1, 0xd5, 0xa6, 0x5e, 0x08, 0x62, 0xf1, 0x9a,
];
/// Key id of a credential encrypted with the host key and the uid (`--user`).
pub(crate) const HOST_SCOPED_ID: [u8; 16] = [
    0x55, 0xb9, 0xed, 0x1d, 0x38, 0x59, 0x4d, 0x43, 0xa8, 0x31, 0x9d, 0x2e, 0xbb, 0x33, 0x2a, 0xc6,
];
/// Key id of a credential that is not encrypted (`--with-key=null`).
pub(crate) const NULL_ID: [u8; 16] = [
    0x05, 0x84, 0x69, 0xda, 0xf6, 0xf5, 0x43, 0x24, 0x80, 0x05, 0x49, 0xda, 0x0f, 0x8e, 0xa2, 0xfb,
];
/// Where the PCR mask of a TPM-bound credential starts.
const MASK_OFFSET: usize = 48;

/// What a credential is bound to, as far as the header says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Binding {
    /// The host key (with the uid), no TPM.
    Host,
    /// A TPM (alone or with the host key), bound to no PCR.
    Tpm,
}

/// Why a credential is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderError {
    /// Too short to hold the header: not a credential.
    TooShort,
    /// The credential is not encrypted (the null key).
    NullKey,
    /// The credential is bound to the PCRs in this mask.
    PcrBound(u64),
}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort => f.write_str("credential too short to have a header"),
            Self::NullKey => f.write_str("credential is not encrypted (null key)"),
            Self::PcrBound(mask) => write!(f, "credential is bound to PCRs (mask {mask:#x})"),
        }
    }
}

impl std::error::Error for HeaderError {}

/// Reads the binding of `credential` (the raw bytes, not base64) and refuses one that names a PCR
/// or has the null key.
///
/// A key id that is neither of the two host ids nor the null id is read as a TPM credential: its
/// mask must be zero, which a non-TPM layout (initialization vector at that offset) practically never
/// is, so an unknown kind is refused rather than stored.
///
/// # Errors
/// [`HeaderError`] as above.
pub fn inspect(credential: &[u8]) -> Result<Binding, HeaderError> {
    let id = credential.get(..16).ok_or(HeaderError::TooShort)?;
    if id == NULL_ID {
        return Err(HeaderError::NullKey);
    }
    if id == HOST_ID || id == HOST_SCOPED_ID {
        return Ok(Binding::Host);
    }
    let mask = credential
        .get(MASK_OFFSET..MASK_OFFSET + 8)
        .and_then(|b| <[u8; 8]>::try_from(b).ok())
        .map(u64::from_le_bytes)
        .ok_or(HeaderError::TooShort)?;
    if mask == 0 {
        Ok(Binding::Tpm)
    } else {
        Err(HeaderError::PcrBound(mask))
    }
}

#[cfg(test)]
mod tests;
