//! The result of an import: the wrapped key as the TPM returned it, and the name of the parent it was wrapped to.
//!
//! The blob holds the public area and the private area as `TPM2B_PUBLIC` and `TPM2B_PRIVATE`, the files `tpm2_load -u`
//! and `-r` read. The private area is encrypted to the parent by the TPM; nothing from which the key could be recomputed
//! is kept. The stored form is the two structures one after the other and is parsed with bounds.

use std::fmt;

use tss_esapi::traits::UnMarshall;

/// Largest `TPMT_PUBLIC` accepted (an RSA 2048 area is 280 bytes).
pub const MAX_PUBLIC: usize = 512;
/// Largest `TPM2B_PRIVATE` content accepted (an RSA 2048 area is about 350 bytes).
pub const MAX_PRIVATE: usize = 1024;
/// Size of the integrity digest at the start of a private area (SHA-256).
const INTEGRITY_LEN: usize = 32;

/// Why stored bytes are not a blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobError {
    /// The input ended inside a field.
    Truncated,
    /// A size field is larger than allowed or than what is left.
    Oversized,
    /// Bytes remain after the two structures.
    Trailing,
    /// The sizes do not agree with the content.
    Inconsistent,
}

impl fmt::Display for BlobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Truncated => "stored TPM key is truncated",
            Self::Oversized => "stored TPM key has an oversized field",
            Self::Trailing => "stored TPM key has trailing bytes",
            Self::Inconsistent => "stored TPM key has inconsistent sizes",
        })
    }
}

impl std::error::Error for BlobError {}

/// The wrapped key: `TPM2B_PUBLIC` and `TPM2B_PRIVATE` as marshalled.
#[derive(Clone, PartialEq, Eq)]
pub struct Blob {
    public: Vec<u8>,
    private: Vec<u8>,
}

/// Splits a `TPM2B`: its content and the rest.
fn take_sized(input: &[u8], max: usize) -> Result<(&[u8], &[u8]), BlobError> {
    let (head, rest) = input.split_at_checked(2).ok_or(BlobError::Truncated)?;
    let len = usize::from(u16::from_be_bytes([
        *head.first().ok_or(BlobError::Truncated)?,
        *head.get(1).ok_or(BlobError::Truncated)?,
    ]));
    if len > max {
        return Err(BlobError::Oversized);
    }
    rest.split_at_checked(len).ok_or(BlobError::Truncated)
}

fn with_size(content: &[u8]) -> Vec<u8> {
    // The contents are bounded by MAX_* (under 64 KiB), so the length fits.
    let len = u16::try_from(content.len()).unwrap_or(u16::MAX);
    let mut out = len.to_be_bytes().to_vec();
    out.extend_from_slice(content);
    out
}

impl Blob {
    /// Builds a blob from the contents of the two structures (without their size fields).
    ///
    /// # Errors
    /// The public area does not parse as a `TPMT_PUBLIC` that uses all its bytes, or the private area is too large or
    /// too short to hold an integrity digest and some data.
    pub fn from_parts(public: &[u8], private: &[u8]) -> Result<Self, BlobError> {
        if public.len() > MAX_PUBLIC || private.len() > MAX_PRIVATE {
            return Err(BlobError::Oversized);
        }
        // An unmarshalled area must account for every byte it was given.
        let parsed = tss_esapi::structures::Public::unmarshall(public)
            .map_err(|_| BlobError::Inconsistent)?;
        let again = {
            use tss_esapi::traits::Marshall;
            parsed.marshall().map_err(|_| BlobError::Inconsistent)?
        };
        if again != public {
            return Err(BlobError::Inconsistent);
        }
        let integrity = private.get(..2).ok_or(BlobError::Truncated)?;
        let declared = usize::from(u16::from_be_bytes([
            *integrity.first().ok_or(BlobError::Truncated)?,
            *integrity.get(1).ok_or(BlobError::Truncated)?,
        ]));
        if declared != INTEGRITY_LEN || private.len() <= 2 + INTEGRITY_LEN {
            return Err(BlobError::Inconsistent);
        }
        Ok(Self {
            public: with_size(public),
            private: with_size(private),
        })
    }

    /// The `TPM2B_PUBLIC`, size field included (the file `tpm2_load -u` reads).
    #[must_use]
    pub fn public_bytes(&self) -> &[u8] {
        &self.public
    }

    /// The public area, parsed. A blob always holds a parseable one (`from_parts` checked it).
    ///
    /// # Errors
    /// [`BlobError::Inconsistent`] when the stored area does not parse.
    pub fn public_area(&self) -> Result<tss_esapi::structures::Public, BlobError> {
        let content = self.public.get(2..).ok_or(BlobError::Truncated)?;
        tss_esapi::structures::Public::unmarshall(content).map_err(|_| BlobError::Inconsistent)
    }

    /// The `TPM2B_PRIVATE`, size field included (the file `tpm2_load -r` reads).
    #[must_use]
    pub fn private_bytes(&self) -> &[u8] {
        &self.private
    }

    /// The stored form: public then private.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.public.clone();
        out.extend_from_slice(&self.private);
        out
    }

    /// Parses the stored form, refusing anything that is not exactly the two structures.
    ///
    /// # Errors
    /// [`BlobError`] naming what is wrong; a size field larger than the input allocates nothing.
    pub fn parse(stored: &[u8]) -> Result<Self, BlobError> {
        let (public, rest) = take_sized(stored, MAX_PUBLIC)?;
        let (private, rest) = take_sized(rest, MAX_PRIVATE)?;
        if !rest.is_empty() {
            return Err(BlobError::Trailing);
        }
        Self::from_parts(public, private)
    }
}

impl fmt::Debug for Blob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Blob({} + {} bytes)",
            self.public.len(),
            self.private.len()
        )
    }
}

/// What an import returns: the blob and the name of the parent it is wrapped to. Nothing else.
#[derive(Clone, PartialEq, Eq)]
pub struct Imported {
    pub blob: Blob,
    pub parent_name: Vec<u8>,
}

impl fmt::Debug for Imported {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Imported({:?}, parent name {} bytes)",
            self.blob,
            self.parent_name.len()
        )
    }
}

/// Whether the name recorded with a blob is the name of the current parent.
#[must_use]
pub fn same_name(recorded: &[u8], current: &[u8]) -> bool {
    recorded == current
}
