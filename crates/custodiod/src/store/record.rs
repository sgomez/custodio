//! The record: one file per key, holding owner, id, kind, certificate and the protected key.
//!
//! ```text
//! "CUSTODIO"  version(1)  kind tag(1)  owner(u32 BE)
//! id: len(u8) bytes   certificate: len(u32 BE) bytes   protected: len(u32 BE) bytes
//! ```
//!
//! The magic cannot start an earlier-format file (those are DER, first byte `0x30`). The protected part
//! is, for a TPM key, `parent name: len(u16 BE) bytes` then the blob as [`Blob::to_bytes`] gives it; for
//! an encrypted key, the raw credential. A [`Record`] can only be built from a [`Protected`], and a
//! [`Protected`] only from what protection returns, so no plaintext key reaches the file. Every length
//! field is compared with its bound before anything is taken from the input, which is never longer than
//! [`MAX_RECORD`].

use std::fmt;

use super::kind::Kind;
use super::valid_key_id;
use crate::creds::Sealed;
use crate::creds::header::{self, Binding, HeaderError};
use crate::tpm::blob::{Blob, BlobError, Imported};

/// What starts every record.
pub const MAGIC: &[u8; 8] = b"CUSTODIO";
const VERSION: u8 = 1;
/// Largest certificate stored (the bound of the API).
pub const MAX_CERTIFICATE: usize = custodio_client::MAX_CERT_LEN;
/// Largest encrypted credential stored.
pub const MAX_CREDENTIAL: usize = 16 * 1024;
/// Largest TPM name stored (a hash algorithm id and a 64-byte digest, with room).
pub const MAX_PARENT_NAME: usize = 68;
/// Largest protected key: a credential, or a parent name and a blob (which are bounded one by one
/// and are far under this).
const MAX_PROTECTED: usize = MAX_CREDENTIAL;
/// Largest record file.
pub const MAX_RECORD: usize =
    MAGIC.len() + 2 + 4 + 1 + 64 + 4 + MAX_CERTIFICATE + 4 + MAX_PROTECTED;

/// The part of a record a bound or a check names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Record,
    Id,
    Certificate,
    Protected,
    ParentName,
}

/// Why bytes are not a record, or why a record must not be written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordError {
    /// The input ended inside a field.
    Truncated,
    /// The input does not start with the magic.
    BadMagic,
    /// A version this code does not read.
    UnknownVersion(u8),
    /// A kind tag that is not one of the three.
    UnknownKind(u8),
    /// A length field above its bound.
    Oversized(Field),
    /// A field that must not be empty.
    Empty(Field),
    /// Bytes remain after the record.
    Trailing,
    /// The id is not a valid key id.
    BadId,
    /// The kind does not fit the protected key (a TPM kind needs a blob, an encrypted kind a credential
    /// whose header names the same binding).
    KindMismatch,
    /// The credential is not one the service keeps.
    Credential(HeaderError),
    /// The TPM blob is not well formed.
    Blob(BlobError),
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("record is truncated"),
            Self::BadMagic => f.write_str("record has a bad magic"),
            Self::UnknownVersion(v) => write!(f, "record has an unknown version {v}"),
            Self::UnknownKind(t) => write!(f, "record has an unknown kind tag {t}"),
            Self::Oversized(field) => write!(f, "record field {field:?} is oversized"),
            Self::Empty(field) => write!(f, "record field {field:?} is empty"),
            Self::Trailing => f.write_str("record has trailing bytes"),
            Self::BadId => f.write_str("record has an invalid key id"),
            Self::KindMismatch => f.write_str("record kind does not fit its protected key"),
            Self::Credential(e) => write!(f, "record credential: {e}"),
            Self::Blob(e) => write!(f, "record blob: {e}"),
        }
    }
}

impl std::error::Error for RecordError {}

/// A key in protected form: a TPM blob with the name of its parent, or an encrypted credential.
/// There is no constructor from raw key bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct Protected(Inner);

#[derive(Clone, PartialEq, Eq)]
enum Inner {
    Tpm { parent_name: Vec<u8>, blob: Blob },
    Credential { bytes: Vec<u8>, binding: Binding },
}

impl Protected {
    /// A TPM key, as the import returns it.
    ///
    /// # Errors
    /// [`RecordError::Empty`] or [`RecordError::Oversized`] for the parent name.
    pub fn from_imported(imported: &Imported) -> Result<Self, RecordError> {
        check_name(&imported.parent_name)?;
        Ok(Self(Inner::Tpm {
            parent_name: imported.parent_name.clone(),
            blob: imported.blob.clone(),
        }))
    }

    /// An encrypted credential, as `creds::seal` returns it.
    #[must_use]
    pub fn from_sealed(sealed: &Sealed) -> Self {
        Self(Inner::Credential {
            bytes: sealed.credential().to_vec(),
            binding: sealed.binding(),
        })
    }

    /// The kind this key can be stored as.
    #[must_use]
    pub fn natural_kind(&self) -> Kind {
        match &self.0 {
            Inner::Tpm { .. } => Kind::Tpm,
            Inner::Credential {
                binding: Binding::Tpm,
                ..
            } => Kind::EncryptedTpm,
            Inner::Credential {
                binding: Binding::Host,
                ..
            } => Kind::EncryptedHost,
        }
    }

    /// The raw credential, for an encrypted key.
    #[must_use]
    pub fn credential(&self) -> Option<&[u8]> {
        match &self.0 {
            Inner::Credential { bytes, .. } => Some(bytes),
            Inner::Tpm { .. } => None,
        }
    }

    /// The blob and the name of the parent it was wrapped to, for a TPM key.
    #[must_use]
    pub fn blob(&self) -> Option<(&Blob, &[u8])> {
        match &self.0 {
            Inner::Tpm { parent_name, blob } => Some((blob, parent_name)),
            Inner::Credential { .. } => None,
        }
    }

    /// A credential as it would be read back: used by tests to dress plaintext as one.
    #[cfg(test)]
    pub(crate) fn credential_unchecked(bytes: Vec<u8>, binding: Binding) -> Self {
        Self(Inner::Credential { bytes, binding })
    }

    /// The checks `put` and `decode` both make.
    fn check(&self, kind: Kind) -> Result<(), RecordError> {
        match &self.0 {
            Inner::Tpm { parent_name, blob } => {
                if kind != Kind::Tpm {
                    return Err(RecordError::KindMismatch);
                }
                check_name(parent_name)?;
                Blob::parse(&blob.to_bytes()).map_err(RecordError::Blob)?;
                blob.public_area().map_err(RecordError::Blob)?;
                Ok(())
            }
            Inner::Credential { bytes, binding } => {
                if bytes.len() > MAX_CREDENTIAL {
                    return Err(RecordError::Oversized(Field::Protected));
                }
                let seen = header::inspect(bytes).map_err(RecordError::Credential)?;
                let expected = match kind {
                    Kind::Tpm => return Err(RecordError::KindMismatch),
                    Kind::EncryptedTpm => Binding::Tpm,
                    Kind::EncryptedHost => Binding::Host,
                };
                if seen != expected || *binding != expected {
                    return Err(RecordError::KindMismatch);
                }
                Ok(())
            }
        }
    }

    fn encode(&self) -> Vec<u8> {
        match &self.0 {
            Inner::Credential { bytes, .. } => bytes.clone(),
            Inner::Tpm { parent_name, blob } => {
                // `check_name` bounded the name under 64 KiB.
                let len = u16::try_from(parent_name.len()).unwrap_or(u16::MAX);
                let mut out = len.to_be_bytes().to_vec();
                out.extend_from_slice(parent_name);
                out.extend_from_slice(&blob.to_bytes());
                out
            }
        }
    }

    fn decode(kind: Kind, bytes: &[u8]) -> Result<Self, RecordError> {
        let this = match kind {
            Kind::Tpm => {
                let mut reader = Reader(bytes);
                let len = usize::from(reader.u16()?);
                if len > MAX_PARENT_NAME {
                    return Err(RecordError::Oversized(Field::ParentName));
                }
                let parent_name = reader.take(len)?.to_vec();
                let blob = Blob::parse(reader.0).map_err(RecordError::Blob)?;
                Self(Inner::Tpm { parent_name, blob })
            }
            Kind::EncryptedTpm | Kind::EncryptedHost => {
                let binding = header::inspect(bytes).map_err(RecordError::Credential)?;
                Self(Inner::Credential {
                    bytes: bytes.to_vec(),
                    binding,
                })
            }
        };
        this.check(kind)?;
        Ok(this)
    }
}

impl fmt::Debug for Protected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Inner::Tpm { blob, .. } => write!(f, "Protected::Tpm({blob:?})"),
            Inner::Credential { bytes, binding } => {
                write!(
                    f,
                    "Protected::Credential({} bytes, {binding:?})",
                    bytes.len()
                )
            }
        }
    }
}

fn check_name(name: &[u8]) -> Result<(), RecordError> {
    if name.is_empty() {
        Err(RecordError::Empty(Field::ParentName))
    } else if name.len() > MAX_PARENT_NAME {
        Err(RecordError::Oversized(Field::ParentName))
    } else {
        Ok(())
    }
}

/// One stored key. Built only by [`Record::new`] and [`Record::decode`], which check everything.
#[derive(Clone, PartialEq, Eq)]
pub struct Record {
    owner: u32,
    id: String,
    kind: Kind,
    certificate: Vec<u8>,
    protected: Protected,
}

impl Record {
    /// A record of `owner`'s key `id`.
    ///
    /// # Errors
    /// [`RecordError`] for a bad id, an empty or oversized certificate, or a kind that does not fit
    /// the protected key.
    pub fn new(
        owner: u32,
        id: &str,
        kind: Kind,
        certificate: &[u8],
        protected: Protected,
    ) -> Result<Self, RecordError> {
        let record = Self::unchecked(owner, id, kind, certificate, protected);
        record.check()?;
        Ok(record)
    }

    fn unchecked(
        owner: u32,
        id: &str,
        kind: Kind,
        certificate: &[u8],
        protected: Protected,
    ) -> Self {
        Self {
            owner,
            id: id.to_owned(),
            kind,
            certificate: certificate.to_vec(),
            protected,
        }
    }

    /// A record that skipped the checks, so a test can show that `put` makes them again.
    #[cfg(test)]
    pub(crate) fn new_unchecked(
        owner: u32,
        id: &str,
        kind: Kind,
        certificate: &[u8],
        protected: Protected,
    ) -> Self {
        Self::unchecked(owner, id, kind, certificate, protected)
    }

    fn check(&self) -> Result<(), RecordError> {
        if !valid_key_id(&self.id) {
            return Err(RecordError::BadId);
        }
        if self.certificate.is_empty() {
            return Err(RecordError::Empty(Field::Certificate));
        }
        if self.certificate.len() > MAX_CERTIFICATE {
            return Err(RecordError::Oversized(Field::Certificate));
        }
        self.protected.check(self.kind)
    }

    /// The same key with another certificate.
    ///
    /// # Errors
    /// An empty or oversized certificate.
    pub fn with_certificate(&self, certificate: &[u8]) -> Result<Self, RecordError> {
        Self::new(
            self.owner,
            &self.id,
            self.kind,
            certificate,
            self.protected.clone(),
        )
    }

    #[must_use]
    pub fn owner(&self) -> u32 {
        self.owner
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn kind(&self) -> Kind {
        self.kind
    }

    #[must_use]
    pub fn certificate(&self) -> &[u8] {
        &self.certificate
    }

    #[must_use]
    pub fn protected(&self) -> &Protected {
        &self.protected
    }

    /// The file content. Checks the record again, so nothing unframed is written.
    ///
    /// # Errors
    /// The same checks as [`Record::new`].
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        self.check()?;
        let protected = self.protected.encode();
        let mut out =
            Vec::with_capacity(MAX_RECORD.min(64 + self.certificate.len() + protected.len()));
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.push(self.kind.tag());
        out.extend_from_slice(&self.owner.to_be_bytes());
        // The id is at most 64 bytes (checked above).
        out.push(u8::try_from(self.id.len()).unwrap_or(u8::MAX));
        out.extend_from_slice(self.id.as_bytes());
        for part in [self.certificate.as_slice(), protected.as_slice()] {
            // Both are bounded under 4 GiB (checked above).
            out.extend_from_slice(&u32::try_from(part.len()).unwrap_or(u32::MAX).to_be_bytes());
            out.extend_from_slice(part);
        }
        Ok(out)
    }

    /// Reads a record, refusing anything that is not exactly one.
    ///
    /// # Errors
    /// [`RecordError`] naming what is wrong. A length field is checked against its bound and then
    /// against what is left before anything is taken, so a field of `u32::MAX` on a short input
    /// allocates nothing.
    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        if bytes.len() > MAX_RECORD {
            return Err(RecordError::Oversized(Field::Record));
        }
        let mut reader = Reader(bytes);
        if reader
            .take(MAGIC.len())
            .map_err(|_| RecordError::BadMagic)?
            != MAGIC
        {
            return Err(RecordError::BadMagic);
        }
        let version = reader.u8()?;
        if version != VERSION {
            return Err(RecordError::UnknownVersion(version));
        }
        let tag = reader.u8()?;
        let kind = Kind::from_tag(tag).ok_or(RecordError::UnknownKind(tag))?;
        let owner = reader.u32()?;
        let id_len = usize::from(reader.u8()?);
        if id_len > 64 {
            return Err(RecordError::Oversized(Field::Id));
        }
        let id = std::str::from_utf8(reader.take(id_len)?).map_err(|_| RecordError::BadId)?;
        let certificate = reader.sized(MAX_CERTIFICATE, Field::Certificate)?;
        let protected = reader.sized(MAX_PROTECTED, Field::Protected)?;
        if !reader.0.is_empty() {
            return Err(RecordError::Trailing);
        }
        let protected = Protected::decode(kind, protected)?;
        Self::new(owner, id, kind, certificate, protected)
    }
}

impl fmt::Debug for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Record(owner {}, id {}, {}, certificate {} bytes, {:?})",
            self.owner,
            self.id,
            self.kind.wire(),
            self.certificate.len(),
            self.protected
        )
    }
}

/// A cursor over the input; it hands out slices of it and never allocates.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], RecordError> {
        let (head, rest) = self.0.split_at_checked(n).ok_or(RecordError::Truncated)?;
        self.0 = rest;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, RecordError> {
        self.take(1)?.first().copied().ok_or(RecordError::Truncated)
    }

    fn u16(&mut self) -> Result<u16, RecordError> {
        let b = <[u8; 2]>::try_from(self.take(2)?).map_err(|_| RecordError::Truncated)?;
        Ok(u16::from_be_bytes(b))
    }

    fn u32(&mut self) -> Result<u32, RecordError> {
        let b = <[u8; 4]>::try_from(self.take(4)?).map_err(|_| RecordError::Truncated)?;
        Ok(u32::from_be_bytes(b))
    }

    /// A `u32` length and that many bytes; the length is bounded before the bytes are taken.
    fn sized(&mut self, max: usize, field: Field) -> Result<&'a [u8], RecordError> {
        let len = usize::try_from(self.u32()?).map_err(|_| RecordError::Oversized(field))?;
        if len > max {
            return Err(RecordError::Oversized(field));
        }
        self.take(len)
    }
}
