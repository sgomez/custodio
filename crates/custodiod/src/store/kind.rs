//! How a stored key is protected: the kind of a record.

/// The storage kind of a key. Three values, each with a wire string and an on-disk tag.
///
/// **The wire strings and the tags are chosen once and only added to.** The wire string is what the
/// D-Bus API and the audit trail will carry (F119, F120); the tag is the byte in the record. They are
/// separate things: renaming a wire string never touches stored records, and a tag is never reused.
///
/// | kind | wire string | tag |
/// |---|---|---|
/// | [`Kind::Tpm`] | `tpm` | 1 |
/// | [`Kind::EncryptedTpm`] | `encrypted-tpm` | 2 |
/// | [`Kind::EncryptedHost`] | `encrypted-host` | 3 |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// A TPM blob, wrapped to the parent whose name is stored with it.
    Tpm,
    /// An encrypted credential whose header names a TPM.
    EncryptedTpm,
    /// An encrypted credential whose header names the host key.
    EncryptedHost,
}

impl Kind {
    /// The wire string.
    #[must_use]
    pub fn wire(self) -> &'static str {
        match self {
            Self::Tpm => "tpm",
            Self::EncryptedTpm => "encrypted-tpm",
            Self::EncryptedHost => "encrypted-host",
        }
    }

    /// The kind with this wire string, if any.
    #[must_use]
    pub fn from_wire(wire: &str) -> Option<Self> {
        [Self::Tpm, Self::EncryptedTpm, Self::EncryptedHost]
            .into_iter()
            .find(|k| k.wire() == wire)
    }

    /// The byte stored in the record.
    pub(super) fn tag(self) -> u8 {
        match self {
            Self::Tpm => 1,
            Self::EncryptedTpm => 2,
            Self::EncryptedHost => 3,
        }
    }

    pub(super) fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::Tpm),
            2 => Some(Self::EncryptedTpm),
            3 => Some(Self::EncryptedHost),
            _ => None,
        }
    }
}
