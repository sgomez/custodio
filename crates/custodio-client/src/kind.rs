//! The storage kind of a key, as `ImportP12` and `ListKeys` report it.

/// How a stored key is protected. The wire strings are fixed and only added to; a kind a later service adds
/// reads as [`Kind::Unknown`] with its text, so an older client keeps working.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Kind {
    /// `tpm`: the key exists only inside the TPM.
    Tpm,
    /// `encrypted-tpm`: a file encrypted with a key bound to the machine's TPM.
    EncryptedTpm,
    /// `encrypted-host`: a file encrypted with the host key.
    EncryptedHost,
    /// A string this client does not know, kept as it came.
    Unknown(String),
}

/// The wire strings of the kinds this client knows, in the order of the documentation.
pub const KNOWN_KINDS: [&str; 3] = ["tpm", "encrypted-tpm", "encrypted-host"];

impl Kind {
    /// The kind with this wire string; a string that is not known gives [`Kind::Unknown`].
    #[must_use]
    pub fn from_wire(wire: &str) -> Self {
        match wire {
            "tpm" => Self::Tpm,
            "encrypted-tpm" => Self::EncryptedTpm,
            "encrypted-host" => Self::EncryptedHost,
            other => Self::Unknown(other.to_owned()),
        }
    }

    /// The wire string.
    #[must_use]
    pub fn wire(&self) -> &str {
        match self {
            Self::Tpm => "tpm",
            Self::EncryptedTpm => "encrypted-tpm",
            Self::EncryptedHost => "encrypted-host",
            Self::Unknown(text) => text,
        }
    }

    /// Whether this is one of the kinds the client knows.
    #[must_use]
    pub const fn is_known(&self) -> bool {
        !matches!(self, Self::Unknown(_))
    }
}

#[cfg(test)]
mod tests;
