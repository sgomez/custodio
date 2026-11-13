//! How a request reached the service, and the label of a socket peer.

/// How a request reached the service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// The system bus.
    Bus,
    /// A snap socket.
    Socket,
}

impl Transport {
    /// Value of `CUSTODIO_TRANSPORT`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Bus => "bus",
            Self::Socket => "socket",
        }
    }
}

/// The security label of a socket peer. Only a label that [`crate::peer_label::check`] accepted can be one, so it
/// holds no newline, NUL or other control byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerLabel(String);

impl PeerLabel {
    /// # Errors
    /// The reason [`crate::peer_label::check`] refuses `bytes`.
    pub fn new(bytes: &[u8]) -> Result<Self, crate::peer_label::Refusal> {
        crate::peer_label::check(bytes)?;
        String::from_utf8(bytes.to_vec())
            .map(Self)
            .map_err(|_| crate::peer_label::Refusal::NotUtf8)
    }

    /// The label.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Appends the transport field and, for a socket entry, the peer's label.
pub(crate) fn push_transport(
    f: &mut Vec<(&'static str, String)>,
    transport: Transport,
    label: Option<&PeerLabel>,
) {
    f.push((TRANSPORT_FIELD, transport.name().to_owned()));
    if let Some(label) = label {
        f.push((PEER_LABEL_FIELD, label.as_str().to_owned()));
    }
}

/// Field holding the [`Transport`] of a request.
pub const TRANSPORT_FIELD: &str = "CUSTODIO_TRANSPORT";
/// Field holding the label of the peer of a socket request.
pub const PEER_LABEL_FIELD: &str = "CUSTODIO_PEER_LABEL";
