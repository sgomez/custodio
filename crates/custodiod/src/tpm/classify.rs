//! The classification of a TPM for one key type, as a pure function over what the TPM answered.
//!
//! The one rule that matters: an error is never turned into `Absent` or `Lacks`. `Lacks` makes the
//! service store the key in the weaker (encrypted) kind, `Error` stores nothing, so when in doubt it
//! is `Error`. Only the TPM saying "this combination is not supported" (a few format-one response
//! codes of `TPM2_TestParms`), or an item missing from a capability list it answered, is `Lacks`.

use std::fmt;

use super::list::{Item, KeyType, Parms, Query};

/// A TPM response code (`TPM_RC`, or a TSS layer code), shown in hex and nothing else.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ResponseCode(pub u32);

impl fmt::Debug for ResponseCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl fmt::Display for ResponseCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:08X}", self.0)
    }
}

/// Why a TPM cannot be used, which is neither "no TPM" nor "lacks a capability".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpmError {
    /// `/dev/tpm0` exists and `/dev/tpmrm0` does not: the platform has a TPM and no resource manager.
    ResourceManagerMissing,
    /// The device is there and could not be opened or connected to (permission, a refused connection, a TCTI failure).
    OpenFailed,
    /// The TPM answered a command with this response code.
    Response(ResponseCode),
    /// The connection failed in the middle of a command; there is no response code.
    Transport,
    /// The owner hierarchy has an authorization value set; the service uses the empty one.
    OwnerAuthSet,
    /// The owner (storage) hierarchy is disabled (`shEnable` clear).
    OwnerDisabled,
    /// The test-only TCTI variable holds something that is not an absolute `swtpm:path=` socket.
    TestTctiRefused,
}

impl fmt::Display for TpmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ResourceManagerMissing => f.write_str("TPM resource manager missing"),
            Self::OpenFailed => f.write_str("TPM device cannot be opened"),
            Self::Response(rc) => write!(f, "TPM response code {rc}"),
            Self::Transport => f.write_str("TPM connection failed"),
            Self::OwnerAuthSet => f.write_str("owner hierarchy has an authorization value"),
            Self::OwnerDisabled => f.write_str("owner hierarchy disabled"),
            Self::TestTctiRefused => f.write_str("test TPM setting refused"),
        }
    }
}

impl std::error::Error for TpmError {}

/// A query that did not get an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// The TPM answered with an error response code.
    Response(ResponseCode),
    /// No response code: the connection or the TSS layer failed.
    Transport,
}

impl From<Fault> for TpmError {
    fn from(fault: Fault) -> Self {
        match fault {
            Fault::Response(rc) => Self::Response(rc),
            Fault::Transport => Self::Transport,
        }
    }
}

/// The state of the owner (storage) hierarchy that decides whether the service can use it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Owner {
    /// `TPMA_PERMANENT.ownerAuthSet`.
    pub auth_set: bool,
    /// `TPMA_STARTUP_CLEAR.shEnable`.
    pub enabled: bool,
}

/// What an opened TPM answered. A query that was not needed (a `TestParms` whose algorithm is absent) is not here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opened {
    pub owner: Result<Owner, Fault>,
    pub algorithms: Result<Vec<u16>, Fault>,
    pub curves: Result<Vec<u16>, Fault>,
    pub commands: Result<Vec<u32>, Fault>,
    pub parms: Vec<(Parms, Result<(), Fault>)>,
}

/// Everything the classification looks at: how opening went, then the answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answers {
    /// The platform exposes no TPM device.
    NoDevice,
    /// A device is there and could not be used.
    OpenFailed(TpmError),
    Opened(Opened),
}

/// The result of classifying a TPM for one key type.
#[derive(Clone, PartialEq, Eq)]
pub enum Classification {
    /// The platform exposes no TPM device.
    Absent,
    /// The TPM answered and these items are absent (never empty; an item that follows from another is not repeated).
    Lacks(Vec<Item>),
    /// Every item of the list is there and the owner hierarchy is usable.
    Ready,
    /// The TPM cannot be judged.
    Error(TpmError),
}

impl fmt::Display for Classification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Absent => f.write_str("no TPM"),
            Self::Ready => f.write_str("TPM ready"),
            Self::Error(e) => write!(f, "TPM error: {e}"),
            Self::Lacks(items) => {
                f.write_str("TPM lacks: ")?;
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    f.write_str(item.name())?;
                }
                Ok(())
            }
        }
    }
}

impl fmt::Debug for Classification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Absent => f.write_str("Absent"),
            Self::Ready => f.write_str("Ready"),
            Self::Error(e) => write!(f, "Error({e:?})"),
            Self::Lacks(items) => write!(f, "Lacks({items:?})"),
        }
    }
}

/// `TPM_RC_TYPE`, `TPM_RC_SCHEME`, `TPM_RC_HASH` and `TPM_RC_CURVE` without their format-one bits.
const REFUSALS: [u32; 4] = [0x0a, 0x12, 0x03, 0x26];

/// Whether `rc` is a format-one code of `TPM2_TestParms` for "this combination is not supported". The parameter number
/// (bits 8 to 11) and the `P` bit (bit 6) are masked: a real TPM answers `0x1C3` where the bare code is `0x083`.
#[must_use]
pub fn is_unsupported(rc: ResponseCode) -> bool {
    let rc = rc.0;
    rc & 0x80 != 0 && rc & !0xfff == 0 && REFUSALS.contains(&(rc & 0x3f))
}

pub(super) fn present(opened: &Opened, query: Query) -> Result<bool, TpmError> {
    let listed = |r: &Result<Vec<u16>, Fault>, id: u16| {
        r.as_ref()
            .map(|l| l.contains(&id))
            .map_err(|f| TpmError::from(*f))
    };
    match query {
        Query::Algorithm(id) => listed(&opened.algorithms, id),
        Query::Curve(id) => listed(&opened.curves, id),
        Query::Command(cc) => opened
            .commands
            .as_ref()
            .map(|l| l.contains(&cc))
            .map_err(|f| TpmError::from(*f)),
        Query::Parms(parms) => match opened.parms.iter().find(|(p, _)| *p == parms) {
            Some((_, Ok(()))) => Ok(true),
            Some((_, Err(Fault::Response(rc)))) if is_unsupported(*rc) => Ok(false),
            Some((_, Err(fault))) => Err((*fault).into()),
            // Asked for nothing: the caller only gets here for an item it decided to ask.
            None => Err(TpmError::Transport),
        },
    }
}

/// Classifies `answers` for `key`. An `Error` anywhere wins over `Lacks`.
#[must_use]
pub fn classify(key: KeyType, answers: &Answers) -> Classification {
    let opened = match answers {
        Answers::NoDevice => return Classification::Absent,
        Answers::OpenFailed(e) => return Classification::Error(*e),
        Answers::Opened(opened) => opened,
    };
    match &opened.owner {
        Err(fault) => return Classification::Error((*fault).into()),
        Ok(owner) if owner.auth_set => return Classification::Error(TpmError::OwnerAuthSet),
        Ok(owner) if !owner.enabled => return Classification::Error(TpmError::OwnerDisabled),
        Ok(_) => {}
    }
    let mut lacking = Vec::new();
    for item in key.items() {
        // An item that is made of an absent one is not asked and not named: the absent one is.
        let mut blocked = false;
        for dependency in item.depends_on() {
            match present(opened, dependency.query()) {
                Ok(true) => {}
                Ok(false) => blocked = true,
                Err(e) => return Classification::Error(e),
            }
        }
        if blocked {
            continue;
        }
        match present(opened, item.query()) {
            Ok(true) => {}
            Ok(false) => lacking.push(*item),
            Err(e) => return Classification::Error(e),
        }
    }
    if lacking.is_empty() {
        Classification::Ready
    } else {
        Classification::Lacks(lacking)
    }
}
