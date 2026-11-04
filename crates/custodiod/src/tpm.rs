//! The TPM behind a replaceable access point (F112).
//!
//! [`TpmAccess`] opens a TPM and gives a [`Session`] that answers capability queries; [`assess`] asks what the list of a
//! key type needs (`list`) and [`classify::classify`] turns the answers into [`Classification`]: absent, lacks (naming
//! the items), ready, or an error. The production access point ([`open::Production`]) opens only the kernel resource
//! manager `/dev/tpmrm0`; tests use a TCTI string ([`open::TestTcti`]).
//!
//! Nothing here creates a TPM object, so nothing has to be flushed. The capability list is documented in `docs/api.md`
//! ("TPM capabilities").

pub mod classify;
pub mod esys;
pub mod list;
pub mod open;

pub use classify::{Answers, Classification, Fault, Opened, Owner, ResponseCode, TpmError};
pub use list::{Item, KeyType, Parms, Query};

/// An open TPM. The methods only ask; none changes the TPM.
pub trait Session {
    /// The state of the owner hierarchy.
    ///
    /// # Errors
    /// The TPM did not answer.
    fn owner(&mut self) -> Result<Owner, Fault>;
    /// `GetCapability(ALGS)`: every `TPM_ALG_ID` the TPM implements.
    ///
    /// # Errors
    /// The TPM did not answer.
    fn algorithms(&mut self) -> Result<Vec<u16>, Fault>;
    /// `GetCapability(ECC_CURVES)`: every `TPM_ECC_CURVE`.
    ///
    /// # Errors
    /// The TPM did not answer.
    fn ecc_curves(&mut self) -> Result<Vec<u16>, Fault>;
    /// `GetCapability(COMMANDS)`: the command codes the TPM implements.
    ///
    /// # Errors
    /// The TPM did not answer.
    fn commands(&mut self) -> Result<Vec<u32>, Fault>;
    /// `TPM2_TestParms`: `Ok` when the TPM supports the combination, a [`Fault::Response`] with the code otherwise.
    ///
    /// # Errors
    /// The TPM refused or did not answer.
    fn test_parms(&mut self, parms: Parms) -> Result<(), Fault>;
}

/// Why no session was opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenError {
    /// The platform exposes no TPM device.
    NoDevice,
    /// A device is there and could not be used.
    Failed(TpmError),
}

/// The replaceable access point: how a TPM is reached.
pub trait TpmAccess: Send + Sync {
    /// Opens the TPM. One session at a time: a software TPM serves one client, and the session is dropped when the
    /// caller is done.
    ///
    /// # Errors
    /// [`OpenError::NoDevice`] only when the platform has no TPM; every other failure is [`OpenError::Failed`].
    fn open(&self) -> Result<Box<dyn Session>, OpenError>;
}

/// Asks the TPM what the list of `key` needs. A `TestParms` is asked only when what it is made of is present.
#[must_use]
pub fn collect(access: &dyn TpmAccess, key: KeyType) -> Answers {
    let mut session = match access.open() {
        Ok(session) => session,
        Err(OpenError::NoDevice) => return Answers::NoDevice,
        Err(OpenError::Failed(e)) => return Answers::OpenFailed(e),
    };
    let owner = session.owner();
    let algorithms = session.algorithms();
    let curves = session.ecc_curves();
    let commands = session.commands();
    let mut opened = Opened {
        owner,
        algorithms,
        curves,
        commands,
        parms: Vec::new(),
    };
    for item in key.items() {
        let Query::Parms(parms) = item.query() else {
            continue;
        };
        let made_of_present = item
            .depends_on()
            .iter()
            .all(|d| classify::present(&opened, d.query()) == Ok(true));
        if made_of_present {
            opened.parms.push((parms, session.test_parms(parms)));
        }
    }
    Answers::Opened(opened)
}

/// Opens the TPM, asks, and classifies it for `key`.
#[must_use]
pub fn assess(access: &dyn TpmAccess, key: KeyType) -> Classification {
    classify::classify(key, &collect(access, key))
}

#[cfg(test)]
mod tests;
