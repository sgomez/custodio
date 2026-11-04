//! The real TPM session: `tss-esapi` over whichever TCTI the access point chose. Queries only; nothing is created in the
//! TPM, so there is nothing to flush.

use std::str::FromStr;

use tss_esapi::Context;
use tss_esapi::constants::{CapabilityType, PropertyTag};
use tss_esapi::error::ReturnCode;
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, SymmetricMode};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::key_bits::{AesKeyBits, RsaKeyBits};
use tss_esapi::structures::{
    CapabilityData, EccScheme, HashScheme, PublicEccParametersBuilder, PublicParameters,
    PublicRsaParametersBuilder, RsaExponent, RsaScheme, SymmetricDefinitionObject,
};
use tss_esapi::tcti_ldr::TctiNameConf;

use super::Session;
use super::blob::Imported;
use super::classify::{Fault, Owner, ResponseCode};
use super::import::ImportError;
use super::key::ImportKey;
use super::list::Parms;

mod primary;

/// `get_capability` pages: far more than any TPM lists, so a TPM that never stops saying "more" is an error.
const MAX_PAGES: usize = 4096;
const PAGE: u32 = 64;
/// `TPMA_PERMANENT.ownerAuthSet`, bit 0.
const OWNER_AUTH_SET: u32 = 1;
/// `TPMA_STARTUP_CLEAR.shEnable`, bit 1 (bit 0 is `phEnable`).
const SH_ENABLE: u32 = 1 << 1;

/// An open `tss-esapi` context.
pub struct EsysSession {
    context: Context,
    page: u32,
    tap: Option<super::wrap::Tap>,
}

impl EsysSession {
    /// Opens the TCTI. The error carries no detail: the caller maps it to "cannot be opened".
    ///
    /// # Errors
    /// The TCTI string is not valid, or the TSS cannot connect to the TPM.
    pub fn open(tcti: &str) -> Result<Self, tss_esapi::Error> {
        Self::open_paged(tcti, PAGE)
    }

    /// Like [`EsysSession::open`], asking the TPM for at most `page` entries per answer (tests use 1 to force paging).
    ///
    /// # Errors
    /// The TCTI string is not valid, or the TSS cannot connect to the TPM.
    pub fn open_paged(tcti: &str, page: u32) -> Result<Self, tss_esapi::Error> {
        let conf = TctiNameConf::from_str(tcti)?;
        Ok(Self {
            context: Context::new(conf)?,
            page,
            tap: None,
        })
    }

    /// Test seam: the import hands its seed and derived keys to `tap`. Never wire this into the daemon.
    #[must_use]
    pub fn with_tap(mut self, tap: super::wrap::Tap) -> Self {
        self.tap = Some(tap);
        self
    }
}

/// A TPM response code is what the TPM said; any other failure of the TSS has no code worth reporting.
fn fault(error: tss_esapi::Error) -> Fault {
    match error {
        tss_esapi::Error::TssError(
            rc @ (ReturnCode::Tpm(_) | ReturnCode::TpmResourceManager(_)),
        ) => Fault::Response(ResponseCode(u32::from(rc) & 0xffff)),
        _ => Fault::Transport,
    }
}

fn parameters(parms: Parms) -> Result<PublicParameters, tss_esapi::Error> {
    Ok(match parms {
        Parms::Parent => PublicParameters::Ecc(
            PublicEccParametersBuilder::new_restricted_decryption_key(
                SymmetricDefinitionObject::Aes {
                    key_bits: AesKeyBits::Aes128,
                    mode: SymmetricMode::Cfb,
                },
                EccCurve::NistP256,
            )
            .build()?,
        ),
        Parms::Rsa2048 => PublicParameters::Rsa(
            PublicRsaParametersBuilder::new()
                .with_scheme(RsaScheme::Null)
                .with_key_bits(RsaKeyBits::Rsa2048)
                .with_exponent(RsaExponent::default())
                .build()?,
        ),
        Parms::EcdsaSha256 => PublicParameters::Ecc(
            PublicEccParametersBuilder::new_unrestricted_signing_key(
                EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)),
                EccCurve::NistP256,
            )
            .build()?,
        ),
    })
}

impl EsysSession {
    /// One property word, from `TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES)`.
    fn property(&mut self, tag: PropertyTag) -> Result<u32, Fault> {
        match self.context.get_tpm_property(tag) {
            Ok(Some(value)) => Ok(value),
            Ok(None) => Err(Fault::Transport),
            Err(e) => Err(fault(e)),
        }
    }

    /// Every entry of one capability, page after page. `entries` turns a page into (property, value) pairs, or `None`
    /// when the TPM answered another capability; the last property of a page is where the next one starts.
    fn listed<T>(
        &mut self,
        capability: CapabilityType,
        entries: impl Fn(CapabilityData) -> Option<Vec<(u32, T)>>,
    ) -> Result<Vec<T>, Fault> {
        let mut out = Vec::new();
        let mut property = 0u32;
        for _ in 0..MAX_PAGES {
            let (data, more) = self
                .context
                .get_capability(capability, property, self.page)
                .map_err(fault)?;
            let page = entries(data).ok_or(Fault::Transport)?;
            let last = page.last().map(|(key, _)| *key);
            out.extend(page.into_iter().map(|(_, value)| value));
            if !more {
                return Ok(out);
            }
            // A page that says "more" and is empty would repeat forever.
            property = last.ok_or(Fault::Transport)?.saturating_add(1);
        }
        Err(Fault::Transport)
    }
}

impl Session for EsysSession {
    fn owner(&mut self) -> Result<Owner, Fault> {
        let permanent = self.property(PropertyTag::Permanent)?;
        let startup_clear = self.property(PropertyTag::StartupClear)?;
        Ok(Owner {
            auth_set: permanent & OWNER_AUTH_SET != 0,
            enabled: startup_clear & SH_ENABLE != 0,
        })
    }

    fn algorithms(&mut self) -> Result<Vec<u16>, Fault> {
        self.listed(CapabilityType::Algorithms, |data| match data {
            CapabilityData::Algorithms(list) => Some(
                list.iter()
                    .map(|p| {
                        let id = u16::from(p.algorithm_identifier());
                        (u32::from(id), id)
                    })
                    .collect(),
            ),
            _ => None,
        })
    }

    fn ecc_curves(&mut self) -> Result<Vec<u16>, Fault> {
        self.listed(CapabilityType::EccCurves, |data| match data {
            CapabilityData::EccCurves(list) => Some(
                list.iter()
                    .map(|c| {
                        let id = u16::from(*c);
                        (u32::from(id), id)
                    })
                    .collect(),
            ),
            _ => None,
        })
    }

    fn commands(&mut self) -> Result<Vec<u32>, Fault> {
        self.listed(CapabilityType::Command, |data| match data {
            CapabilityData::Commands(list) => Some(
                list.iter()
                    .map(|a| {
                        let cc = u32::from(a.command_index());
                        (cc, cc)
                    })
                    .collect(),
            ),
            _ => None,
        })
    }

    fn test_parms(&mut self, parms: Parms) -> Result<(), Fault> {
        let parameters = parameters(parms).map_err(|_| Fault::Transport)?;
        self.context.test_parms(parameters).map_err(fault)
    }

    fn parent_name(&mut self) -> Result<Vec<u8>, ImportError> {
        self.parent_name_of()
    }

    fn import_key(&mut self, key: &ImportKey) -> Result<Imported, ImportError> {
        self.import_under_parent(key)
    }
}
