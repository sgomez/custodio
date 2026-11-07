//! The capability list per key type: what a TPM must have for the service to store a key of that type on it.
//!
//! Written once in `docs/api.md` ("TPM capabilities"); `tpm::tests::list_matches_document` ties this file to it. The
//! items come from `docs/findings/F107.md` as `docs/decisions.md` narrows them (the parent is an ECC P-256
//! primary with an AES-128-CFB symmetric and a SHA-256 name; the service pads RSA, so no RSA scheme is needed).
//! SHA-384 and SHA-512 are on no list: the hardware TPM of F111 lacks SHA-512 and must be `Ready`.

use std::fmt;

/// A key type a TPM can hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// RSA 2048 with the `decrypt` attribute (the service pads, the TPM does the raw operation).
    Rsa2048,
    /// ECC NIST P-256, signed with `TPM2_Sign`.
    EccP256,
}

/// One thing a TPM must have, as the document names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Item {
    AlgEcc,
    CurveP256,
    AlgSha256,
    AlgAes,
    ParentParms,
    CmdCreatePrimary,
    CmdImport,
    CmdLoad,
    AlgRsa,
    Rsa2048Parms,
    CmdRsaDecrypt,
    EcdsaSha256Parms,
    CmdSign,
}

/// How an item is asked of the TPM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Query {
    /// `GetCapability(ALGS)` lists the `TPM_ALG_ID`.
    Algorithm(u16),
    /// `GetCapability(ECC_CURVES)` lists the `TPM_ECC_CURVE`.
    Curve(u16),
    /// `GetCapability(COMMANDS)` lists the `TPM_CC`.
    Command(u32),
    /// `TPM2_TestParms` accepts the combination.
    Parms(Parms),
}

/// A `TPM2_TestParms` combination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Parms {
    /// ECC P-256 with AES-128-CFB and the null scheme: the parent template.
    Parent,
    /// RSA 2048 with the null scheme (the key has the `decrypt` attribute).
    Rsa2048,
    /// ECC P-256 with ECDSA and SHA-256.
    EcdsaSha256,
}

pub const ALG_RSA: u16 = 0x0001;
pub const ALG_AES: u16 = 0x0006;
pub const ALG_SHA256: u16 = 0x000b;
pub const ALG_ECC: u16 = 0x0023;
pub const CURVE_P256: u16 = 0x0003;
pub const CC_CREATE_PRIMARY: u32 = 0x131;
pub const CC_IMPORT: u32 = 0x156;
pub const CC_LOAD: u32 = 0x157;
pub const CC_RSA_DECRYPT: u32 = 0x159;
pub const CC_SIGN: u32 = 0x15d;

impl Item {
    /// The name the document, `Display` and the journal use.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::AlgEcc => "algorithm ECC",
            Self::CurveP256 => "curve NIST P-256",
            Self::AlgSha256 => "name algorithm SHA-256",
            Self::AlgAes => "algorithm AES",
            Self::ParentParms => "parent template ECC P-256 AES-128-CFB",
            Self::CmdCreatePrimary => "command CreatePrimary",
            Self::CmdImport => "command Import",
            Self::CmdLoad => "command Load",
            Self::AlgRsa => "algorithm RSA",
            Self::Rsa2048Parms => "rsa2048 null scheme",
            Self::CmdRsaDecrypt => "command RSA_Decrypt",
            Self::EcdsaSha256Parms => "ECDSA with SHA-256 on P-256",
            Self::CmdSign => "command Sign",
        }
    }

    /// The question put to the TPM.
    #[must_use]
    pub const fn query(self) -> Query {
        match self {
            Self::AlgEcc => Query::Algorithm(ALG_ECC),
            Self::CurveP256 => Query::Curve(CURVE_P256),
            Self::AlgSha256 => Query::Algorithm(ALG_SHA256),
            Self::AlgAes => Query::Algorithm(ALG_AES),
            Self::ParentParms => Query::Parms(Parms::Parent),
            Self::CmdCreatePrimary => Query::Command(CC_CREATE_PRIMARY),
            Self::CmdImport => Query::Command(CC_IMPORT),
            Self::CmdLoad => Query::Command(CC_LOAD),
            Self::AlgRsa => Query::Algorithm(ALG_RSA),
            Self::Rsa2048Parms => Query::Parms(Parms::Rsa2048),
            Self::CmdRsaDecrypt => Query::Command(CC_RSA_DECRYPT),
            Self::EcdsaSha256Parms => Query::Parms(Parms::EcdsaSha256),
            Self::CmdSign => Query::Command(CC_SIGN),
        }
    }

    /// The items this one is made of. When one of them is absent only that one is named, and this item is not
    /// asked: a `TestParms` refusal that follows from a missing algorithm names nothing a second time.
    #[must_use]
    pub const fn depends_on(self) -> &'static [Item] {
        match self {
            Self::CurveP256 => &[Self::AlgEcc],
            Self::Rsa2048Parms => &[Self::AlgRsa],
            Self::ParentParms => &[Self::AlgEcc, Self::CurveP256, Self::AlgAes],
            Self::EcdsaSha256Parms => &[Self::AlgEcc, Self::CurveP256, Self::AlgSha256],
            _ => &[],
        }
    }
}

/// Every item of the document, in its order. The first eight are the parent's, needed by both key types.
pub const ALL: [Item; 13] = [
    Item::AlgEcc,
    Item::CurveP256,
    Item::AlgSha256,
    Item::AlgAes,
    Item::ParentParms,
    Item::CmdCreatePrimary,
    Item::CmdImport,
    Item::CmdLoad,
    Item::AlgRsa,
    Item::Rsa2048Parms,
    Item::CmdRsaDecrypt,
    Item::EcdsaSha256Parms,
    Item::CmdSign,
];

const RSA_2048: [Item; 11] = [
    Item::AlgEcc,
    Item::CurveP256,
    Item::AlgSha256,
    Item::AlgAes,
    Item::ParentParms,
    Item::CmdCreatePrimary,
    Item::CmdImport,
    Item::CmdLoad,
    Item::AlgRsa,
    Item::Rsa2048Parms,
    Item::CmdRsaDecrypt,
];

const ECC_P256: [Item; 10] = [
    Item::AlgEcc,
    Item::CurveP256,
    Item::AlgSha256,
    Item::AlgAes,
    Item::ParentParms,
    Item::CmdCreatePrimary,
    Item::CmdImport,
    Item::CmdLoad,
    Item::EcdsaSha256Parms,
    Item::CmdSign,
];

impl KeyType {
    /// What the TPM needs for this key type.
    #[must_use]
    pub const fn items(self) -> &'static [Item] {
        match self {
            Self::Rsa2048 => &RSA_2048,
            Self::EccP256 => &ECC_P256,
        }
    }
}

impl fmt::Display for Item {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}
