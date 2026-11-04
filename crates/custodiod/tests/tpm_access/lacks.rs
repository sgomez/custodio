//! A lacking TPM, item by item, through the F107 filter.

use custodio_it::swtpm::Swtpm;
use custodio_it::tpm_filter::{Lacks, alg, cc};
use custodiod::tpm::{Classification, Item, KeyType};

use super::{BOTH, TestResult, classify, filter};

fn lacking(expected: [Classification; 2], lacks: Lacks, what: &str) -> TestResult {
    let tpm = Swtpm::start()?;
    let filtered = filter(&tpm, lacks)?;
    let [rsa, ecc] = expected;
    assert_eq!(
        classify(&filtered.tcti(), KeyType::Rsa2048),
        rsa,
        "RSA 2048, {what}"
    );
    assert_eq!(
        classify(&filtered.tcti(), KeyType::EccP256),
        ecc,
        "ECC P-256, {what}"
    );
    Ok(())
}

fn named(item: Item) -> Classification {
    Classification::Lacks(vec![item])
}

fn algs(ids: &[u16]) -> Lacks {
    Lacks {
        algorithms: ids.to_vec(),
        ..Lacks::default()
    }
}

fn cmds(ids: &[u32]) -> Lacks {
    Lacks {
        commands: ids.to_vec(),
        ..Lacks::default()
    }
}

const ALG_RSA: u16 = 0x0001;
const ALG_AES: u16 = 0x0006;
const ALG_ECC: u16 = 0x0023;

#[test]
fn lacks_each_item() -> TestResult {
    use Classification::Ready;
    lacking(
        [named(Item::AlgRsa), Ready],
        algs(&[ALG_RSA]),
        "RSA algorithm",
    )?;
    // The ECC algorithm is the parent's: named once, for both key types. The curve and the TestParms items that depend on
    // it are folded into it.
    lacking(
        [named(Item::AlgEcc), named(Item::AlgEcc)],
        algs(&[ALG_ECC]),
        "ECC algorithm",
    )?;
    lacking(
        [named(Item::CurveP256), named(Item::CurveP256)],
        Lacks {
            curves: vec![alg::CURVE_P256],
            ..Lacks::default()
        },
        "curve P-256",
    )?;
    lacking(
        [named(Item::AlgSha256), named(Item::AlgSha256)],
        algs(&[alg::SHA256]),
        "SHA-256",
    )?;
    lacking(
        [named(Item::AlgAes), named(Item::AlgAes)],
        algs(&[ALG_AES]),
        "AES",
    )?;
    lacking(
        [named(Item::CmdCreatePrimary), named(Item::CmdCreatePrimary)],
        cmds(&[cc::CREATE_PRIMARY]),
        "CreatePrimary",
    )?;
    lacking(
        [named(Item::CmdImport), named(Item::CmdImport)],
        cmds(&[cc::IMPORT]),
        "Import",
    )?;
    lacking(
        [named(Item::CmdLoad), named(Item::CmdLoad)],
        cmds(&[cc::LOAD]),
        "Load",
    )?;
    lacking(
        [named(Item::CmdRsaDecrypt), Ready],
        cmds(&[cc::RSA_DECRYPT]),
        "RSA_Decrypt",
    )?;
    lacking([Ready, named(Item::CmdSign)], cmds(&[cc::SIGN]), "Sign")?;
    // A scheme the filter refuses in TestParms while ALGS still lists everything the list queries: the TestParms item.
    lacking(
        [Ready, named(Item::EcdsaSha256Parms)],
        algs(&[alg::ECDSA]),
        "ECDSA scheme",
    )?;
    Ok(())
}

#[test]
fn several_absent_items_are_all_named_in_list_order() -> TestResult {
    let tpm = Swtpm::start()?;
    let filtered = filter(
        &tpm,
        Lacks {
            algorithms: vec![ALG_AES],
            commands: vec![cc::IMPORT, cc::SIGN, cc::RSA_DECRYPT],
            ..Lacks::default()
        },
    )?;
    assert_eq!(
        classify(&filtered.tcti(), KeyType::EccP256),
        Classification::Lacks(vec![Item::AlgAes, Item::CmdImport, Item::CmdSign])
    );
    assert_eq!(
        classify(&filtered.tcti(), KeyType::Rsa2048),
        Classification::Lacks(vec![Item::AlgAes, Item::CmdImport, Item::CmdRsaDecrypt])
    );
    Ok(())
}

#[test]
fn sha512_absent_is_ready() -> TestResult {
    // The hardware TPM of F111 lacks SHA-512, and must be Ready.
    let tpm = Swtpm::start()?;
    let filtered = filter(&tpm, algs(&[alg::SHA384, alg::SHA512]))?;
    for key in BOTH {
        assert_eq!(
            classify(&filtered.tcti(), key),
            Classification::Ready,
            "{key:?}"
        );
    }
    // Control: the filter does remove hashes, so lacking SHA-256 is Lacks.
    let tpm = Swtpm::start()?;
    let filtered = filter(&tpm, algs(&[alg::SHA256]))?;
    for key in BOTH {
        assert_eq!(
            classify(&filtered.tcti(), key),
            named(Item::AlgSha256),
            "{key:?}"
        );
    }
    Ok(())
}
