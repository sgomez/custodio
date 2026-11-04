//! Refused requests, missing capabilities, a wrong result from the TPM, and what goes over the wire.
// A test fails by panicking: unwrap, expect and indexing on data the test itself built are the intended failure mode.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use custodio_it::tpm_filter::{CommandFault, FaultAction, Flip, Lacks, alg, cc};
use custodiod::sign::{Mechanism, PssHash, SignError, sign as software_sign};
use custodiod::tpm::list::Item;
use custodiod::tpm::open::TestTcti;
use custodiod::tpm::sign::TpmSignError;
use custodiod::tpm::{ResponseCode, TpmError};
use secrecy::SecretSlice;

use super::oracle::{Subject, digest_of, ecdsa_der, mechanisms_pss, verifies};
use super::support::{Kind, Rig, TestResult};

fn fault(command: u32, rc: u32) -> Lacks {
    Lacks {
        faults: vec![CommandFault {
            command,
            action: FaultAction::Respond(rc),
        }],
        ..Lacks::default()
    }
}

#[test]
fn errors_match_the_software_signer() -> TestResult {
    let rig = Rig::new()?;
    let direct = TestTcti::new(&rig.tcti());
    let rsa = Subject::new(&rig, &direct, Kind::Rsa)?;
    let ec = Subject::new(&rig, &direct, Kind::P256)?;
    let (filter, record) = rig.filter(Lacks::default())?;
    let access = TestTcti::new(&filter.tcti());
    let pss = |salt_len| Mechanism::RsaPkcsPss {
        hash: PssHash::Sha256,
        salt_len,
    };
    // One request per error class: (subject, mechanism, data).
    let cases = [
        (&rsa, Mechanism::RsaPkcs, vec![0u8; 246]),
        (&rsa, pss(32), vec![0u8; 31]),
        (&rsa, pss(223), vec![0u8; 32]),
        (&ec, Mechanism::Ecdsa, vec![]),
        (&ec, Mechanism::RsaPkcs, vec![0u8; 32]),
        (&rsa, Mechanism::Ecdsa, vec![0u8; 32]),
    ];
    for (subject, mechanism, data) in cases {
        let software = SecretSlice::from(subject.key.pkcs8.clone());
        let want = software_sign(&software, mechanism, &data).unwrap_err();
        assert!(matches!(
            want,
            SignError::BadData | SignError::MechanismMismatch
        ));
        assert_eq!(
            subject.sign(&access, mechanism, &data).unwrap_err(),
            TpmSignError::Refused(want),
            "{mechanism:?} {}",
            data.len()
        );
    }
    assert_eq!(
        record.codes(),
        Vec::<u32>::new(),
        "no command for a refused request"
    );
    // Control: a valid request records commands, in the order create, load, sign, flush, flush.
    rsa.sign(&access, Mechanism::RsaPkcs, &[1; 20])?;
    ec.sign(&access, Mechanism::Ecdsa, &[1; 32])?;
    let codes = record.codes();
    assert!(codes.contains(&cc::CREATE_PRIMARY) && codes.contains(&cc::LOAD));
    assert!(codes.contains(&cc::RSA_DECRYPT) && codes.contains(&cc::SIGN));
    assert!(codes.contains(&cc::FLUSH_CONTEXT));
    Ok(())
}

#[test]
fn missing_capability_is_reported() -> TestResult {
    let rig = Rig::new()?;
    let direct = TestTcti::new(&rig.tcti());
    let rsa = Subject::new(&rig, &direct, Kind::Rsa)?;
    let ec = Subject::new(&rig, &direct, Kind::P256)?;
    let digest = digest_of(PssHash::Sha256, b"m");
    let rsa_calls: [(Mechanism, &[u8]); 2] = [
        (Mechanism::RsaPkcs, b"payload"),
        (mechanisms_pss(PssHash::Sha256, 32), &digest),
    ];
    // The TPM lacks TPM2_RSA_Decrypt: each RSA mechanism says so, and nothing else is tried.
    let (filter, record) = rig.filter(fault(cc::RSA_DECRYPT, 0x143))?;
    let access = TestTcti::new(&filter.tcti());
    for (mechanism, data) in rsa_calls {
        assert_eq!(
            rsa.sign(&access, mechanism, data).unwrap_err(),
            TpmSignError::Lacks(Item::CmdRsaDecrypt),
            "{mechanism:?}"
        );
    }
    let codes = record.codes();
    assert_eq!(
        codes.iter().filter(|c| **c == cc::RSA_DECRYPT).count(),
        2,
        "one attempt per call"
    );
    assert!(!codes.contains(&cc::SIGN), "no fallback to TPM2_Sign");
    drop(filter);
    rig.assert_nothing_loaded("after a lacking RSA_Decrypt")?;

    // The TPM lacks TPM2_Sign, or ECDSA with SHA-256.
    let (filter, record) = rig.filter(fault(cc::SIGN, 0x143))?;
    let access = TestTcti::new(&filter.tcti());
    assert_eq!(
        ec.sign(&access, Mechanism::Ecdsa, &[7; 32]).unwrap_err(),
        TpmSignError::Lacks(Item::CmdSign)
    );
    assert!(!record.codes().contains(&cc::RSA_DECRYPT));
    drop(filter);
    let (filter, record) = rig.filter(Lacks {
        algorithms: vec![alg::ECDSA],
        ..Lacks::default()
    })?;
    let access = TestTcti::new(&filter.tcti());
    assert_eq!(
        ec.sign(&access, Mechanism::Ecdsa, &[7; 32]).unwrap_err(),
        TpmSignError::Lacks(Item::EcdsaSha256Parms)
    );
    assert_eq!(record.codes().iter().filter(|c| **c == cc::SIGN).count(), 1);
    drop(filter);
    // ... or TPM2_Load.
    let (filter, _) = rig.filter(fault(cc::LOAD, 0x143))?;
    let access = TestTcti::new(&filter.tcti());
    assert_eq!(
        ec.sign(&access, Mechanism::Ecdsa, &[7; 32]).unwrap_err(),
        TpmSignError::Lacks(Item::CmdLoad)
    );
    drop(filter);

    // A TPM error that is not a lack stays a TPM error with its code, on the same commands.
    for (command, subject, mechanism, data) in [
        (cc::RSA_DECRYPT, &rsa, Mechanism::RsaPkcs, &b"payload"[..]),
        (cc::SIGN, &ec, Mechanism::Ecdsa, &[7u8; 32][..]),
    ] {
        let (filter, _) = rig.filter(fault(command, 0x101))?;
        let access = TestTcti::new(&filter.tcti());
        assert_eq!(
            subject.sign(&access, mechanism, data).unwrap_err(),
            TpmSignError::Tpm(TpmError::Response(ResponseCode(0x101))),
            "{command:#x}"
        );
    }
    // Control: with no rule the same calls sign and verify.
    let signature = rsa.sign(&direct, Mechanism::RsaPkcs, b"payload")?;
    assert!(verifies(
        &rig,
        &rsa.cert,
        b"payload",
        &signature,
        &["-pkeyopt", "rsa_padding_mode:pkcs1"]
    )?);
    let signature = ec.sign(&direct, Mechanism::Ecdsa, &[7; 32])?;
    assert!(verifies(
        &rig,
        &ec.cert,
        &[7; 32],
        &ecdsa_der(&signature),
        &[]
    )?);
    rig.assert_nothing_loaded("at the end")?;
    Ok(())
}

#[test]
fn a_wrong_rsa_result_is_not_returned() -> TestResult {
    let rig = Rig::new()?;
    let direct = TestTcti::new(&rig.tcti());
    let rsa = Subject::new(&rig, &direct, Kind::Rsa)?;
    // The first parameter byte of the answer to a command with a session is at offset 16 (header 10, parameterSize 4,
    // size of the TPM2B 2); flipping a bit of the result makes the TPM "return a wrong block".
    let wrong = Lacks {
        flips: vec![Flip {
            command: cc::RSA_DECRYPT,
            offset: 16 + 100,
        }],
        ..Lacks::default()
    };
    let (filter, record) = rig.filter(wrong)?;
    let access = TestTcti::new(&filter.tcti());
    for mechanism in [Mechanism::RsaPkcs, mechanisms_pss(PssHash::Sha256, 32)] {
        let data = digest_of(PssHash::Sha256, b"m");
        assert_eq!(
            rsa.sign(&access, mechanism, &data).unwrap_err(),
            TpmSignError::BadResult,
            "{mechanism:?}"
        );
    }
    assert!(record.codes().contains(&cc::RSA_DECRYPT));
    drop(filter);
    rig.assert_nothing_loaded("after a wrong result")?;
    // Control: the same calls through no flip sign.
    rsa.sign(&direct, Mechanism::RsaPkcs, b"m")?;
    Ok(())
}

#[test]
fn private_key_not_on_the_wire_or_in_the_result() -> TestResult {
    let rig = Rig::new()?;
    let direct = TestTcti::new(&rig.tcti());
    for kind in [Kind::Rsa, Kind::P256] {
        let subject = Subject::new(&rig, &direct, kind)?;
        let (filter, record) = rig.filter(Lacks::default())?;
        let access = TestTcti::new(&filter.tcti());
        let (mechanism, data): (_, Vec<u8>) = match kind {
            Kind::Rsa => (Mechanism::RsaPkcs, b"payload".to_vec()),
            Kind::P256 => (Mechanism::Ecdsa, vec![9; 32]),
        };
        let signature = subject.sign(&access, mechanism, &data)?;
        let sent = record.bytes();
        assert!(
            sent.len() > 400,
            "{kind:?}: the load and the sign were recorded"
        );
        assert_eq!(
            subject.key.found_in(&sent),
            Vec::<&str>::new(),
            "{kind:?}: sent"
        );
        assert_eq!(
            subject.key.found_in(&signature),
            Vec::<&str>::new(),
            "{kind:?}: result"
        );
        // Control: the search finds a key the test plants in the recording.
        let planted = [sent.clone(), subject.key.pkcs8.clone()].concat();
        assert!(!subject.key.found_in(&planted).is_empty(), "{kind:?}");
        let planted = [sent, subject.key.secrets[2].1.clone()].concat();
        assert!(!subject.key.found_in(&planted).is_empty(), "{kind:?}");
    }
    Ok(())
}
