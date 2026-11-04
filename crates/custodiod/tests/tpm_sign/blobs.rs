//! Blobs that do not load, the parent check before the load, and what is flushed on every path.
// A test fails by panicking: unwrap, expect and indexing on data the test itself built are the intended failure mode.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use custodio_it::tpm_filter::{CommandFault, FaultAction, Lacks, cc};
use custodiod::sign::Mechanism;
use custodiod::tpm::blob::{Blob, BlobError, Imported};
use custodiod::tpm::open::TestTcti;
use custodiod::tpm::sign::TpmSignError;

use super::oracle::{Subject, ecdsa_der, verifies};
use super::support::{BOTH, Kind, Rig, TestResult, hex};

fn call(kind: Kind) -> (Mechanism, Vec<u8>) {
    match kind {
        Kind::Rsa => (Mechanism::RsaPkcs, b"payload".to_vec()),
        Kind::P256 => (Mechanism::Ecdsa, vec![3; 32]),
    }
}

fn opts(kind: Kind) -> &'static [&'static str] {
    match kind {
        Kind::Rsa => &["-pkeyopt", "rsa_padding_mode:pkcs1"],
        Kind::P256 => &[],
    }
}

/// The signature in the form `openssl` reads.
fn wire(kind: Kind, signature: &[u8]) -> Vec<u8> {
    match kind {
        Kind::Rsa => signature.to_vec(),
        Kind::P256 => ecdsa_der(signature),
    }
}

#[test]
fn unloadable_blobs_are_distinct() -> TestResult {
    for kind in BOTH {
        let mut rig = Rig::new()?;
        let direct = TestTcti::new(&rig.tcti());
        let subject = Subject::new(&rig, &direct, kind)?;
        let (mechanism, data) = call(kind);

        // Control, first: after a restart without a clear the same blob signs and verifies.
        rig.tpm.restart()?;
        let signature = subject.sign(&direct, mechanism, &data)?;
        assert!(verifies(
            &rig,
            &subject.cert,
            &data,
            &wire(kind, &signature),
            opts(kind)
        )?);

        // (c) one byte of the private area changed, on the right TPM: the load error.
        let mut stored = subject.imported.blob.to_bytes();
        let last = stored.len() - 5;
        stored[last] ^= 0x40;
        let damaged = Imported {
            blob: Blob::parse(&stored)?,
            parent_name: subject.imported.parent_name.clone(),
        };
        let (filter, record) = rig.filter(Lacks::default())?;
        let via = TestTcti::new(&filter.tcti());
        let request = custodiod::tpm::sign::SignRequest {
            imported: &damaged,
            mechanism,
            data: &data,
        };
        let error = custodiod::tpm::sign::sign(&via, &request).unwrap_err();
        assert!(
            matches!(error, TpmSignError::LoadFailed(_)),
            "{kind:?}: {error:?}"
        );
        assert!(record.codes().contains(&cc::LOAD));
        assert!(!record.codes().contains(&cc::RSA_DECRYPT) && !record.codes().contains(&cc::SIGN));
        drop(filter);
        rig.assert_nothing_loaded("after a failed load")?;

        // (d) a truncated or oversized private area is a parse error and no command is built.
        let good = subject.imported.blob.to_bytes();
        let public_len = subject.imported.blob.public_bytes().len();
        assert!(matches!(
            Blob::parse(&good[..good.len() - 1]),
            Err(BlobError::Truncated | BlobError::Inconsistent)
        ));
        let mut oversized = good[..public_len].to_vec();
        oversized.extend([0x7f, 0xff]);
        oversized.extend(vec![0u8; 100]);
        assert_eq!(Blob::parse(&oversized), Err(BlobError::Oversized));
        let mut trailing = good.clone();
        trailing.push(0);
        assert_eq!(Blob::parse(&trailing), Err(BlobError::Trailing));

        // (b) a second, independent swtpm.
        let other = Rig::new()?;
        let (filter, record) = other.filter(Lacks::default())?;
        let via = TestTcti::new(&filter.tcti());
        let mismatch = subject.sign(&via, mechanism, &data).unwrap_err();
        assert_eq!(mismatch, TpmSignError::ParentMismatch);
        assert!(record.codes().contains(&cc::CREATE_PRIMARY));
        assert!(!record.codes().contains(&cc::LOAD), "no TPM2_Load");
        drop(filter);
        other.assert_nothing_loaded("after a mismatch on another TPM")?;

        // (a) the TPM cleared.
        rig.tpm.clear()?;
        let (filter, record) = rig.filter(Lacks::default())?;
        let via = TestTcti::new(&filter.tcti());
        let cleared = subject.sign(&via, mechanism, &data).unwrap_err();
        assert_eq!(cleared, TpmSignError::ParentMismatch);
        assert!(!record.codes().contains(&cc::LOAD) && !record.codes().contains(&cc::SIGN));
        drop(filter);
        rig.assert_nothing_loaded("after a mismatch on a cleared TPM")?;

        // The messages differ, and name nothing.
        let load = format!("{error}");
        let mismatch_text = format!("{mismatch} {mismatch:?}");
        assert_ne!(load, format!("{mismatch}"));
        assert!(!mismatch_text.contains(&hex(&subject.imported.parent_name)));
        assert!(!load.contains(&hex(&subject.imported.parent_name)));
    }
    Ok(())
}

#[test]
fn no_load_before_the_check() -> TestResult {
    let rig = Rig::new()?;
    let direct = TestTcti::new(&rig.tcti());
    let subject = Subject::new(&rig, &direct, Kind::P256)?;
    let (mechanism, data) = call(Kind::P256);
    // A good blob: the parent is created before the key is loaded.
    let (filter, record) = rig.filter(Lacks::default())?;
    subject.sign(&TestTcti::new(&filter.tcti()), mechanism, &data)?;
    let codes = record.codes();
    let create = codes.iter().position(|c| *c == cc::CREATE_PRIMARY).unwrap();
    let load = codes.iter().position(|c| *c == cc::LOAD).unwrap();
    assert!(create < load, "{codes:x?}");
    drop(filter);
    // A bad blob: no TPM2_Load and no signing command at all.
    rig.tpm.clear()?;
    let (filter, record) = rig.filter(Lacks::default())?;
    let error = subject
        .sign(&TestTcti::new(&filter.tcti()), mechanism, &data)
        .unwrap_err();
    assert_eq!(error, TpmSignError::ParentMismatch);
    let codes = record.codes();
    assert!(codes.contains(&cc::CREATE_PRIMARY), "{codes:x?}");
    for forbidden in [cc::LOAD, cc::SIGN, cc::RSA_DECRYPT] {
        assert!(!codes.contains(&forbidden), "{forbidden:#x} in {codes:x?}");
    }
    Ok(())
}

fn fault(command: u32, action: FaultAction) -> Lacks {
    Lacks {
        faults: vec![CommandFault { command, action }],
        ..Lacks::default()
    }
}

#[test]
fn nothing_left_loaded() -> TestResult {
    let mut rig = Rig::new()?;
    let direct = TestTcti::new(&rig.tcti());
    let subjects: Vec<Subject> = BOTH
        .iter()
        .map(|k| Subject::new(&rig, &direct, *k))
        .collect::<Result<_, _>>()?;

    // A signature, a refused request and a failed load leave nothing.
    for subject in &subjects {
        let (mechanism, data) = call(subject.kind);
        subject.sign(&direct, mechanism, &data)?;
        rig.assert_nothing_loaded("after a signature")?;
        subject.sign(&direct, mechanism, &[]).ok();
        let refused = match subject.kind {
            Kind::Rsa => Mechanism::Ecdsa,
            Kind::P256 => Mechanism::RsaPkcs,
        };
        assert!(subject.sign(&direct, refused, &data).is_err());
        rig.assert_nothing_loaded("after a refused request")?;
    }

    // An error response on each command before the last flush: everything is flushed all the same.
    for (command, label) in [
        (cc::CREATE_PRIMARY, "create primary"),
        (cc::LOAD, "load"),
        (cc::RSA_DECRYPT, "rsa decrypt"),
        (cc::SIGN, "sign"),
    ] {
        for subject in &subjects {
            let (mechanism, data) = call(subject.kind);
            let (filter, record) = rig.filter(fault(command, FaultAction::Respond(0x101)))?;
            let result = subject.sign(&TestTcti::new(&filter.tcti()), mechanism, &data);
            let reached = record.codes().contains(&command);
            drop(filter);
            // TPM2_Sign is never sent for an RSA key, nor TPM2_RSA_Decrypt for P-256.
            if reached {
                assert!(result.is_err(), "{label} {:?}", subject.kind);
            } else {
                assert!(result.is_ok(), "{label} {:?}", subject.kind);
            }
            rig.assert_nothing_loaded(&format!("after a failed {label}"))?;
        }
    }

    // The flush itself fails, or the connection drops: the call says so, and what the TPM still holds is what the
    // kernel resource manager cleans up when the connection closes (`tpm2_flushcontext -t` here). A later signature
    // on the same swtpm succeeds and a restart leaves nothing.
    let signer = &subjects[1];
    let (mechanism, data) = call(signer.kind);
    for (command, action) in [
        (cc::FLUSH_CONTEXT, FaultAction::Respond(0x101)),
        (cc::SIGN, FaultAction::DropMidReply),
    ] {
        let (filter, _) = rig.filter(fault(command, action))?;
        let result = signer.sign(&TestTcti::new(&filter.tcti()), mechanism, &data);
        assert!(
            matches!(result, Err(TpmSignError::Tpm(_))),
            "{action:?}: {result:?}"
        );
        drop(filter);
        if command == cc::FLUSH_CONTEXT {
            assert!(
                !rig.handles("handles-transient")?.is_empty(),
                "the faulted flush leaves the handles"
            );
        }
        rig.tpm.tool_ok("tpm2_flushcontext", ["-t"])?;
        signer.sign(&direct, mechanism, &data)?;
        rig.tpm.restart()?;
        rig.assert_nothing_loaded("after a restart")?;
    }

    // After a parent mismatch.
    rig.tpm.clear()?;
    for subject in &subjects {
        let (mechanism, data) = call(subject.kind);
        assert_eq!(
            subject.sign(&direct, mechanism, &data).unwrap_err(),
            TpmSignError::ParentMismatch
        );
    }
    rig.assert_nothing_loaded("after a parent mismatch")?;

    // Control: a primary left by a tool that does not flush shows a handle, so the checks above can see a leak.
    rig.tpm.tool_ok(
        "tpm2_createprimary",
        ["-C", "o", "-c", &rig.path("leak.ctx")],
    )?;
    assert_eq!(rig.handles("handles-transient")?.len(), 1);
    Ok(())
}
