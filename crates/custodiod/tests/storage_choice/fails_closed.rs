//! Every failure that is not "lacks" or "absent" fails the import: the documented error, nothing stored, one journal
//! entry, and never a weaker kind.
// A test fails by panicking: unwrap, expect and indexing on data the test itself built are the intended failure mode.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use custodio_it::tpm_filter::cc;
use custodiod::creds::CredsError;
use custodiod::creds::memory::MemoryCreds;
use custodiod::tpm::open::{NoTpm, Production, TestTcti};

use crate::rig::{ERR_CREDS, ERR_TPM, Rig, SpyCreds, TestResult, fault, lacks_import};
use crate::row::{Row, run};

#[test]
fn device_unopenable() -> TestResult {
    // A directory where the node should be: the device is there and cannot be opened.
    let root = tempfile::tempdir()?;
    std::fs::create_dir_all(root.path().join("dev/tpmrm0"))?;
    run(
        &Row {
            err: ERR_TPM,
            encrypts: 0,
        },
        &|_| {
            (
                Production::under(root.path()),
                SpyCreds::new(MemoryCreds::host()),
            )
        },
        &|svc| svc.tpm.swap(NoTpm),
    )
}

#[test]
fn tpm_error_in_query() -> TestResult {
    let rig = Rig::new()?;
    let (filter, _) = rig.filter(fault(cc::GET_CAPABILITY, 0x101))?;
    run(
        &Row {
            err: ERR_TPM,
            encrypts: 0,
        },
        &|_| {
            (
                TestTcti::new(&filter.tcti()),
                SpyCreds::new(MemoryCreds::host()),
            )
        },
        &|svc| svc.tpm.swap(TestTcti::new(&rig.tcti())),
    )
}

#[test]
fn owner_hierarchy_unusable() -> TestResult {
    let rig = Rig::new()?;
    run(
        &Row {
            err: ERR_TPM,
            encrypts: 0,
        },
        // Set for every key type: the healing of the first one removed it.
        &|_| {
            rig.tpm
                .tool_ok("tpm2_changeauth", ["-c", "o", "owner-secret"])
                .unwrap();
            (
                TestTcti::new(&rig.tcti()),
                SpyCreds::new(MemoryCreds::host()),
            )
        },
        &|svc| {
            rig.tpm
                .tool_ok("tpm2_changeauth", ["-c", "o", "-p", "owner-secret"])
                .unwrap();
            svc.tpm.swap(TestTcti::new(&rig.tcti()));
        },
    )
}

#[test]
fn tpm_error_during_import() -> TestResult {
    let rig = Rig::new()?;
    let (filter, record) = rig.filter(fault(cc::IMPORT, 0x101))?;
    run(
        &Row {
            err: ERR_TPM,
            encrypts: 0,
        },
        &|_| {
            (
                TestTcti::new(&filter.tcti()),
                SpyCreds::new(MemoryCreds::host()),
            )
        },
        &|svc| svc.tpm.swap(TestTcti::new(&rig.tcti())),
    )?;
    // The import was attempted: the TPM was Ready and the failure came after the choice.
    assert!(record.codes().contains(&cc::IMPORT));
    Ok(())
}

#[test]
fn import_refused_with_lack_like_code() -> TestResult {
    // TPM_RC_COMMAND_CODE on Import looks like a lack, but the choice was made: no encrypted record, no retry.
    let rig = Rig::new()?;
    let (filter, record) = rig.filter(fault(cc::IMPORT, 0x143))?;
    run(
        &Row {
            err: ERR_TPM,
            encrypts: 0,
        },
        &|_| {
            (
                TestTcti::new(&filter.tcti()),
                SpyCreds::new(MemoryCreds::tpm()),
            )
        },
        &|svc| svc.tpm.swap(TestTcti::new(&rig.tcti())),
    )?;
    assert!(record.codes().contains(&cc::IMPORT));
    Ok(())
}

#[test]
fn credentials_down_with_no_tpm() -> TestResult {
    run(
        &Row {
            err: ERR_CREDS,
            encrypts: 1,
        },
        &|_| {
            let creds = SpyCreds::new(MemoryCreds::host());
            creds.fail_with(Some(CredsError::Unavailable));
            (NoTpm, creds)
        },
        &|svc| svc.creds.fail_with(None),
    )
}

#[test]
fn credentials_down_with_lacking_tpm() -> TestResult {
    let rig = Rig::new()?;
    let (filter, _) = rig.filter(lacks_import())?;
    run(
        &Row {
            err: ERR_CREDS,
            encrypts: 1,
        },
        &|_| {
            let creds = SpyCreds::new(MemoryCreds::tpm());
            creds.fail_with(Some(CredsError::Unavailable));
            (TestTcti::new(&filter.tcti()), creds)
        },
        &|svc| svc.creds.fail_with(None),
    )
}

#[test]
fn credentials_cannot_encrypt() -> TestResult {
    run(
        &Row {
            err: ERR_CREDS,
            encrypts: 1,
        },
        &|_| {
            let creds = SpyCreds::new(MemoryCreds::host());
            creds.fail_with(Some(CredsError::BadRequest));
            (NoTpm, creds)
        },
        &|svc| svc.creds.fail_with(None),
    )
}

#[test]
fn binding_disagrees_with_kind_tpm() -> TestResult {
    // The TPM lacks something, so the kind is encrypted TPM-bound; the credential names the host.
    let rig = Rig::new()?;
    let (filter, _) = rig.filter(lacks_import())?;
    run(
        &Row {
            err: ERR_CREDS,
            encrypts: 1,
        },
        &|_| {
            (
                TestTcti::new(&filter.tcti()),
                SpyCreds::new(MemoryCreds::host()),
            )
        },
        &|svc| svc.tpm.swap(NoTpm),
    )
}

#[test]
fn binding_disagrees_with_kind_host() -> TestResult {
    // No TPM, so the kind is encrypted host-bound; the credential names a TPM.
    let rig = Rig::new()?;
    run(
        &Row {
            err: ERR_CREDS,
            encrypts: 1,
        },
        &|_| (NoTpm, SpyCreds::new(MemoryCreds::tpm())),
        &|svc| svc.tpm.swap(TestTcti::new(&rig.tcti())),
    )
}
