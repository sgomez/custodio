//! A blob of another parent is detected before use.
// A test fails by panicking: unwrap, expect and indexing on data the test itself built are the intended failure mode.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use custodio_it::tpm_filter::{CommandFault, FaultAction, Lacks, cc};
use custodiod::tpm::TpmError;
use custodiod::tpm::import::{ImportError, check_parent, import_pkcs8};
use custodiod::tpm::open::TestTcti;

use super::support::{BOTH, Rig, SRK_ATTRS, TestKey, TestResult, hex};

#[test]
fn parent_mismatch_before_use() -> TestResult {
    for kind in BOTH {
        let mut rig = Rig::new()?;
        let key = TestKey::new(kind);
        let imported = import_pkcs8(&TestTcti::new(&rig.tcti()), &key.pkcs8)?;
        let name = imported.parent_name.clone();

        // (c) control, first: the same instance, and the same TPM after a restart, accept it and `tpm2_load` loads it.
        let (filter, record) = rig.filter(Lacks::default())?;
        let via = TestTcti::new(&filter.tcti());
        assert_eq!(check_parent(&via, &name), Ok(()));
        assert!(record.codes().contains(&cc::CREATE_PRIMARY));
        rig.tpm.restart()?;
        assert_eq!(check_parent(&via, &name), Ok(()));
        rig.primary(SRK_ATTRS)?;
        rig.load(&imported.blob)?;
        drop(filter);

        // (a) after a clear the owner seed changes.
        rig.tpm.clear()?;
        let (filter, record) = rig.filter(Lacks::default())?;
        let via = TestTcti::new(&filter.tcti());
        let error = check_parent(&via, &name).unwrap_err();
        assert_eq!(error, ImportError::ParentMismatch);
        let shown = format!("{error} {error:?}");
        assert!(shown.contains("another TPM parent"), "{shown}");
        assert!(!shown.contains(&hex(&name)) && !shown.contains(&hex(&name[2..10])));
        assert!(!record.codes().is_empty(), "the check did ask the TPM");
        assert!(!record.codes().contains(&cc::LOAD), "no TPM2_Load");
        drop(filter);

        // (b) a second TPM.
        let other = Rig::new()?;
        let (filter, record) = other.filter(Lacks::default())?;
        assert_eq!(
            check_parent(&TestTcti::new(&filter.tcti()), &name),
            Err(ImportError::ParentMismatch)
        );
        assert!(!record.codes().contains(&cc::LOAD));
        drop(filter);

        // (d) a TPM that would drop `TPM2_Load` is not even asked.
        let (filter, _) = other.filter(Lacks {
            faults: vec![CommandFault {
                command: cc::LOAD,
                action: FaultAction::DropMidReply,
            }],
            ..Lacks::default()
        })?;
        assert_eq!(
            check_parent(&TestTcti::new(&filter.tcti()), &name),
            Err(ImportError::ParentMismatch)
        );
        drop(filter);

        // (e) an owner hierarchy with an authorization value is a TPM error, not a mismatch, for both calls.
        other.tool("tpm2_changeauth", &["-c", "o", "secret"])?;
        let access = TestTcti::new(&other.tcti());
        assert_eq!(
            check_parent(&access, &name),
            Err(ImportError::Tpm(TpmError::OwnerAuthSet))
        );
        assert_eq!(
            import_pkcs8(&access, &key.pkcs8).unwrap_err(),
            ImportError::Tpm(TpmError::OwnerAuthSet)
        );
    }
    Ok(())
}
