//! Every object and session is flushed; many imports in a row.
// A test fails by panicking: unwrap, expect and indexing on data the test itself built are the intended failure mode.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use custodio_it::tpm_filter::{CommandFault, FaultAction, Lacks, cc};
use custodiod::tpm::import::{ImportError, check_parent, import_pkcs8};
use custodiod::tpm::open::TestTcti;
use custodiod::tpm::{ResponseCode, TpmError};

use super::support::{BOTH, Rig, TestKey, TestResult};

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
    let keys: Vec<TestKey> = BOTH.iter().map(|k| TestKey::new(*k)).collect();

    // Successful imports, and a parent mismatch.
    let mut recorded = Vec::new();
    for key in &keys {
        let imported = import_pkcs8(&direct, &key.pkcs8)?;
        rig.assert_nothing_loaded("after an import")?;
        recorded = imported.parent_name;
    }
    rig.tpm.clear()?;
    assert_eq!(
        check_parent(&direct, &recorded),
        Err(ImportError::ParentMismatch)
    );
    rig.assert_nothing_loaded("after a parent mismatch")?;

    // An error response on each command that precedes the last flush: the object is flushed all the same.
    for command in [cc::CREATE_PRIMARY, cc::IMPORT] {
        for key in &keys {
            let (filter, record) = rig.filter(fault(command, FaultAction::Respond(0x101)))?;
            let result = import_pkcs8(&TestTcti::new(&filter.tcti()), &key.pkcs8);
            assert_eq!(
                result.unwrap_err(),
                ImportError::Tpm(TpmError::Response(ResponseCode(0x101))),
                "{command:#x}"
            );
            assert!(record.codes().contains(&command));
            drop(filter);
            rig.assert_nothing_loaded(&format!("after a failed {command:#x}"))?;
        }
    }
    // A parent check whose reply is an error also flushes what it created.
    let (filter, _) = rig.filter(fault(cc::CREATE_PRIMARY, FaultAction::Respond(0x101)))?;
    assert!(check_parent(&TestTcti::new(&filter.tcti()), &recorded).is_err());
    drop(filter);
    rig.assert_nothing_loaded("after a failed parent check")?;

    // Where the flush itself fails, or the connection drops, the call says so; a later import still works and a restart
    // (what the kernel resource manager does when the connection closes) leaves nothing.
    for action in [FaultAction::Respond(0x101), FaultAction::DropMidReply] {
        let command = if action == FaultAction::DropMidReply {
            cc::IMPORT
        } else {
            cc::FLUSH_CONTEXT
        };
        let (filter, _) = rig.filter(fault(command, action))?;
        let result = import_pkcs8(&TestTcti::new(&filter.tcti()), &keys[1].pkcs8);
        assert!(
            matches!(result, Err(ImportError::Tpm(_))),
            "{action:?}: {result:?}"
        );
        drop(filter);
        import_pkcs8(&direct, &keys[1].pkcs8)?;
        rig.tpm.restart()?;
        rig.assert_nothing_loaded("after a restart")?;
    }

    // Control: the flush-free `tpm2_createprimary` leaves one handle, so the check above can see a leak.
    rig.tpm.tool_ok(
        "tpm2_createprimary",
        ["-C", "o", "-c", &rig.path("leak.ctx")],
    )?;
    assert_eq!(rig.handles("handles-transient")?.len(), 1);
    Ok(())
}

#[test]
fn many_imports_in_a_row() -> TestResult {
    let rig = Rig::new()?;
    let access = TestTcti::new(&rig.tcti());
    for kind in BOTH {
        let key = TestKey::new(kind);
        for _ in 0..10 {
            import_pkcs8(&access, &key.pkcs8)?;
        }
    }
    assert_eq!(rig.handles("handles-transient")?, Vec::<String>::new());
    Ok(())
}
