//! Errors are errors: never absent, never lacking.

use std::os::unix::net::UnixListener;

use custodio_it::swtpm::Swtpm;
use custodio_it::tpm_filter::{CommandFault, FaultAction, Lacks, alg, cc};
use custodiod::tpm::open::Production;
use custodiod::tpm::{Classification, KeyType, ResponseCode, TpmError, assess};

use super::{BOTH, TestResult, classify, filter, is_root, root_with};

fn response(code: u32) -> Classification {
    Classification::Error(TpmError::Response(ResponseCode(code)))
}

fn fault(command: u32, action: FaultAction) -> Lacks {
    Lacks {
        faults: vec![CommandFault { command, action }],
        ..Lacks::default()
    }
}

#[test]
fn device_nodes_that_cannot_be_opened() -> TestResult {
    // (a) the node is there with mode 000: an open failure, not "absent".
    if !is_root() {
        let root = root_with(&[("tpmrm0", 0o000)])?;
        for key in BOTH {
            assert_eq!(
                assess(&Production::under(root.path()), key),
                Classification::Error(TpmError::OpenFailed)
            );
        }
    }
    // (b) a directory where the node should be (EISDIR), and a socket (ENXIO).
    let root = root_with(&[])?;
    std::fs::create_dir(root.path().join("dev/tpmrm0"))?;
    assert_eq!(
        assess(&Production::under(root.path()), KeyType::EccP256),
        Classification::Error(TpmError::OpenFailed)
    );
    let root = root_with(&[])?;
    let _listener = UnixListener::bind(root.path().join("dev/tpmrm0"))?;
    assert_eq!(
        assess(&Production::under(root.path()), KeyType::EccP256),
        Classification::Error(TpmError::OpenFailed)
    );
    Ok(())
}

#[test]
fn faults_are_errors() -> TestResult {
    // (c) the TPM answers FAILURE (the code a lacking capability does not use) to GetCapability, and to TestParms.
    for command in [cc::GET_CAPABILITY, cc::TEST_PARMS] {
        let tpm = Swtpm::start()?;
        let faulty = filter(&tpm, fault(command, FaultAction::Respond(0x101)))?;
        for key in BOTH {
            assert_eq!(
                classify(&faulty.tcti(), key),
                response(0x101),
                "{command:#x} {key:?}"
            );
        }
    }
    // A code that means "unsupported" for TestParms is still an error from GetCapability.
    let tpm = Swtpm::start()?;
    let faulty = filter(&tpm, fault(cc::GET_CAPABILITY, FaultAction::Respond(0x1c3)))?;
    assert_eq!(classify(&faulty.tcti(), KeyType::EccP256), response(0x1c3));
    // The connection drops in the middle of a reply: an error without a response code.
    let tpm = Swtpm::start()?;
    let faulty = filter(&tpm, fault(cc::GET_CAPABILITY, FaultAction::DropMidReply))?;
    for key in BOTH {
        assert_eq!(
            classify(&faulty.tcti(), key),
            Classification::Error(TpmError::Transport),
            "{key:?}"
        );
    }
    let faulty = filter(
        &Swtpm::start()?,
        fault(cc::TEST_PARMS, FaultAction::DropMidReply),
    )?;
    assert!(matches!(
        classify(&faulty.tcti(), KeyType::EccP256),
        Classification::Error(_)
    ));
    Ok(())
}

#[test]
fn owner_hierarchy_the_service_cannot_use() -> TestResult {
    let tpm = Swtpm::start()?;
    // (d) an owner authorization value is set.
    tpm.tool_ok("tpm2_changeauth", ["-c", "o", "owner-secret"])?;
    for key in BOTH {
        assert_eq!(
            classify(&tpm.tcti(), key),
            Classification::Error(TpmError::OwnerAuthSet)
        );
    }
    // (e) on a TPM that also lacks something, the error wins.
    let lacking = filter(
        &tpm,
        Lacks {
            algorithms: vec![alg::SHA256],
            ..Lacks::default()
        },
    )?;
    for key in BOTH {
        assert_eq!(
            classify(&lacking.tcti(), key),
            Classification::Error(TpmError::OwnerAuthSet)
        );
    }
    drop(lacking);
    // Control: the authorization value removed again gives Ready.
    tpm.tool_ok("tpm2_changeauth", ["-c", "o", "-p", "owner-secret"])?;
    for key in BOTH {
        assert_eq!(classify(&tpm.tcti(), key), Classification::Ready);
    }
    // (d) the owner hierarchy is disabled (shEnable clear), with the platform hierarchy.
    tpm.tool_ok("tpm2_hierarchycontrol", ["-C", "p", "shEnable", "clear"])?;
    for key in BOTH {
        assert_eq!(
            classify(&tpm.tcti(), key),
            Classification::Error(TpmError::OwnerDisabled)
        );
    }
    // Control: enabled again.
    tpm.tool_ok("tpm2_hierarchycontrol", ["-C", "p", "shEnable", "set"])?;
    for key in BOTH {
        assert_eq!(classify(&tpm.tcti(), key), Classification::Ready);
    }
    Ok(())
}
