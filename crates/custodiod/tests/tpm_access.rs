//! The TPM access point against a software TPM, a lacking one, and injected faults (F112).
//!
//! `swtpm` serves one client at a time, so every classification opens its session and drops it before the next
//! command (a tool or another classification) runs.

#[path = "tpm_access/faults.rs"]
mod faults;
#[path = "tpm_access/lacks.rs"]
mod lacks;

use std::ffi::OsStr;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::Command;

use custodio_it::swtpm::Swtpm;
use custodio_it::tpm_filter::{Lacks, TpmFilter};
use custodiod::tpm::open::{self, Production, TEST_SOCKET_VARIABLE, TestTcti};
use custodiod::tpm::{Classification, KeyType, TpmAccess, TpmError, assess};

type Res<T> = Result<T, Box<dyn std::error::Error>>;
type TestResult = Res<()>;

const BOTH: [KeyType; 2] = [KeyType::Rsa2048, KeyType::EccP256];

/// Classifies the TPM behind a TCTI string for one key type.
fn classify(tcti: &str, key: KeyType) -> Classification {
    assess(&TestTcti::new(tcti), key)
}

/// A filter in front of `tpm`, listening in its state directory.
fn filter(tpm: &Swtpm, lacks: Lacks) -> Res<TpmFilter> {
    let upstream: PathBuf = tpm
        .tcti()
        .strip_prefix("swtpm:path=")
        .ok_or("not an swtpm TCTI")?
        .into();
    Ok(TpmFilter::start(
        &upstream,
        &tpm.state_dir().join("filter.sock"),
        lacks,
    )?)
}

fn is_root() -> bool {
    rustix::process::geteuid().is_root()
}

/// A fake `/`: `dev/` exists, with the named nodes as empty regular files of the given mode.
fn root_with(nodes: &[(&str, u32)]) -> Res<tempfile::TempDir> {
    let root = tempfile::tempdir()?;
    std::fs::create_dir(root.path().join("dev"))?;
    for (name, mode) in nodes {
        let node = root.path().join("dev").join(name);
        std::fs::write(&node, b"")?;
        std::fs::set_permissions(&node, std::fs::Permissions::from_mode(*mode))?;
    }
    Ok(root)
}

#[test]
fn ready_both_key_types() -> TestResult {
    let tpm = Swtpm::start()?;
    for key in BOTH {
        assert_eq!(classify(&tpm.tcti(), key), Classification::Ready, "{key:?}");
    }
    Ok(())
}

/// Every capability list arrives one entry per answer: paging loses nothing and invents nothing.
#[test]
fn paged_answers_give_the_same_classification() -> TestResult {
    let tpm = Swtpm::start()?;
    for key in BOTH {
        assert_eq!(
            assess(&TestTcti::new(&tpm.tcti()).with_page(1), key),
            Classification::Ready,
            "{key:?}"
        );
    }
    Ok(())
}

/// Only "does not exist" is "no TPM": a path that cannot be looked at (`ENOTDIR`) and a node that is not what the
/// variable promises are errors of their own kind.
#[test]
fn unreadable_paths_are_errors_not_absent() -> TestResult {
    let dir = tempfile::tempdir()?;
    let plain = dir.path().join("plain");
    std::fs::write(&plain, b"")?;
    // `dev` is a regular file, so `dev/tpmrm0` fails with ENOTDIR.
    let root = tempfile::tempdir()?;
    std::fs::write(root.path().join("dev"), b"")?;
    // The same through the dedicated variable.
    let below = format!("swtpm:path={}/sock", plain.display());
    for key in BOTH {
        assert_eq!(
            assess(&Production::under(root.path()), key),
            Classification::Error(TpmError::OpenFailed)
        );
        assert_eq!(
            assess(open::from_value(Some(OsStr::new(&below))).as_ref(), key),
            Classification::Error(TpmError::OpenFailed)
        );
        // A regular file is refused as such, not merely "cannot be opened".
        let file = format!("swtpm:path={}", plain.display());
        assert_eq!(
            assess(open::from_value(Some(OsStr::new(&file))).as_ref(), key),
            Classification::Error(TpmError::TestTctiRefused)
        );
    }
    Ok(())
}

#[test]
fn absent_when_no_device() -> TestResult {
    let empty = tempfile::tempdir()?;
    for key in BOTH {
        assert_eq!(
            assess(&Production::under(empty.path()), key),
            Classification::Absent
        );
    }
    // A root with a `dev/` and no TPM node at all is the same.
    let dev = root_with(&[])?;
    assert_eq!(
        assess(&Production::under(dev.path()), KeyType::EccP256),
        Classification::Absent
    );
    // The real production constructor in this container: no `/dev/tpmrm0` (it fails loudly on a host that has one).
    assert!(
        !Path::new("/dev/tpmrm0").exists(),
        "this test needs a platform without /dev/tpmrm0"
    );
    assert_eq!(
        assess(&Production::new(), KeyType::EccP256),
        Classification::Absent
    );
    // The test-only variable naming a socket nobody listens on: the e2e "no TPM" shape of F108.
    let missing = format!("swtpm:path={}/gone.sock", empty.path().display());
    for key in BOTH {
        assert_eq!(
            assess(open::from_value(Some(OsStr::new(&missing))).as_ref(), key),
            Classification::Absent
        );
    }
    Ok(())
}

#[test]
fn raw_device_without_resource_manager_is_an_error_and_never_opened() -> TestResult {
    // The raw node is mode 000: opening it would fail with a different error (`OpenFailed`), so the kind shows it was
    // only stat-ed.
    let root = root_with(&[("tpm0", 0o000)])?;
    for key in BOTH {
        assert_eq!(
            assess(&Production::under(root.path()), key),
            Classification::Error(TpmError::ResourceManagerMissing)
        );
    }
    // Control, same layout with the resource manager at mode 000: an open failure, a different kind.
    if !is_root() {
        let root = root_with(&[("tpm0", 0o000), ("tpmrm0", 0o000)])?;
        assert_eq!(
            assess(&Production::under(root.path()), KeyType::EccP256),
            Classification::Error(TpmError::OpenFailed)
        );
    }
    Ok(())
}

/// The child of `production_ignores_environment`: classifies through the real production constructor and prints it.
#[test]
fn production_child() {
    if std::env::var_os("TPM_ACCESS_CHILD").is_none() {
        return;
    }
    let access: Box<dyn TpmAccess> = open::from_environment();
    println!("\nchild: {:?}", assess(access.as_ref(), KeyType::EccP256));
}

fn child_output(env: &[(&str, &str)]) -> Res<String> {
    let out = Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "production_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env("TPM_ACCESS_CHILD", "1")
        .envs(env.iter().copied())
        .output()?;
    assert!(out.status.success(), "{out:?}");
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("child: "))
        .ok_or("the child printed its result")?
        .to_owned())
}

#[test]
fn production_ignores_environment() -> TestResult {
    assert!(
        !Path::new("/dev/tpmrm0").exists(),
        "this test needs a platform without /dev/tpmrm0"
    );
    let tpm = Swtpm::start()?;
    let tcti = tpm.tcti();
    let generic = [
        "TPM2TOOLS_TCTI",
        "TSS2_TCTI",
        "TPM20TEST_TCTI",
        "TCTI",
        "TEST_TCTI",
    ]
    .map(|n| (n, tcti.as_str()));
    assert_eq!(child_output(&generic)?, "Absent");
    // The same TCTI in the dedicated variable is the control: it reaches the software TPM.
    assert_eq!(
        child_output(&[(TEST_SOCKET_VARIABLE, tcti.as_str())])?,
        "Ready"
    );
    // Both together: the dedicated one decides.
    let mut both = generic.to_vec();
    both.push((TEST_SOCKET_VARIABLE, tcti.as_str()));
    assert_eq!(child_output(&both)?, "Ready");
    Ok(())
}

#[test]
fn dedicated_variable_refusals() -> TestResult {
    let tpm = Swtpm::start()?;
    let socket = tpm
        .tcti()
        .strip_prefix("swtpm:path=")
        .ok_or("not an swtpm TCTI")?
        .to_owned();
    let dir = tempfile::tempdir()?;
    let file = dir.path().join("not-a-socket");
    std::fs::write(&file, b"")?;
    let dead = dir.path().join("dead.sock");
    drop(UnixListener::bind(&dead)?); // a socket file nobody listens on: a refused connection
    let values = [
        String::new(),
        "garbage".to_owned(),
        format!("device:{socket}"),
        "device:/dev/tpmrm0".to_owned(),
        "mssim:host=localhost,port=2321".to_owned(),
        "tabrmd:".to_owned(),
        "swtpm:path=relative.sock".to_owned(),
        "swtpm:host=localhost,port=2321".to_owned(),
        format!("swtpm:path={socket},host=x"),
        format!("swtpm:path={}", file.display()),
        format!("swtpm:path={}", dir.path().display()),
        format!("swtpm:path={}", dead.display()),
    ];
    for value in &values {
        for key in BOTH {
            let got = assess(open::from_value(Some(OsStr::new(value))).as_ref(), key);
            assert!(
                matches!(got, Classification::Error(_)),
                "{value:?} gave {got:?}, want an error"
            );
        }
    }
    // The well-formed value is Ready (control), the same socket as above.
    assert_eq!(
        assess(
            open::from_value(Some(OsStr::new(&tpm.tcti()))).as_ref(),
            KeyType::Rsa2048
        ),
        Classification::Ready
    );
    Ok(())
}

#[test]
fn nothing_is_shipped_with_the_variable() -> TestResult {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for dir in ["data", "packaging"] {
        let out = Command::new("grep")
            .args(["-rc", TEST_SOCKET_VARIABLE])
            .arg(root.join(dir))
            .output()?;
        let total: usize = String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| l.rsplit(':').next()?.parse::<usize>().ok())
            .sum();
        assert_eq!(total, 0, "{dir} mentions {TEST_SOCKET_VARIABLE}");
    }
    Ok(())
}

fn handles(tpm: &Swtpm, what: &str) -> Res<String> {
    Ok(tpm.tool_ok("tpm2_getcap", [what])?)
}

#[test]
fn nothing_left_loaded() -> TestResult {
    let tpm = Swtpm::start()?;
    let lacking = filter(
        &tpm,
        Lacks {
            commands: vec![0x159],
            ..Lacks::default()
        },
    )?;
    for key in BOTH {
        assert_eq!(classify(&tpm.tcti(), key), Classification::Ready);
        assert!(matches!(
            classify(&lacking.tcti(), key),
            Classification::Lacks(_) | Classification::Ready
        ));
    }
    tpm.tool_ok("tpm2_changeauth", ["-c", "o", "owner-secret"])?;
    assert_eq!(
        classify(&tpm.tcti(), KeyType::EccP256),
        Classification::Error(TpmError::OwnerAuthSet)
    );
    for what in [
        "handles-transient",
        "handles-loaded-session",
        "handles-saved-session",
        "handles-persistent",
    ] {
        assert_eq!(
            handles(&tpm, what)?.trim(),
            "",
            "{what} after the classifications"
        );
    }
    // Control: a primary left loaded shows up, so the check can fail.
    let fresh = Swtpm::start()?;
    fresh.tool_ok("tpm2_createprimary", ["-C", "o", "-c", "primary.ctx"])?;
    assert!(
        handles(&fresh, "handles-transient")?.contains("0x80"),
        "control"
    );
    let _ = Path::new("");
    Ok(())
}
