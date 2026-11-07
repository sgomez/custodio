//! The `systemd-creds` child inherits no descriptor of the service (F118, `docs/findings/F118.md`).
//!
//! The TSS libraries open their TPM connection without close-on-exec, so a child forked while another thread talks to
//! the TPM would keep that connection open. The test does not depend on timing: this binary is re-run with descriptor 7
//! open (left by the shell that starts it), and the real `SystemdCreds` path starts a substitute program that prints
//! its own descriptors.
// A test fails by panicking: unwrap, expect and indexing on data the test itself built are the intended failure mode.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use custodiod::creds::Credentials;
use custodiod::creds::memory::MemoryCreds;
use custodiod::creds::systemd::SystemdCreds;
use secrecy::{ExposeSecret, SecretSlice};

use crate::rig::TestResult;

/// Set in the re-run test binary, which holds descriptor 7 without close-on-exec.
const HOLDS_FD: &str = "CUSTODIO_SIGN_KINDS_HOLDS_FD";

/// Prints the descriptors of the shell that runs it. 255 is the shell's own descriptor for the script.
const SUBSTITUTE: &str = "#!/bin/bash\nls -1 /proc/$$/fd | cat\n";

fn fds(text: &[u8]) -> Vec<u32> {
    String::from_utf8_lossy(text)
        .lines()
        .filter_map(|l| l.trim().parse().ok())
        .filter(|fd| *fd != 255)
        .collect()
}

#[test]
fn creds_child_inherits_no_descriptor() -> TestResult {
    if std::env::var_os(HOLDS_FD).is_some() {
        return inner();
    }
    let out = Command::new("bash")
        .args(["-c", "exec 7</dev/null; exec \"$@\"", "holds-fd"])
        .arg(std::env::current_exe()?)
        .args(["--exact", "descriptor::creds_child_inherits_no_descriptor"])
        .env(HOLDS_FD, "1")
        .output()?;
    assert!(
        out.status.success(),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    // The re-run ran the test (and did not filter it out).
    assert!(String::from_utf8_lossy(&out.stdout).contains("1 passed"));
    Ok(())
}

fn inner() -> TestResult {
    let dir = tempfile::tempdir()?;
    let program = dir.path().join("systemd-creds-substitute");
    std::fs::write(&program, SUBSTITUTE)?;
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755))?;

    // Negative control: a plain `Command` in this process does inherit descriptor 7.
    let plain = Command::new(&program).output()?;
    assert!(
        fds(&plain.stdout).contains(&7),
        "the harness holds no descriptor: {:?}",
        fds(&plain.stdout)
    );

    // The service's own path: `SystemdCreds::decrypt` of a TPM-bound credential starts the command.
    let client = SystemdCreds::new(dir.path().join("no-socket"), program, Some("device".into()));
    let name = "k";
    let secret = SecretSlice::new(Box::from(b"x".as_slice()));
    let credential = MemoryCreds::tpm().encrypt(name, &secret)?;
    let printed = client.decrypt(name, &credential)?;
    let seen = fds(printed.expose_secret());
    assert!(!seen.is_empty(), "the substitute printed nothing");
    assert!(
        seen.iter().all(|fd| *fd <= 2),
        "the child inherited descriptors: {seen:?}"
    );
    Ok(())
}
