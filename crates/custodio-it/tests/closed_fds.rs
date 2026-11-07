//! A child started through `custodio_it::spawn::closed_fds` inherits no descriptor above stderr. The TSS
//! libraries open a socket without close-on-exec for each TPM command; here the test binary is re-run with
//! such a descriptor (7, left open by the shell that starts it) so the check does not depend on timing.

use std::process::Command;

use custodio_it::spawn::closed_fds;

/// Set in the re-run test binary, which holds descriptor 7 without close-on-exec.
const HOLDS_FD: &str = "CUSTODIO_CLOSED_FDS_CHILD";

/// The descriptors a `bash` started by `cmd` holds, read by `ls` from outside it (the pipe keeps `bash` from
/// exec-ing `ls`, whose own directory descriptor would show).
fn fds_of_bash(mut cmd: Command) -> Vec<u32> {
    let out = cmd
        .args(["-c", "ls -1 /proc/$$/fd | cat"])
        .output()
        .expect("run bash");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.trim().parse().ok())
        .collect()
}

#[test]
fn an_inherited_descriptor_does_not_reach_the_child() {
    if std::env::var_os(HOLDS_FD).is_some() {
        // Negative control: a plain child does inherit it.
        let plain = fds_of_bash(Command::new("bash"));
        assert!(plain.contains(&7), "plain child: {plain:?}");
        let closed = fds_of_bash(closed_fds("bash"));
        assert!(
            closed.iter().all(|&fd| fd <= 2),
            "closed_fds child: {closed:?}"
        );
        return;
    }
    let out = Command::new("bash")
        .args(["-c", "exec 7</dev/null; exec \"$@\"", "holds-fd"])
        .arg(std::env::current_exe().expect("test binary"))
        .args([
            "--exact",
            "an_inherited_descriptor_does_not_reach_the_child",
        ])
        .env(HOLDS_FD, "1")
        .output()
        .expect("re-run the test binary");
    assert!(
        out.status.success(),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
