//! Tests of the `swtpm` fixture itself (F105): start, TCTI for `tss-esapi` and `tpm2-tools`, PCR extend,
//! restart on the same state, clear, independent instances, cleanup on drop (panics included) and after a SIGKILL.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::time::{Duration, Instant};

use custodio_it::swtpm::{Swtpm, process_exists};
use sha2::{Digest, Sha256};
use tss_esapi::Context;
use tss_esapi::constants::PropertyTag;
use tss_esapi::tcti_ldr::TctiNameConf;

/// `TPM2_PT_MANUFACTURER` of swtpm: "IBM\0".
const SWTPM_MANUFACTURER: u32 = 0x4942_4D00;
const PERSISTENT: &str = "0x81010001";

fn start() -> Swtpm {
    Swtpm::start().unwrap_or_else(|e| panic!("{e}"))
}

/// Reads `TPM2_PT_MANUFACTURER` through a `tss-esapi` context on the fixture's TCTI string.
/// The context is dropped on return: swtpm serves one client at a time.
fn manufacturer(tpm: &Swtpm) -> u32 {
    let tcti = TctiNameConf::from_str(&tpm.tcti()).expect("TCTI string");
    let mut ctx = Context::new(tcti).expect("open an ESYS context");
    ctx.get_tpm_property(PropertyTag::Manufacturer)
        .expect("get_capability")
        .expect("manufacturer property present")
}

/// Creates the same ECC primary in the given hierarchy and returns its public area (the file the tool writes).
fn primary_public(tpm: &Swtpm, hierarchy: &str, name: &str) -> Vec<u8> {
    let ctx = format!("{name}.ctx");
    let public = format!("{name}.pub");
    tpm.tool_ok(
        "tpm2_createprimary",
        ["-C", hierarchy, "-G", "ecc", "-c", &ctx],
    )
    .expect("createprimary");
    tpm.tool_ok("tpm2_readpublic", ["-c", &ctx, "-o", &public])
        .expect("readpublic");
    // Saved contexts and loaded transients count against the TPM's small object slots.
    tpm.tool_ok("tpm2_flushcontext", ["-t"])
        .expect("flushcontext");
    fs::read(tpm.state_dir().join(public)).expect("public area")
}

/// Makes the owner primary persistent at [`PERSISTENT`]; returns its public area.
fn persist_primary(tpm: &Swtpm, name: &str) -> Vec<u8> {
    let public = primary_public(tpm, "o", name);
    tpm.tool_ok(
        "tpm2_evictcontrol",
        ["-C", "o", "-c", &format!("{name}.ctx"), PERSISTENT],
    )
    .expect("evictcontrol");
    public
}

fn persistent_handles(tpm: &Swtpm) -> String {
    tpm.tool_ok("tpm2_getcap", ["handles-persistent"])
        .expect("getcap")
}

fn pcr16(tpm: &Swtpm) -> String {
    let out = tpm.tool_ok("tpm2_pcrread", ["sha256:16"]).expect("pcrread");
    let line = out
        .lines()
        .find(|l| l.trim_start().starts_with("16"))
        .expect("PCR 16 line");
    line.split_once(':')
        .expect("colon")
        .1
        .trim()
        .trim_start_matches("0x")
        .to_lowercase()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

#[test]
fn context_through_the_tcti_reads_a_property() {
    let tpm = start();
    assert_eq!(manufacturer(&tpm), SWTPM_MANUFACTURER);
}

#[test]
fn tpm2_tools_work_on_a_private_socket_inside_the_state_directory() {
    let a = start();
    let b = start();
    for tpm in [&a, &b] {
        let out = tpm
            .tool("tpm2_getcap", ["properties-fixed"])
            .expect("run tpm2_getcap");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let sock = tpm
            .tcti()
            .strip_prefix("swtpm:path=")
            .expect("swtpm TCTI")
            .to_owned();
        assert!(
            Path::new(&sock).starts_with(tpm.state_dir()),
            "{sock} outside {}",
            tpm.state_dir().display()
        );
    }
    assert_ne!(a.state_dir(), b.state_dir());
    assert_ne!(a.tcti(), b.tcti());
}

#[test]
fn extend_pcr_changes_it_to_the_chained_digest() {
    let tpm = start();
    assert_eq!(pcr16(&tpm), "0".repeat(64), "PCR 16 starts at zero");
    let digest = Sha256::digest(b"custodio");
    tpm.extend_pcr(16, &hex(&digest)).expect("extend");
    let mut chained = Sha256::new();
    chained.update([0_u8; 32]);
    chained.update(digest);
    assert_eq!(pcr16(&tpm), hex(&chained.finalize()));
}

#[test]
fn restart_keeps_persistent_objects_and_resets_pcrs() {
    let mut tpm = start();
    let public = persist_primary(&tpm, "before");
    tpm.extend_pcr(16, &hex(&Sha256::digest(b"x")))
        .expect("extend");
    assert_ne!(pcr16(&tpm), "0".repeat(64));
    let old_pid = tpm.pid();

    tpm.restart().expect("restart");

    assert_ne!(tpm.pid(), old_pid, "a new swtpm process");
    assert!(!process_exists(old_pid), "the old process is gone");
    assert_eq!(
        manufacturer(&tpm),
        SWTPM_MANUFACTURER,
        "a new context works, on the same TCTI string"
    );
    assert!(
        persistent_handles(&tpm).contains(PERSISTENT),
        "persistent handle survives the restart"
    );
    assert_eq!(
        primary_public(&tpm, "o", "after"),
        public,
        "same owner seed, same public key"
    );
    assert_eq!(
        pcr16(&tpm),
        "0".repeat(64),
        "TPM2_Startup(CLEAR) reset the PCR: a restart really happened"
    );
}

#[test]
fn clear_flushes_persistent_objects_and_changes_the_owner_seed() {
    let mut tpm = start();
    let public = persist_primary(&tpm, "before");
    tpm.restart().expect("restart");
    assert!(persistent_handles(&tpm).contains(PERSISTENT));

    tpm.clear().expect("clear");

    assert!(
        persistent_handles(&tpm).trim().is_empty(),
        "no persistent handle after the clear"
    );
    // The clear changes the owner (storage) seed, not the endorsement seed: compare the owner primary.
    assert_ne!(
        primary_public(&tpm, "o", "after"),
        public,
        "owner primary differs after the clear"
    );
}

#[test]
fn two_instances_are_independent() {
    let a = start();
    let b = start();
    let (pa, pb) = (primary_public(&a, "o", "p"), primary_public(&b, "o", "p"));
    assert_ne!(pa, pb, "different owner primaries");
    let (ea, eb) = (primary_public(&a, "e", "e"), primary_public(&b, "e", "e"));
    assert_ne!(ea, eb, "different endorsement primaries");

    persist_primary(&a, "keep");
    assert!(persistent_handles(&a).contains(PERSISTENT));
    assert!(
        !persistent_handles(&b).contains(PERSISTENT),
        "the object is absent in the other instance"
    );

    a.clear().expect("clear a");
    assert_eq!(
        manufacturer(&b),
        SWTPM_MANUFACTURER,
        "b still works after clearing a"
    );
    let b_pid = b.pid();
    drop(a);
    assert!(process_exists(b_pid), "dropping a leaves b running");
    assert_eq!(primary_public(&b, "o", "p"), pb, "b is unchanged");
}

#[test]
fn consecutive_instances_start_with_fresh_state() {
    let first = start();
    persist_primary(&first, "keep");
    assert!(persistent_handles(&first).contains(PERSISTENT));
    drop(first);
    let second = start();
    assert_eq!(persistent_handles(&second).trim(), "");
}

fn assert_alive(pid: u32, dir: &Path) {
    assert!(process_exists(pid), "swtpm {pid} should be running");
    assert!(dir.exists(), "{} should exist", dir.display());
}

fn assert_gone(pid: u32, dir: &Path) {
    // Drop waits (bounded) for the process, so by now it is reaped.
    assert!(!process_exists(pid), "swtpm {pid} is still there");
    assert!(!dir.exists(), "{} is still there", dir.display());
}

#[test]
fn drop_stops_the_process_and_removes_the_state() {
    let tpm = start();
    let (pid, dir) = (tpm.pid(), tpm.state_dir().to_owned());
    // Negative control: before the drop the same checks see a live instance.
    assert_alive(pid, &dir);
    assert!(
        std::panic::catch_unwind(|| assert_gone(pid, &dir)).is_err(),
        "the check can fail"
    );
    drop(tpm);
    assert_gone(pid, &dir);
}

#[test]
fn drop_during_a_panic_cleans_up() {
    let (tx, rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        let tpm = start();
        tx.send((tpm.pid(), tpm.state_dir().to_owned()))
            .expect("send");
        let _keep = &tpm;
        panic!("test panic with the fixture alive");
    });
    let (pid, dir) = rx.recv().expect("pid and dir");
    assert!(handle.join().is_err(), "the thread panicked");
    assert_gone(pid, &dir);
}

/// Set in the child processes of the tests below: what the child does with its fixture.
const CHILD: &str = "CUSTODIO_SWTPM_CHILD";

/// Runs `test` of this binary again as a child in its own process group, as nextest does, with [`CHILD`] set to
/// `mode` and `path` as its `PATH`. Returns the child, its still open stdout, and its swtpm's pid and state directory.
fn fixture_child(
    test: &str,
    mode: &str,
    path: &std::ffi::OsStr,
) -> (
    std::process::Child,
    BufReader<std::process::ChildStdout>,
    u32,
    PathBuf,
) {
    use std::os::unix::process::CommandExt;
    let mut child = Command::new(std::env::current_exe().expect("test binary"))
        .args(["--exact", test, "--nocapture"])
        .env(CHILD, mode)
        .env("PATH", path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .process_group(0)
        .spawn()
        .expect("spawn the child");
    let mut out = BufReader::new(child.stdout.take().expect("stdout"));
    let line = out
        .by_ref()
        .lines()
        .map_while(Result::ok)
        .find(|l| l.starts_with("fixture "))
        .expect("the child reports its swtpm");
    let mut parts = line.split(' ').skip(1);
    let pid: u32 = parts.next().and_then(|p| p.parse().ok()).expect("pid");
    let dir = PathBuf::from(parts.next().expect("dir"));
    (child, out, pid, dir)
}

/// The child side: starts a fixture and reports it. `hold` then sleeps until killed; any other mode drops it.
fn fixture_child_body(mode: &std::ffi::OsStr) {
    let tpm = start();
    println!("fixture {} {}", tpm.pid(), tpm.state_dir().display());
    std::io::stdout().flush().expect("flush");
    if mode == "hold" {
        loop {
            std::thread::sleep(Duration::from_secs(60));
        }
    }
    drop(tpm);
    println!("dropped");
}

fn wait_gone(pid: u32, dir: &Path) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while (process_exists(pid) || dir.exists()) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_gone(pid, dir);
}

fn signal(target: &str) {
    let status = Command::new("bash")
        .args(["-c", "kill -KILL -- \"$1\"", "kill", target])
        .status()
        .expect("run kill");
    assert!(status.success(), "kill {target}");
}

#[test]
fn a_killed_test_binary_leaves_no_swtpm() {
    const TEST: &str = "a_killed_test_binary_leaves_no_swtpm";
    if let Some(mode) = std::env::var_os(CHILD) {
        return fixture_child_body(&mode);
    }
    let path = std::env::var_os("PATH").expect("PATH");
    let (mut child, _out, pid, dir) = fixture_child(TEST, "hold", &path);
    // Negative control: the child's swtpm is up before the kill.
    assert_alive(pid, &dir);
    signal(&child.id().to_string());
    child.wait().expect("reap the child");
    wait_gone(pid, &dir);
}

/// nextest ends a test (fail-fast, a timeout) with SIGKILL to its whole process group.
#[test]
fn a_killed_process_group_leaves_no_swtpm() {
    const TEST: &str = "a_killed_process_group_leaves_no_swtpm";
    if let Some(mode) = std::env::var_os(CHILD) {
        return fixture_child_body(&mode);
    }
    let path = std::env::var_os("PATH").expect("PATH");
    let (mut child, _out, pid, dir) = fixture_child(TEST, "hold", &path);
    assert_alive(pid, &dir);
    signal(&format!("-{}", child.id()));
    child.wait().expect("reap the child");
    wait_gone(pid, &dir);
}

/// A swtpm that survives the drop must stay stoppable: its control socket is in the state directory.
#[test]
fn a_swtpm_that_does_not_stop_keeps_its_control_socket() {
    const TEST: &str = "a_swtpm_that_does_not_stop_keeps_its_control_socket";
    if let Some(mode) = std::env::var_os(CHILD) {
        return fixture_child_body(&mode);
    }
    // The child (and its guardian) find a `swtpm_ioctl` that always fails.
    let shim = std::env::temp_dir().join(format!("custodio-swtpm-shim.{}", std::process::id()));
    fs::create_dir(&shim).expect("shim directory");
    let tool = shim.join("swtpm_ioctl");
    fs::write(&tool, "#!/bin/sh\nexit 1\n").expect("shim");
    fs::set_permissions(&tool, std::os::unix::fs::PermissionsExt::from_mode(0o755)).expect("chmod");
    let mut path = vec![shim.clone()];
    path.extend(std::env::split_paths(
        &std::env::var_os("PATH").expect("PATH"),
    ));
    let path = std::env::join_paths(path).expect("PATH");

    let (mut child, out, pid, dir) = fixture_child(TEST, "drop", &path);
    assert!(
        out.lines().map_while(Result::ok).any(|l| l == "dropped"),
        "the child dropped its fixture"
    );
    child.wait().expect("reap the child");
    let ctrl = dir.join("swtpm.sock.ctrl");
    let stoppable = !process_exists(pid) || ctrl.exists();
    if ctrl.exists() {
        let stopped = Command::new("swtpm_ioctl")
            .arg("--unix")
            .arg(&ctrl)
            .arg("-s")
            .status()
            .expect("run swtpm_ioctl");
        assert!(stopped.success(), "stop over the kept control socket");
    }
    fs::remove_dir_all(&shim).expect("remove the shim");
    assert!(
        stoppable,
        "swtpm {pid} is running without its control socket"
    );
    // The guardian, still there, removes the state once swtpm is gone.
    wait_gone(pid, &dir);
}
