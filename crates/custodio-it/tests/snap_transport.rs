//! The module's transport choice (F178): inside a snap it talks to the snap's socket and never the bus.
//!
//! Arrangement (the one the contract allows as a fallback): the service runs in this process, in the test user's own
//! namespace, on a socket in a tempdir (`snap_rig`: the real `custodiod::snap_socket::handle` behind a counting
//! listener, the `test-seam` source giving the Firefox label, uid `UID` and this process as the peer, a real key, a
//! scripted polkit on a private `dbus-daemon`). The module runs as a child (this binary re-executed, because the
//! environment cannot be set in a threaded process) through `unshare -Ur`, in which the test user is root, so a
//! directory the test made is root-owned for the module's check. Only the child is namespaced; the service's own
//! directory check is not involved (the rig serves the listener itself). The "system bus" is a listener that counts
//! connections and hangs up. The module is exercised through `DbusBackend`, the one place that talks to the service,
//! and, for the fork case, through the module's own C entry points (its state lock is held across `fork` there; the
//! backend has no lock of its own). The PKCS#11 layer shows `Unavailable` as no slots (unit tests of
//! `custodio-pkcs11`). Waits are on the child's exit and on the service's counters.

use std::error::Error;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::process::{Child, Command, Output, Stdio};
use std::thread;

use custodio_pkcs11::backend::{Backend, BackendError, DbusBackend, SignParams};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use x509_cert::Certificate;
use x509_cert::der::Decode;

#[allow(
    dead_code,
    reason = "the rig is shared with module_compat.rs, which uses other parts"
)]
mod snap_rig;
use snap_rig::{Answer, CERT, Rig, TestResult, UID, dir_mode};

const MODE_VAR: &str = "SNAP_TRANSPORT_CHILD";
const BASE_VAR: &str = "CUSTODIO_TEST_SOCKET_BASE_DIR";
const DIGEST: [u8; 32] = [7; 32];

/// The module as a child. `instance`: the value of `SNAP_INSTANCE_NAME`, unset for `None`. `namespaced`: root-mapped.
fn command(rig: &Rig, mode: &str, instance: Option<&str>, namespaced: bool) -> Command {
    let exe = std::env::current_exe().unwrap_or_default();
    let mut cmd = if namespaced {
        let mut c = Command::new("unshare");
        c.arg("-Ur").arg(&exe);
        c
    } else {
        Command::new(&exe)
    };
    cmd.args(["--exact", "module_child", "--nocapture", "--test-threads=1"])
        .env(MODE_VAR, mode)
        .env(BASE_VAR, rig.base.path())
        .env(
            "DBUS_SYSTEM_BUS_ADDRESS",
            format!("unix:path={}", rig.bus.display()),
        )
        .env_remove("SNAP_INSTANCE_NAME");
    if let Some(name) = instance {
        cmd.env("SNAP_INSTANCE_NAME", name);
    }
    cmd
}

fn results(stdout: &[u8]) -> String {
    String::from_utf8_lossy(stdout)
        .lines()
        .filter_map(|l| l.find("RESULT ").map(|at| &l[at..]))
        .collect::<Vec<_>>()
        .join("\n")
}

fn lines(
    rig: &Rig,
    mode: &str,
    instance: Option<&str>,
    namespaced: bool,
) -> Result<String, Box<dyn Error>> {
    let out: Output = command(rig, mode, instance, namespaced).output()?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(results(&out.stdout))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .filter_map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).ok())
        .collect()
}

unsafe extern "C" {
    /// The module's own export, linked from the `custodio-pkcs11` rlib.
    fn C_GetFunctionList(list: *mut *mut cryptoki_sys::CK_FUNCTION_LIST) -> cryptoki_sys::CK_RV;
}

/// Slots with a token, through the module's C entry points (its state lock and fork handlers are in play).
fn slots_through_the_module() -> String {
    let mut list = std::ptr::null_mut();
    // SAFETY: `list` is valid for one pointer.
    let rv = unsafe { C_GetFunctionList(&raw mut list) };
    if rv != 0 || list.is_null() {
        return format!("no function list {rv}");
    }
    // SAFETY: the module returns a pointer to its static function list.
    let list = unsafe { &*list };
    let (Some(init), Some(slots)) = (list.C_Initialize, list.C_GetSlotList) else {
        return "entry points missing".to_owned();
    };
    // SAFETY: NULL arguments are allowed for `C_Initialize`.
    let rv = unsafe { init(std::ptr::null_mut()) };
    if rv != 0 {
        return format!("C_Initialize {rv}");
    }
    let mut count = 0;
    // SAFETY: a NULL list asks for the count; `count` is valid for one write.
    let rv = unsafe { slots(1, std::ptr::null_mut(), &raw mut count) };
    format!("rv {rv} slots {count}")
}

/// The child: calls the backend as the module does and prints one `RESULT` line per call.
#[test]
fn module_child() {
    let Ok(mode) = std::env::var(MODE_VAR) else {
        return;
    };
    let params = SignParams {
        mechanism: 0x1041,
        hash: 0,
        salt_len: 0,
    };
    let show = |what: &str, r: Result<String, BackendError>| match r {
        Ok(v) => println!("RESULT {what} ok {v}"),
        Err(e) => println!("RESULT {what} {e:?}"),
    };
    let list = || {
        DbusBackend.list_certificates().map(|k| {
            format!(
                "{:?}",
                k.iter().map(|(id, _)| id.clone()).collect::<Vec<_>>()
            )
        })
    };
    match mode.as_str() {
        "list" => show("list", list()),
        "sign" => show(
            "sign",
            DbusBackend.sign("ec", params, &DIGEST).map(|s| hex(&s)),
        ),
        "both" => {
            show("list", list());
            show(
                "sign",
                DbusBackend.sign("ec", params, &DIGEST).map(|s| hex(&s)),
            );
        }
        "threads" => {
            let before = thread_count();
            let handles: Vec<_> = (0..8).map(|_| thread::spawn(list)).collect();
            for h in handles {
                show("list", h.join().unwrap_or(Err(BackendError::Unavailable)));
            }
            // A joined thread leaves `/proc` a moment later; wait for the count, not for a time.
            let mut left = 0;
            for _ in 0..100_000 {
                left = thread_count().saturating_sub(before);
                if left == 0 {
                    break;
                }
                thread::yield_now();
            }
            println!("RESULT leaked threads {left}");
        }
        "sequential" => {
            // The parent answers each `RESULT` with a line once the service saw the connection end.
            let (fds, threads) = (open_fds(), thread_count());
            let mut ack = String::new();
            for _ in 0..5 {
                show("list", list());
                ack.clear();
                let _ = std::io::stdin().read_line(&mut ack);
            }
            println!("RESULT leaked fds {}", open_fds().saturating_sub(fds));
            println!(
                "RESULT leaked threads {}",
                thread_count().saturating_sub(threads)
            );
        }
        "fork" => {
            // The module is initialized (its fork handlers hold its state lock across `fork`), then forks; the child
            // lists through the module and signs through the backend.
            println!("RESULT parent {}", slots_through_the_module());
            // SAFETY: the process has one thread here (`--test-threads=1`, nothing spawned); the child only calls the
            // module, prints and leaves with `_exit`.
            let pid = unsafe { libc::fork() };
            if pid == 0 {
                // SAFETY: a deadlock in the child ends as a failure, not a hang.
                unsafe { libc::alarm(60) };
                println!("RESULT child {}", slots_through_the_module());
                show(
                    "forked sign",
                    DbusBackend.sign("ec", params, &DIGEST).map(|s| hex(&s)),
                );
                // SAFETY: leaves the child without running the parent's destructors.
                unsafe { libc::_exit(0) };
            }
            let mut status = 0;
            // SAFETY: `pid` is our child.
            unsafe { libc::waitpid(pid, &raw mut status, 0) };
            println!("RESULT child status {status}");
        }
        "dirs" => {
            // The module's directory rule and the service's, on the same directories (`directory_rule_matches_the_service`).
            let root = std::path::PathBuf::from(std::env::var(BASE_VAR).unwrap_or_default());
            for name in [
                "d700", "d755", "d770", "d707", "d777", "link", "afile", "missing",
            ] {
                let dir = root.join(name);
                let ours = custodio_pkcs11::backend::check_dir(&dir);
                let theirs = custodiod::snap_socket::check_dir(&dir).is_ok();
                println!("RESULT dir {name} {ours} {theirs}");
            }
        }
        _ => println!("RESULT unknown mode"),
    }
}

fn open_fds() -> usize {
    std::fs::read_dir("/proc/self/fd").map_or(0, Iterator::count)
}

fn thread_count() -> usize {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("Threads:"))
                .and_then(|n| n.trim().parse().ok())
        })
        .unwrap_or(0)
}

fn verify(signature_hex: &str) -> TestResult {
    let point = Certificate::from_der(CERT)?
        .tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .raw_bytes()
        .to_vec();
    p256::ecdsa::VerifyingKey::from_sec1_bytes(&point)?.verify_prehash(
        &DIGEST,
        &p256::ecdsa::Signature::from_slice(&unhex(signature_hex))?,
    )?;
    Ok(())
}

fn signature_of(lines: &str, what: &str) -> Result<String, Box<dyn Error>> {
    lines
        .lines()
        .find_map(|l| l.strip_prefix(&format!("RESULT {what} ok ")))
        .map(str::to_owned)
        .ok_or_else(|| format!("no signature in {lines}").into())
}

#[test]
fn each_call_opens_and_closes_its_own_connection() -> TestResult {
    let rig = Rig::start("firefox", 0o700)?;
    let mut child: Child = command(&rig, "sequential", Some("firefox"), true)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut input = child.stdin.take().ok_or("no stdin")?;
    let mut output = BufReader::new(child.stdout.take().ok_or("no stdout")?);
    let mut seen = Vec::new();
    let mut calls = 0;
    let mut text = String::new();
    while output.read_line(&mut text)? > 0 {
        if let Some(at) = text.find("RESULT ") {
            seen.push(text[at..].trim_end().to_owned());
            if text.contains("RESULT list") {
                calls += 1;
                // The call has returned: the service must see that connection end before the next call starts.
                let state = rig.counts.wait_closed(calls);
                assert_eq!(state.accepted, calls, "one connection per call: {state:?}");
                assert_eq!(state.open, 0, "{state:?}");
                input.write_all(b"\n")?;
            }
        }
        text.clear();
    }
    assert!(child.wait()?.success());
    assert_eq!(
        seen.iter()
            .filter(|l| *l == "RESULT list ok [\"ec\"]")
            .count(),
        5,
        "{seen:?}"
    );
    let state = rig.counts.snapshot();
    assert_eq!((state.accepted, state.closed, state.max_open), (5, 5, 1));
    assert!(seen.contains(&"RESULT leaked fds 0".to_owned()), "{seen:?}");
    assert!(
        seen.contains(&"RESULT leaked threads 0".to_owned()),
        "{seen:?}"
    );
    Ok(())
}

#[test]
fn a_forked_child_can_call_through_the_socket() -> TestResult {
    let rig = Rig::start("firefox", 0o700)?;
    rig.answers(&[Answer::Yes]);
    let lines = lines(&rig, "fork", Some("firefox"), true)?;
    assert!(lines.contains("RESULT parent rv 0 slots 1"), "{lines}");
    // The child re-initializes (it is a fork of an initialized process) and lists through the module.
    assert!(lines.contains("RESULT child rv 0 slots 1"), "{lines}");
    verify(&signature_of(&lines, "forked sign")?)?;
    assert!(lines.contains("RESULT child status 0"), "{lines}");
    assert_eq!(rig.bus_connections(), 0);
    Ok(())
}

#[test]
fn directory_rule_matches_the_service() -> TestResult {
    let rig = Rig::start("firefox", 0o700)?;
    let base = rig.base.path();
    for (name, mode) in [
        ("d700", 0o700),
        ("d755", 0o755),
        ("d770", 0o770),
        ("d707", 0o707),
        ("d777", 0o777),
    ] {
        let d = base.join(name);
        std::fs::create_dir(&d)?;
        dir_mode(&d, mode)?;
    }
    std::os::unix::fs::symlink(base.join("d700"), base.join("link"))?;
    File::create(base.join("afile"))?;
    let lines = lines(&rig, "dirs", Some("firefox"), true)?;
    // (name, both accept) in the namespace where the test user is root.
    let want = [
        ("d700", true),
        ("d755", true),
        ("d770", false),
        ("d707", false),
        ("d777", false),
        ("link", false),
        ("afile", false),
        ("missing", false),
    ];
    for (name, ok) in want {
        assert!(
            lines.contains(&format!("RESULT dir {name} {ok} {ok}")),
            "{name}: {lines}"
        );
    }
    Ok(())
}

#[test]
fn socket_is_used_and_the_bus_is_never_touched() -> TestResult {
    let rig = Rig::start("firefox", 0o700)?;
    rig.answers(&[Answer::Yes]);
    let lines = lines(&rig, "both", Some("firefox"), true)?;
    assert!(lines.contains("RESULT list ok [\"ec\"]"), "{lines}");
    verify(&signature_of(&lines, "sign")?)?;
    // One polkit question for the one signature, about the peer (this process, by its uid and its pidfd).
    let asked = rig.polkit_calls();
    assert_eq!(asked.len(), 1, "{asked:?}");
    assert_eq!(asked[0].uid, Some(UID), "{asked:?}");
    assert_eq!(asked[0].fd_pid, Some(std::process::id()), "{asked:?}");
    let state = rig.counts.wait_closed(2);
    assert_eq!(state.accepted, 2, "{state:?}");
    assert_eq!(rig.bus_connections(), 0);
    Ok(())
}

/// The control of the case above: without the variable the same child uses the bus and never the socket.
#[test]
fn unset_uses_the_bus() -> TestResult {
    let rig = Rig::start("firefox", 0o700)?;
    assert_eq!(
        lines(&rig, "both", None, true)?,
        "RESULT list Unavailable\nRESULT sign Unavailable"
    );
    assert_eq!(rig.bus_connections(), 2);
    assert_eq!(rig.counts.snapshot().accepted, 0);
    Ok(())
}

#[test]
fn an_invalid_instance_name_gives_no_slots() -> TestResult {
    let rig = Rig::start("firefox", 0o700)?;
    // A service on a socket at the path each name would reach if it were not rejected.
    let names = [
        "",
        "../firefox",
        "Firefox",
        "fire/fox",
        "firefox_",
        "-firefox",
        "firefox_Work",
        "f",
    ];
    let listeners: Vec<_> = names
        .iter()
        .map(|name| rig.listen(&format!("snap.{name}"), 0o700))
        .collect::<Result<_, _>>()?;
    for name in names {
        assert_eq!(
            lines(&rig, "list", Some(name), true)?,
            "RESULT list Unavailable",
            "{name:?}"
        );
    }
    for (name, counts) in names.iter().zip(&listeners) {
        assert_eq!(counts.snapshot().accepted, 0, "{name:?}");
    }
    assert_eq!(rig.bus_connections(), 0);
    Ok(())
}

#[test]
fn a_missing_socket_gives_no_slots() -> TestResult {
    let rig = Rig::start("firefox", 0o700)?;
    assert_eq!(
        lines(&rig, "list", Some("chromium"), true)?,
        "RESULT list Unavailable"
    );
    let dir = rig.base.path().join("snap.chromium");
    std::fs::create_dir(&dir)?;
    dir_mode(&dir, 0o700)?;
    assert_eq!(
        lines(&rig, "list", Some("chromium"), true)?,
        "RESULT list Unavailable"
    );
    assert_eq!(rig.bus_connections(), 0);
    assert_eq!(rig.counts.snapshot().accepted, 0);
    Ok(())
}

#[test]
fn a_stale_socket_file_gives_no_slots() -> TestResult {
    let rig = Rig::start("firefox", 0o700)?;
    let dir = rig.base.path().join("snap.chromium");
    std::fs::create_dir(&dir)?;
    dir_mode(&dir, 0o700)?;
    drop(UnixListener::bind(dir.join("custodio.sock"))?);
    assert_eq!(
        lines(&rig, "list", Some("chromium"), true)?,
        "RESULT list Unavailable"
    );
    assert_eq!(rig.bus_connections(), 0);
    assert_eq!(rig.counts.snapshot().accepted, 0);
    Ok(())
}

#[test]
fn a_directory_that_is_not_root_owned_and_root_only_writable_gives_no_slots() -> TestResult {
    // Group- and other-writable, even though root-owned in the namespace.
    for mode in [0o770, 0o707, 0o777] {
        let rig = Rig::start("firefox", mode)?;
        assert_eq!(
            lines(&rig, "list", Some("firefox"), true)?,
            "RESULT list Unavailable",
            "{mode:o}"
        );
        assert_eq!(rig.bus_connections(), 0);
        assert_eq!(rig.counts.snapshot().accepted, 0, "{mode:o}");
    }
    // Owned by the test user, outside the namespace.
    let rig = Rig::start("firefox", 0o700)?;
    assert_eq!(
        lines(&rig, "list", Some("firefox"), false)?,
        "RESULT list Unavailable"
    );
    // A symbolic link to a good directory.
    let link = rig.base.path().join("snap.linked");
    std::os::unix::fs::symlink(rig.base.path().join("snap.firefox"), &link)?;
    assert_eq!(
        lines(&rig, "list", Some("linked"), true)?,
        "RESULT list Unavailable"
    );
    // A file in place of the directory.
    File::create(rig.base.path().join("snap.afile"))?;
    assert_eq!(
        lines(&rig, "list", Some("afile"), true)?,
        "RESULT list Unavailable"
    );
    assert_eq!(rig.bus_connections(), 0);
    assert_eq!(rig.counts.snapshot().accepted, 0);
    Ok(())
}

#[test]
fn a_root_owned_root_only_directory_serves() -> TestResult {
    let rig = Rig::start("firefox_work1", 0o755)?;
    assert_eq!(
        lines(&rig, "list", Some("firefox_work1"), true)?,
        "RESULT list ok [\"ec\"]"
    );
    Ok(())
}

#[test]
fn concurrent_calls_use_separate_connections() -> TestResult {
    let rig = Rig::start("firefox", 0o700)?;
    let lines = lines(&rig, "threads", Some("firefox"), true)?;
    assert_eq!(
        lines
            .lines()
            .filter(|l| *l == "RESULT list ok [\"ec\"]")
            .count(),
        8,
        "{lines}"
    );
    // Eight calls, eight connections, each ended; the module's threads are as many after as before.
    let state = rig.counts.wait_closed(8);
    assert_eq!((state.accepted, state.closed, state.open), (8, 8, 0));
    assert!(lines.contains("RESULT leaked threads 0"), "{lines}");
    assert_eq!(rig.bus_connections(), 0);
    Ok(())
}
