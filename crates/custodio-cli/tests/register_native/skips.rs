//! Skips, refusals, the module path, interruption and the command line (F182).

use std::fs;
use std::io::Read;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::fixture::{self, Fixture, entries, listed};
use custodio_cli::register_native::Outcome;

fn fixture_file() -> &'static str {
    custodio_cli::register_native::MODULE_FILE
}

fn fixture_local() -> std::net::Ipv4Addr {
    fixture::LOCAL
}

const RECORD: &str = r#"echo "$@" >> "$MARKER""#;

fn real_path() -> std::path::PathBuf {
    std::env::var_os("PATH").unwrap().into()
}

#[test]
fn refuses_root_and_sudo() {
    let f = Fixture::new();
    let m = f.module("a");
    f.root(".mozilla/firefox", &["a.default", "b.default"]);
    let stub = f.stub("record", RECORD);
    let marker = f.marker();
    let (mk, ms) = (marker.to_str().unwrap(), m.to_str().unwrap());
    let before = f.snapshot();
    let args = ["register", "--module", ms];
    let root = f
        .command(&args, &stub, &[("MARKER", mk)], true)
        .output()
        .unwrap();
    let sudo = f.binary(&args, &stub, &[("MARKER", mk), ("SUDO_UID", "1000")]);
    for (out, why) in [(&root, "root"), (&sudo, "sudo")] {
        assert_eq!(out.status.code(), Some(2), "{why}: {out:?}");
        assert!(String::from_utf8_lossy(&out.stderr).contains(why), "{why}");
    }
    assert_eq!(f.snapshot(), before);
    assert!(!marker.exists(), "modutil never ran");
    // control: the same invocation as the user proceeds, and the option reaches modutil as -libfile once per profile
    let ok = f.binary(&args, &stub, &[("MARKER", mk)]);
    assert_eq!(ok.status.code(), Some(0), "{ok:?}");
    let recorded = fs::read_to_string(&marker).unwrap();
    assert_eq!(recorded.lines().count(), 2);
    assert!(
        recorded
            .lines()
            .all(|l| l.contains(&format!("-libfile {ms} "))),
        "{recorded}"
    );
}

#[test]
fn the_default_module_path_is_the_installed_one() {
    let installed = "/usr/lib/custodio/libcustodio_pkcs11.so";
    assert!(
        !Path::new(installed).exists(),
        "{installed} exists: Custodio is installed on this machine, where this test cannot tell the default from a \
         build-tree path. It is meant to fail here; do not turn it into a skip"
    );
    let f = Fixture::new();
    f.root(".mozilla/firefox", &["a.default"]);
    let stub = f.stub("record", RECORD);
    let marker = f.marker();
    let before = f.snapshot();
    let out = f.binary(
        &["register"],
        &stub,
        &[("MARKER", marker.to_str().unwrap())],
    );
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(err.lines().count(), 1, "{err}");
    assert!(err.contains(installed), "{err}");
    assert!(!marker.exists());
    assert_eq!(f.snapshot(), before);
}

#[test]
fn a_missing_module_file_is_one_error() {
    let f = Fixture::new();
    let m = f.module("a");
    f.root(".mozilla/firefox", &["a.default", "b.default"]);
    let stub = f.stub("record", RECORD);
    let marker = f.marker();
    let before = f.snapshot();
    let absent = "/nonexistent/libcustodio_pkcs11.so";
    let out = f.binary(
        &["register", "--module", absent],
        &stub,
        &[("MARKER", marker.to_str().unwrap())],
    );
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(err.lines().count(), 1, "{err}");
    assert!(err.contains(absent));
    assert!(!marker.exists());
    assert_eq!(f.snapshot(), before);
    // removal does not need the file
    let ok = f.binary(
        &["register", "--module", m.to_str().unwrap()],
        &real_path(),
        &[],
    );
    assert_eq!(ok.status.code(), Some(0), "{ok:?}");
    let gone = f.binary(
        &["register", "--remove", "--module", absent],
        &real_path(),
        &[],
    );
    assert_eq!(gone.status.code(), Some(0), "{gone:?}");
    assert!(
        entries(&f.home().join(".mozilla/firefox/a.default"))
            .iter()
            .all(|e| !e.library.ends_with(fixture_file()))
    );
}

#[test]
fn a_missing_modutil_is_an_error_naming_it() {
    let f = Fixture::new();
    let m = f.module("a");
    f.root(".mozilla/firefox", &["a.default"]);
    let empty = f.dir.path().join("empty");
    fs::create_dir(&empty).unwrap();
    let before = f.snapshot();
    let out = f.binary(&["register", "--module", m.to_str().unwrap()], &empty, &[]);
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        err.lines().count(),
        1,
        "one error, not one per profile: {err}"
    );
    assert!(err.contains("modutil was not found"), "{err}");
    assert_eq!(f.snapshot(), before);
}

fn command_result(f: &Fixture, m: &Path) -> (Result<(), String>, String) {
    let args = custodio_cli::register_native::RegisterArgs {
        module: Some(m.to_owned()),
        remove: false,
        refresh_only: false,
    };
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let r = custodio_cli::register_native::register_command(
        &args,
        &f.env(),
        1000,
        |_| None,
        &mut out,
        &mut err,
    )
    .map_err(|e| e.to_string());
    assert!(err.is_empty() || r.is_err());
    (r, String::from_utf8(out).unwrap())
}

#[test]
fn a_held_profile_is_skipped_named_and_fails_the_exit() {
    let f = Fixture::new();
    let m = f.module("a");
    let root = f.root(
        ".mozilla/firefox",
        &["a.default", "held.default", "locked.default"],
    );
    let live = root.join("held.default");
    symlink(
        format!("{}:+{}", fixture_local(), std::process::id()),
        live.join("lock"),
    )
    .unwrap();
    // a `.parentlock` held by a child process, released through a pipe
    let locked = root.join("locked.default");
    let mut child = Command::new("python3")
        .arg("-I")
        .arg("-c")
        .arg("import fcntl,sys\nf=open(sys.argv[1],'w')\nfcntl.lockf(f,fcntl.LOCK_EX)\nprint('held',flush=True)\nsys.stdin.read()")
        .arg(locked.join(".parentlock"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut seen = [0u8; 5];
    child
        .stdout
        .as_mut()
        .unwrap()
        .read_exact(&mut seen)
        .unwrap();
    let held_before = (
        fs::read(live.join("pkcs11.txt")).unwrap(),
        fs::read(locked.join("pkcs11.txt")).unwrap(),
    );
    let (result, out) = command_result(&f, &m);
    let err = result.unwrap_err();
    assert!(err.contains("2 profile"), "{err}");
    assert_eq!(
        out.lines()
            .filter(|l| l.contains("close the browser"))
            .count(),
        2,
        "{out}"
    );
    assert!(
        out.contains("held.default") && out.contains("locked.default") && out.contains("Firefox")
    );
    assert!(out.contains("a.default: registered"));
    assert_eq!(
        (
            fs::read(live.join("pkcs11.txt")).unwrap(),
            fs::read(locked.join("pkcs11.txt")).unwrap()
        ),
        held_before
    );
    // released: a re-run registers it
    drop(child.stdin.take());
    child.wait().unwrap();
    fs::remove_file(live.join("lock")).unwrap();
    let (result, out) = command_result(&f, &m);
    assert!(result.is_ok(), "{out}");
    assert_eq!(listed(&live, &m), 1);
    assert_eq!(listed(&locked, &m), 1);
}

#[test]
fn skip_reasons_decide_the_exit_code() {
    // p11-kit: every native profile skipped with the reason, exit zero, nothing changed
    let f = Fixture::new();
    let m = f.module("a");
    f.root(".mozilla/firefox", &["a.default"]);
    fs::write(
        f.dir.path().join("nss.config"),
        "name=x\nlibrary=p11-kit-proxy.so\n",
    )
    .unwrap();
    let before = f.snapshot();
    let (result, out) = command_result(&f, &m);
    assert!(result.is_ok());
    assert!(out.contains("p11-kit"), "{out}");
    assert_eq!(f.snapshot(), before);
    // an unwritable profile directory
    let f = Fixture::new();
    let m = f.module("a");
    let root = f.root(".mozilla/firefox", &["a.default"]);
    let p = root.join("a.default");
    fs::set_permissions(&p, fs::Permissions::from_mode(0o500)).unwrap();
    let (result, out) = command_result(&f, &m);
    fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(result.is_err());
    assert!(out.contains("not writable"), "{out}");
    // nothing at all
    let f = Fixture::new();
    let (result, out) = command_result(&f, &f.module("a"));
    assert!(result.is_ok());
    assert!(out.contains("No native browser profiles"), "{out}");
}

#[test]
fn a_failing_modutil_leaves_the_profile_untouched() {
    let f = Fixture::new();
    let m = f.module("a");
    let root = f.root(".mozilla/firefox", &["a.default"]);
    let stub = f.stub(
        "fail",
        r#"d=${2#sql:}; echo junk >> "$d/pkcs11.txt"; echo "boom: no" >&2; exit 3"#,
    );
    let before = f.snapshot();
    let report = custodio_cli::register_native::run(
        &f.env(),
        &custodio_cli::register_native::Options {
            module: m,
            modutil: stub.join("modutil").into(),
            remove: false,
        },
    )
    .unwrap();
    let Outcome::Failed(why) = &report.lines[0].outcome else {
        panic!("{report:?}")
    };
    assert!(why.contains("boom"), "{why}");
    assert!(report.has_fixable_skip());
    assert_eq!(
        f.snapshot(),
        before,
        "the three files are as they were and the scratch directory is gone"
    );
    assert!(root.join("a.default").exists());
}

#[test]
fn a_killed_run_leaves_the_old_state_and_the_next_run_cleans_up() {
    let f = Fixture::new();
    let m = f.module("a");
    let root = f.root(".mozilla/firefox", &["a.default"]);
    let p = root.join("a.default");
    let fifos = f.dir.path().join("fifos");
    fs::create_dir(&fifos).unwrap();
    let (up, go, pid_file) = (fifos.join("up"), fifos.join("go"), fifos.join("pid"));
    for fifo in [&up, &go] {
        assert!(Command::new("mkfifo").arg(fifo).status().unwrap().success());
    }
    let stub = f.stub(
        "block",
        r#"d=${2#sql:}; echo junk >> "$d/pkcs11.txt"; echo $$ > "$PIDF"; echo up > "$UP"; read x < "$GO"; exit 1"#,
    );
    let before = (
        fs::read(p.join("pkcs11.txt")).unwrap(),
        fs::read(p.join("cert9.db")).unwrap(),
        fs::read(p.join("key4.db")).unwrap(),
    );
    let env = [
        ("UP", up.to_str().unwrap()),
        ("GO", go.to_str().unwrap()),
        ("PIDF", pid_file.to_str().unwrap()),
    ];
    let mut child = f
        .command(
            &["register", "--module", m.to_str().unwrap()],
            &stub,
            &env,
            false,
        )
        .spawn()
        .unwrap();
    let mut line = String::new();
    fs::File::open(&up)
        .unwrap()
        .read_to_string(&mut line)
        .unwrap();
    let scratch = root.join(".a.default.custodio-scratch");
    assert!(scratch.exists(), "the stub runs on the scratch copy");
    child.kill().unwrap();
    assert_eq!(child.wait().unwrap().signal(), Some(9));
    // let the stub finish (it writes nothing more) and wait until it is gone
    drop(fs::OpenOptions::new().write(true).open(&go).unwrap());
    let pid = fs::read_to_string(&pid_file).unwrap();
    let stat = format!("/proc/{}/stat", pid.trim());
    while fs::read_to_string(&stat).is_ok_and(|s| !s.contains(") Z")) {
        std::thread::yield_now();
    }
    assert_eq!(
        (
            fs::read(p.join("pkcs11.txt")).unwrap(),
            fs::read(p.join("cert9.db")).unwrap(),
            fs::read(p.join("key4.db")).unwrap()
        ),
        before
    );
    assert!(
        scratch.exists(),
        "a killed run leaves its scratch directory"
    );
    let out = f.binary(
        &["register", "--module", m.to_str().unwrap()],
        &real_path(),
        &[],
    );
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert!(!scratch.exists());
    assert_eq!(listed(&p, &m), 1);
}

#[test]
fn only_handled_profiles_change() {
    let f = Fixture::new();
    let m = f.module("a");
    let root = f.root(".mozilla/firefox", &["a.default"]);
    f.root(".zen", &["z.default"]);
    f.root("snap/firefox/common/.mozilla/firefox", &["s.default"]);
    fs::write(f.home().join("notes.txt"), "x").unwrap();
    let handled = root.join("a.default");
    // the Firefox snap is handled since F183: its profile and its copy are the other two lines
    let snap = f.home().join("snap/firefox");
    let outside = |s: std::collections::BTreeMap<std::path::PathBuf, Vec<u8>>| {
        s.into_iter()
            .filter(|(k, _)| !k.starts_with(&handled) && !k.starts_with(&snap))
            .collect::<Vec<_>>()
    };
    let before = outside(f.snapshot());
    let report = f.run(&m, false);
    assert_eq!(report.lines.len(), 3, "{report:?}");
    assert_eq!(outside(f.snapshot()), before);
    assert_ne!(listed(&handled, &m), 0);
}

#[test]
fn the_register_command_line() {
    use custodio_cli::register_native::{RegisterArgs, parse_register_args};
    let a = |v: &[&str]| parse_register_args(v.iter().map(|s| (*s).to_owned()));
    assert_eq!(a(&[]), Some(RegisterArgs::default()));
    assert_eq!(
        a(&["--remove"]),
        Some(RegisterArgs {
            module: None,
            remove: true,
            refresh_only: false
        })
    );
    assert_eq!(
        a(&["--module", "/x/lib.so", "--remove"]),
        Some(RegisterArgs {
            module: Some("/x/lib.so".into()),
            remove: true,
            refresh_only: false
        })
    );
    for bad in [
        &["--module"][..],
        &["--module", ""],
        &["--remove", "--remove"],
        &["--module", "a", "--module", "b"],
        &["--force"],
        &["x"],
    ] {
        assert_eq!(a(bad), None, "{bad:?}");
    }
    let bin = env!("CARGO_BIN_EXE_custodio-cli");
    let out = Command::new(bin)
        .args(["register", "--bogus"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("custodio register"));
}
