//! Refresh-only mode: its journal entries and what it leaves alone (F183).

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::fixture::listed;
use crate::{Snap, args, command, module_bytes, plant, snap};
use custodio_cli::register_native::RegisterArgs;
use custodio_cli::register_snap::JOURNAL_IDENTIFIER;

/// A datagram socket standing for journald.
pub struct Journal {
    pub path: PathBuf,
    socket: UnixDatagram,
}

impl Journal {
    pub fn new(s: &Snap) -> Self {
        let path = s.f.dir.path().join(format!(
            "journal-{}.sock",
            s.f.dir.path().file_name().unwrap().to_string_lossy()
        ));
        let socket = UnixDatagram::bind(&path).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        Self { path, socket }
    }

    pub fn recv(&self) -> String {
        let mut buf = vec![0u8; 8192];
        let n = self.socket.recv(&mut buf).expect("a journal entry");
        String::from_utf8(buf[..n].to_vec()).unwrap()
    }
}

#[test]
fn refresh_only_logs_its_outcome_to_the_journal() {
    let s = snap();
    let sock = Journal::new(&s);
    let copy = s.copy.to_str().unwrap();
    let run = |s: &Snap| command(s, &args(&s.module, false, true), &sock.path);
    let check = |entry: &str, priority: u8, word: &str| {
        assert!(
            entry.contains(&format!("SYSLOG_IDENTIFIER={JOURNAL_IDENTIFIER}\n")),
            "{entry}"
        );
        assert!(entry.contains(&format!("PRIORITY={priority}\n")), "{entry}");
        assert!(
            entry.contains(copy) && entry.contains(word),
            "{word}: {entry}"
        );
    };
    let (_, out, _) = run(&s);
    check(&sock.recv(), 6, "no copy");
    assert!(out.contains("no copy"));
    plant(&s.copy, b"stale");
    let (result, out, _) = run(&s);
    assert!(result.is_ok());
    check(&sock.recv(), 6, "refreshed");
    assert!(out.contains("refreshed"));
    let _ = run(&s);
    check(&sock.recv(), 6, "up to date");
    // a failure: the directory is read-only
    plant(&s.copy, b"stale");
    let dir = s.copy.parent().unwrap();
    fs::set_permissions(dir, fs::Permissions::from_mode(0o555)).unwrap();
    let (result, ..) = run(&s);
    fs::set_permissions(dir, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(result.is_err());
    let entry = sock.recv();
    check(&entry, 3, "failed");
    assert!(entry.contains("cannot create"), "{entry}");
    // no installed module: nothing changes, exit zero, a journal line saying so
    let before = s.f.snapshot();
    let gone = s.f.dir.path().join("gone").join("libcustodio_pkcs11.so");
    let (result, ..) = command(&s, &args(&gone, false, true), &sock.path);
    assert!(result.is_ok());
    check(&sock.recv(), 6, "no installed module");
    assert_eq!(s.f.snapshot(), before);
    // control: an unreachable journal keeps the status and says why on stderr
    let (result, _, err) = command(
        &s,
        &args(&s.module, false, true),
        Path::new("/nonexistent/journal"),
    );
    assert!(result.is_ok());
    assert!(
        err.contains("journal") && err.contains("/nonexistent/journal"),
        "{err}"
    );
    plant(&s.copy, b"stale");
    fs::set_permissions(dir, fs::Permissions::from_mode(0o555)).unwrap();
    let (result, _, err) = command(
        &s,
        &args(&s.module, false, true),
        Path::new("/nonexistent/journal"),
    );
    fs::set_permissions(dir, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(result.is_err());
    assert!(err.contains("journal"));
}

#[test]
fn refresh_only_touches_nothing_but_the_copy() {
    let s = snap();
    let native = s.f.root(".mozilla/firefox", &["a.default"]);
    s.f.run(&s.module, false);
    plant(&s.copy, b"stale");
    let stub = s.f.stub("record", r#"echo "$@" >> "$MARKER""#);
    let marker = s.f.marker();
    let mk = marker.to_str().unwrap();
    let ms = s.module.to_str().unwrap();
    let args = ["register", "--refresh-only", "--module", ms];
    let tracked = |s: &Snap| -> BTreeMap<PathBuf, Vec<u8>> {
        s.f.snapshot()
            .into_iter()
            .filter(|(k, _)| k != &s.copy)
            .collect()
    };
    let before = tracked(&s);
    // root and sudo are refused, the home is as it was
    let root =
        s.f.command(&args, &stub, &[("MARKER", mk)], true)
            .output()
            .unwrap();
    let sudo =
        s.f.binary(&args, &stub, &[("MARKER", mk), ("SUDO_USER", "x")]);
    assert_eq!(root.status.code(), Some(2), "{root:?}");
    assert_eq!(sudo.status.code(), Some(2), "{sudo:?}");
    assert_eq!(fs::read(&s.copy).unwrap(), b"stale");
    // the real run: the stub modutil is not called; an empty PATH works too
    let empty = s.f.dir.path().join("empty-path");
    fs::create_dir(&empty).unwrap();
    for path in [&stub, &empty] {
        plant(&s.copy, b"stale");
        let out = s.f.binary(&args, path, &[("MARKER", mk)]);
        assert_eq!(out.status.code(), Some(0), "{out:?}");
        assert_eq!(fs::read(&s.copy).unwrap(), module_bytes(&s));
        assert!(String::from_utf8_lossy(&out.stdout).contains("refreshed"));
        assert!(!marker.exists(), "modutil was not run");
        assert_eq!(tracked(&s), before, "only the copy changed");
    }
    assert_eq!(listed(&native.join("a.default"), &s.module), 1);
    // a usage error is exit 2
    let bad =
        s.f.binary(&["register", "--refresh-only", "--remove"], &stub, &[]);
    assert_eq!(bad.status.code(), Some(2));
}

#[test]
fn the_refresh_only_command_line() {
    use custodio_cli::register_native::parse_register_args;
    let a = |v: &[&str]| parse_register_args(v.iter().map(|s| (*s).to_owned()));
    assert_eq!(
        a(&["--refresh-only"]),
        Some(RegisterArgs {
            refresh_only: true,
            ..RegisterArgs::default()
        })
    );
    assert_eq!(
        a(&["--module", "/x/lib.so", "--refresh-only"]),
        Some(RegisterArgs {
            module: Some("/x/lib.so".into()),
            remove: false,
            refresh_only: true
        })
    );
    for bad in [
        &["--refresh-only", "--remove"][..],
        &["--remove", "--refresh-only"],
        &["--refresh-only", "--refresh-only"],
        &["--refresh-only", "x"],
    ] {
        assert_eq!(a(bad), None, "{bad:?}");
    }
}
