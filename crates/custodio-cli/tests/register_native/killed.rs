//! A failing or killed `custodio setup browsers enable` leaves the old state (F182).

use std::fs;
use std::io::Read;
use std::os::unix::process::ExitStatusExt;
use std::process::Command;

use custodio_cli::register_native::Outcome;

use crate::fixture::{Fixture, listed};
use crate::skips::{probe_dir, real_path};

#[test]
fn a_failing_modutil_leaves_the_profile_untouched() {
    let f = Fixture::new();
    let m = f.module("a");
    let root = f.root(".mozilla/firefox", &["a.default"]);
    let marker = f.marker();
    let fail = r#"d=${2#sql:}; echo junk >> "$d/pkcs11.txt"; echo "boom: no" >&2; exit 3"#;
    let record = format!(r#"echo "$@" >> '{}'"#, marker.display());
    // the probe fails, then only the registration call fails
    let probe_fails = f.stub("fail", &format!("{record}\n{fail}"));
    let add_fails = f.stub(
        "fail-add",
        &format!("{record}\ncase \"$3\" in -create|-list) exit 0;; esac\n{fail}"),
    );
    for (stub, calls) in [(probe_fails, 1), (add_fails, 3)] {
        let before = f.snapshot();
        let report = custodio_cli::register_native::run(
            &f.env(),
            &custodio_cli::register_native::Options {
                module: m.clone(),
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
        let recorded = fs::read_to_string(&marker).unwrap();
        assert_eq!(recorded.lines().count(), calls, "{recorded}");
        probe_dir(&f, recorded.lines().next().unwrap());
        fs::remove_file(&marker).unwrap();
    }
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
        r#"case "$3" in -create|-list) exit 0;; esac; d=${2#sql:}; echo junk >> "$d/pkcs11.txt"; echo $$ > "$PIDF"; echo up > "$UP"; read x < "$GO"; exit 1"#,
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
            &[
                "setup",
                "browsers",
                "enable",
                "--module",
                m.to_str().unwrap(),
            ],
            &stub,
            &env,
            false,
        )
        .spawn()
        .unwrap();
    // The stub writes its pid before it opens the FIFO: a run that ends without it would block the open below for ever.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while fs::read_to_string(&pid_file).map_or(true, |pid| pid.is_empty()) {
        let ended = child.try_wait().unwrap();
        assert!(
            ended.is_none(),
            "register ended before modutil ran: {ended:?}"
        );
        assert!(
            std::time::Instant::now() < deadline,
            "modutil did not start"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
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
        &[
            "setup",
            "browsers",
            "enable",
            "--module",
            m.to_str().unwrap(),
        ],
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
