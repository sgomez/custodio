//! Acceptance 10 as one scenario, through the real binary on one fixture home (F183).

mod fixture;

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use custodio_cli::register_snap::COPY_REL;
use fixture::{Fixture, add_by_hand, entries, modutil_list, write_entry};

fn path() -> PathBuf {
    std::env::var_os("PATH").unwrap().into()
}

/// The Custodio modules `modutil -list` shows in each profile, as `(profile, count)`; the first that does not have
/// exactly one is named in the error.
fn exactly_one_in_each(profiles: &[&Path]) -> Result<(), String> {
    for p in profiles {
        let custodio = modutil_list(p)
            .lines()
            .filter(|l| l.contains("library name:") && l.contains("libcustodio_pkcs11.so"))
            .count();
        if custodio != 1 {
            return Err(format!("{}: {custodio} Custodio modules", p.display()));
        }
    }
    Ok(())
}

fn others(profile: &Path) -> Vec<String> {
    entries(profile)
        .into_iter()
        .filter(|e| !e.library.ends_with("libcustodio_pkcs11.so"))
        .map(|e| format!("{}={}", e.name, e.library))
        .collect()
}

#[test]
fn the_check_catches_a_profile_without_its_entry() {
    let f = Fixture::new();
    let m = f.module("a");
    let root = f.root(".mozilla/firefox", &["a.default", "b.default"]);
    let (a, b) = (root.join("a.default"), root.join("b.default"));
    f.run(&m, false);
    assert_eq!(exactly_one_in_each(&[&a, &b]), Ok(()));
    let out = std::process::Command::new("modutil")
        .arg("-dbdir")
        .arg(format!("sql:{}", b.display()))
        .args(["-delete", "Custodio", "-force"])
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert!(out.status.success());
    let err = exactly_one_in_each(&[&a, &b]).unwrap_err();
    assert!(
        err.contains("b.default") && err.contains("0 Custodio"),
        "{err}"
    );
}

/// A child process holding the profile's `.parentlock` (as a running browser does) until it is dropped.
struct Browser(Child);

impl Browser {
    fn open(profile: &Path) -> Self {
        let mut child = Command::new("python3")
            .arg("-I")
            .arg("-c")
            .arg("import fcntl,sys\nf=open(sys.argv[1],'w')\nfcntl.lockf(f,fcntl.LOCK_EX)\nprint('held',flush=True)\nsys.stdin.read()")
            .arg(profile.join(".parentlock"))
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
        Self(child)
    }

    fn close(mut self) {
        drop(self.0.stdin.take());
        self.0.wait().unwrap();
    }
}

#[test]
fn acceptance_10_on_one_home() {
    let f = Fixture::new();
    let m = f.module("a");
    let ms = m.to_str().unwrap();
    let legacy = f.root(".mozilla/firefox", &["l.default"]).join("l.default");
    let xdg = f
        .root(".config/mozilla/firefox", &["x.default"])
        .join("x.default");
    let snap = f
        .root("snap/firefox/common/.mozilla/firefox", &["s.default"])
        .join("s.default");
    let copy = f.home().join(COPY_REL);
    let all: [&Path; 3] = [&legacy, &xdg, &snap];
    // a hand-registered entry under another name, and a foreign module in each
    add_by_hand(&legacy, "my token", &m);
    for p in all {
        write_entry(p, "foreign", "/old/libother.so");
    }
    let foreign_before: Vec<_> = all.iter().map(|p| others(p)).collect();
    let run = |extra: &[&str]| {
        let mut a = vec!["register", "--module", ms];
        a.extend_from_slice(extra);
        f.binary(&a, &path(), &[])
    };
    let shown = |o: &std::process::Output| {
        format!(
            "{}{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        )
    };

    // a locked native profile is skipped and named, the others are done, the exit is non-zero
    let browser = Browser::open(&xdg);
    let locked = run(&[]);
    assert_eq!(locked.status.code(), Some(1), "{}", shown(&locked));
    let text = shown(&locked);
    assert!(
        text.contains("x.default") && text.contains("close the browser"),
        "{text}"
    );
    assert_eq!(
        exactly_one_in_each(&[legacy.as_path(), snap.as_path()]),
        Ok(())
    );
    assert!(
        exactly_one_in_each(&[xdg.as_path()]).is_err(),
        "the locked profile was not touched"
    );
    browser.close();

    let first = run(&[]);
    assert_eq!(first.status.code(), Some(0), "{}", shown(&first));
    assert_eq!(exactly_one_in_each(&all), Ok(()));
    let hand: Vec<_> = entries(&legacy)
        .into_iter()
        .filter(|e| e.library == ms)
        .collect();
    assert_eq!(
        (hand.len(), hand[0].name.as_str()),
        (1, "my token"),
        "the hand entry keeps its name"
    );
    let snap_entry: Vec<_> = entries(&snap)
        .into_iter()
        .filter(|e| e.library.ends_with("libcustodio_pkcs11.so"))
        .collect();
    assert_eq!(
        snap_entry[0].library,
        copy.to_str().unwrap(),
        "the snap profile points to the copy"
    );
    assert_eq!(fs::read(&copy).unwrap(), fs::read(&m).unwrap());

    // a second run leaves the whole home equal
    let one = f.snapshot();
    assert_eq!(run(&[]).status.code(), Some(0));
    assert_eq!(f.snapshot(), one);

    // root and sudo are refused, the home is equal
    let root = f
        .command(&["register", "--module", ms], &path(), &[], true)
        .output()
        .unwrap();
    let sudo = f.binary(
        &["register", "--module", ms],
        &path(),
        &[("SUDO_UID", "1000")],
    );
    assert_eq!(root.status.code(), Some(2), "{root:?}");
    assert_eq!(sudo.status.code(), Some(2), "{sudo:?}");
    assert_eq!(f.snapshot(), one);

    // removal with a locked profile: the others are cleaned, the locked one keeps its entry
    let browser = Browser::open(&xdg);
    let removal = run(&["--remove"]);
    assert_eq!(removal.status.code(), Some(1), "{}", shown(&removal));
    assert!(shown(&removal).contains("x.default"));
    assert_eq!(exactly_one_in_each(&[xdg.as_path()]), Ok(()));
    assert!(
        exactly_one_in_each(&[legacy.as_path()]).is_err()
            && exactly_one_in_each(&[snap.as_path()]).is_err()
    );
    browser.close();

    let removal = run(&["--remove"]);
    assert_eq!(removal.status.code(), Some(0), "{}", shown(&removal));
    for p in all {
        assert!(
            entries(p)
                .iter()
                .all(|e| !e.library.ends_with("libcustodio_pkcs11.so")),
            "{}",
            p.display()
        );
    }
    assert!(fs::symlink_metadata(&copy).is_err(), "no copy");
    let foreign_after: Vec<_> = all.iter().map(|p| others(p)).collect();
    assert_eq!(
        foreign_after, foreign_before,
        "every other entry as before the first run"
    );
}
