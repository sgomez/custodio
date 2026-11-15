//! Discovery of browser profiles over fixture homes (F181, F172's data table and Decisions).

use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::net::Ipv4Addr;
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::process::Command;

use custodio_cli::browser_files::{HeldReason, LockState};
use custodio_cli::register_discover::{BROWSERS, Environment, Profile, discover};
use tempfile::TempDir;

const LOCAL: Ipv4Addr = Ipv4Addr::new(10, 1, 2, 3);

struct Home {
    dir: TempDir,
    xdg: Option<OsString>,
}

impl Home {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
            xdg: None,
        }
    }

    fn path(&self) -> PathBuf {
        fs::canonicalize(self.dir.path()).unwrap()
    }

    /// A root with a `profiles.ini` naming each of `profiles` (relative) and the directories.
    fn root(&self, rel: &str, profiles: &[&str]) -> PathBuf {
        let root = self.path().join(rel);
        fs::create_dir_all(&root).unwrap();
        let mut ini = String::from("[General]\nVersion=2\n");
        for (i, p) in profiles.iter().enumerate() {
            fs::create_dir_all(root.join(p)).unwrap();
            writeln!(ini, "[Profile{i}]\nName=n{i}\nIsRelative=1\nPath={p}\n").unwrap();
        }
        fs::write(root.join("profiles.ini"), ini).unwrap();
        root
    }

    fn env(&self) -> Environment {
        Environment {
            home: self.path(),
            xdg_config_home: self.xdg.clone(),
            local_address: LOCAL,
        }
    }

    fn found(&self) -> Vec<Profile> {
        discover(&self.env()).unwrap()
    }

    /// (browser, path relative to home) of everything found.
    fn set(&self) -> Vec<(String, String)> {
        let home = self.path();
        let mut v: Vec<_> = self
            .found()
            .iter()
            .map(|p| {
                (
                    p.browser.to_owned(),
                    p.path.strip_prefix(&home).unwrap().display().to_string(),
                )
            })
            .collect();
        v.sort();
        v
    }
}

fn pair(b: &str, p: &str) -> (String, String) {
    (b.to_owned(), p.to_owned())
}

#[test]
fn lists_every_browser_root_and_channel() {
    // Firefox: legacy only, XDG only, both
    let h = Home::new();
    h.root(".mozilla/firefox", &["a.default-release"]);
    assert_eq!(
        h.set(),
        [pair("Firefox", ".mozilla/firefox/a.default-release")]
    );
    let h = Home::new();
    h.root(".config/mozilla/firefox", &["b.default"]);
    assert_eq!(
        h.set(),
        [pair("Firefox", ".config/mozilla/firefox/b.default")]
    );
    let h = Home::new();
    h.root(".mozilla/firefox", &["a.default-release"]);
    h.root(".config/mozilla/firefox", &["b.default"]);
    assert_eq!(
        h.set().len(),
        2,
        "both roots are scanned, legacy does not hide the XDG one"
    );

    // channels: several [InstallHASH] sections in one root, plus a profile only an install names
    let h = Home::new();
    let root = h.root(
        ".mozilla/firefox",
        &["rel.default-release", "esr.default-esr"],
    );
    fs::create_dir_all(root.join("dev.dev-edition-default")).unwrap();
    let mut ini = fs::read_to_string(root.join("profiles.ini")).unwrap();
    ini += "[InstallAAAA]\nDefault=rel.default-release\n[InstallBBBB]\nDefault=esr.default-esr\n\
            [InstallCCCC]\nDefault=dev.dev-edition-default\n";
    fs::write(root.join("profiles.ini"), ini).unwrap();
    assert_eq!(h.found().len(), 3);

    // Thunderbird, both roots
    let h = Home::new();
    h.root(".thunderbird", &["t1.default"]);
    h.root(".config/thunderbird", &["t2.default"]);
    assert_eq!(
        h.set(),
        [
            pair("Thunderbird", ".config/thunderbird/t2.default"),
            pair("Thunderbird", ".thunderbird/t1.default")
        ]
    );

    // derivatives
    let h = Home::new();
    h.root(".floorp", &["f.default"]);
    h.root(".waterfox", &["w.default"]);
    h.root(".librewolf", &["l1.default"]);
    h.root(".config/librewolf/librewolf", &["l2.default"]);
    assert_eq!(
        h.set(),
        [
            pair("Floorp", ".floorp/f.default"),
            pair("LibreWolf", ".config/librewolf/librewolf/l2.default"),
            pair("LibreWolf", ".librewolf/l1.default"),
            pair("Waterfox", ".waterfox/w.default"),
        ]
    );
    // LibreWolf's `~/.librewolf` without `profiles.ini` is not a root
    let h = Home::new();
    fs::create_dir_all(h.path().join(".librewolf/x.default")).unwrap();
    h.root(".config/librewolf/librewolf", &["l2.default"]);
    assert_eq!(
        h.set(),
        [pair("LibreWolf", ".config/librewolf/librewolf/l2.default")]
    );

    // excluded browsers are not listed even with a profile
    let h = Home::new();
    h.root(".zen", &["z.default"]);
    h.root(".mullvad", &["m.default"]);
    h.root(".tor-browser", &["t.default"]);
    h.root(
        ".var/app/org.mozilla.firefox/.mozilla/firefox",
        &["fp.default"],
    );
    assert_eq!(h.found().len(), 0);
    for b in BROWSERS {
        assert!(!["Zen", "Mullvad", "Tor"].iter().any(|x| b.name.contains(x)));
    }

    // a profile without cert9.db is listed (a profile never opened has none)
    let h = Home::new();
    let root = h.root(".mozilla/firefox", &["new.default"]);
    assert!(!root.join("new.default/cert9.db").exists());
    assert_eq!(h.found().len(), 1);
    // a profile the index names but that is not there is not
    fs::remove_dir(root.join("new.default")).unwrap();
    assert_eq!(h.found().len(), 0);
}

#[test]
fn xdg_config_home_moves_the_xdg_roots_only() {
    for (xdg, expect_custom) in [
        (Some("CUSTOM"), true),
        (Some(""), false),
        (None, false),
        (Some("relative/dir"), false),
    ] {
        let mut h = Home::new();
        let custom = h.path().join("custom-config");
        h.xdg = xdg.map(|x| {
            if x == "CUSTOM" {
                custom.clone().into_os_string()
            } else {
                x.into()
            }
        });
        h.root("custom-config/mozilla/firefox", &["c.default"]);
        h.root("custom-config/thunderbird", &["ct.default"]);
        h.root(".config/mozilla/firefox", &["d.default"]);
        h.root(".config/thunderbird", &["dt.default"]);
        // LibreWolf's second root is the literal `~/.config/librewolf/librewolf` in F172's table
        h.root(".config/librewolf/librewolf", &["l.default"]);
        h.root("custom-config/librewolf/librewolf", &["lc.default"]);
        let set = h.set();
        let has = |p: &str| set.iter().any(|(_, x)| x == p);
        assert_eq!(
            has("custom-config/mozilla/firefox/c.default"),
            expect_custom,
            "{xdg:?}"
        );
        assert_eq!(
            has("custom-config/thunderbird/ct.default"),
            expect_custom,
            "{xdg:?}"
        );
        assert_eq!(
            has(".config/mozilla/firefox/d.default"),
            !expect_custom,
            "{xdg:?}"
        );
        assert_eq!(
            has(".config/thunderbird/dt.default"),
            !expect_custom,
            "{xdg:?}"
        );
        assert!(has(".config/librewolf/librewolf/l.default"), "{xdg:?}");
        assert!(
            !has("custom-config/librewolf/librewolf/lc.default"),
            "{xdg:?}"
        );
    }
}

#[test]
fn each_profile_carries_its_lock_state() {
    let h = Home::new();
    let root = h.root(
        ".mozilla/firefox",
        &["free.default", "stale.default", "held.default"],
    );
    let mut dead = Command::new("true").spawn().unwrap();
    let dead_pid = dead.id();
    dead.wait().unwrap();
    symlink(
        format!("{LOCAL}:+{dead_pid}"),
        root.join("stale.default/lock"),
    )
    .unwrap();
    symlink("10.99.99.99:+1", root.join("held.default/lock")).unwrap();
    let found = h.found();
    let state = |n: &str| {
        found
            .iter()
            .find(|p| p.path.ends_with(n))
            .unwrap()
            .lock
            .clone()
    };
    assert_eq!(state("free.default"), LockState::Free);
    assert_eq!(state("stale.default"), LockState::Free);
    assert_eq!(
        state("held.default"),
        LockState::Held(HeldReason::ForeignHost("10.99.99.99".into()))
    );
}

#[test]
fn one_directory_reached_two_ways_is_listed_once() {
    // legacy root a symlink to the XDG root
    let h = Home::new();
    let xdg = h.root(".config/mozilla/firefox", &["a.default"]);
    fs::create_dir_all(h.path().join(".mozilla")).unwrap();
    symlink(&xdg, h.path().join(".mozilla/firefox")).unwrap();
    assert_eq!(h.found().len(), 1);

    // an absolute and a relative `Path` to the same directory, and a Default= that repeats it
    let h = Home::new();
    let root = h.root(".mozilla/firefox", &["a.default"]);
    let abs = root.join("a.default");
    fs::write(
        root.join("profiles.ini"),
        format!(
            "[Profile0]\nPath=a.default\nIsRelative=1\n[Profile1]\nPath={}\nIsRelative=0\n[Profile2]\nPath=./a.default/../a.default\n\
             IsRelative=1\n[InstallX]\nDefault=a.default\n",
            abs.display()
        ),
    )
    .unwrap();
    let found = h.found();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].path, abs);

    // control: two distinct directories stay two
    let h = Home::new();
    h.root(".mozilla/firefox", &["a.default", "b.default"]);
    assert_eq!(h.found().len(), 2);
    // a symlinked profile directory and its target are one
    let h = Home::new();
    let root = h.root(".mozilla/firefox", &["a.default"]);
    symlink(root.join("a.default"), root.join("link.default")).unwrap();
    fs::write(
        root.join("profiles.ini"),
        "[Profile0]\nPath=a.default\nIsRelative=1\n[Profile1]\nPath=link.default\nIsRelative=1\n",
    )
    .unwrap();
    assert_eq!(h.found().len(), 1);
}

#[test]
fn the_snap_profile_is_listed_only_with_a_profile() {
    let rel = "snap/firefox/common/.mozilla/firefox";
    // absent
    let h = Home::new();
    assert_eq!(h.found().len(), 0);
    // present, no profile
    let h = Home::new();
    fs::create_dir_all(h.path().join("snap/firefox")).unwrap();
    assert_eq!(h.found().len(), 0);
    fs::create_dir_all(h.path().join(rel)).unwrap();
    assert_eq!(h.found().len(), 0);
    fs::write(
        h.path().join(rel).join("profiles.ini"),
        "[General]\nVersion=2\n",
    )
    .unwrap();
    assert_eq!(h.found().len(), 0);
    // with a profile
    let h = Home::new();
    h.root(rel, &["s.default"]);
    let found = h.found();
    assert_eq!(found.len(), 1);
    assert!(found[0].snap);
    assert_eq!(found[0].browser, "Firefox (snap)");
    assert_eq!(found[0].lock, LockState::Free);
    // the snap's lock state is real: a foreign link holds it
    symlink("10.99.99.99:+1", h.path().join(rel).join("s.default/lock")).unwrap();
    assert!(matches!(
        h.found()[0].lock,
        LockState::Held(HeldReason::ForeignHost(_))
    ));
    // a native Firefox next to it stays separate
    h.root(".mozilla/firefox", &["n.default"]);
    assert_eq!(h.found().len(), 2);
}

#[test]
fn a_malformed_index_fails_discovery_naming_the_file() {
    let h = Home::new();
    let root = h.root(".mozilla/firefox", &["a.default"]);
    fs::write(root.join("profiles.ini"), "[Profile0\n").unwrap();
    let err = discover(&h.env()).unwrap_err();
    assert!(
        err.to_string()
            .contains(&root.join("profiles.ini").display().to_string()),
        "{err}"
    );
}
