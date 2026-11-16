//! `custodio doctor`, check 4 (the module in Firefox): fixture homes, no bus, a `modutil` stub that records its
//! arguments. Every run leaves the fixture tree (root and home) byte-identical and runs `modutil` on no profile.

mod fprint_fixture;

use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use fprint_fixture::{Bus, Fake, Fingers, Fx, err, out, serve_all, state};

const CHECK: &str = "module in Firefox";
const MODULE_REL: &str = "usr/lib/custodio/libcustodio_pkcs11.so";

/// The fixture system, with the installed module, and a directory outside it for the `modutil` stub and its record.
struct Case {
    fx: Fx,
    outside: tempfile::TempDir,
}

impl Case {
    fn new(p11_kit: bool) -> Self {
        let fx = Fx::new();
        fx.put(MODULE_REL, "the module, version 1");
        let outside = tempfile::tempdir().unwrap();
        let stub = outside.path().join("bin");
        fs::create_dir(&stub).unwrap();
        fs::create_dir(outside.path().join("tmp")).unwrap();
        let listing = if p11_kit { "  2. p11-kit-proxy\\n" } else { "" };
        let script = format!(
            "#!/bin/sh\necho \"$*\" >> {}\ncase \"$*\" in *-list*) printf '{listing}';; esac\n",
            outside.path().join("record").display()
        );
        let file = stub.join("modutil");
        fs::write(&file, script).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o755)).unwrap();
        Self { fx, outside }
    }

    fn module(&self) -> PathBuf {
        self.fx.path(MODULE_REL)
    }

    /// A `profiles.ini` under the home naming `names`, each a directory with a `pkcs11.txt` of `entries` lines.
    fn root(&self, rel: &str, names: &[&str], entries: &str) -> PathBuf {
        let root = self.fx.home().join(rel);
        let mut ini = String::from("[General]\nVersion=2\n");
        for (i, n) in names.iter().enumerate() {
            fs::create_dir_all(root.join(n)).unwrap();
            fs::write(root.join(n).join("pkcs11.txt"), entries).unwrap();
            writeln!(ini, "[Profile{i}]\nName=n{i}\nIsRelative=1\nPath={n}\n").unwrap();
        }
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("profiles.ini"), ini).unwrap();
        root
    }

    fn entry(name: &str, library: &Path) -> String {
        format!("library={}\nname={name}\n\n", library.display())
    }

    /// Runs doctor as the person, on `bus`; checks the tree is the same afterwards and that `modutil` was run only
    /// in a scratch directory. Returns the output and what `modutil` was asked.
    fn run(&self, bus: &str) -> (Output, String, Vec<String>) {
        let before = self.fx.tree();
        let o = Command::new(env!("CARGO_BIN_EXE_custodio-cli"))
            .arg("doctor")
            .env_clear()
            .env("PATH", self.outside.path().join("bin"))
            .env("TMPDIR", self.outside.path().join("tmp"))
            .env("CUSTODIO_FIXTURE_ROOT", self.fx.root())
            .env("CUSTODIO_FIXTURE_EUID", "1000")
            .env("DBUS_SYSTEM_BUS_ADDRESS", bus)
            .env("HOME", self.fx.home())
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(self.fx.tree(), before, "doctor changed the tree");
        let record = fs::read_to_string(self.outside.path().join("record")).unwrap_or_default();
        let runs: Vec<String> = record.lines().map(str::to_owned).collect();
        for r in &runs {
            assert!(
                r.contains("custodio-nss-probe") && !r.contains(self.fx.root().to_str().unwrap()),
                "modutil ran on something but a scratch database: {r}"
            );
        }
        (o.clone(), out(&o), runs)
    }

    fn doctor(&self) -> (Output, String, Vec<String>) {
        self.run(&self.fx.no_bus())
    }
}

fn check4(text: &str) -> String {
    let mut found = Vec::new();
    let mut in_check = false;
    for l in text.lines() {
        if l.contains(&format!(" {CHECK}: ")) {
            in_check = true;
        } else if !l.starts_with(' ') {
            in_check = false;
        }
        if in_check {
            found.push(l);
        }
    }
    found.join("\n")
}

#[test]
fn a_profile_with_the_module_in_pkcs11_txt_is_ok_and_named() {
    let c = Case::new(false);
    let e = Case::entry("Custodio", &c.module());
    let root = c.root(".mozilla/firefox", &["a.default"], &e);
    let (_, text, runs) = c.doctor();
    let s = check4(&text);
    assert!(s.starts_with("ok"), "{text}");
    assert!(s.contains(root.join("a.default").to_str().unwrap()), "{s}");
    assert!(!s.contains("fix:"), "{s}");
    assert_eq!(runs.len(), 0, "nothing needs the p11-kit probe: {runs:?}");
}

#[test]
fn a_profile_without_the_module_is_not_ok_and_the_fix_names_register() {
    let c = Case::new(false);
    c.root(".mozilla/firefox", &["a.default"], "");
    let (_, text, runs) = c.doctor();
    let s = check4(&text);
    assert!(
        s.starts_with("not ok") && s.contains("not registered"),
        "{s}"
    );
    assert!(s.contains("fix: Run: custodio register"), "{s}");
    // the probe of register's p11-kit decision runs in a scratch database only
    assert_eq!(runs.len(), 2, "{runs:?}");
}

#[test]
fn an_entry_whose_file_is_gone_is_stale_with_the_same_fix() {
    let c = Case::new(false);
    let gone = c.fx.path("usr/lib/old/libcustodio_pkcs11.so");
    c.root(
        ".mozilla/firefox",
        &["a.default"],
        &Case::entry("Custodio", &gone),
    );
    let (_, text, _) = c.doctor();
    let s = check4(&text);
    assert!(s.starts_with("not ok") && s.contains("stale"), "{s}");
    assert!(s.contains("custodio register"), "{s}");
}

#[test]
fn another_module_with_the_name_is_not_taken_for_ours() {
    let c = Case::new(false);
    let other = c.fx.path("usr/lib/other/libother.so");
    c.root(
        ".mozilla/firefox",
        &["a.default"],
        &Case::entry("Custodio", &other),
    );
    let (_, text, _) = c.doctor();
    assert!(check4(&text).starts_with("not ok"), "{text}");
}

#[test]
fn a_custodio_module_at_another_path_that_exists_is_ok() {
    let c = Case::new(false);
    c.fx.put("opt/c/libcustodio_pkcs11.so", "x");
    let at = c.fx.path("opt/c/libcustodio_pkcs11.so");
    c.root(
        ".mozilla/firefox",
        &["a.default"],
        &Case::entry("Custodio", &at),
    );
    let (_, text, _) = c.doctor();
    assert!(check4(&text).starts_with("ok"), "{text}");
}

#[test]
fn every_profile_has_its_own_line_and_the_other_browsers_are_listed_by_the_same_discovery_as_register()
 {
    let c = Case::new(false);
    let e = Case::entry("Custodio", &c.module());
    c.root(".mozilla/firefox", &["a.default", "b.default"], &e);
    c.root(".thunderbird", &["t.default"], "");
    c.root(".config/librewolf/librewolf", &["l.default"], &e);
    let (_, text, _) = c.doctor();
    let doctor_lines: Vec<String> = text
        .lines()
        .filter(|l| l.contains(&format!(" {CHECK}: ")))
        .map(str::to_owned)
        .collect();
    assert_eq!(doctor_lines.len(), 4, "{text}");
    assert_eq!(
        doctor_lines.iter().filter(|l| l.starts_with("ok")).count(),
        3
    );
    assert_eq!(
        doctor_lines
            .iter()
            .filter(|l| l.starts_with("not ok"))
            .count(),
        1
    );
    // `register` runs after doctor's comparison, on the same fixture: it names the same profiles.
    let reg = Command::new(env!("CARGO_BIN_EXE_custodio-cli"))
        .args(["register", "--module"])
        .arg(c.module())
        .env_clear()
        .env("HOME", c.fx.home())
        .env("PATH", c.outside.path().join("bin"))
        .env("TMPDIR", c.outside.path().join("tmp"))
        .output()
        .unwrap();
    let registered = out(&reg);
    let named = |s: &str| {
        let mut v: Vec<String> = s
            .lines()
            .filter_map(|l| l.split_once(" profile "))
            .map(|(_, rest)| rest.split(':').next().unwrap().to_owned())
            .collect();
        v.sort();
        v
    };
    let from_register = |s: &str| {
        let mut v: Vec<String> = s
            .lines()
            .filter_map(|l| l.split_whitespace().find(|w| w.starts_with('/')))
            .map(|w| w.trim_end_matches(':').to_owned())
            .collect();
        v.sort();
        v
    };
    assert_eq!(
        named(&doctor_lines.join("\n")).len(),
        from_register(&registered).len(),
        "{text}\n{registered}\n{}",
        err(&reg)
    );
    assert_eq!(
        named(&doctor_lines.join("\n")),
        from_register(&registered),
        "{registered}"
    );
}

fn snap(c: &Case, copy: Option<&str>) -> PathBuf {
    let copy_path =
        c.fx.home()
            .join("snap/firefox/common/libcustodio_pkcs11.so");
    if let Some(bytes) = copy {
        fs::create_dir_all(copy_path.parent().unwrap()).unwrap();
        fs::write(&copy_path, bytes).unwrap();
    }
    c.root(
        "snap/firefox/common/.mozilla/firefox",
        &["s.default"],
        &Case::entry("Custodio", &copy_path),
    );
    copy_path
}

#[test]
fn a_snap_profile_with_the_copy_missing_is_not_ok() {
    let c = Case::new(false);
    snap(&c, None);
    let (_, text, _) = c.doctor();
    let s = check4(&text);
    assert!(s.starts_with("not ok") && s.contains("copy"), "{s}");
    assert!(
        s.contains("custodio register") && s.contains("restart Firefox"),
        "{s}"
    );
}

#[test]
fn a_snap_profile_with_the_copy_up_to_date_is_ok() {
    let c = Case::new(false);
    snap(&c, Some("the module, version 1"));
    let (_, text, _) = c.doctor();
    assert!(check4(&text).starts_with("ok"), "{text}");
}

#[test]
fn a_stale_snap_copy_is_not_ok_and_called_stale() {
    let c = Case::new(false);
    snap(&c, Some("the module, version 0"));
    let (_, text, _) = c.doctor();
    let s = check4(&text);
    assert!(s.starts_with("not ok") && s.contains("stale"), "{s}");
    assert!(s.contains("restart Firefox"), "{s}");
}

#[test]
fn a_p11_kit_system_is_ok_with_the_reason_and_no_register_fix() {
    let c = Case::new(true);
    c.root(".mozilla/firefox", &["a.default"], "");
    let (_, text, runs) = c.doctor();
    let s = check4(&text);
    assert!(s.starts_with("ok") && s.contains("p11-kit"), "{s}");
    assert!(!s.contains("fix:"), "{s}");
    assert_eq!(runs.len(), 2, "{runs:?}");
}

#[test]
fn no_profile_at_all_is_ok_says_so_and_the_exit_status_is_unaffected() {
    let c = Case::new(false);
    let bus = Bus::new();
    serve_all(
        &bus.address,
        Fake {
            fingers: Fingers::List(&["left-thumb"]),
            ..Fake::new(1)
        },
    );
    let (o, text, runs) = c.run(&bus.address);
    let s = check4(&text);
    assert!(
        s.starts_with("ok") && s.contains("no browser profile"),
        "{s}"
    );
    assert_eq!(state(&text, CHECK), "ok");
    assert_eq!(o.status.code(), Some(0), "{text}{}", err(&o));
    assert_eq!(runs.len(), 0, "{runs:?}");
}

#[test]
fn a_malformed_profiles_ini_is_could_not_check_naming_the_file() {
    let c = Case::new(false);
    let root = c.fx.home().join(".mozilla/firefox");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("profiles.ini"), "[Profile0\nPath\n\u{0}").unwrap();
    let (_, text, runs) = c.doctor();
    let s = check4(&text);
    assert!(s.starts_with("could not check"), "{s}");
    assert!(s.contains("profiles.ini"), "{s}");
    assert_eq!(runs.len(), 0, "{runs:?}");
}

#[test]
fn an_unreadable_pkcs11_txt_is_could_not_check_naming_the_file() {
    let c = Case::new(false);
    let root = c.root(".mozilla/firefox", &["a.default"], "");
    let file = root.join("a.default/pkcs11.txt");
    fs::remove_file(&file).unwrap();
    fs::create_dir(&file).unwrap();
    let (_, text, _) = c.doctor();
    let s = check4(&text);
    assert!(
        s.starts_with("could not check") && s.contains("pkcs11.txt"),
        "{s}"
    );
}

#[test]
fn a_snap_copy_that_is_a_link_is_stale_even_when_it_points_to_the_same_bytes() {
    let c = Case::new(false);
    let copy = snap(&c, None);
    fs::create_dir_all(copy.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(c.module(), &copy).unwrap();
    let (_, text, _) = c.doctor();
    let s = check4(&text);
    assert!(s.starts_with("not ok") && s.contains("stale"), "{s}");
}
