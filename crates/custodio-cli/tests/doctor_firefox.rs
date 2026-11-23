//! `custodio doctor`, check 4 (the module in browsers): fixture homes, no bus, a `modutil` stub that records its
//! arguments. Every run leaves the fixture tree (root and home) byte-identical and runs `modutil` on no profile.

mod fprint_fixture;
mod lines;

use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use custodio_cli::doctor_decide::FIREFOX;
use fprint_fixture::{Bus, Fake, Fingers, Fx, Line, err, out, report, serve_all};

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
        self.run_with(bus, true)
    }

    fn run_with(&self, bus: &str, home: bool) -> (Output, String, Vec<String>) {
        let before = self.fx.tree();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_custodio-cli"));
        cmd.arg("doctor")
            .env_clear()
            // Under cargo llvm-cov the instrumented binary writes its profile where this says.
            .envs(std::env::var_os("LLVM_PROFILE_FILE").map(|v| ("LLVM_PROFILE_FILE", v)))
            .env("PATH", self.outside.path().join("bin"))
            .env("TMPDIR", self.outside.path().join("tmp"))
            .env("CUSTODIO_FIXTURE_ROOT", self.fx.root())
            .env("CUSTODIO_FIXTURE_EUID", "1000")
            .env("DBUS_SYSTEM_BUS_ADDRESS", bus)
            .stdin(Stdio::null());
        if home {
            cmd.env("HOME", self.fx.home());
        }
        let o = cmd.output().unwrap();
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

/// The check lines of the Browsers section, one per profile (or one for none or a failed discovery).
fn browsers(text: &str) -> Vec<Line> {
    report(text)
        .into_iter()
        .filter(|l| l.section == "Browsers")
        .collect()
}

/// The only browser line: one profile in the fixture.
fn only(text: &str) -> Line {
    let lines = browsers(text);
    assert_eq!(lines.len(), 1, "{text}");
    lines.into_iter().next().unwrap()
}

/// The profile directory a browser line names.
fn dir_of(line: &Line) -> String {
    line.text.split(':').next().unwrap().to_owned()
}

fn fixed_by_register(line: &Line) {
    assert_eq!(line.state, "not ok", "{line:?}");
    assert_eq!(line.fixes.len(), 1, "{line:?}");
    assert!(
        line.fixes[0].contains("custodio setup browsers enable"),
        "{line:?}"
    );
}

#[test]
fn a_profile_with_the_module_in_pkcs11_txt_is_ok_and_named() {
    let c = Case::new(false);
    let e = Case::entry("Custodio", &c.module());
    c.root(".mozilla/firefox", &["a.default"], &e);
    let (_, text, runs) = c.doctor();
    let l = only(&text);
    assert_eq!((l.state, l.name.as_str()), ("ok", "Firefox"), "{text}");
    assert_eq!(dir_of(&l), "a.default", "{text}");
    assert!(l.fixes.is_empty(), "{text}");
    assert_eq!(runs.len(), 0, "nothing needs the p11-kit probe: {runs:?}");
}

#[test]
fn a_profile_without_the_module_is_not_ok_and_the_fix_names_register() {
    let c = Case::new(false);
    c.root(".mozilla/firefox", &["a.default"], "");
    let (_, text, runs) = c.doctor();
    let l = only(&text);
    fixed_by_register(&l);
    assert_eq!(dir_of(&l), "a.default", "{text}");
    // the probe of register's p11-kit decision runs in a scratch database only
    assert_eq!(runs.len(), 2, "{runs:?}");
}

#[test]
fn an_entry_whose_file_is_gone_is_told_apart_from_a_missing_one_with_the_same_fix() {
    let c = Case::new(false);
    let gone = c.fx.path("usr/lib/old/libcustodio_pkcs11.so");
    c.root(
        ".mozilla/firefox",
        &["a.default"],
        &Case::entry("Custodio", &gone),
    );
    let (_, text, _) = c.doctor();
    let stale = only(&text);
    fixed_by_register(&stale);
    let m = Case::new(false);
    m.root(".mozilla/firefox", &["a.default"], "");
    let missing = only(&m.doctor().1);
    assert_ne!(stale.text, missing.text, "the two states read the same");
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
    fixed_by_register(&only(&text));
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
    assert_eq!(only(&text).state, "ok", "{text}");
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
    let lines = browsers(&text);
    assert_eq!(lines.len(), 4, "{text}");
    let states: Vec<&str> = lines.iter().map(|l| l.state).collect();
    assert_eq!(states.iter().filter(|s| **s == "ok").count(), 3, "{text}");
    let bad: Vec<&Line> = lines.iter().filter(|l| l.state == "not ok").collect();
    assert_eq!(bad.len(), 1, "{text}");
    assert_eq!(dir_of(bad[0]), "t.default", "{text}");
    assert_eq!(
        lines.iter().map(|l| l.fixes.len()).sum::<usize>(),
        1,
        "one fix for the whole section: {text}"
    );
    fixed_by_register(bad[0]);
    // `register` runs after doctor's comparison, on the same fixture: it names the same profiles.
    let reg = Command::new(env!("CARGO_BIN_EXE_custodio-cli"))
        .args(["setup", "browsers", "enable", "--module"])
        .arg(c.module())
        .env_clear()
        // Under cargo llvm-cov the instrumented binary writes its profile where this says.
        .envs(std::env::var_os("LLVM_PROFILE_FILE").map(|v| ("LLVM_PROFILE_FILE", v)))
        .env("HOME", c.fx.home())
        .env("PATH", c.outside.path().join("bin"))
        .env("TMPDIR", c.outside.path().join("tmp"))
        .output()
        .unwrap();
    let registered = out(&reg);
    let mut from_register: Vec<String> = lines::rows(&registered)
        .iter()
        .filter_map(|r| r.text.split_once(": ").map(|(dir, _)| dir.to_owned()))
        .collect();
    from_register.sort();
    let mut from_doctor: Vec<String> = lines.iter().map(dir_of).collect();
    from_doctor.sort();
    assert_eq!(
        from_doctor,
        from_register,
        "{text}\n{registered}\n{}",
        err(&reg)
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

/// The browser line of a snap profile whose copy of the module holds `copy`.
fn snap_line(copy: Option<&str>) -> Line {
    let c = Case::new(false);
    snap(&c, copy);
    only(&c.doctor().1)
}

#[test]
fn a_snap_profile_with_the_copy_missing_is_not_ok() {
    fixed_by_register(&snap_line(None));
}

#[test]
fn a_snap_profile_with_the_copy_up_to_date_is_ok() {
    let l = snap_line(Some("the module, version 1"));
    assert_eq!(l.state, "ok", "{l:?}");
    assert!(l.fixes.is_empty(), "{l:?}");
}

#[test]
fn a_stale_snap_copy_is_not_ok_and_told_apart_from_a_missing_one() {
    let stale = snap_line(Some("the module, version 0"));
    fixed_by_register(&stale);
    assert_ne!(stale.text, snap_line(None).text);
}

#[test]
fn a_p11_kit_system_is_ok_with_no_register_fix() {
    let c = Case::new(true);
    c.root(".mozilla/firefox", &["a.default"], "");
    let (_, text, runs) = c.doctor();
    let l = only(&text);
    assert_eq!(l.state, "ok", "{text}");
    assert!(l.fixes.is_empty(), "{text}");
    assert_eq!(runs.len(), 2, "{runs:?}");
}

#[test]
fn a_stale_entry_on_a_p11_kit_system_is_ok_because_register_skips_it() {
    let c = Case::new(true);
    let gone = c.fx.path("usr/lib/old/libcustodio_pkcs11.so");
    c.root(
        ".mozilla/firefox",
        &["a.default"],
        &Case::entry("Custodio", &gone),
    );
    let (_, text, runs) = c.doctor();
    let l = only(&text);
    assert_eq!(l.state, "ok", "{text}");
    assert!(l.fixes.is_empty(), "{text}");
    assert_eq!(runs.len(), 2, "{runs:?}");
}

#[test]
fn no_profile_at_all_is_ok_and_the_exit_status_is_unaffected() {
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
    let l = only(&text);
    assert_eq!((l.state, l.name.as_str()), ("ok", FIREFOX), "{text}");
    assert!(l.fixes.is_empty(), "{text}");
    assert_eq!(o.status.code(), Some(0), "{text}{}", err(&o));
    assert_eq!(runs.len(), 0, "{runs:?}");
}

#[test]
fn without_home_the_profiles_are_could_not_check_and_the_fix_is_about_home() {
    let c = Case::new(false);
    let (o, text, _) = c.run_with(&c.fx.no_bus(), false);
    let l = only(&text);
    assert_eq!(
        (l.state, l.name.as_str()),
        ("could not check", FIREFOX),
        "{text}"
    );
    assert_eq!(l.fixes.len(), 1, "{text}");
    assert!(l.fixes[0].contains("HOME"), "{text}");
    assert_eq!(o.status.code(), Some(1), "{text}");
}

#[test]
fn a_malformed_profiles_ini_is_could_not_check_naming_the_file() {
    let c = Case::new(false);
    let root = c.fx.home().join(".mozilla/firefox");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("profiles.ini"), "[Profile0\nPath\n\u{0}").unwrap();
    let (o, text, runs) = c.doctor();
    let l = only(&text);
    assert_eq!(
        (l.state, l.name.as_str()),
        ("could not check", FIREFOX),
        "{text}"
    );
    assert!(l.text.contains("profiles.ini"), "{text}");
    assert_eq!(l.fixes.len(), 1, "{text}");
    assert_eq!(o.status.code(), Some(1), "{text}");
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
    let l = only(&text);
    assert_eq!(l.state, "could not check", "{text}");
    assert!(l.text.contains("pkcs11.txt"), "{text}");
    assert_eq!(l.fixes.len(), 1, "{text}");
}

#[test]
fn a_snap_copy_that_is_a_link_is_stale_even_when_it_points_to_the_same_bytes() {
    let c = Case::new(false);
    let copy = snap(&c, None);
    fs::create_dir_all(copy.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(c.module(), &copy).unwrap();
    let link = only(&c.doctor().1);
    fixed_by_register(&link);
    assert_eq!(link.text, snap_line(Some("the module, version 0")).text);
}
