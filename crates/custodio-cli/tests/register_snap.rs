//! The Firefox snap half of `custodio register` (F183): the copy, its refresh, removal and refresh-only mode.

mod fixture;
#[path = "register_snap/refresh_only.rs"]
mod refresh_only;

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use custodio_cli::register_native::{
    Outcome, RegisterArgs, RegisterError, refresh_only_command, register_command,
};
use custodio_cli::register_snap::{COPY_REL, TEMP_NAME};
use fixture::{Fixture, add_by_hand, entries, listed, modutil_list, write_entry};
use refresh_only::Journal;

const SNAP_PROFILES: &str = "snap/firefox/common/.mozilla/firefox";

pub struct Snap {
    f: Fixture,
    module: PathBuf,
    profile: PathBuf,
    copy: PathBuf,
}

/// A home with a snap profile (no copy yet).
fn snap() -> Snap {
    let f = Fixture::new();
    let module = f.module("a");
    let profile = f.root(SNAP_PROFILES, &["s.default"]).join("s.default");
    let copy = f.home().join(COPY_REL);
    Snap {
        f,
        module,
        profile,
        copy,
    }
}

fn module_bytes(s: &Snap) -> Vec<u8> {
    fs::read(&s.module).unwrap()
}

fn plant(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o644)).unwrap();
}

fn text(r: &custodio_cli::register_native::Report) -> String {
    r.lines
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n")
}

fn modules_of(profile: &Path) -> Vec<String> {
    modutil_list(profile)
        .lines()
        .filter(|l| l.contains("library name:"))
        .map(|l| l.trim().to_owned())
        .collect()
}

fn args(module: &Path, remove: bool, refresh_only: bool) -> RegisterArgs {
    RegisterArgs {
        module: Some(module.to_owned()),
        remove,
        refresh_only,
    }
}

/// Run the command as the library does, with a journal socket; returns the result and what was written to stdout.
fn command(
    s: &Snap,
    a: &RegisterArgs,
    journal: &Path,
) -> (Result<(), RegisterError>, String, String) {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let result = if a.refresh_only {
        refresh_only_command(a, &s.f.env(), 1000, |_| None, journal, &mut out, &mut err)
    } else {
        register_command(a, &s.f.env(), 1000, |_| None, &mut out, &mut err)
    };
    (
        result,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

fn hold(profile: &Path) {
    symlink(
        format!("{}:+{}", fixture::LOCAL, std::process::id()),
        profile.join("lock"),
    )
    .unwrap();
}

#[test]
fn a_snap_profile_gets_the_copy_and_one_entry() {
    let s = snap();
    let report = s.f.run(&s.module, false);
    assert_eq!(fs::read(&s.copy).unwrap(), module_bytes(&s));
    assert_eq!(fs::metadata(&s.copy).unwrap().mode() & 0o7777, 0o755);
    assert_eq!(listed(&s.profile, &s.copy), 1);
    assert_eq!(
        modules_of(&s.profile).len(),
        1,
        "{}",
        modutil_list(&s.profile)
    );
    let t = text(&report);
    assert!(
        t.contains("Firefox (snap)") && t.contains("s.default: registered"),
        "{t}"
    );
    assert!(t.contains("copy placed"), "{t}");
    // a second run leaves the home as it was
    let after = s.f.snapshot();
    s.f.run(&s.module, false);
    assert_eq!(s.f.snapshot(), after);

    // controls: no snap directory, and a snap directory without a profile
    for with_dir in [false, true] {
        let f = Fixture::new();
        let m = f.module("a");
        if with_dir {
            fs::create_dir_all(f.home().join("snap/firefox/common")).unwrap();
        }
        let before = f.snapshot();
        let report = f.run(&m, false);
        assert!(report.lines.is_empty(), "{report:?}");
        assert_eq!(f.snapshot(), before);
        assert!(!f.home().join(COPY_REL).exists());
    }
}

#[test]
fn the_copy_is_written_by_rename() {
    let s = snap();
    plant(&s.copy, b"old bytes");
    let old = fs::File::open(&s.copy).unwrap();
    let old_inode = fs::metadata(&s.copy).unwrap().ino();
    s.f.run(&s.module, false);
    assert_eq!(fs::read(&s.copy).unwrap(), module_bytes(&s));
    assert_ne!(fs::metadata(&s.copy).unwrap().ino(), old_inode);
    let mut still = Vec::new();
    std::io::Read::read_to_end(&mut &old, &mut still).unwrap();
    assert_eq!(still, b"old bytes", "the old inode keeps its bytes");

    // a temporary file left by a killed run (a file, then a link) is removed by the next run
    let tmp = s.copy.with_file_name(TEMP_NAME);
    for leftover in ["file", "link"] {
        plant(&s.copy, b"old bytes");
        if leftover == "file" {
            plant(&tmp, b"half");
        } else {
            let target = s.f.dir.path().join("elsewhere");
            plant(&target, b"keep");
            symlink(&target, &tmp).unwrap();
        }
        s.f.run(&s.module, false);
        assert!(fs::symlink_metadata(&tmp).is_err(), "{leftover}");
        assert_eq!(fs::read(&s.copy).unwrap(), module_bytes(&s));
    }

    // a directory at the temporary name: not deleted, the run fails naming it, the old copy stays
    plant(&s.copy, b"old bytes");
    fs::create_dir(&tmp).unwrap();
    let before = s.f.snapshot();
    let (result, _, err) = command(
        &s,
        &args(&s.module, false, false),
        Path::new("/nonexistent"),
    );
    assert!(result.is_err());
    assert!(err.contains(tmp.to_str().unwrap()), "{err}");
    assert!(err.contains("is a directory"), "{err}");
    assert!(tmp.is_dir());
    assert_eq!(s.f.snapshot(), before);
    fs::remove_dir(&tmp).unwrap();
    let (result, ..) = command(
        &s,
        &args(&s.module, false, false),
        Path::new("/nonexistent"),
    );
    assert!(result.is_ok());
    assert_eq!(fs::read(&s.copy).unwrap(), module_bytes(&s));
}

#[test]
fn a_symlink_at_the_copy_path_is_replaced_not_followed() {
    for mode in ["register", "refresh-only", "remove", "control"] {
        let s = snap();
        let outside = s.f.dir.path().join("outside.so");
        plant(&outside, b"someone else's file");
        let inode = fs::metadata(&outside).unwrap().ino();
        if mode == "control" {
            plant(&s.copy, b"stale");
        } else {
            symlink(&outside, &s.copy).unwrap();
        }
        let a = match mode {
            "refresh-only" => args(&s.module, false, true),
            "remove" => args(&s.module, true, false),
            _ => args(&s.module, false, false),
        };
        let (result, ..) = command(&s, &a, Path::new("/nonexistent"));
        assert!(result.is_ok(), "{mode}");
        assert_eq!(
            fs::read(&outside).unwrap(),
            b"someone else's file",
            "{mode}"
        );
        assert_eq!(fs::metadata(&outside).unwrap().ino(), inode, "{mode}");
        if mode == "remove" {
            assert!(fs::symlink_metadata(&s.copy).is_err());
        } else {
            let meta = fs::symlink_metadata(&s.copy).unwrap();
            assert!(
                meta.file_type().is_file(),
                "{mode}: a regular file, not a link"
            );
            assert_eq!(fs::read(&s.copy).unwrap(), module_bytes(&s), "{mode}");
        }
    }
}

#[test]
fn a_snap_entry_at_the_installed_path_is_kept() {
    let s = snap();
    // the entry points to the installed (here: --module) path
    add_by_hand(&s.profile, "Custodio", &s.module);
    let before = modules_of(&s.profile);
    assert_eq!(before.len(), 1);
    let report = s.f.run(&s.module, false);
    assert_eq!(modules_of(&s.profile), before, "entry kept line for line");
    assert!(
        text(&report).contains("already registered"),
        "{}",
        text(&report)
    );
    assert_eq!(
        fs::read(&s.copy).unwrap(),
        module_bytes(&s),
        "the copy is placed"
    );
    assert_eq!(
        listed(&s.profile, &s.copy),
        0,
        "the profile does not point to it"
    );
    // control: a profile with no entry gets the entry at the copy path
    let c = snap();
    c.f.run(&c.module, false);
    assert_eq!(listed(&c.profile, &c.copy), 1);
    assert_eq!(listed(&c.profile, &c.module), 0);
}

#[test]
fn a_stale_copy_is_replaced_in_place() {
    let s = snap();
    s.f.run(&s.module, false);
    let entry = modules_of(&s.profile);
    plant(&s.copy, b"stale");
    let report = s.f.run(&s.module, false);
    assert_eq!(fs::read(&s.copy).unwrap(), module_bytes(&s));
    assert!(text(&report).contains("refreshed"), "{}", text(&report));
    assert_eq!(modules_of(&s.profile), entry);
    // up to date: untouched (inode and mtime)
    let meta = fs::metadata(&s.copy).unwrap();
    let report = s.f.run(&s.module, false);
    let again = fs::metadata(&s.copy).unwrap();
    assert_eq!(
        (meta.ino(), meta.mtime_nsec()),
        (again.ino(), again.mtime_nsec())
    );
    assert!(text(&report).contains("up to date"), "{}", text(&report));
    assert!(!text(&report).contains("refreshed"));
    // a held snap profile does not stop the refresh
    plant(&s.copy, b"stale");
    hold(&s.profile);
    let (_, out, _) = command(
        &s,
        &args(&s.module, false, false),
        Path::new("/nonexistent"),
    );
    assert_eq!(fs::read(&s.copy).unwrap(), module_bytes(&s));
    assert!(out.contains("close the browser"), "{out}");
}

#[test]
fn a_held_snap_profile_gets_no_new_copy() {
    let s = snap();
    hold(&s.profile);
    let before = s.f.snapshot();
    let (result, out, err) = command(
        &s,
        &args(&s.module, false, false),
        Path::new("/nonexistent"),
    );
    assert!(result.is_err());
    assert!(
        out.contains("s.default") && err.contains("close the browser"),
        "{out}{err}"
    );
    assert_eq!(
        s.f.snapshot(),
        before,
        "nothing is created for a profile that cannot be registered"
    );
}

#[test]
fn a_refresh_never_creates_a_copy() {
    let s = snap();
    let native = s.f.root(".mozilla/firefox", &["a.default"]);
    s.f.run(&s.module, false);
    fs::remove_file(&s.copy).unwrap();
    // refresh-only on a home with a snap profile and a registered native profile, but no copy
    let before = s.f.snapshot();
    let sock = Journal::new(&s);
    let (result, out, _) = command(&s, &args(&s.module, false, true), &sock.path);
    assert!(result.is_ok());
    assert!(out.contains("no copy"), "{out}");
    assert_eq!(s.f.snapshot(), before);
    assert!(sock.recv().contains("no copy"));
    assert_eq!(listed(&native.join("a.default"), &s.module), 1);
    // control: registration creates it
    s.f.run(&s.module, false);
    assert!(s.copy.exists());
}

#[test]
fn an_unreplaceable_copy_fails_naming_it() {
    for refresh_only in [false, true] {
        let s = snap();
        let native = s.f.root(".mozilla/firefox", &["a.default"]);
        let dir = s.copy.parent().unwrap().to_owned();
        plant(&s.copy, b"stale");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o555)).unwrap();
        let sock = Journal::new(&s);
        let (result, out, err) = command(&s, &args(&s.module, false, refresh_only), &sock.path);
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(result.is_err(), "{refresh_only}: {out}");
        let shown = format!("{out}{err}{}", result.unwrap_err());
        assert!(shown.contains(s.copy.to_str().unwrap()), "{shown}");
        assert!(
            shown.contains("Permission denied"),
            "the reason is given: {shown}"
        );
        assert_eq!(fs::read(&s.copy).unwrap(), b"stale");
        assert!(!s.copy.with_file_name(TEMP_NAME).exists());
        if refresh_only {
            let entry = sock.recv();
            assert!(
                entry.contains("PRIORITY=3") && entry.contains(s.copy.to_str().unwrap()),
                "{entry}"
            );
        } else {
            assert_eq!(
                listed(&native.join("a.default"), &s.module),
                1,
                "native profiles still processed"
            );
        }
        // control: a writable directory works
        let (result, ..) = command(&s, &args(&s.module, false, refresh_only), &sock.path);
        assert!(result.is_ok());
        assert_eq!(fs::read(&s.copy).unwrap(), module_bytes(&s));
    }
    // a directory at the copy path
    let s = snap();
    fs::create_dir(&s.copy).unwrap();
    let (result, out, err) = command(
        &s,
        &args(&s.module, false, false),
        Path::new("/nonexistent"),
    );
    assert!(result.is_err());
    assert!(format!("{out}{err}").contains(s.copy.to_str().unwrap()));
    assert!(s.copy.is_dir());
    assert!(format!("{out}{err}").contains("is a directory"));
    // and a removal does not delete it either
    let (result, out, err) = command(&s, &args(&s.module, true, false), Path::new("/nonexistent"));
    assert!(result.is_err());
    assert!(
        format!("{out}{err}").contains("is a directory"),
        "{out}{err}"
    );
    assert!(s.copy.is_dir());
}

#[test]
fn removal_deletes_the_copy_and_the_entry() {
    let s = snap();
    write_entry(&s.profile, "foreign", "/old/libother.so");
    s.f.run(&s.module, false);
    let foreign: Vec<_> = entries(&s.profile)
        .into_iter()
        .filter(|e| e.name == "foreign")
        .collect();
    let report = s.f.run(&s.module, true);
    assert!(!s.copy.exists() && fs::symlink_metadata(&s.copy).is_err());
    assert!(
        entries(&s.profile)
            .iter()
            .all(|e| !e.library.ends_with("libcustodio_pkcs11.so"))
    );
    assert_eq!(
        entries(&s.profile)
            .into_iter()
            .filter(|e| e.name == "foreign")
            .collect::<Vec<_>>(),
        foreign
    );
    assert!(text(&report).contains("copy removed"), "{}", text(&report));
    let after = s.f.snapshot();
    s.f.run(&s.module, true);
    assert_eq!(s.f.snapshot(), after, "a second removal changes nothing");

    // a held snap profile keeps its entry and its copy, is named, and the exit is non-zero
    let s = snap();
    s.f.run(&s.module, false);
    let (bytes, inode) = (
        fs::read(&s.copy).unwrap(),
        fs::metadata(&s.copy).unwrap().ino(),
    );
    let entry = modules_of(&s.profile);
    hold(&s.profile);
    let (result, out, err) = command(&s, &args(&s.module, true, false), Path::new("/nonexistent"));
    assert!(result.is_err());
    assert!(format!("{out}{err}").contains("close the browser"));
    assert_eq!(fs::read(&s.copy).unwrap(), bytes);
    assert_eq!(
        fs::metadata(&s.copy).unwrap().ino(),
        inode,
        "kept, not deleted and written again"
    );
    assert_eq!(modules_of(&s.profile), entry);
}

#[test]
fn removal_deletes_a_copy_with_no_profile() {
    let f = Fixture::new();
    let m = f.module("a");
    let copy = f.home().join(COPY_REL);
    fs::create_dir_all(copy.parent().unwrap()).unwrap();
    plant(&copy, b"inert");
    f.run(&m, true);
    assert!(!copy.exists());
    // registration refreshes a stale copy even when the snap has no profile, but never creates one
    plant(&copy, b"inert");
    f.run(&m, false);
    assert_eq!(fs::read(&copy).unwrap(), fs::read(&m).unwrap());
}

#[test]
fn the_outcomes_of_the_copy_are_fixable_only_when_they_failed() {
    assert!(Outcome::CopyFailed("x".into()).is_fixable_skip());
    for o in [
        Outcome::CopyPlaced,
        Outcome::CopyRefreshed,
        Outcome::CopyUpToDate,
        Outcome::CopyRemoved,
        Outcome::CopyKept,
    ] {
        assert!(!o.is_fixable_skip(), "{o:?}");
    }
}
