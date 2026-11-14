//! `custodio register` over fixture homes with the real `modutil` (F182, F172's Decisions).

mod fixture;
#[path = "register_native/real.rs"]
mod real;
#[path = "register_native/skips.rs"]
mod skips;

use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;

use custodio_cli::register_native::{Outcome, Refusal, refuse_root_and_sudo};
use fixture::{Fixture, add_by_hand, entries, listed, modutil_list, new_profile, write_entry};

fn outcomes(r: &custodio_cli::register_native::Report) -> Vec<Outcome> {
    r.lines.iter().map(|l| l.outcome.clone()).collect()
}

#[test]
fn registers_every_native_profile_once() {
    let f = Fixture::new();
    let m = f.module("a");
    let legacy = f.root(".mozilla/firefox", &["a.default", "bare.default"]);
    let xdg = f.root(".config/mozilla/firefox", &["b.default"]);
    let tb = f.root(".thunderbird", &["t.default"]);
    // a profile that lacks pkcs11.txt: registered by the direct route
    fs::remove_file(legacy.join("bare.default/pkcs11.txt")).unwrap();
    // a foreign entry that must stay
    write_foreign(&legacy.join("a.default"));
    // the same profile reached from a second root through a link
    symlink(&xdg, f.home().join(".config/linked")).unwrap();
    let profiles = [
        legacy.join("a.default"),
        legacy.join("bare.default"),
        xdg.join("b.default"),
        tb.join("t.default"),
    ];
    let report = f.run(&m, false);
    assert_eq!(report.lines.len(), 4, "{report:?}");
    assert!(outcomes(&report).iter().all(|o| *o == Outcome::Registered));
    for p in &profiles {
        assert_eq!(listed(p, &m), 1, "{}", p.display());
        let e = entries(p);
        assert_eq!(
            e.iter()
                .filter(|e| e.library == m.to_str().unwrap())
                .count(),
            1
        );
    }
    assert!(entries(&profiles[0]).iter().any(|e| e.name == "foreign"));
    let names: Vec<_> = report
        .lines
        .iter()
        .map(|l| (l.browser, l.path.clone()))
        .collect();
    assert!(names.contains(&("Thunderbird", tb.join("t.default"))));
    assert!(names.contains(&("Firefox", xdg.join("b.default"))));
    let text = report.lines[0].to_string();
    assert!(text.contains("Firefox") && text.contains("a.default") && text.contains("registered"));
}

fn write_foreign(profile: &Path) {
    write_entry(profile, "foreign", "/old/libother.so");
}

#[test]
fn a_second_run_is_byte_identical() {
    let f = Fixture::new();
    let m = f.module("a");
    f.root(".mozilla/firefox", &["a.default"]);
    f.root(".thunderbird", &["t.default"]);
    let before = f.snapshot();
    let first = f.run(&m, false);
    let after_one = f.snapshot();
    assert_ne!(before, after_one, "the comparison can fail");
    let second = f.run(&m, false);
    assert_eq!(after_one, f.snapshot());
    assert_eq!(first.lines.len(), second.lines.len());
    for l in &second.lines {
        assert!(matches!(l.outcome, Outcome::AlreadyRegistered(_)), "{l}");
        assert!(l.to_string().contains("already registered"));
    }
}

#[test]
fn an_entry_added_by_hand_under_another_name_is_not_duplicated() {
    let f = Fixture::new();
    let m = f.module("a");
    let root = f.root(".mozilla/firefox", &["a.default", "b.default"]);
    add_by_hand(&root.join("a.default"), "my token", &m);
    add_by_hand(&root.join("b.default"), "other name", &m);
    let before = f.snapshot();
    let report = f.run(&m, false);
    assert_eq!(f.snapshot(), before);
    let mut names: Vec<_> = report
        .lines
        .iter()
        .map(|l| match &l.outcome {
            Outcome::AlreadyRegistered(n) => n.clone(),
            o => panic!("{o:?}"),
        })
        .collect();
    names.sort();
    assert_eq!(names, ["my token", "other name"]);
    assert_eq!(listed(&root.join("a.default"), &m), 1);
}

#[test]
fn an_entry_for_a_vanished_custodio_path_is_updated() {
    let f = Fixture::new();
    let m = f.module("a");
    let root = f.root(".mozilla/firefox", &["a.default"]);
    let p = root.join("a.default");
    write_entry(&p, "Custodio", "/old/libcustodio_pkcs11.so");
    write_foreign(&p);
    let report = f.run(&m, false);
    assert_eq!(outcomes(&report), [Outcome::Refreshed]);
    assert!(report.lines[0].to_string().contains("refreshed"));
    let e = entries(&p);
    let ours: Vec<_> = e
        .iter()
        .filter(|e| e.library.ends_with(fixture_file()))
        .collect();
    assert_eq!(ours.len(), 1);
    assert_eq!(
        (ours[0].name.as_str(), ours[0].library.as_str()),
        ("Custodio", m.to_str().unwrap())
    );
    assert!(e.iter().any(|e| e.name == "foreign"), "other entries stay");
    assert_eq!(listed(&p, &m), 1);
}

fn fixture_file() -> &'static str {
    custodio_cli::register_native::MODULE_FILE
}

#[test]
fn a_foreign_entry_with_a_missing_library_is_left_alone() {
    let f = Fixture::new();
    let m = f.module("a");
    let root = f.root(".mozilla/firefox", &["a.default"]);
    let p = root.join("a.default");
    write_foreign(&p);
    let before = fs::read(p.join("pkcs11.txt")).unwrap();
    f.run(&m, false);
    let after = fs::read_to_string(p.join("pkcs11.txt")).unwrap();
    assert!(
        after.starts_with(&String::from_utf8(before).unwrap()),
        "the old text is kept byte for byte"
    );
    assert_eq!(entries(&p).len(), 3);
}

#[test]
fn a_custodio_library_at_another_existing_path_is_kept_and_never_doubled() {
    let f = Fixture::new();
    let installed = f.module("a");
    let other = f.module("b");
    let root = f.root(".mozilla/firefox", &["a.default"]);
    let p = root.join("a.default");
    add_by_hand(&p, "Custodio", &other);
    let before = f.snapshot();
    let report = f.run(&installed, false);
    assert!(matches!(
        outcomes(&report)[0],
        Outcome::AlreadyRegisteredElsewhere(_)
    ));
    assert_eq!(f.snapshot(), before);
    assert_eq!(modutil_list(&p).matches("library name:").count(), 1);
}

#[test]
fn removal_keeps_every_other_entry_as_it_was() {
    let f = Fixture::new();
    let m = f.module("a");
    let root = f.root(".mozilla/firefox", &["a.default"]);
    let p = root.join("a.default");
    write_foreign(&p);
    let foreign_before: Vec<String> = fs::read_to_string(p.join("pkcs11.txt"))
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    f.run(&m, false);
    let report = f.run(&m, true);
    assert_eq!(outcomes(&report), [Outcome::Removed(1)]);
    let after: Vec<String> = fs::read_to_string(p.join("pkcs11.txt"))
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(
        after, foreign_before,
        "internal module (parameters, NSS lines) and foreign entries unchanged"
    );
    assert!(!modutil_list(&p).contains("Custodio"));
}

#[test]
fn removal_leaves_no_custodio_entry_and_is_idempotent() {
    let f = Fixture::new();
    let m = f.module("a");
    let legacy = f.root(
        ".mozilla/firefox",
        &["a.default", "hand.default", "never.default"],
    );
    let held = f.root(".thunderbird", &["held.default"]);
    add_by_hand(&legacy.join("hand.default"), "mine", &m);
    f.run(&m, false);
    let held_dir = held.join("held.default");
    symlink(
        format!("{}:+{}", fixture_local(), std::process::id()),
        held_dir.join("lock"),
    )
    .unwrap();
    let never = legacy.join("never.default");
    // `never.default` got registered by the first run; give it a profile that never had an entry
    fs::remove_dir_all(&never).unwrap();
    new_profile(&never);
    let report = f.run(&m, true);
    for p in ["a.default", "hand.default"] {
        assert!(
            entries(&legacy.join(p))
                .iter()
                .all(|e| !e.library.ends_with(fixture_file())),
            "{p}"
        );
    }
    let held_line = report.lines.iter().find(|l| l.path == held_dir).unwrap();
    assert!(matches!(held_line.outcome, Outcome::Held(_)));
    assert!(report.has_fixable_skip());
    assert!(
        entries(&held_dir)
            .iter()
            .any(|e| e.library.ends_with(fixture_file())),
        "held profile untouched"
    );
    let again_before = f.snapshot();
    f.run(&m, true);
    assert_eq!(f.snapshot(), again_before);
    let none = report.lines.iter().find(|l| l.path == never).unwrap();
    assert_eq!(none.outcome, Outcome::NothingToRemove);
}

fn fixture_local() -> std::net::Ipv4Addr {
    fixture::LOCAL
}

#[test]
fn sudo_and_root_are_refused_by_the_check() {
    let none = |_: &str| None;
    assert_eq!(refuse_root_and_sudo(0, none), Err(Refusal::Root));
    assert_eq!(refuse_root_and_sudo(1000, none), Ok(()));
    for var in ["SUDO_USER", "SUDO_UID"] {
        let only = |n: &str| (n == var).then(|| "x".into());
        assert_eq!(
            refuse_root_and_sudo(1000, only),
            Err(Refusal::Sudo),
            "{var}"
        );
    }
}
