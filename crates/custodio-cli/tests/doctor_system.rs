//! `custodio doctor`, checks 5 (the persistent journal, on fixture roots) and 6 (the state directory's storage, against a
//! fake Custodio service on a private bus).

mod fprint_fixture;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

use custodio_cli::doctor_decide::{JOURNAL, STORAGE, SYSTEM_SECTION};
use fprint_fixture::{Bus, Fake, Fx, Line, NO_BUS, Svc, check, err, out, serve_all};

/// Everything the report says about a check: its text, notes, warnings and fixes.
fn said(l: &Line) -> String {
    let mut all = vec![l.text.clone()];
    all.extend(l.notes.iter().chain(&l.warnings).chain(&l.fixes).cloned());
    all.join("\n")
}

/// Check 5 of a report: in the System section, and with a fix whenever it is not `ok`.
fn journal_line(text: &str) -> Line {
    let l = check(text, JOURNAL);
    assert_eq!(l.section, SYSTEM_SECTION, "{text}");
    assert_eq!(l.state != "ok", !l.fixes.is_empty(), "{text}");
    l
}

/// Doctor on a fixture whose journald files are `files` (the default main file is removed) and whose
/// `/var/log/journal` is `dir`; check 5.
fn journal(files: &[(&str, &str)], dir: Dir) -> Line {
    let fx = Fx::new();
    fx.remove("etc/systemd/journald.conf");
    for (path, text) in files {
        fx.put(path, text);
    }
    match dir {
        Dir::Present => fs::create_dir_all(fx.path("var/log/journal")).unwrap(),
        Dir::Absent => {}
        Dir::File => fx.put("var/log/journal", "not a directory"),
    }
    let before = fx.tree();
    let o = fx.doctor(NO_BUS);
    assert_eq!(fx.tree(), before, "doctor changed the tree");
    journal_line(&out(&o))
}

#[derive(Clone, Copy)]
enum Dir {
    Present,
    Absent,
    File,
}

const ETC: &str = "etc/systemd/journald.conf";
const USR: &str = "usr/lib/systemd/journald.conf";

macro_rules! journal_case {
    ($name:ident, $files:expr, $dir:expr, $state:expr $(, $needle:expr)*) => {
        #[test]
        fn $name() {
            let l = journal(&$files, $dir);
            assert_eq!(l.state, $state, "{l:?}");
            $(assert!(said(&l).contains($needle), "{} not in {l:?}", $needle);)*
        }
    };
}

const MKDIR: &str = "sudo mkdir -p /var/log/journal";
const RESTART: &str = "sudo systemctl restart systemd-journald";
const DROP: &str = "/etc/systemd/journald.conf.d/50-persistent.conf";

// states of the table
journal_case!(
    persistent_with_no_directory_is_ok,
    [(ETC, "[Journal]\nStorage=persistent\n")],
    Dir::Absent,
    "ok"
);
journal_case!(
    auto_with_a_directory_is_ok,
    [(ETC, "[Journal]\nStorage=auto\n")],
    Dir::Present,
    "ok"
);
journal_case!(
    auto_without_the_directory_is_not_ok_with_the_fix,
    [(ETC, "[Journal]\nStorage=auto\n")],
    Dir::Absent,
    "not ok",
    MKDIR,
    RESTART
);
journal_case!(
    volatile_with_a_directory_names_the_line,
    [(ETC, "[Journal]\n#c\nStorage=volatile\n")],
    Dir::Present,
    "not ok",
    "/etc/systemd/journald.conf:3",
    "Storage=volatile",
    RESTART
);
journal_case!(
    volatile_without_a_directory_is_not_ok,
    [(ETC, "[Journal]\nStorage=volatile\n")],
    Dir::Absent,
    "not ok",
    "Storage=volatile"
);
journal_case!(
    volatile_under_usr_lib_says_to_copy_it_to_etc,
    [(USR, "[Journal]\nStorage=volatile\n")],
    Dir::Present,
    "not ok",
    "/usr/lib/systemd/journald.conf:2",
    "/etc/systemd/"
);
journal_case!(
    none_is_not_ok_and_named,
    [(ETC, "[Journal]\nStorage=none\n")],
    Dir::Present,
    "not ok",
    "Storage=none",
    "/etc/systemd/journald.conf:2"
);
journal_case!(
    unset_with_a_persistent_comment_is_ok,
    [(USR, "[Journal]\n#Storage=persistent\n")],
    Dir::Absent,
    "ok"
);
journal_case!(
    unset_with_an_auto_comment_and_a_directory_is_ok,
    [(USR, "[Journal]\n#Storage=auto\n")],
    Dir::Present,
    "ok"
);
journal_case!(
    unset_with_an_auto_comment_and_no_directory_is_not_ok,
    [(USR, "[Journal]\n#Storage=auto\n")],
    Dir::Absent,
    "not ok",
    MKDIR
);
journal_case!(
    unset_with_a_volatile_comment_is_not_ok_by_default,
    [(USR, "[Journal]\n#Storage=volatile\n")],
    Dir::Present,
    "not ok",
    "Storage=volatile",
    DROP
);
journal_case!(
    unset_with_a_none_comment_is_not_ok_by_default,
    [(USR, "[Journal]\n#Storage=none\n")],
    Dir::Present,
    "not ok",
    "Storage=none",
    DROP
);

// precedence
journal_case!(
    the_etc_main_file_beats_usr_lib,
    [
        (ETC, "[Journal]\nStorage=none\n"),
        (USR, "[Journal]\nStorage=persistent\n")
    ],
    Dir::Present,
    "not ok",
    "/etc/systemd/journald.conf:2"
);
journal_case!(
    the_etc_main_file_beats_usr_lib_the_other_way,
    [
        (ETC, "[Journal]\nStorage=persistent\n"),
        (USR, "[Journal]\nStorage=none\n")
    ],
    Dir::Present,
    "ok"
);
journal_case!(
    main_files_are_not_merged,
    [
        (ETC, "[Journal]\n#Storage=auto\n"),
        (USR, "[Journal]\nStorage=volatile\n")
    ],
    Dir::Present,
    "ok"
);
journal_case!(
    the_run_main_file_comes_before_usr_local_and_usr_lib,
    [
        ("run/systemd/journald.conf", "[Journal]\nStorage=volatile\n"),
        (
            "usr/local/lib/systemd/journald.conf",
            "[Journal]\nStorage=persistent\n"
        )
    ],
    Dir::Present,
    "not ok",
    "/run/systemd/journald.conf:2"
);
journal_case!(
    a_drop_in_beats_the_main_file,
    [
        (ETC, "[Journal]\nStorage=persistent\n"),
        (
            "etc/systemd/journald.conf.d/a.conf",
            "[Journal]\nStorage=volatile\n"
        )
    ],
    Dir::Present,
    "not ok",
    "journald.conf.d/a.conf:2"
);
journal_case!(
    drop_ins_sort_by_name_across_the_dirs,
    [
        (ETC, "[Journal]\n"),
        (
            "etc/systemd/journald.conf.d/a.conf",
            "[Journal]\nStorage=volatile\n"
        ),
        (
            "usr/lib/systemd/journald.conf.d/b.conf",
            "[Journal]\nStorage=persistent\n"
        )
    ],
    Dir::Present,
    "ok"
);
journal_case!(
    drop_ins_sort_by_name_across_the_dirs_the_other_way,
    [
        (ETC, "[Journal]\n"),
        (
            "etc/systemd/journald.conf.d/b.conf",
            "[Journal]\nStorage=volatile\n"
        ),
        (
            "usr/lib/systemd/journald.conf.d/a.conf",
            "[Journal]\nStorage=persistent\n"
        )
    ],
    Dir::Present,
    "not ok",
    "etc/systemd/journald.conf.d/b.conf:2"
);
journal_case!(
    a_name_in_several_dirs_comes_from_the_first,
    [
        (ETC, "[Journal]\n"),
        (
            "etc/systemd/journald.conf.d/x.conf",
            "[Journal]\nStorage=volatile\n"
        ),
        (
            "usr/lib/systemd/journald.conf.d/x.conf",
            "[Journal]\nStorage=persistent\n"
        )
    ],
    Dir::Present,
    "not ok",
    "etc/systemd/journald.conf.d/x.conf:2"
);
journal_case!(
    a_run_drop_in_with_a_later_name_beats_an_etc_one,
    [
        (ETC, "[Journal]\n"),
        (
            "etc/systemd/journald.conf.d/a.conf",
            "[Journal]\nStorage=persistent\n"
        ),
        (
            "run/systemd/journald.conf.d/c.conf",
            "[Journal]\nStorage=volatile\n"
        )
    ],
    Dir::Present,
    "not ok",
    "run/systemd/journald.conf.d/c.conf:2"
);
journal_case!(
    the_last_valid_assignment_wins,
    [(ETC, "[Journal]\nStorage=volatile\nStorage=persistent\n")],
    Dir::Present,
    "ok"
);
journal_case!(
    a_key_before_any_section_has_no_effect,
    [(ETC, "Storage=volatile\n[Journal]\n#Storage=persistent\n")],
    Dir::Present,
    "ok"
);
journal_case!(
    another_section_has_no_effect,
    [(
        ETC,
        "[Journal]\nStorage=persistent\n[Other]\nStorage=volatile\n"
    )],
    Dir::Present,
    "ok"
);
journal_case!(
    a_lower_case_key_has_no_effect,
    [(ETC, "[Journal]\nStorage=persistent\nstorage=volatile\n")],
    Dir::Present,
    "ok"
);
journal_case!(
    spaces_around_the_equals_sign_work,
    [(ETC, "[Journal]\n Storage = volatile \n")],
    Dir::Present,
    "not ok",
    "/etc/systemd/journald.conf:2"
);
journal_case!(
    a_comment_character_line_is_skipped,
    [(
        ETC,
        "[Journal]\n;Storage=volatile\n#Storage=volatile\nStorage=persistent\n"
    )],
    Dir::Present,
    "ok"
);
journal_case!(
    the_run_journal_directory_changes_nothing,
    [
        (ETC, "[Journal]\nStorage=auto\n"),
        ("run/log/journal/id/system.journal", "x")
    ],
    Dir::Absent,
    "not ok",
    MKDIR
);

// could not check
journal_case!(
    unset_with_no_main_file_is_could_not_check,
    [(
        "etc/systemd/journald.conf.d/a.conf",
        "[Journal]\nForwardToSyslog=yes\n"
    )],
    Dir::Present,
    "could not check"
);
journal_case!(
    unset_with_no_comment_line_is_could_not_check,
    [(ETC, "[Journal]\nForwardToSyslog=yes\n")],
    Dir::Present,
    "could not check",
    "/etc/systemd/journald.conf"
);
journal_case!(
    an_empty_value_is_could_not_check,
    [(ETC, "[Journal]\nStorage=persistent\nStorage=\n")],
    Dir::Present,
    "could not check",
    "/etc/systemd/journald.conf:3"
);
journal_case!(
    an_invalid_value_is_could_not_check,
    [(ETC, "[Journal]\nStorage=Persistent\n")],
    Dir::Present,
    "could not check",
    "/etc/systemd/journald.conf:2"
);
journal_case!(
    a_backslash_line_is_could_not_check,
    [(ETC, "[Journal]\nForwardToSyslog=yes \\\nStorage=volatile\n")],
    Dir::Present,
    "could not check",
    "/etc/systemd/journald.conf:2"
);
journal_case!(
    a_journal_directory_that_is_a_file_is_could_not_check,
    [(ETC, "[Journal]\nStorage=auto\n")],
    Dir::File,
    "could not check",
    "/var/log/journal"
);
journal_case!(
    a_backslash_outside_journal_is_could_not_check,
    [(ETC, "[Other]\nx=y \\\n[Journal]\nStorage=persistent\n")],
    Dir::Present,
    "could not check",
    "/etc/systemd/journald.conf:2"
);

/// A main file of exactly `len` bytes: valid content, padded by a comment.
fn padded(len: usize) -> String {
    let head = "[Journal]\nStorage=persistent\n#";
    format!("{head}{}", "x".repeat(len - head.len()))
}

#[test]
fn a_file_of_exactly_1_mib_is_read() {
    let l = journal(&[(ETC, &padded(1024 * 1024))], Dir::Present);
    assert_eq!(l.state, "ok", "{l:?}");
}

#[test]
fn a_file_of_100_kib_is_read() {
    let l = journal(&[(ETC, &padded(100 * 1024))], Dir::Present);
    assert_eq!(l.state, "ok", "{l:?}");
}

#[test]
fn a_file_one_byte_over_1_mib_is_could_not_check() {
    let l = journal(&[(ETC, &padded(1024 * 1024 + 1))], Dir::Present);
    assert_eq!(l.state, "could not check", "{l:?}");
    assert!(said(&l).contains("/etc/systemd/journald.conf"), "{l:?}");
}

journal_case!(
    a_comment_ending_in_a_backslash_is_not_a_continued_line,
    [(
        ETC,
        "[Journal]\n# a note \\\n;another \\\nStorage=persistent\n"
    )],
    Dir::Present,
    "ok"
);
journal_case!(
    the_default_names_the_line_of_the_comment,
    [(USR, "[Journal]\n#x\n#Storage=volatile\n")],
    Dir::Present,
    "not ok",
    "/usr/lib/systemd/journald.conf:3"
);

#[test]
fn a_drop_in_directory_that_cannot_be_read_is_could_not_check() {
    let fx = Fx::new();
    fx.put("etc/systemd/journald.conf.d/a.conf", "[Journal]\n");
    let dir = fx.path("etc/systemd/journald.conf.d");
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o000)).unwrap();
    let o = fx.doctor(NO_BUS);
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    let l = journal_line(&out(&o));
    assert_eq!(l.state, "could not check", "{l:?}");
    assert!(said(&l).contains("/etc/systemd/journald.conf.d"), "{l:?}");
}

#[test]
fn a_file_that_is_not_utf_8_is_could_not_check() {
    let fx = Fx::new();
    fs::write(fx.path(ETC), b"[Journal]\nStorage=persistent\n\xff\xfe\n").unwrap();
    let l = journal_line(&out(&fx.doctor(NO_BUS)));
    assert_eq!(l.state, "could not check", "{l:?}");
    assert!(said(&l).contains("/etc/systemd/journald.conf"), "{l:?}");
}

#[test]
fn an_unreadable_file_is_could_not_check_naming_it() {
    let fx = Fx::new();
    let target = fx.path(ETC);
    let original = fs::metadata(&target).unwrap().permissions();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o000)).unwrap();
    let o = fx.doctor(NO_BUS);
    fs::set_permissions(&target, original).unwrap();
    let l = journal_line(&out(&o));
    assert_eq!(l.state, "could not check", "{l:?}");
    assert!(said(&l).contains("/etc/systemd/journald.conf"), "{l:?}");
}

#[test]
fn a_journal_directory_that_cannot_be_stat_ed_is_could_not_check() {
    // `var/log` with mode 0: `stat(/var/log/journal)` gives EACCES, not ENOENT
    let fx = Fx::new();
    fx.put(ETC, "[Journal]\nStorage=auto\n");
    fs::create_dir_all(fx.path("var/log/journal")).unwrap();
    let parent = fx.path("var/log");
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o000)).unwrap();
    let o = fx.doctor(NO_BUS);
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o755)).unwrap();
    let l = journal_line(&out(&o));
    assert_eq!(l.state, "could not check", "{l:?}");
    assert!(said(&l).contains("/var/log/journal"), "{l:?}");
}

// ---- check 6 ----

struct Run {
    text: String,
    exit: i32,
    elapsed: Duration,
    err: String,
    served: fprint_fixture::Served,
}

fn storage(service: Option<Svc>) -> Run {
    let fx = Fx::new();
    let bus = Bus::new();
    let served = serve_all(
        &bus.address,
        Fake {
            service,
            ..Fake::new(1)
        },
    );
    let before = fx.tree();
    let started = Instant::now();
    let o = fx.doctor(&bus.address);
    let elapsed = started.elapsed();
    assert_eq!(fx.tree(), before);
    Run {
        text: out(&o),
        exit: o.status.code().unwrap(),
        elapsed,
        err: err(&o),
        served,
    }
}

/// Check 6 of the run: in the System section, with a fix whenever it is not `ok`.
fn line(r: &Run) -> Line {
    let l = check(&r.text, STORAGE);
    assert_eq!(l.section, SYSTEM_SECTION, "{}", r.text);
    assert_eq!(l.state != "ok", !l.fixes.is_empty(), "{}", r.text);
    l
}

/// Check 6 when the service answers `unknown` with this reason (`None`: no reason method).
fn unknown(reason: Option<&'static str>) -> (Run, Line) {
    let r = storage(Some(Svc::answering("unknown", reason)));
    let l = line(&r);
    assert_eq!(l.state, "not ok", "{l:?}");
    assert_eq!(r.exit, 1);
    (r, l)
}

#[test]
fn encrypted_is_ok_and_only_the_read_only_methods_are_called_without_the_flag() {
    let r = storage(Some(Svc::answering("encrypted", Some(""))));
    assert_eq!(line(&r).state, "ok", "{}", r.text);
    assert_eq!(r.exit, 0, "{}{}", r.text, r.err);
    // the reason is asked only when the answer is `unknown`; no call sets the interactive flag
    assert_eq!(
        r.served.service.lock().unwrap().as_slice(),
        ["StateStorage"]
    );
    assert!(r.served.polkit.lock().unwrap().is_empty());
}

#[test]
fn not_encrypted_is_a_warning_with_what_it_means_and_the_full_disk_encryption_fix() {
    let r = storage(Some(Svc::answering("not-encrypted", Some(""))));
    let l = line(&r);
    assert_eq!(l.state, "warn", "{}", r.text);
    assert!(!l.notes.is_empty(), "{l:?}");
    assert!(l.fixes.concat().contains("LUKS"), "{l:?}");
    assert!(!said(&l).contains("README"), "{l:?}");
    assert_eq!(r.exit, 1);
    assert_eq!(
        r.served.service.lock().unwrap().as_slice(),
        ["StateStorage"]
    );
}

const REASONS: [&str; 7] = [
    "no-mount",
    "not-block-filesystem",
    "sysfs-incomplete",
    "layer-not-classified",
    "members-disagree",
    "fscrypt-not-excluded",
    "state-dir-unresolved",
];

#[test]
fn each_known_reason_of_unknown_has_its_own_text_and_fix_and_asks_for_the_reason() {
    let mut seen: Vec<(String, Vec<String>)> = Vec::new();
    for reason in REASONS {
        let (r, l) = unknown(Some(reason));
        assert_eq!(
            r.served.service.lock().unwrap().as_slice(),
            ["StateStorage", "StateStorageReason"]
        );
        let said = (l.text.clone(), l.fixes.clone());
        assert!(
            seen.iter().all(|(t, f)| *t != said.0 && *f != said.1),
            "{reason} says what another reason says: {l:?}"
        );
        seen.push(said);
    }
    let (_, none) = unknown(None);
    assert!(
        seen.iter().all(|(t, _)| *t != none.text),
        "a known reason reads like no reason: {none:?}"
    );
}

#[test]
fn unknown_no_mount_points_at_proc() {
    let (_, l) = unknown(Some("no-mount"));
    assert!(l.fixes.concat().contains("/proc"), "{l:?}");
}

#[test]
fn a_reason_string_it_does_not_know_is_reported_as_no_reason_and_not_repeated() {
    let (_, none) = unknown(None);
    let (_, future) = unknown(Some("from-the-future"));
    assert!(!said(&future).contains("from-the-future"), "{future:?}");
    assert_eq!(future, none);
}

#[test]
fn a_wire_value_the_cli_does_not_know_is_not_ok() {
    let r = storage(Some(Svc::answering("quantum", Some(""))));
    assert_eq!(line(&r).state, "not ok", "{}", r.text);
}

fn could_not_check(r: &Run) -> Line {
    let l = line(r);
    assert_eq!(l.state, "could not check", "{l:?}");
    assert!(l.fixes.concat().contains("custodio.service"), "{l:?}");
    assert_eq!(r.exit, 1, "{}", r.text);
    l
}

#[test]
fn a_bus_without_the_service_name_is_could_not_check_and_names_it() {
    let l = could_not_check(&storage(None));
    assert!(l.text.contains(custodio_client::BUS_NAME), "{l:?}");
}

#[test]
fn an_error_reply_is_could_not_check() {
    let mut svc = Svc::answering("encrypted", Some(""));
    svc.error = true;
    could_not_check(&storage(Some(svc)));
}

#[test]
fn a_slow_answer_is_could_not_check_within_a_bound() {
    let mut svc = Svc::answering("encrypted", Some(""));
    svc.delay = Duration::from_millis(2500);
    let r = storage(Some(svc));
    could_not_check(&r);
    assert!(r.elapsed < Duration::from_millis(2300), "{:?}", r.elapsed);
}

#[test]
fn no_bus_socket_is_could_not_check() {
    let fx = Fx::new();
    let o = fx.doctor(NO_BUS);
    let l = check(&out(&o), STORAGE);
    assert_eq!(l.state, "could not check", "{l:?}");
    assert!(l.fixes.concat().contains("custodio.service"), "{l:?}");
    assert_eq!(o.status.code(), Some(1));
}
