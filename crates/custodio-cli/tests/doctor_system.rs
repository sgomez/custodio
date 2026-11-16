//! `custodio doctor`, checks 5 (the persistent journal, on fixture roots) and 6 (the state directory's storage, against a
//! fake Custodio service on a private bus).

mod fprint_fixture;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

use fprint_fixture::{Bus, Fake, Fx, NO_BUS, Svc, err, out, section, serve_all, state};

const JOURNAL: &str = "persistent journal";
const STORAGE: &str = "state directory storage";

/// Doctor on a fixture whose journald files are `files` (the default main file is removed) and whose
/// `/var/log/journal` is `dir`; the section of check 5.
fn journal(files: &[(&str, &str)], dir: Dir) -> (String, String) {
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
    let text = out(&o);
    (state(&text, JOURNAL), section(&text, JOURNAL).join("\n"))
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
    ($name:ident, $files:expr, $dir:expr, $state:expr, $($needle:expr),*) => {
        #[test]
        fn $name() {
            let (state, section) = journal(&$files, $dir);
            assert_eq!(state, $state, "{section}");
            $(assert!(section.contains($needle), "{} not in {section}", $needle);)*
        }
    };
}

const FIX1: &str = "mkdir -p /var/log/journal";
const TMPFILES: &str = "systemd-tmpfiles --create --prefix /var/log/journal";
const DROP: &str = "50-persistent.conf";

// states of the table
journal_case!(
    persistent_with_no_directory_is_ok,
    [(ETC, "[Journal]\nStorage=persistent\n")],
    Dir::Absent,
    "ok",
    "persistent"
);
journal_case!(
    auto_with_a_directory_is_ok,
    [(ETC, "[Journal]\nStorage=auto\n")],
    Dir::Present,
    "ok",
    "exists"
);
journal_case!(
    auto_without_the_directory_is_not_ok_with_the_fix,
    [(ETC, "[Journal]\nStorage=auto\n")],
    Dir::Absent,
    "not ok",
    FIX1,
    TMPFILES,
    DROP,
    "journalctl --flush",
    "/etc/systemd/journald.conf:2"
);
journal_case!(
    volatile_with_a_directory_names_the_line,
    [(ETC, "[Journal]\n#c\nStorage=volatile\n")],
    Dir::Present,
    "not ok",
    "/etc/systemd/journald.conf:3",
    "volatile"
);
journal_case!(
    volatile_without_a_directory_is_not_ok,
    [(ETC, "[Journal]\nStorage=volatile\n")],
    Dir::Absent,
    "not ok",
    "volatile"
);
journal_case!(
    volatile_under_usr_lib_says_to_copy_it_to_etc,
    [(USR, "[Journal]\nStorage=volatile\n")],
    Dir::Present,
    "not ok",
    "/usr/lib/systemd/journald.conf:2",
    "same name in /etc"
);
journal_case!(
    none_says_the_entries_are_lost_now,
    [(ETC, "[Journal]\nStorage=none\n")],
    Dir::Present,
    "not ok",
    "every journal entry is lost now",
    "/etc/systemd/journald.conf:2"
);
journal_case!(
    unset_with_a_persistent_comment_is_ok,
    [(USR, "[Journal]\n#Storage=persistent\n")],
    Dir::Absent,
    "ok",
    "default"
);
journal_case!(
    unset_with_an_auto_comment_and_a_directory_is_ok,
    [(USR, "[Journal]\n#Storage=auto\n")],
    Dir::Present,
    "ok",
    "exists"
);
journal_case!(
    unset_with_an_auto_comment_and_no_directory_is_not_ok,
    [(USR, "[Journal]\n#Storage=auto\n")],
    Dir::Absent,
    "not ok",
    FIX1
);
journal_case!(
    unset_with_a_volatile_comment_is_not_ok_by_default,
    [(USR, "[Journal]\n#Storage=volatile\n")],
    Dir::Present,
    "not ok",
    "the default",
    DROP
);
journal_case!(
    unset_with_a_none_comment_is_not_ok_by_default,
    [(USR, "[Journal]\n#Storage=none\n")],
    Dir::Present,
    "not ok",
    "the default"
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
    "ok",
    "persistent"
);
journal_case!(
    main_files_are_not_merged,
    [
        (ETC, "[Journal]\n#Storage=auto\n"),
        (USR, "[Journal]\nStorage=volatile\n")
    ],
    Dir::Present,
    "ok",
    "exists"
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
    "ok",
    "persistent"
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
    "ok",
    "persistent"
);
journal_case!(
    a_key_before_any_section_has_no_effect,
    [(ETC, "Storage=volatile\n[Journal]\n#Storage=persistent\n")],
    Dir::Present,
    "ok",
    "default"
);
journal_case!(
    another_section_has_no_effect,
    [(
        ETC,
        "[Journal]\nStorage=persistent\n[Other]\nStorage=volatile\n"
    )],
    Dir::Present,
    "ok",
    "persistent"
);
journal_case!(
    a_lower_case_key_has_no_effect,
    [(ETC, "[Journal]\nStorage=persistent\nstorage=volatile\n")],
    Dir::Present,
    "ok",
    "persistent"
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
    "ok",
    "persistent"
);
journal_case!(
    the_run_journal_directory_changes_nothing,
    [
        (ETC, "[Journal]\nStorage=auto\n"),
        ("run/log/journal/id/system.journal", "x")
    ],
    Dir::Absent,
    "not ok",
    FIX1
);

// could not check
journal_case!(
    unset_with_no_main_file_is_could_not_check,
    [(
        "etc/systemd/journald.conf.d/a.conf",
        "[Journal]\nForwardToSyslog=yes\n"
    )],
    Dir::Present,
    "could not check",
    "257",
    "259"
);
journal_case!(
    unset_with_no_comment_line_is_could_not_check,
    [(ETC, "[Journal]\nForwardToSyslog=yes\n")],
    Dir::Present,
    "could not check",
    "#Storage="
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
    "backslash"
);
journal_case!(
    a_journal_directory_that_is_a_file_is_could_not_check,
    [(ETC, "[Journal]\nStorage=auto\n")],
    Dir::File,
    "could not check",
    "not a directory"
);
journal_case!(
    a_backslash_outside_journal_is_not_looked_at,
    [(ETC, "[Other]\nx=y \\\n[Journal]\nStorage=persistent\n")],
    Dir::Present,
    "ok",
    "persistent"
);

#[test]
fn a_file_over_1_mib_is_could_not_check() {
    let big = format!(
        "[Journal]\nStorage=persistent\n#{}\n",
        "x".repeat(1024 * 1024)
    );
    let (s, section) = journal(&[(ETC, &big)], Dir::Present);
    assert_eq!(s, "could not check", "{section}");
    assert!(section.contains("longer than"), "{section}");
}

#[test]
fn a_file_that_is_not_utf_8_is_could_not_check() {
    let fx = Fx::new();
    fs::write(fx.path(ETC), b"[Journal]\nStorage=persistent\n\xff\xfe\n").unwrap();
    let text = out(&fx.doctor(NO_BUS));
    assert_eq!(state(&text, JOURNAL), "could not check", "{text}");
    assert!(
        section(&text, JOURNAL).join("").contains("not UTF-8"),
        "{text}"
    );
}

fn unreadable(rel: &str, auto_dir: bool) -> String {
    let fx = Fx::new();
    fx.put(ETC, "[Journal]\nStorage=auto\n");
    let target = fx.path(rel);
    if auto_dir {
        fs::create_dir_all(&target).unwrap();
    }
    let original = fs::metadata(&target).unwrap().permissions();
    fs::set_permissions(&target, fs::Permissions::from_mode(0)).unwrap();
    let o = fx.doctor(NO_BUS);
    fs::set_permissions(&target, original).unwrap();
    let text = out(&o);
    assert_eq!(state(&text, JOURNAL), "could not check", "{text}");
    section(&text, JOURNAL).join("\n")
}

#[test]
fn an_unreadable_file_is_could_not_check_naming_it() {
    assert!(unreadable(ETC, false).contains("/etc/systemd/journald.conf"));
}

#[test]
fn a_journal_directory_that_cannot_be_stat_ed_is_could_not_check() {
    // `var/log` with mode 0: `stat(/var/log/journal)` gives EACCES, not ENOENT
    let fx = Fx::new();
    fx.put(ETC, "[Journal]\nStorage=auto\n");
    fs::create_dir_all(fx.path("var/log/journal")).unwrap();
    let parent = fx.path("var/log");
    fs::set_permissions(&parent, fs::Permissions::from_mode(0)).unwrap();
    let o = fx.doctor(NO_BUS);
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o755)).unwrap();
    let text = out(&o);
    assert_eq!(state(&text, JOURNAL), "could not check", "{text}");
    assert!(
        section(&text, JOURNAL).join("").contains("cannot stat"),
        "{text}"
    );
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

fn line(r: &Run) -> String {
    section(&r.text, STORAGE).join("\n")
}

#[test]
fn encrypted_is_ok_and_only_the_read_only_methods_are_called_without_the_flag() {
    let r = storage(Some(Svc::answering("encrypted", Some(""))));
    assert_eq!(state(&r.text, STORAGE), "ok", "{}", r.text);
    assert!(!line(&r).contains("fix:"), "{}", line(&r));
    assert_eq!(r.exit, 0, "{}{}", r.text, r.err);
    // the reason is asked only when the answer is `unknown`; no call sets the interactive flag
    assert_eq!(
        r.served.service.lock().unwrap().as_slice(),
        ["StateStorage"]
    );
    assert!(r.served.polkit.lock().unwrap().is_empty());
}

#[test]
fn not_encrypted_is_not_ok_with_the_full_disk_encryption_advice() {
    let r = storage(Some(Svc::answering("not-encrypted", Some(""))));
    assert_eq!(state(&r.text, STORAGE), "not ok", "{}", r.text);
    assert!(
        line(&r).contains("README.md#full-disk-encryption"),
        "{}",
        line(&r)
    );
    assert_eq!(r.exit, 1);
    assert_eq!(
        r.served.service.lock().unwrap().as_slice(),
        ["StateStorage"]
    );
}

macro_rules! reason_case {
    ($name:ident, $reason:expr, $todo:expr) => {
        #[test]
        fn $name() {
            let r = storage(Some(Svc::answering("unknown", Some($reason))));
            let l = line(&r);
            assert_eq!(state(&r.text, STORAGE), "not ok", "{l}");
            assert!(l.contains("not known to be on an encrypted device"), "{l}");
            assert!(l.contains(concat!("reason ", $reason)), "{l}");
            assert!(l.contains($todo), "{l}");
            assert_eq!(r.exit, 1);
            assert_eq!(
                r.served.service.lock().unwrap().as_slice(),
                ["StateStorage", "StateStorageReason"]
            );
        }
    };
}

reason_case!(unknown_no_mount, "no-mount", "/proc is available");
reason_case!(
    unknown_not_block_filesystem,
    "not-block-filesystem",
    "local ext4, xfs"
);
reason_case!(
    unknown_sysfs_incomplete,
    "sysfs-incomplete",
    "Restart the service"
);
reason_case!(
    unknown_layer_not_classified,
    "layer-not-classified",
    "plain dm-crypt"
);
reason_case!(
    unknown_members_disagree,
    "members-disagree",
    "Encrypt every member"
);
reason_case!(
    unknown_fscrypt_not_excluded,
    "fscrypt-not-excluded",
    "dm-crypt (LUKS) under the filesystem"
);
reason_case!(
    unknown_state_dir_unresolved,
    "state-dir-unresolved",
    "state directory exists"
);

#[test]
fn unknown_with_no_reason_method_invents_no_reason() {
    let r = storage(Some(Svc::answering("unknown", None)));
    let l = line(&r);
    assert_eq!(state(&r.text, STORAGE), "not ok", "{l}");
    assert!(!l.contains("(reason "), "{l}");
    assert!(l.contains("not known to be on an encrypted device"), "{l}");
}

#[test]
fn unknown_with_a_reason_string_it_does_not_know_is_not_ok_and_not_repeated_as_a_cause() {
    let r = storage(Some(Svc::answering("unknown", Some("from-the-future"))));
    let l = line(&r);
    assert_eq!(state(&r.text, STORAGE), "not ok", "{l}");
    assert!(!l.contains("from-the-future"), "{l}");
}

#[test]
fn a_wire_value_the_cli_does_not_know_is_not_ok() {
    let r = storage(Some(Svc::answering("quantum", Some(""))));
    assert_eq!(state(&r.text, STORAGE), "not ok", "{}", line(&r));
}

fn could_not_check(r: &Run) {
    let l = line(r);
    assert_eq!(state(&r.text, STORAGE), "could not check", "{l}");
    assert!(l.contains("custodio.service"), "{l}");
    assert_eq!(r.exit, 1, "{}", r.text);
}

#[test]
fn a_bus_without_the_service_name_is_could_not_check() {
    let r = storage(None);
    could_not_check(&r);
    assert!(line(&r).contains("nothing owns"), "{}", line(&r));
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
    assert!(line(&r).contains("no answer within"), "{}", line(&r));
    assert!(r.elapsed < Duration::from_millis(2300), "{:?}", r.elapsed);
}

#[test]
fn no_bus_socket_is_could_not_check() {
    let fx = Fx::new();
    let o = fx.doctor(NO_BUS);
    let text = out(&o);
    assert_eq!(state(&text, STORAGE), "could not check", "{text}");
    assert!(
        section(&text, STORAGE)
            .join("")
            .contains("custodio.service")
    );
    assert_eq!(o.status.code(), Some(1));
}
