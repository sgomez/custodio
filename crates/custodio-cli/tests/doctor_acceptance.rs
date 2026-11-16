//! Acceptance 6: `custodio doctor` as a whole command. Each run is a full fixture system (files, a fake `fprintd`, a fake
//! Custodio service and a fake polkit authority on one private bus) with several checks varied together, so that every
//! state of every check occurs. The per-state texts of checks 1 to 3 are F202's; here only the state word, the fix and the
//! order are asserted.

mod fprint_fixture;

use std::fs;
use std::process::Output;
use std::time::Duration;

use custodio_cli::fingerprint_decide::file_bytes;
use fprint_fixture::{
    Bus, FINGER, Fake, Fingers, Fx, GLOBAL_PAM, POLKIT, POLKIT_CHECK, READER, Svc, err, fixes, out,
    section, serve_all, state,
};

const FIREFOX: &str = "module in browsers";
const JOURNAL: &str = "persistent journal";
const STORAGE: &str = "state directory storage";

struct Run {
    text: String,
    code: i32,
    stderr: String,
}

/// One whole run: `setup` shapes the fixture, `fake` the bus. Checks what every run promises.
fn run(setup: impl FnOnce(&Fx), fake: Fake) -> Run {
    let fx = Fx::new();
    setup(&fx);
    let bus = Bus::new();
    let served = serve_all(&bus.address, fake);
    let before = fx.tree();
    let o = fx.doctor(&bus.address);
    assert_eq!(fx.tree(), before, "doctor changed the tree (root and home)");
    // only read-only questions, none allowed to raise a dialog, and polkit itself was never asked
    for call in served.fprintd.lock().unwrap().iter() {
        assert!(
            call == "GetDevices" || call == "ListEnrolledFingers",
            "fprintd was asked {call}"
        );
    }
    for call in served.service.lock().unwrap().iter() {
        assert!(
            call == "StateStorage" || call == "StateStorageReason",
            "the service was asked {call}"
        );
    }
    assert_eq!(
        served.polkit.lock().unwrap().as_slice(),
        Vec::<String>::new().as_slice(),
        "polkit was asked"
    );
    Run {
        text: out(&o),
        code: o.status.code().unwrap(),
        stderr: err(&o),
    }
}

/// Every check in `want` has this state word and (if given) a fix with this text; and the lines come in order.
fn expect(r: &Run, want: &[(&str, &str, Option<&str>)]) {
    let text = &r.text;
    let mut last = 0;
    for (name, word, fix) in want {
        assert_eq!(state(text, name), *word, "{name}:\n{text}");
        let fix_lines = fixes(text, name).join("\n");
        match fix {
            Some(needle) => assert!(fix_lines.contains(needle), "{name} fix {needle}:\n{text}"),
            None => assert!(fix_lines.is_empty(), "{name} has a fix:\n{text}"),
        }
        let at = text
            .lines()
            .position(|l| l.contains(&format!(" {name}: ")))
            .unwrap();
        assert!(at >= last, "{name} is out of order:\n{text}");
        last = at;
    }
}

fn custodios(fx: &Fx) {
    fx.put(POLKIT, std::str::from_utf8(file_bytes()).unwrap());
}

fn finger() -> Fake {
    Fake {
        fingers: Fingers::List(&["right-index-finger"]),
        ..Fake::new(1)
    }
}

fn register_profile(fx: &Fx, entry: bool) {
    let module = fx.path("usr/lib/custodio/libcustodio_pkcs11.so");
    fx.put("usr/lib/custodio/libcustodio_pkcs11.so", "module");
    let root = fx.home().join(".mozilla/firefox");
    fs::create_dir_all(root.join("a.default")).unwrap();
    fs::write(
        root.join("profiles.ini"),
        "[Profile0]\nName=n\nIsRelative=1\nPath=a.default\n",
    )
    .unwrap();
    let text = if entry {
        format!("library={}\nname=Custodio\n\n", module.display())
    } else {
        String::new()
    };
    fs::write(root.join("a.default/pkcs11.txt"), text).unwrap();
}

#[test]
fn everything_satisfied_is_exit_status_0_with_the_six_checks_in_order() {
    let r = run(
        |fx| {
            custodios(fx);
            register_profile(fx, true);
        },
        finger(),
    );
    expect(
        &r,
        &[
            (READER, "ok", None),
            (FINGER, "ok", None),
            (POLKIT_CHECK, "ok", None),
            (FIREFOX, "ok", None),
            (JOURNAL, "ok", None),
            (STORAGE, "ok", None),
        ],
    );
    assert_eq!((r.code, r.stderr.as_str()), (0, ""), "{}", r.text);
}

#[test]
fn no_reader_no_override_and_no_profile_leave_checks_1_to_3_unsatisfied_and_exit_status_0() {
    let r = run(|_| {}, Fake::new(0));
    expect(
        &r,
        &[
            (READER, "not ok", Some("Plug the reader in")),
            (FINGER, "could not check", Some("Fix the reader first")),
            (POLKIT_CHECK, "not ok", Some("custodio fingerprint enable")),
            (FIREFOX, "ok", None),
            (JOURNAL, "ok", None),
            (STORAGE, "ok", None),
        ],
    );
    assert!(r.text.contains("no browser profile"), "{}", r.text);
    assert_eq!(r.code, 0, "{}", r.text);
}

#[test]
fn fprintd_not_installed_and_no_finger_enrolled_are_unsatisfied_and_exit_status_0() {
    let r = run(
        |fx| fx.remove("usr/share/dbus-1/system-services/net.reactivated.Fprint.service"),
        Fake {
            fprintd: false,
            ..Fake::new(1)
        },
    );
    expect(
        &r,
        &[
            (READER, "not ok", Some("Install libpam-fprintd")),
            (FINGER, "could not check", Some("Fix the reader first")),
        ],
    );
    assert_eq!(r.code, 0, "{}", r.text);
    let r = run(|_| {}, Fake::new(1));
    expect(
        &r,
        &[
            (READER, "ok", None),
            (FINGER, "not ok", Some("fprintd-enroll")),
        ],
    );
    assert_eq!(r.code, 0);
}

#[test]
fn a_service_file_with_no_owner_is_could_not_check_on_check_1_and_exit_status_0() {
    let r = run(
        |fx| {
            custodios(fx);
            register_profile(fx, true);
        },
        Fake {
            fprintd: false,
            ..finger()
        },
    );
    expect(
        &r,
        &[
            (READER, "could not check", Some("fprintd")),
            (FIREFOX, "ok", None),
            (JOURNAL, "ok", None),
            (STORAGE, "ok", None),
        ],
    );
    assert_eq!(r.code, 0, "{}", r.text);
}

#[test]
fn a_refused_listing_is_could_not_check_and_exit_status_0() {
    let r = run(
        |_| {},
        Fake {
            fingers: Fingers::Refused,
            ..Fake::new(1)
        },
    );
    expect(
        &r,
        &[
            (READER, "ok", None),
            (FINGER, "could not check", Some("desktop session")),
        ],
    );
    assert!(r.text.contains("Not Authorized"), "{}", r.text);
    assert_eq!(r.code, 0);
}

#[test]
fn the_finger_active_elsewhere_is_ok_with_no_fix() {
    let r = run(|fx| fx.put("etc/pam.d/common-auth", GLOBAL_PAM), finger());
    expect(&r, &[(POLKIT_CHECK, "ok", None)]);
    assert!(
        section(&r.text, POLKIT_CHECK)[0].contains("whole system"),
        "{}",
        r.text
    );
    assert_eq!(r.code, 0);
}

#[test]
fn a_broken_include_is_first_and_exit_status_1_with_everything_else_ok() {
    let r = run(
        |fx| {
            custodios(fx);
            fx.remove("usr/lib/pam.d/polkit-1");
        },
        finger(),
    );
    assert!(
        r.text.lines().next().unwrap().contains(POLKIT_CHECK),
        "{}",
        r.text
    );
    expect(
        &r,
        &[
            (POLKIT_CHECK, "not ok", Some("Reinstall polkit")),
            (READER, "ok", None),
            (FINGER, "ok", None),
            (FIREFOX, "ok", None),
            (JOURNAL, "ok", None),
            (STORAGE, "ok", None),
        ],
    );
    assert_eq!(r.code, 1, "{}", r.text);
}

#[test]
fn an_unregistered_profile_is_not_ok_with_the_register_fix_and_exit_status_1() {
    let r = run(|fx| register_profile(fx, false), finger());
    expect(&r, &[(FIREFOX, "not ok", Some("custodio register"))]);
    assert_eq!(r.code, 1);
}

#[test]
fn a_malformed_profiles_ini_alone_is_could_not_check_and_exit_status_1() {
    let r = run(
        |fx| {
            fs::create_dir_all(fx.home().join(".mozilla/firefox")).unwrap();
            fs::write(fx.home().join(".mozilla/firefox/profiles.ini"), "[P\n\u{0}").unwrap();
        },
        finger(),
    );
    expect(
        &r,
        &[
            (FIREFOX, "could not check", Some("Fix or remove")),
            (JOURNAL, "ok", None),
            (STORAGE, "ok", None),
        ],
    );
    assert_eq!(r.code, 1);
}

#[test]
fn a_volatile_journal_alone_is_not_ok_and_exit_status_1() {
    let r = run(
        |fx| fx.put("etc/systemd/journald.conf", "[Journal]\nStorage=volatile\n"),
        finger(),
    );
    expect(
        &r,
        &[
            (FIREFOX, "ok", None),
            (JOURNAL, "not ok", Some("journald.conf:2")),
            (STORAGE, "ok", None),
        ],
    );
    assert_eq!(r.code, 1);
}

#[test]
fn a_journal_that_cannot_be_judged_alone_is_could_not_check_and_exit_status_1() {
    let r = run(|fx| fx.remove("etc/systemd/journald.conf"), finger());
    expect(
        &r,
        &[
            (JOURNAL, "could not check", Some("doctor")),
            (STORAGE, "ok", None),
        ],
    );
    assert_eq!(r.code, 1);
}

#[test]
fn storage_not_encrypted_alone_is_not_ok_and_exit_status_1() {
    let r = run(
        |_| {},
        Fake {
            service: Some(Svc::answering("not-encrypted", Some(""))),
            ..finger()
        },
    );
    expect(
        &r,
        &[
            (JOURNAL, "ok", None),
            (STORAGE, "not ok", Some("full-disk encryption")),
        ],
    );
    assert_eq!(r.code, 1);
}

#[test]
fn storage_unknown_alone_is_not_ok_with_the_reason_and_exit_status_1() {
    let r = run(
        |_| {},
        Fake {
            service: Some(Svc::answering("unknown", Some("no-mount"))),
            ..finger()
        },
    );
    expect(&r, &[(STORAGE, "not ok", Some("/proc"))]);
    assert_eq!(r.code, 1);
}

#[test]
fn an_unreachable_service_alone_is_could_not_check_and_exit_status_1() {
    let r = run(
        |_| {},
        Fake {
            service: None,
            ..finger()
        },
    );
    expect(
        &r,
        &[(STORAGE, "could not check", Some("custodio.service"))],
    );
    assert_eq!(r.code, 1);
}

#[test]
fn a_slow_service_is_could_not_check_and_the_other_checks_still_answer() {
    let mut svc = Svc::answering("encrypted", Some(""));
    svc.delay = Duration::from_millis(2500);
    let r = run(
        |_| {},
        Fake {
            service: Some(svc),
            ..finger()
        },
    );
    expect(
        &r,
        &[
            (FINGER, "ok", None),
            (STORAGE, "could not check", Some("custodio.service")),
        ],
    );
    assert_eq!(r.code, 1);
}

#[test]
fn doctor_refuses_root_with_two_lines_and_nothing_on_standard_output() {
    let fx = Fx::new();
    let bus = Bus::new();
    let served = serve_all(&bus.address, finger());
    let before = fx.tree();
    let o: Output = fx.doctor_as(&bus.address, "0");
    assert_eq!(fx.tree(), before);
    assert_ne!(o.status.code(), Some(0));
    assert!(out(&o).is_empty(), "{}", out(&o));
    assert_eq!(err(&o).lines().count(), 2, "{}", err(&o));
    assert!(served.fprintd.lock().unwrap().is_empty() && served.service.lock().unwrap().is_empty());
}

#[test]
fn the_polkit_recorder_records_a_call_so_that_an_empty_record_means_something() {
    // The control of "no polkit request was made": a direct CheckAuthorization call is recorded.
    let bus = Bus::new();
    let served = serve_all(&bus.address, Fake::new(0));
    let connection =
        zbus::block_on(zbus::connection::Builder::address(bus.address.as_str()).build()).unwrap();
    let subject = (
        "unix-process",
        std::collections::HashMap::<String, zbus::Variant<'_>>::new(),
    );
    zbus::block_on(connection.call_method(
        Some("org.freedesktop.PolicyKit1"),
        "/org/freedesktop/PolicyKit1/Authority",
        Some("org.freedesktop.PolicyKit1.Authority"),
        "CheckAuthorization",
        &(
            subject,
            "com.rfirma.custodio.sign",
            std::collections::HashMap::<String, String>::new(),
            0u32,
            "",
        ),
    ))
    .unwrap();
    assert_eq!(
        served.polkit.lock().unwrap().as_slice(),
        ["CheckAuthorization com.rfirma.custodio.sign"]
    );
}
