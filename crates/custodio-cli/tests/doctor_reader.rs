//! `custodio doctor`, checks 1 and 2 (the reader and the enrolled finger) and what the command promises about
//! itself (root, read-only, no prompt), against fixture roots and a fake `fprintd` on a private bus.

mod fprint_fixture;

use std::time::{Duration, Instant};

use fprint_fixture::{
    Bus, FINGER, Fake, Fingers, Fx, NO_BUS, READER, err, fixes, out, section, serve, state,
};

const SERVICE: &str = "usr/share/dbus-1/system-services/net.reactivated.Fprint.service";

/// Runs doctor on `fx` against `bus`, and checks what every run promises: the tree is the same afterwards, the
/// run is short, and standard error is empty.
fn doctor(fx: &Fx, bus: &str) -> (std::process::Output, String) {
    let before = fx.tree();
    let started = Instant::now();
    let o = fx.doctor(bus);
    assert!(
        started.elapsed() < Duration::from_secs(8),
        "doctor took too long"
    );
    assert_eq!(fx.tree(), before, "doctor changed the tree");
    let text = out(&o);
    // Checks 1 and 2 never write to standard error; a bus with no Custodio service leaves check 6 `could not check`,
    // which is the one thing doctor may say there (and exit 1 for).
    let e = err(&o);
    assert!(e.is_empty() || e.contains("checks 4 to 6"), "{e}");
    (o, text)
}

fn exit(o: &std::process::Output) -> i32 {
    o.status.code().unwrap()
}

#[test]
fn a_reader_and_an_enrolled_finger_are_ok_and_only_the_two_questions_are_asked() {
    let fx = Fx::new();
    let bus = Bus::new();
    let calls = serve(
        &bus.address,
        Fake {
            fingers: Fingers::List(&["right-index-finger", "left-thumb"]),
            ..Fake::new(1)
        },
    );
    let (o, text) = doctor(&fx, &bus.address);
    assert_eq!(state(&text, READER), "ok", "{text}");
    assert_eq!(state(&text, FINGER), "ok", "{text}");
    assert!(section(&text, FINGER)[0].contains("2 fingers"), "{text}");
    assert!(
        fixes(&text, READER).is_empty() && fixes(&text, FINGER).is_empty(),
        "{text}"
    );
    assert_eq!(exit(&o), 0);
    // no Claim, no VerifyStart, and no call allowed to ask polkit
    assert_eq!(
        calls.lock().unwrap().as_slice(),
        ["GetDevices", "ListEnrolledFingers"]
    );
}

#[test]
fn the_fake_records_the_flag_that_allows_a_polkit_dialog() {
    // The control of the assertion above: a call that sets the flag shows up in the record.
    let bus = Bus::new();
    let calls = serve(&bus.address, Fake::new(1));
    let connection =
        zbus::block_on(zbus::connection::Builder::address(bus.address.as_str()).build()).unwrap();
    let message =
        zbus::message::Message::method_call("/net/reactivated/Fprint/Manager", "GetDevices")
            .destination("net.reactivated.Fprint")
            .interface("net.reactivated.Fprint.Manager")
            .with_flags(zbus::message::Flags::ALLOW_INTERACTIVE_AUTH)
            .build(&())
            .unwrap();
    zbus::block_on(connection.send(&message)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while calls.lock().unwrap().is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(calls.lock().unwrap().as_slice(), ["GetDevices interactive"]);
}

#[test]
fn no_device_is_not_ok_with_its_fix_and_the_finger_could_not_be_checked() {
    let fx = Fx::new();
    let bus = Bus::new();
    let calls = serve(&bus.address, Fake::new(0));
    let (o, text) = doctor(&fx, &bus.address);
    assert_eq!(state(&text, READER), "not ok", "{text}");
    assert_eq!(fixes(&text, READER).len(), 1, "{text}");
    assert_eq!(state(&text, FINGER), "could not check", "{text}");
    assert!(section(&text, FINGER)[0].contains("no reader"), "{text}");
    assert_eq!(exit(&o), 0, "the fingerprint is optional");
    assert_eq!(calls.lock().unwrap().as_slice(), ["GetDevices"]);
}

fn not_installed(os: &str, must: &[&str], must_not: &[&str]) {
    let bus = Bus::new();
    let fx = Fx::new();
    fx.put("etc/os-release", os);
    fx.remove(SERVICE);
    let (o, text) = doctor(&fx, &bus.address);
    assert_eq!(state(&text, READER), "not ok", "{os}: {text}");
    let fix = fixes(&text, READER).join("\n");
    assert!(
        must.iter().all(|p| fix.contains(p)) && !must_not.iter().any(|p| fix.contains(p)),
        "{os}: {fix}"
    );
    assert_eq!(
        exit(&o),
        1,
        "checks 1 to 3 do not count; check 6 has no service on this bus"
    );
}

#[test]
fn fprintd_not_installed_names_the_debian_packages() {
    not_installed(
        "ID=ubuntu\nID_LIKE=debian\n",
        &["libpam-fprintd"],
        &["fprintd-pam"],
    );
}

#[test]
fn fprintd_not_installed_names_the_fedora_packages() {
    not_installed(
        "ID=\"almalinux\"\nID_LIKE=\"rhel centos fedora\"\n",
        &["fprintd-pam"],
        &["libpam-fprintd"],
    );
}

#[test]
fn fprintd_not_installed_names_the_arch_package() {
    not_installed("ID=arch\n", &["Install fprintd."], &["pam"]);
}

#[test]
fn fprintd_not_installed_on_an_unknown_family_names_all_three() {
    not_installed(
        "ID=plan9\n",
        &["libpam-fprintd", "fprintd-pam", "fprintd (Arch)"],
        &[],
    );
}

#[test]
fn a_service_file_with_no_owner_is_could_not_check_not_missing() {
    let fx = Fx::new();
    let bus = Bus::new();
    let (o, text) = doctor(&fx, &bus.address);
    assert_eq!(state(&text, READER), "could not check", "{text}");
    assert_eq!(
        exit(&o),
        1,
        "checks 1 to 3 do not count; check 6 has no service on this bus"
    );
}

#[test]
fn a_bus_that_cannot_be_reached_is_could_not_check_with_the_reason() {
    let fx = Fx::new();
    let (o, text) = doctor(&fx, NO_BUS);
    assert_eq!(state(&text, READER), "could not check", "{text}");
    assert!(
        section(&text, READER)[0].contains("could not ask fprintd:"),
        "{text}"
    );
    assert_eq!(
        exit(&o),
        1,
        "checks 1 to 3 do not count; check 6 has no service on this bus"
    );
}

#[test]
fn a_name_that_is_there_and_does_not_answer_is_could_not_check_even_without_a_service_file() {
    let fx = Fx::new();
    fx.remove(SERVICE);
    let bus = Bus::new();
    // the limit is 1.5 s; the fake answers after 3
    serve(
        &bus.address,
        Fake {
            delay: Duration::from_secs(3),
            ..Fake::new(1)
        },
    );
    let (o, text) = doctor(&fx, &bus.address);
    assert_eq!(state(&text, READER), "could not check", "{text}");
    assert!(
        section(&text, READER)[0].contains("no answer within 1500 ms"),
        "{text}"
    );
    assert_eq!(state(&text, FINGER), "could not check", "{text}");
    assert_eq!(exit(&o), 0);
}

#[test]
fn an_error_from_a_name_that_is_there_is_could_not_check_even_without_a_service_file() {
    let fx = Fx::new();
    fx.remove(SERVICE);
    let bus = Bus::new();
    serve(
        &bus.address,
        Fake {
            devices_error: true,
            ..Fake::new(1)
        },
    );
    let (o, text) = doctor(&fx, &bus.address);
    assert_eq!(state(&text, READER), "could not check", "{text}");
    assert!(
        section(&text, READER)[0].contains("the manager is broken"),
        "{text}"
    );
    assert_eq!(exit(&o), 0);
}

fn finger_case(fingers: Fingers) -> (std::process::Output, String, Vec<String>) {
    let fx = Fx::new();
    let bus = Bus::new();
    let calls = serve(
        &bus.address,
        Fake {
            fingers,
            ..Fake::new(1)
        },
    );
    let (o, text) = doctor(&fx, &bus.address);
    let calls = calls.lock().unwrap().clone();
    (o, text, calls)
}

#[test]
fn no_enrolled_prints_is_not_ok_with_the_way_to_enrol() {
    let (o, text, _) = finger_case(Fingers::NoPrints);
    assert_eq!(state(&text, FINGER), "not ok", "{text}");
    let fix = fixes(&text, FINGER).join("\n");
    assert!(
        fix.contains("fprintd-enroll") && fix.contains("Fingerprint Login"),
        "{fix}"
    );
    assert_eq!(exit(&o), 0);
}

#[test]
fn a_refusal_to_answer_is_could_not_check_never_missing() {
    let (o, text, calls) = finger_case(Fingers::Refused);
    assert_eq!(state(&text, FINGER), "could not check", "{text}");
    let line = &section(&text, FINGER)[0];
    assert!(
        line.contains("Not Authorized: net.reactivated.fprint.device.verify"),
        "{line}"
    );
    assert!(
        !line.contains("missing") && !line.contains("no finger"),
        "{line}"
    );
    assert_eq!(exit(&o), 0, "could not check on the finger does not count");
    assert_eq!(
        calls,
        ["GetDevices", "ListEnrolledFingers"],
        "no polkit flag"
    );
}

#[test]
fn another_error_is_could_not_check() {
    let (o, text, _) = finger_case(Fingers::Other);
    assert_eq!(state(&text, FINGER), "could not check", "{text}");
    assert!(
        section(&text, FINGER)[0].contains("the device is broken"),
        "{text}"
    );
    assert_eq!(exit(&o), 0);
}

#[test]
fn a_slow_listing_is_could_not_check() {
    let fx = Fx::new();
    let bus = Bus::new();
    serve(
        &bus.address,
        Fake {
            fingers: Fingers::List(&["left-thumb"]),
            fingers_delay: Duration::from_secs(3),
            ..Fake::new(1)
        },
    );
    let (o, text) = doctor(&fx, &bus.address);
    assert_eq!(state(&text, READER), "ok", "{text}");
    assert_eq!(state(&text, FINGER), "could not check", "{text}");
    assert_eq!(exit(&o), 0);
}

#[test]
fn doctor_refuses_root_with_two_lines_and_writes_nothing() {
    let fx = Fx::new();
    let bus = Bus::new();
    let calls = serve(&bus.address, Fake::new(1));
    let before = fx.tree();
    let o = fx.doctor_as(&bus.address, "0");
    assert_eq!(exit(&o), 2);
    assert_eq!(out(&o), "");
    assert_eq!(err(&o).lines().count(), 2, "{}", err(&o));
    assert!(err(&o).contains("refused to run as root"), "{}", err(&o));
    assert_eq!(fx.tree(), before);
    assert!(
        calls.lock().unwrap().is_empty(),
        "nothing was asked of fprintd"
    );
    // control: the same root and bus as the person
    assert_eq!(exit(&fx.doctor(&bus.address)), 0);
}

#[test]
fn an_extra_argument_is_a_usage_error() {
    let o = std::process::Command::new(env!("CARGO_BIN_EXE_custodio-cli"))
        .args(["doctor", "extra"])
        .output()
        .unwrap();
    assert_eq!(exit(&o), 2);
    assert!(err(&o).contains("custodio doctor --help"), "{}", err(&o));
}
