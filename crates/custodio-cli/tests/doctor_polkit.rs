//! `custodio doctor`, check 3 (fingerprint active for polkit), one fixture root per state. The fake `fprintd` answers
//! nothing here (no bus), except where a case needs checks 1 and 2 satisfied or not.

mod fprint_fixture;

use std::fs;
use std::process::Output;

use custodio_cli::fingerprint_decide::file_bytes;
use fprint_fixture::{
    Bus, Fake, Fingers, Fx, GLOBAL_FORMS, NO_BUS, OMARCHY, POLKIT, POLKIT_CHECK, err, fixes, out,
    section, serve, state,
};

const VENDOR: &str = "usr/lib/pam.d/polkit-1";
const ASKS_TWICE: &str = "asked twice";

fn doctor(fx: &Fx, bus: &str) -> (Output, String) {
    let before = fx.tree();
    // Checks 4 to 6 are satisfied (a fake service answers `encrypted`) so that the exit status is check 3's alone;
    // `NO_BUS` means "nothing to say about checks 1 and 2" here: a bus whose fprintd lists no reader.
    let private = (bus == NO_BUS).then(Bus::new);
    let address = private.as_ref().map_or(bus, |b| b.address.as_str());
    if private.is_some() {
        serve(address, Fake::new(0));
    }
    let o = fx.doctor(address);
    assert_eq!(fx.tree(), before, "doctor changed the tree");
    assert!(err(&o).lines().count() != 1, "{}", err(&o));
    let text = out(&o);
    (o, text)
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap()
}

fn custodios(fx: &Fx) {
    fx.put(POLKIT, std::str::from_utf8(file_bytes()).unwrap());
}

fn polkit_text(text: &str) -> String {
    section(text, POLKIT_CHECK).join("\n")
}

#[test]
fn custodios_override_with_its_vendor_file_is_active_and_has_no_warning() {
    let fx = Fx::new();
    custodios(&fx);
    let (o, text) = doctor(&fx, NO_BUS);
    assert_eq!(state(&text, POLKIT_CHECK), "ok", "{text}");
    assert!(polkit_text(&text).contains("Custodio's override"), "{text}");
    assert!(fixes(&text, POLKIT_CHECK).is_empty(), "{text}");
    assert!(!text.contains("warning"), "each alone: {text}");
    assert_eq!(code(&o), 0);
}

fn broken_include(setup: impl FnOnce(&Fx), why: &str) {
    let fx = Fx::new();
    custodios(&fx);
    setup(&fx);
    let (o, text) = doctor(&fx, NO_BUS);
    let first = text.lines().next().unwrap();
    assert!(
        first.starts_with("not ok") && first.contains(POLKIT_CHECK),
        "{text}"
    );
    assert!(first.contains(why), "{first}");
    let fix = fixes(&text, POLKIT_CHECK);
    assert_eq!(fix.len(), 1, "{text}");
    assert!(fix[0].contains("Reinstall polkit"), "{text}");
    assert_eq!(code(&o), 1, "{text}");
    assert_eq!(err(&o).lines().count(), 2, "{}", err(&o));
}

#[test]
fn a_missing_vendor_file_is_the_first_line_and_the_exit_status_is_1() {
    broken_include(|fx| fx.remove(VENDOR), "missing");
}

#[test]
fn a_vendor_file_that_is_not_a_regular_file_is_the_first_line_too() {
    broken_include(
        |fx| {
            fx.remove(VENDOR);
            fs::create_dir(fx.path(VENDOR)).unwrap();
        },
        "not a regular file",
    );
}

#[test]
fn a_vendor_less_root_without_the_override_is_not_a_broken_include() {
    let fx = Fx::new();
    fx.remove(VENDOR);
    let (o, text) = doctor(&fx, NO_BUS);
    assert_eq!(state(&text, POLKIT_CHECK), "not ok", "{text}");
    assert!(!polkit_text(&text).contains("includes"), "{text}");
    assert!(
        !text.lines().next().unwrap().contains(POLKIT_CHECK),
        "{text}"
    );
    assert_eq!(code(&o), 0);
}

fn broken_include_exit(fake: Fake) {
    let fx = Fx::new();
    custodios(&fx);
    fx.remove(VENDOR);
    let bus = Bus::new();
    serve(&bus.address, fake);
    let (o, text) = doctor(&fx, &bus.address);
    assert_eq!(code(&o), 1, "{text}");
    assert!(
        text.lines().next().unwrap().contains(POLKIT_CHECK),
        "{text}"
    );
}

#[test]
fn a_broken_include_is_exit_status_1_with_everything_else_satisfied() {
    broken_include_exit(Fake {
        fingers: Fingers::List(&["left-thumb"]),
        ..Fake::new(1)
    });
}

#[test]
fn a_broken_include_is_exit_status_1_with_no_reader() {
    broken_include_exit(Fake::new(0));
}

#[test]
fn someone_elses_file_with_an_auth_line_is_active_through_that_file() {
    let fx = Fx::new();
    fx.put(POLKIT, OMARCHY);
    let (o, text) = doctor(&fx, NO_BUS);
    assert_eq!(state(&text, POLKIT_CHECK), "ok", "{text}");
    assert!(polkit_text(&text).contains("not Custodio's"), "{text}");
    assert!(!text.contains("warning"), "each alone: {text}");
    assert_eq!(code(&o), 0);
}

fn not_active(text: &str) {
    let fx = Fx::new();
    fx.put(POLKIT, text);
    let (o, out) = doctor(&fx, NO_BUS);
    assert_eq!(state(&out, POLKIT_CHECK), "not ok", "{text}: {out}");
    assert_eq!(code(&o), 0);
}

#[test]
fn a_file_with_the_module_only_in_a_comment_is_not_active() {
    not_active("#%PAM-1.0\n# auth sufficient pam_fprintd.so\nauth include system-auth\n");
}

#[test]
fn a_file_with_the_module_only_in_an_account_line_is_not_active() {
    not_active("auth include system-auth\naccount sufficient pam_fprintd.so\n");
}

#[test]
fn a_dash_auth_line_counts_as_active_as_enable_reads_it() {
    // `-auth` is an auth line to PAM and to `first_fprintd_auth_line`, which `enable` uses.
    let fx = Fx::new();
    fx.put(
        POLKIT,
        "-auth sufficient pam_fprintd.so\nauth include system-auth\n",
    );
    let (o, text) = doctor(&fx, NO_BUS);
    assert_eq!(state(&text, POLKIT_CHECK), "ok", "{text}");
    assert!(polkit_text(&text).contains("not Custodio's"), "{text}");
    assert_eq!(code(&o), 0);
}

fn global_on(i: usize, named: &str) {
    let (os, file, content) = GLOBAL_FORMS[i];
    let fx = Fx::new();
    fx.put("etc/os-release", os);
    fx.put(file, content);
    let (o, text) = doctor(&fx, NO_BUS);
    assert_eq!(state(&text, POLKIT_CHECK), "ok", "{file}: {text}");
    let line = polkit_text(&text);
    assert!(
        line.contains("whole system")
            && line.contains("sudo uses the finger too")
            && line.contains(named),
        "{file}: {line}"
    );
    assert!(!text.contains("warning"), "global alone: {text}");
    assert_eq!(code(&o), 0);
}

#[test]
fn fingerprint_for_the_whole_system_says_sudo_uses_the_finger_too_on_debian() {
    global_on(0, "common-auth");
}

#[test]
fn fingerprint_for_the_whole_system_says_sudo_uses_the_finger_too_on_fedora() {
    global_on(1, "authselect");
}

#[test]
fn fingerprint_for_the_whole_system_says_sudo_uses_the_finger_too_on_arch_system_auth() {
    global_on(2, "system-auth");
}

#[test]
fn fingerprint_for_the_whole_system_says_sudo_uses_the_finger_too_on_arch_sudo() {
    global_on(3, "pam.d/sudo");
}

#[test]
fn nothing_active_says_how_to_enable_it() {
    let fx = Fx::new();
    let (o, text) = doctor(&fx, NO_BUS);
    assert_eq!(state(&text, POLKIT_CHECK), "not ok", "{text}");
    let fix = fixes(&text, POLKIT_CHECK);
    assert_eq!(fix.len(), 1, "{text}");
    assert!(
        fix[0].contains("sudo custodio fingerprint enable"),
        "{text}"
    );
    assert_eq!(code(&o), 0);
}

fn combination(own: &str) -> (Output, String) {
    let fx = Fx::new();
    fx.put(POLKIT, own);
    fx.put("etc/pam.d/common-auth", fprint_fixture::GLOBAL_PAM);
    doctor(&fx, NO_BUS)
}

#[test]
fn custodios_override_with_common_auth_is_a_warning_with_the_disable_fix_and_exit_status_0() {
    let (o, text) = combination(std::str::from_utf8(file_bytes()).unwrap());
    let lines = section(&text, POLKIT_CHECK).join("\n");
    assert!(
        lines.contains("warning") && lines.contains(ASKS_TWICE),
        "{text}"
    );
    assert!(
        lines.contains("fix: sudo custodio fingerprint disable"),
        "{text}"
    );
    assert_eq!(state(&text, POLKIT_CHECK), "ok", "{text}");
    assert_eq!(code(&o), 0, "the warning does not count");
}

#[test]
fn someone_elses_file_with_common_auth_is_a_warning_with_the_two_other_fixes() {
    let (o, text) = combination(OMARCHY);
    let lines = section(&text, POLKIT_CHECK).join("\n");
    assert!(
        lines.contains("warning") && lines.contains(ASKS_TWICE),
        "{text}"
    );
    assert!(
        lines.contains("remove the pam_fprintd.so line")
            && lines.contains("pam-auth-update --disable fprintd"),
        "{text}"
    );
    assert!(!lines.contains("custodio fingerprint disable"), "{text}");
    assert_eq!(code(&o), 0);
}
