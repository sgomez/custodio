//! `custodio fingerprint enable` and `disable` against a fixture file system: the binary is built with the
//! `fixture-root` seam (a dev-dependency of the crate on itself), so every path is under a temporary root.
//! Owner `root:root` and the `SELinux` label need a real `/etc`: F199 proves them.

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::Duration;

use custodio_cli::fingerprint_decide::file_bytes;

mod fprint_fixture;

use fprint_fixture::{
    Bus, Fx, GLOBAL_FORMS, MULTIARCH, OMARCHY, POLKIT, Tree, err, fake_fprintd, out,
};

/// Restores a directory's mode on drop, so a failed assert still lets the temporary tree be deleted.
struct RestoreMode(PathBuf);

impl Drop for RestoreMode {
    fn drop(&mut self) {
        let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o755));
    }
}

/// The command refused: non-zero, a message of at least two lines naming the next step, nothing changed.
fn assert_refused(fx: &Fx, args: &[&str], before: &Tree, what: &str) -> String {
    let o = fx.run(args);
    assert_ne!(o.status.code(), Some(0), "{what}: {}", out(&o));
    let e = err(&o);
    assert!(e.lines().count() >= 2, "{what}: {e}");
    assert!(e.starts_with("custodio"), "{what}: {e}");
    assert_eq!(&fx.tree(), before, "{what}: the tree changed");
    e
}

const WARNING: &str = "no fingerprint reader";

// ---- acceptance 1 ----

#[test]
fn enable_writes_the_exact_file_and_a_second_run_changes_nothing() {
    let fx = Fx::new();
    let bus = Bus::new();
    let calls = fake_fprintd(&bus.address, 1, Duration::ZERO);
    let before = fx.tree();
    // umask 077 would make the file 0600 if the mode were only asked for
    let run = |fx: &Fx| {
        Command::new("sh")
            .args([
                "-c",
                "umask 077; exec \"$0\" fingerprint enable",
                env!("CARGO_BIN_EXE_custodio-cli"),
            ])
            .env("CUSTODIO_FIXTURE_ROOT", fx.root())
            .env("CUSTODIO_FIXTURE_EUID", "0")
            .env("DBUS_SYSTEM_BUS_ADDRESS", &bus.address)
            .output()
            .unwrap()
    };
    let first = run(&fx);
    assert_eq!(first.status.code(), Some(0), "{}", err(&first));
    assert!(!err(&first).contains(WARNING), "{}", err(&first));
    assert_eq!(fs::read(fx.path(POLKIT)).unwrap(), file_bytes());
    assert_eq!(
        fs::metadata(fx.path(POLKIT)).unwrap().permissions().mode() & 0o7777,
        0o644
    );
    let mut expected = before.clone();
    expected.insert(
        POLKIT.into(),
        ("file".into(), file_bytes().to_vec(), 0o100_644),
    );
    assert_eq!(fx.tree(), expected, "only the override was added");
    let text = out(&first);
    for part in [
        "Every polkit dialog",
        "accepts a finger",
        "A wrong finger, or 10 s without a touch, falls back to the password",
        "sudo and the login are unchanged",
        "sudo custodio fingerprint disable",
    ] {
        assert!(text.contains(part), "{part}: {text}");
    }
    let after_first = fx.tree();
    let second = run(&fx);
    assert_eq!(second.status.code(), Some(0));
    assert!(
        out(&second).contains("nothing was changed"),
        "{}",
        out(&second)
    );
    assert_eq!(fx.tree(), after_first);
    assert_eq!(
        calls.lock().unwrap().as_slice(),
        ["GetDevices"],
        "only the listing is asked, once"
    );
}

// ---- the device probe ----

fn enable_on(address: &str) -> (Fx, Output) {
    let fx = Fx::new();
    let o = fx.run_with(&["enable"], &[("DBUS_SYSTEM_BUS_ADDRESS", address)]);
    (fx, o)
}

fn assert_written_with_warning(fx: &Fx, o: &Output) {
    assert_eq!(o.status.code(), Some(0), "{}", err(o));
    assert_eq!(fs::read(fx.path(POLKIT)).unwrap(), file_bytes());
    let e = err(o);
    assert!(
        e.contains(WARNING) && e.contains("custodio doctor") && e.contains("password"),
        "{e}"
    );
}

#[test]
fn a_zero_device_listing_is_a_warning() {
    let bus = Bus::new();
    let calls = fake_fprintd(&bus.address, 0, Duration::ZERO);
    let (fx, o) = enable_on(&bus.address);
    assert_written_with_warning(&fx, &o);
    assert_eq!(calls.lock().unwrap().as_slice(), ["GetDevices"]);
}

#[test]
fn no_name_owner_is_a_warning_not_a_refusal() {
    let bus = Bus::new();
    let (fx, o) = enable_on(&bus.address);
    assert_written_with_warning(&fx, &o);
}

#[test]
fn a_bus_that_does_not_exist_is_a_warning_not_a_refusal() {
    let (fx, o) = enable_on("unix:path=/nonexistent/custodio-bus");
    assert_written_with_warning(&fx, &o);
}

#[test]
fn an_answer_after_the_limit_is_a_warning_not_a_refusal() {
    let bus = Bus::new();
    // the probe waits 1.5 s
    let calls = fake_fprintd(&bus.address, 1, Duration::from_millis(2000));
    let (fx, o) = enable_on(&bus.address);
    assert_written_with_warning(&fx, &o);
    assert_eq!(calls.lock().unwrap().as_slice(), ["GetDevices"]);
}

// ---- the lock-screen note ----

const SCHEMA: &str = "usr/share/glib-2.0/schemas/org.gnome.login-screen.gschema.xml";

#[test]
fn the_lock_screen_note_is_shown_on_gnome_and_changes_no_setting() {
    let fx = Fx::new();
    fx.put(SCHEMA, "<schemalist/>");
    fx.put(
        "etc/dconf/db/local.d/00-other",
        "[org/gnome/desktop]\nx=true\n",
    );
    let mut expected = fx.tree();
    let o = fx.run(&["enable"]);
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    assert!(out(&o).contains("lock screen"), "{}", out(&o));
    expected.insert(
        POLKIT.into(),
        ("file".into(), file_bytes().to_vec(), 0o100_644),
    );
    assert_eq!(
        fx.tree(),
        expected,
        "only the override was added: no dconf file changed"
    );
}

#[test]
fn the_lock_screen_note_is_not_shown_when_the_key_is_set_false() {
    let fx = Fx::new();
    fx.put(SCHEMA, "<schemalist/>");
    fx.put(
        "etc/dconf/db/local.d/10-fp",
        "[org/gnome/login-screen]\nenable-fingerprint-authentication=false\n",
    );
    let o = fx.run(&["enable"]);
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    assert!(!out(&o).contains("lock screen"), "{}", out(&o));
}

// ---- atomic write ----

fn failed_step_leaves_nothing(step: &str) {
    let fx = Fx::new();
    let before = fx.tree();
    let o = fx.run_with(
        &["enable"],
        &[
            ("DBUS_SYSTEM_BUS_ADDRESS", &fx.no_bus()),
            ("CUSTODIO_FIXTURE_FAIL", step),
        ],
    );
    assert_ne!(o.status.code(), Some(0), "{step}");
    assert!(err(&o).lines().count() >= 2, "{step}: {}", err(&o));
    assert!(!fx.path(POLKIT).exists(), "{step}");
    assert_eq!(fx.tree(), before, "{step}: a file was left behind");
}

#[test]
fn a_failed_rename_leaves_no_file_and_no_temporary_file() {
    failed_step_leaves_nothing("rename");
}

#[test]
fn a_failed_flush_takes_the_file_back() {
    failed_step_leaves_nothing("flush");
}

#[test]
fn a_failed_label_leaves_no_file_and_no_temporary_file() {
    failed_step_leaves_nothing("label");
}

#[test]
fn an_unwritable_pam_directory_is_refused_and_nothing_is_created() {
    assert_ne!(
        rustix::process::geteuid().as_raw(),
        0,
        "the suite must run unprivileged"
    );
    let fx = Fx::new();
    let _restore = RestoreMode(fx.path("etc/pam.d"));
    fs::set_permissions(fx.path("etc/pam.d"), fs::Permissions::from_mode(0o555)).unwrap();
    let before = fx.tree();
    let e = assert_refused(&fx, &["enable"], &before, "unwritable");
    assert!(e.contains("custodio fingerprint"), "{e}");
}

// ---- not root ----

fn not_root_is_refused(action: &str) {
    assert_ne!(
        rustix::process::geteuid().as_raw(),
        0,
        "the suite must run unprivileged"
    );
    let fx = Fx::new();
    let before = fx.tree();
    let o = Command::new(env!("CARGO_BIN_EXE_custodio-cli"))
        .args(["fingerprint", action])
        .env("CUSTODIO_FIXTURE_ROOT", fx.root())
        .env_remove("CUSTODIO_FIXTURE_EUID")
        .env("DBUS_SYSTEM_BUS_ADDRESS", fx.no_bus())
        .output()
        .unwrap();
    assert_ne!(o.status.code(), Some(0), "{action}");
    assert!(
        err(&o).contains("must run as root") && err(&o).lines().count() == 2,
        "{}",
        err(&o)
    );
    assert_eq!(fx.tree(), before);
}

#[test]
fn enable_is_refused_by_the_real_uid() {
    not_root_is_refused("enable");
}

#[test]
fn disable_is_refused_by_the_real_uid() {
    not_root_is_refused("disable");
}

// ---- acceptance 2: every other refusal ----

fn refused_with(what: &str, setup: impl FnOnce(&Fx)) -> String {
    let fx = Fx::new();
    setup(&fx);
    let before = fx.tree();
    assert_refused(&fx, &["enable"], &before, what)
}

#[test]
fn an_omarchy_style_file_is_refused() {
    refused_with("omarchy", |fx| fx.put(POLKIT, OMARCHY));
}

#[test]
fn an_administrators_file_is_refused() {
    refused_with("administrator", |fx| {
        fx.put(POLKIT, "#%PAM-1.0\nauth include system-auth\n");
    });
}

#[test]
fn a_file_with_one_byte_changed_is_refused() {
    let mut changed = file_bytes().to_vec();
    changed[40] ^= 1;
    refused_with("one byte changed", |fx| {
        fs::write(fx.path(POLKIT), &changed).unwrap();
    });
}

#[test]
fn a_symlink_to_a_custodio_file_is_refused() {
    refused_with("symlink to a custodio file", |fx| {
        fs::write(fx.path("elsewhere"), file_bytes()).unwrap();
        symlink("../../elsewhere", fx.path(POLKIT)).unwrap();
    });
}

#[test]
fn a_symlink_to_nothing_is_refused() {
    refused_with("symlink to nothing", |fx| {
        symlink("/nonexistent/x", fx.path(POLKIT)).unwrap();
    });
}

#[test]
fn no_vendor_file_is_refused() {
    refused_with("no vendor file", |fx| fx.remove("usr/lib/pam.d/polkit-1"));
}

#[test]
fn a_vendor_file_that_is_a_directory_is_refused() {
    refused_with("vendor is a directory", |fx| {
        fx.remove("usr/lib/pam.d/polkit-1");
        fs::create_dir(fx.path("usr/lib/pam.d/polkit-1")).unwrap();
    });
}

#[test]
fn no_module_is_refused_naming_the_package() {
    let e = refused_with("no module", |fx| {
        fx.remove(&format!("{MULTIARCH}/pam_fprintd.so"));
    });
    assert!(e.contains("libpam-fprintd"), "{e}");
}

#[test]
fn no_fprintd_is_refused() {
    refused_with("no fprintd", |fx| {
        fx.remove("usr/share/dbus-1/system-services/net.reactivated.Fprint.service");
    });
}

fn module_found_only_in(dir: &str) {
    let fx = Fx::new();
    fx.remove(&format!("{MULTIARCH}/pam_fprintd.so"));
    let before = fx.tree();
    assert_refused(&fx, &["enable"], &before, &format!("absent from {dir}"));
    fx.put(&format!("{dir}/pam_fprintd.so"), "module");
    let o = fx.run(&["enable"]);
    assert_eq!(o.status.code(), Some(0), "present in {dir}: {}", err(&o));
    assert_eq!(fs::read(fx.path(POLKIT)).unwrap(), file_bytes());
}

#[test]
fn the_module_is_found_in_the_multiarch_layout() {
    module_found_only_in(MULTIARCH);
}

#[test]
fn the_module_is_found_in_usr_lib64() {
    module_found_only_in("usr/lib64/security");
}

#[test]
fn the_module_is_found_in_usr_lib() {
    module_found_only_in("usr/lib/security");
}

// ---- acceptance 3: fingerprint already global ----

fn global_form_refused((os, file, text): (&str, &str, &str)) {
    let fx = Fx::new();
    fx.put("etc/os-release", os);
    fx.put(file, text);
    let before = fx.tree();
    let e = assert_refused(&fx, &["enable"], &before, file);
    assert!(
        e.contains("redundant") && e.contains("Turn the global switch off"),
        "{file}: {e}"
    );
}

#[test]
fn global_fingerprint_on_debian_is_refused_as_redundant() {
    global_form_refused(GLOBAL_FORMS[0]);
}

#[test]
fn global_fingerprint_on_fedora_is_refused_as_redundant() {
    global_form_refused(GLOBAL_FORMS[1]);
}

#[test]
fn global_fingerprint_in_arch_system_auth_is_refused_as_redundant() {
    global_form_refused(GLOBAL_FORMS[2]);
}

#[test]
fn global_fingerprint_in_arch_sudo_is_refused_as_redundant() {
    global_form_refused(GLOBAL_FORMS[3]);
}

// ---- acceptance 4: disable ----

#[test]
fn disable_removes_only_custodios_file() {
    let fx = Fx::new();
    let before = fx.tree();
    fs::write(fx.path(POLKIT), file_bytes()).unwrap();
    let o = fx.run(&["disable"]);
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    assert!(out(&o).contains("Removed"), "{}", out(&o));
    assert_eq!(fx.tree(), before);
}

#[test]
fn disable_with_no_file_says_so_and_changes_nothing() {
    let fx = Fx::new();
    let before = fx.tree();
    let o = fx.run(&["disable"]);
    assert_eq!(o.status.code(), Some(0));
    assert!(out(&o).contains("nothing to disable"), "{}", out(&o));
    assert_eq!(fx.tree(), before);
}

#[test]
fn disable_refuses_a_foreign_file() {
    let fx = Fx::new();
    fx.put(POLKIT, OMARCHY);
    let before = fx.tree();
    let e = assert_refused(&fx, &["disable"], &before, "foreign");
    assert!(e.contains("dpkg -S") && e.contains("pacman -Qo"), "{e}");
}

#[test]
fn a_file_that_cannot_be_looked_at_is_not_taken_for_missing() {
    assert_ne!(
        rustix::process::geteuid().as_raw(),
        0,
        "the suite must run unprivileged"
    );
    let fx = Fx::new();
    let _restore = RestoreMode(fx.path("etc/pam.d"));
    fs::set_permissions(fx.path("etc/pam.d"), fs::Permissions::from_mode(0o000)).unwrap();
    let o = fx.run(&["disable"]);
    assert_ne!(o.status.code(), Some(0), "{}", out(&o));
    assert!(err(&o).lines().count() >= 2, "{}", err(&o));
}
