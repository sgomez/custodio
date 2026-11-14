//! The real service, the built module and NSS's own tools (acceptances 10 and 11, native part).

use std::path::Path;
use std::process::{Command, Stdio};

use crate::fixture::{self, Fixture, new_profile};

fn real_path() -> std::path::PathBuf {
    std::env::var_os("PATH").unwrap().into()
}

/// `tool args...` with the module's bus address in its environment, stdout.
fn nss(tool: &str, address: &str, profile: &Path, args: &[&str]) -> (bool, String) {
    let out = Command::new(tool)
        .arg(if tool == "modutil" { "-dbdir" } else { "-d" })
        .arg(format!("sql:{}", profile.display()))
        .args(args)
        .env("DBUS_SYSTEM_BUS_ADDRESS", address)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr),
    )
}

#[test]
fn nss_sees_the_custodio_token_and_the_certificate() {
    let service = fixture::Service::start("mykey");
    let f = Fixture::new();
    let m = f.module("a");
    let root = f.root(".mozilla/firefox", &["reg.default"]);
    // the control is a profile no browser lists, so the command leaves it alone
    let plain = f.home().join("plain.default");
    new_profile(&plain);
    let out = f.binary(
        &["register", "--module", m.to_str().unwrap()],
        &real_path(),
        &[],
    );
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let reg = root.join("reg.default");
    let a = service.address.as_str();
    let (ok, list) = nss("modutil", a, &reg, &["-list"]);
    assert!(ok, "{list}");
    assert_eq!(list.matches("library name:").count(), 1, "{list}");
    assert!(list.contains("Custodio"), "{list}");
    let token = list
        .lines()
        .find_map(|l| {
            l.trim()
                .strip_prefix("token: ")
                .filter(|t| t.contains("mykey") || t.contains("Custodio"))
        })
        .unwrap_or_else(|| panic!("no Custodio token in {list}"))
        .trim()
        .to_owned();
    let (ok, certs) = nss("certutil", a, &reg, &["-L", "-h", &token]);
    assert!(ok, "{certs}");
    assert!(certs.contains("mykey:mykey"), "{certs}");
    let (ok, keys) = nss("certutil", a, &reg, &["-K", "-h", &token]);
    assert!(ok, "{keys}");
    assert!(keys.contains("< 0> ec") && keys.contains("mykey"), "{keys}");
    // control: the unregistered profile shows neither
    let (_, list) = nss("modutil", a, &plain, &["-list"]);
    assert!(
        !list.contains("Custodio") && !list.contains("mykey"),
        "{list}"
    );
}
