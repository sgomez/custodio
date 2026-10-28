//! The built module loaded through the `cryptoki` crate, against the real service on a private
//! `dbus-daemon` with a fake polkit authority.
//!
//! The module reads the bus address from `DBUS_SYSTEM_BUS_ADDRESS`, which cannot be set safely
//! in a running multi-threaded test process. So each scenario runs the `client` test below in a
//! child process (this same test binary) with that variable set; the parent hosts the bus, the
//! fake polkit and the service, and checks what the child printed and what polkit was asked.

use std::collections::HashMap;
use std::error::Error;
use std::fmt::Write as _;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Once};

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error as P11Error, RvError};
use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsPssParams};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType, ObjectClass, ObjectHandle};
use cryptoki::session::Session;
use cryptoki::types::Ulong;
use custodiod::dbus::{BUS_NAME, Custodio, OBJECT_PATH};
use custodiod::import::import_p12;
use custodiod::polkit::PolkitAuthorizer;
use custodiod::sign::{Mechanism as ServiceMechanism, sign};
use custodiod::store::KeyStore;
use secrecy::SecretString;
use zbus::connection::Builder;
use zbus::{OwnedVariant, block_on, interface};

type TestResult = Result<(), Box<dyn Error>>;

const RSA_P12: &[u8] = include_bytes!("../fixtures/rsa2048.p12");
const EC_P12: &[u8] = include_bytes!("../fixtures/p256.p12");
const PASSWORD: &str = "test-password";
const DATA: &[u8] = b"data to be signed by the custodio test";
const MODE_VAR: &str = "CUSTODIO_TEST_MODE";
const MODULE_VAR: &str = "CUSTODIO_TEST_MODULE";

/// Distinctive 16 bytes the composed messages are made of; they must never reach the service.
const MARKER: &[u8; 16] = b"CUSTODIO-MARKER!";
const COMPOSED_LEN: usize = 1024;
const LARGE_LEN: usize = 64 << 20;

/// The marker repeated to `len` bytes.
fn message(len: usize) -> Vec<u8> {
    MARKER.iter().copied().cycle().take(len).collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

mod child;
mod composed;
mod composed_child;
mod login;
mod login_child;
mod multipart;
mod multipart_child;
mod parent;

use child::*;
use composed_child::*;
use login_child::*;
use multipart_child::*;
use parent::*;

/// Entry point of the child scenarios. Without `MODE_VAR` (a plain `cargo test`) it does nothing.
#[test]
fn client() -> TestResult {
    let Ok(mode) = std::env::var(MODE_VAR) else {
        return Ok(());
    };
    let pkcs11 = module()?;
    match mode.as_str() {
        "basic" => basic(&pkcs11),
        "denied" => denied(&pkcs11),
        "unsupported" => unsupported(&pkcs11),
        "no_service" => no_service(&pkcs11),
        "threads" => threads(&pkcs11),
        "forks" => forks(&pkcs11),
        "tasks" => tasks(&pkcs11),
        "mechanisms" => mechanisms(&pkcs11),
        "composed_sign" => composed_sign(&pkcs11),
        "composed_large" => composed_large(&pkcs11),
        "composed_refusals" => composed_refusals(&pkcs11),
        "composed_retry" => composed_retry(&pkcs11),
        "composed_denied" => composed_denied(&pkcs11),
        "login_baseline" => login_baseline(&pkcs11),
        "login_variants" => login_variants(&pkcs11),
        "login_flags" => login_flags(&pkcs11),
        "login_sign" => login_sign(&pkcs11),
        "login_open_operation" => login_open_operation(&pkcs11),
        "login_denied" => login_denied(&pkcs11),
        "multipart_equivalence" => multipart_equivalence(&pkcs11),
        "multipart_large" => multipart_large(&pkcs11),
        "multipart_retry" => multipart_retry(&pkcs11),
        "multipart_raw" => multipart_raw(&pkcs11),
        "multipart_sign_after_update" => multipart_sign_after_update(&pkcs11),
        "multipart_denied" => multipart_denied(&pkcs11),
        "multipart_allowed" => multipart_allowed(&pkcs11),
        "multipart_tasks" => multipart_tasks(&pkcs11),
        "multipart_forks" => multipart_forks(&pkcs11),
        "multipart_threads" => multipart_threads(&pkcs11),
        other => Err(format!("unknown mode {other}").into()),
    }
}

fn lines<'a>(stdout: &'a str, tag: &'a str) -> impl Iterator<Item = Vec<&'a str>> {
    stdout
        .lines()
        .filter(move |l| l.starts_with(tag))
        .map(|l| l.split_whitespace().skip(1).collect())
}

#[test]
fn lists_certificates_and_signs_through_the_service() -> TestResult {
    let f = Fixture::start(true, true)?;
    let (ok, stdout) = f.run("basic")?;
    assert!(ok);
    let store = f.store()?;
    let secret = |id: &str| store.get(id);
    for line in lines(&stdout, "CERT") {
        let cert = store.get(&format!("{}-cert", line[0]))?;
        assert_eq!(line[1], hex(secrecy::ExposeSecret::expose_secret(&cert)));
    }
    let mut seen = 0;
    for line in lines(&stdout, "SIG") {
        seen += 1;
        match (line[0], line[1]) {
            ("ec", _) => {
                let expected = sign(&secret("ec")?, ServiceMechanism::Ecdsa, &[7; 32])?;
                assert_eq!(line[2], hex(&expected));
            }
            ("rsa", "pkcs") => {
                let expected = sign(&secret("rsa")?, ServiceMechanism::RsaPkcs, DATA)?;
                assert_eq!(line[2], hex(&expected));
            }
            _ => assert_eq!(line[2], "256"),
        }
    }
    assert_eq!(seen, 3);
    // Three signatures reached the service; each asked polkit.
    assert_eq!(f.asked(), 3);
    Ok(())
}

#[test]
fn a_refused_signature_fails_and_every_attempt_asks() -> TestResult {
    let f = Fixture::start(false, true)?;
    assert!(f.run("denied")?.0);
    assert_eq!(f.asked(), 2);
    Ok(())
}

#[test]
fn everything_else_is_not_supported() -> TestResult {
    let f = Fixture::start(true, true)?;
    assert!(f.run("unsupported")?.0);
    assert_eq!(f.asked(), 0);
    Ok(())
}

#[test]
fn without_the_service_there_are_no_tokens() -> TestResult {
    let f = Fixture::start(true, false)?;
    assert!(f.run("no_service")?.0);
    Ok(())
}

#[test]
fn threads_can_sign_at_once() -> TestResult {
    let f = Fixture::start(true, true)?;
    assert!(f.run("threads")?.0);
    assert_eq!(f.asked(), 24);
    Ok(())
}

#[test]
fn signing_leaves_no_helper_threads() -> TestResult {
    let f = Fixture::start(true, true)?;
    let (ok, out) = f.run("tasks")?;
    assert!(ok);
    let counts = lines(&out, "TASKS").next().ok_or("no TASKS line")?;
    assert_eq!(counts[0], counts[1], "threads left behind by C_Sign: {out}");
    assert_eq!(counts[0], counts[2], "threads linger after C_Sign: {out}");
    Ok(())
}

#[test]
fn fork_while_other_threads_use_the_module() -> TestResult {
    let f = Fixture::start(true, true)?;
    assert!(f.run("forks")?.0);
    assert_eq!(f.asked(), 5);
    Ok(())
}

#[test]
fn bus_names_match_the_service() {
    // The module repeats these constants rather than link the service.
    assert_eq!(BUS_NAME, "com.rfirma.Custodio1");
    assert_eq!(OBJECT_PATH, "/com/rfirma/Custodio1");
}

#[test]
fn p11_kit_module_file_points_at_the_library() -> TestResult {
    let file = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../data/custodio.module"
    ))?;
    let entries: Vec<(&str, &str)> = file
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim(), v.trim()))
        .collect();
    let module = entries
        .iter()
        .find(|(k, _)| *k == "module")
        .ok_or("no module entry")?
        .1;
    assert!(
        module.starts_with('/'),
        "p11-kit needs an absolute path or a name in its module dir"
    );
    assert!(module.ends_with("libcustodio_pkcs11.so"), "{module}");
    // The module must not be treated as a trust anchor store or a critical module.
    assert!(entries.contains(&("critical", "no")));
    assert!(entries.contains(&("trust-policy", "no")));
    Ok(())
}
