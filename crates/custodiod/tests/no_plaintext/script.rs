//! Running `scripts/check-no-plaintext.sh`, and the encodings of a key the test derives without it.
// A test fails by panicking: unwrap, expect and indexing on data the test itself built are the intended failure mode.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use crate::support::{Kind, TestKey, hex};

pub fn script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/check-no-plaintext.sh")
}

/// Runs the script with `password` on stdin; `path` goes first on `PATH` when given.
pub fn run_script(state: &Path, p12: &Path, password: &str, path: Option<&Path>) -> Output {
    let mut command = Command::new(script());
    command.arg(state).arg(p12);
    if let Some(dir) = path {
        let old = std::env::var("PATH").unwrap_or_default();
        command.env("PATH", format!("{}:{old}", dir.display()));
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{password}\n").as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

/// The files the script named.
pub fn named(out: &Output) -> Vec<String> {
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_owned)
        .collect()
}

pub fn openssl(args: &[&str], stdin: &[u8]) -> Vec<u8> {
    let mut child = Command::new("openssl")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "openssl {args:?}");
    out.stdout
}

/// The PEM private key of a `.p12`, by `openssl` with the password on the command line (the test, not the script).
pub fn key_pem(p12: &Path, password: &str, legacy: bool) -> Vec<u8> {
    let pass = format!("pass:{password}");
    let file = p12.to_str().unwrap();
    let mut args = vec!["pkcs12"];
    if legacy {
        args.push("-legacy");
    }
    args.extend(["-in", file, "-passin", &pass, "-nocerts", "-noenc"]);
    openssl(&args, b"")
}

/// Every secret encoding of the key in a `.p12`: the Rust-side parse of the key (`TestKey`: scalar and primes
/// normalised by the `p256` and `rsa` crates, not by `openssl`'s text output), PKCS#1 or SEC1, PKCS#8, and the file.
pub fn encodings(p12: &Path, password: &str) -> Vec<(&'static str, Vec<u8>)> {
    let key = TestKey::from_pem(key_pem(p12, password, false));
    let mut out: Vec<(&'static str, Vec<u8>)> = key
        .secrets
        .iter()
        .map(|(n, b)| {
            let n = match (*n, key_kind(&key)) {
                ("traditional", Kind::P256) => "sec1",
                ("traditional", Kind::Rsa) => "pkcs1",
                (n, _) => n,
            };
            (n, b.clone())
        })
        .collect();
    out.push(("p12", std::fs::read(p12).unwrap()));
    out
}

pub fn key_kind(key: &TestKey) -> Kind {
    if key.secrets.iter().any(|(n, _)| *n == "scalar") {
        Kind::P256
    } else {
        Kind::Rsa
    }
}

/// One encoding of `bytes` as a file would hold it, with text around it: `(form, file content)`.
pub fn forms(bytes: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
    let around = |text: String| format!("key = {text}\n").into_bytes();
    let b64 = |prefix: &[u8]| {
        let mut input = prefix.to_vec();
        input.extend_from_slice(bytes);
        String::from_utf8(openssl(&["enc", "-base64", "-A"], &input)).unwrap()
    };
    let lower = hex(bytes);
    // `openssl`'s own text layout: 15 bytes a line, ':' separated, indented.
    let colon = bytes
        .chunks(15)
        .map(|c| {
            format!(
                "    {}",
                c.iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(":")
            )
        })
        .collect::<Vec<_>>()
        .join(":\n");
    let mut wrapped = b"z".to_vec();
    wrapped.extend_from_slice(bytes);
    let wrapped = String::from_utf8(openssl(&["enc", "-base64"], &wrapped)).unwrap();
    let mut raw = b"junk".to_vec();
    raw.extend_from_slice(bytes);
    raw.extend_from_slice(b"tail");
    vec![
        ("raw", raw),
        ("hex-lower", around(lower.clone())),
        ("hex-upper", around(lower.to_uppercase())),
        ("hex-colon", around(colon)),
        ("base64", around(b64(b""))),
        ("base64-offset-1", around(b64(b"x"))),
        ("base64-offset-2", around(b64(b"xy"))),
        (
            "pem-wrapped",
            format!("-----BEGIN PRIVATE KEY-----\n{wrapped}-----END PRIVATE KEY-----\n")
                .into_bytes(),
        ),
    ]
}
