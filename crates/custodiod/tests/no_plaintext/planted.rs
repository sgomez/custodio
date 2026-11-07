//! The script's own behaviour on state directories the test builds: every encoding planted is found, public material
//! is not, bad input is never clean, and the password stays off the command line and out of the output.
// A test fails by panicking: unwrap, expect and indexing on data the test itself built are the intended failure mode.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use crate::common::{EC_SENTINEL_P12, RSA_SENTINEL_P12, SENTINEL_PASSWORD};
use crate::rig::TestResult;
use crate::script::{encodings, forms, key_pem, named, openssl, run_script};

const KEYS: [(&str, &[u8]); 2] = [("rsa2048", RSA_SENTINEL_P12), ("p256", EC_SENTINEL_P12)];

/// A state directory with a few unrelated files, and the sentinel `.p12` of a key type outside it.
struct Fixture {
    _dir: tempfile::TempDir,
    state: PathBuf,
    p12: PathBuf,
}

fn fixture(p12: &[u8]) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    fs::create_dir_all(state.join("keys/1000")).unwrap();
    fs::write(state.join("keys/1000/record"), b"CUSTODIO\x01 sealed bytes").unwrap();
    fs::write(state.join("note.txt"), b"nothing to see").unwrap();
    let p12_path = dir.path().join("key.p12");
    fs::write(&p12_path, p12).unwrap();
    Fixture {
        _dir: dir,
        state,
        p12: p12_path,
    }
}

fn plant(state: &Path, relative: &str, content: &[u8]) -> PathBuf {
    let path = state.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, content).unwrap();
    path
}

/// Where the n-th plant goes: flat, nested, hidden file, hidden nested directory.
fn place(n: usize) -> &'static str {
    ["plant.bin", "a/b/c/plant.bin", ".plant", ".h/d/.plant"][n % 4]
}

#[test]
fn planted_encoding_is_found() {
    let mut cases = 0;
    for (name, p12) in KEYS {
        let fx = fixture(p12);
        let clean = run_script(&fx.state, &fx.p12, SENTINEL_PASSWORD, None);
        assert_eq!(clean.status.code(), Some(0), "{name} before");
        let all = encodings(&fx.p12, SENTINEL_PASSWORD);
        let names: Vec<_> = all.iter().map(|(n, _)| *n).collect();
        let expected: &[&str] = if name == "rsa2048" {
            &["pkcs8", "pkcs1", "p", "q", "d", "p12"]
        } else {
            &["pkcs8", "sec1", "scalar", "p12"]
        };
        let mut sorted = names.clone();
        sorted.sort_unstable();
        let mut want = expected.to_vec();
        want.sort_unstable();
        assert_eq!(sorted, want, "{name}: the encodings under test");
        for (encoding, bytes) in &all {
            for (form, content) in forms(bytes) {
                let path = plant(&fx.state, place(cases), &content);
                cases += 1;
                let out = run_script(&fx.state, &fx.p12, SENTINEL_PASSWORD, None);
                let who = format!("{name} {encoding} {form}");
                assert_eq!(
                    out.status.code(),
                    Some(1),
                    "{who}: {}",
                    String::from_utf8_lossy(&out.stderr)
                );
                assert_eq!(named(&out), vec![path.display().to_string()], "{who}");
                fs::remove_file(&path).unwrap();
            }
        }
        let after = run_script(&fx.state, &fx.p12, SENTINEL_PASSWORD, None);
        assert_eq!(after.status.code(), Some(0), "{name} after");
    }
    assert_eq!(cases, 10 * 8, "every encoding in every form ran");
}

#[test]
fn every_file_is_named_and_symlinks_are_not_followed() -> TestResult {
    let fx = fixture(EC_SENTINEL_P12);
    let pkcs8 = &encodings(&fx.p12, SENTINEL_PASSWORD)[0].1;
    let one = plant(&fx.state, "x/one", pkcs8);
    let two = plant(&fx.state, ".two", &openssl(&["enc", "-base64"], pkcs8));
    let out = run_script(&fx.state, &fx.p12, SENTINEL_PASSWORD, None);
    assert_eq!(out.status.code(), Some(1));
    let mut want = vec![one.display().to_string(), two.display().to_string()];
    want.sort();
    let mut got = named(&out);
    got.sort();
    assert_eq!(got, want);
    fs::remove_file(&one)?;
    fs::remove_file(&two)?;
    // Reachable only through a symlink to a file and a symlink to a directory: not followed.
    let outside = tempfile::tempdir()?;
    fs::write(outside.path().join("leak"), pkcs8)?;
    symlink(outside.path().join("leak"), fx.state.join("link"))?;
    symlink(outside.path(), fx.state.join("linked-dir"))?;
    let out = run_script(&fx.state, &fx.p12, SENTINEL_PASSWORD, None);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    Ok(())
}

#[test]
fn legacy_p12_is_read() -> TestResult {
    let dir = tempfile::tempdir()?;
    let p12 = dir.path().join("legacy.p12");
    fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rsa2048-legacy.p12"),
        &p12,
    )?;
    let state = dir.path().join("state");
    fs::create_dir(&state)?;
    let clean = run_script(&state, &p12, "test-password", None);
    assert_eq!(
        clean.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&clean.stderr)
    );
    let pkcs8 = openssl(
        &["pkcs8", "-topk8", "-nocrypt", "-outform", "DER"],
        &key_pem(&p12, "test-password", true),
    );
    let leak = plant(&state, "leak", &pkcs8);
    let out = run_script(&state, &p12, "test-password", None);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(named(&out), vec![leak.display().to_string()]);
    Ok(())
}

#[test]
fn certificate_is_not_a_match() {
    for (name, p12) in KEYS {
        let fx = fixture(p12);
        let file = fx.p12.to_str().unwrap();
        let pass = format!("pass:{SENTINEL_PASSWORD}");
        let cert_pem = openssl(&["pkcs12", "-in", file, "-passin", &pass, "-nokeys"], b"");
        let cert_der = openssl(&["x509", "-outform", "DER"], &cert_pem);
        let public_pem = openssl(&["x509", "-pubkey", "-noout"], &cert_pem);
        let public_der = openssl(&["pkey", "-pubin", "-outform", "DER"], &public_pem);
        let public_text = openssl(&["pkey", "-pubin", "-noout", "-text"], &public_pem);
        for (i, content) in [cert_pem, cert_der, public_pem, public_der, public_text]
            .iter()
            .enumerate()
        {
            plant(&fx.state, &format!("pub{i}"), content);
        }
        let out = run_script(&fx.state, &fx.p12, SENTINEL_PASSWORD, None);
        assert_eq!(out.status.code(), Some(0), "{name}: {:?}", named(&out));
    }
}

#[test]
fn bad_input_is_not_clean() -> TestResult {
    let fx = fixture(EC_SENTINEL_P12);
    let not_p12 = plant(
        fx.state.parent().unwrap(),
        "not.p12",
        b"this is not a pkcs12 file",
    );
    let unreadable_dir = fx.state.parent().unwrap().join("closed");
    fs::create_dir(&unreadable_dir)?;
    fs::set_permissions(&unreadable_dir, fs::Permissions::from_mode(0o000))?;
    let missing = fx.state.join("missing");
    let cases: Vec<(&str, PathBuf, PathBuf, &str)> = vec![
        (
            "no state directory",
            missing.clone(),
            fx.p12.clone(),
            SENTINEL_PASSWORD,
        ),
        (
            "no p12",
            fx.state.clone(),
            missing.clone(),
            SENTINEL_PASSWORD,
        ),
        ("wrong password", fx.state.clone(), fx.p12.clone(), "wrong"),
        ("empty password", fx.state.clone(), fx.p12.clone(), ""),
        ("not a p12", fx.state.clone(), not_p12, SENTINEL_PASSWORD),
        (
            "a file as state",
            fx.p12.clone(),
            fx.p12.clone(),
            SENTINEL_PASSWORD,
        ),
        (
            "unreadable state",
            unreadable_dir.clone(),
            fx.p12.clone(),
            SENTINEL_PASSWORD,
        ),
    ];
    for (what, state, p12, password) in cases {
        let out = run_script(&state, &p12, password, None);
        let code = out.status.code();
        assert!(
            matches!(code, Some(c) if c != 0 && c != 1),
            "{what}: {code:?}"
        );
        assert!(out.stdout.is_empty(), "{what}");
    }
    // Missing arguments.
    for args in [
        vec![],
        vec![fx.state.clone()],
        vec![fx.state.clone(), fx.p12.clone(), fx.p12.clone()],
    ] {
        let out = std::process::Command::new(crate::script::script())
            .args(args)
            .stdin(std::process::Stdio::null())
            .output()?;
        assert!(
            matches!(out.status.code(), Some(c) if c != 0 && c != 1),
            "{:?}",
            out.status
        );
    }
    // A file under the state directory that cannot be read is not a clean result either.
    let hidden = plant(&fx.state, "secret", b"x");
    fs::set_permissions(&hidden, fs::Permissions::from_mode(0o000))?;
    let out = run_script(&fx.state, &fx.p12, SENTINEL_PASSWORD, None);
    let readable = fs::File::open(&hidden).is_ok(); // running as root reads it
    fs::set_permissions(&hidden, fs::Permissions::from_mode(0o600))?;
    fs::set_permissions(&unreadable_dir, fs::Permissions::from_mode(0o700))?;
    if !readable {
        assert!(
            matches!(out.status.code(), Some(c) if c != 0 && c != 1),
            "{:?}",
            out.status
        );
    }
    Ok(())
}

#[test]
fn password_only_on_stdin() -> TestResult {
    let shim = tempfile::tempdir()?;
    let log = shim.path().join("argv.log");
    let real = String::from_utf8(
        std::process::Command::new("sh")
            .args(["-c", "command -v openssl"])
            .output()?
            .stdout,
    )?;
    let script = format!(
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\nexec '{}' \"$@\"\n",
        log.display(),
        real.trim()
    );
    let shim_path = shim.path().join("openssl");
    fs::write(&shim_path, script)?;
    fs::set_permissions(&shim_path, fs::Permissions::from_mode(0o755))?;

    for (name, p12) in KEYS {
        let fx = fixture(p12);
        let all = encodings(&fx.p12, SENTINEL_PASSWORD);
        let pkcs8 = all.iter().find(|(n, _)| *n == "pkcs8").unwrap().1.clone();
        let mut outputs = Vec::new();
        // Clean, a match, and a failure (wrong password).
        outputs.push(run_script(
            &fx.state,
            &fx.p12,
            SENTINEL_PASSWORD,
            Some(shim.path()),
        ));
        plant(&fx.state, "leak", &forms(&pkcs8)[1].1);
        let hit = run_script(&fx.state, &fx.p12, SENTINEL_PASSWORD, Some(shim.path()));
        assert_eq!(hit.status.code(), Some(1), "{name}");
        outputs.push(hit);
        let bad = run_script(&fx.state, &fx.p12, "wrong-password-9", Some(shim.path()));
        assert_eq!(bad.status.code(), Some(3), "{name}");
        outputs.push(bad);

        let argv = fs::read_to_string(&log)?;
        assert!(argv.lines().count() >= 6, "the shim saw the calls: {argv}");
        for secret in [SENTINEL_PASSWORD, "sentinel-7f3a91c4", "wrong-password-9"] {
            assert!(!argv.contains(secret), "{name}: password in argv");
            for out in &outputs {
                for stream in [&out.stdout, &out.stderr] {
                    assert!(
                        !String::from_utf8_lossy(stream).contains(secret),
                        "{name}: password in output"
                    );
                }
            }
        }
        for out in &outputs {
            for stream in [&out.stdout, &out.stderr] {
                for (encoding, bytes) in &all {
                    for (form, content) in forms(bytes) {
                        let needle =
                            &content[content.len().min(8)..content.len().saturating_sub(8)];
                        let found = stream
                            .windows(needle.len().min(24))
                            .any(|w| w == &needle[..needle.len().min(24)]);
                        assert!(!found, "{name}: {encoding} {form} in output");
                    }
                }
            }
        }
        fs::remove_file(&log)?;
    }
    Ok(())
}
