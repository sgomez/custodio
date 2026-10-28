//! The composed mechanisms checked by the `openssl` command line: a signature made through
//! `sign_input` and the service's `sign` must verify with `openssl dgst -verify`.
//!
//! This is an integration test, not a unit test, because it starts an external process, which
//! Miri cannot do (`just miri` runs the `--lib` tests only). Skipped when `openssl` is missing.

use std::error::Error;
use std::io::Write;
use std::process::{Command, Stdio};

use custodio_pkcs11::composed::{Composed, DigestHasher, Hash, KeyType, sign_input};
use custodiod::import::parse_p12;
use custodiod::sign::{Mechanism, sign};
use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey};
use rsa::{RsaPrivateKey, RsaPublicKey};
use secrecy::{ExposeSecret, SecretSlice, SecretString};

type TestResult = Result<(), Box<dyn Error>>;

const ALL: [Composed; 6] = [
    Composed::Sha256RsaPkcs,
    Composed::Sha384RsaPkcs,
    Composed::Sha512RsaPkcs,
    Composed::EcdsaSha256,
    Composed::EcdsaSha384,
    Composed::EcdsaSha512,
];

const MESSAGE: &[u8] = b"the message that is signed through the composed mechanisms";

fn fixture_key(name: &str) -> Result<SecretSlice<u8>, Box<dyn Error>> {
    let data = std::fs::read(format!(
        "{}/tests/fixtures/{name}.p12",
        env!("CARGO_MANIFEST_DIR")
    ))?;
    Ok(parse_p12(&data, &SecretString::from("test-password".to_owned()))?.key)
}

fn service_sign(
    composed: Composed,
    key: &SecretSlice<u8>,
    message: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut h = DigestHasher::new(composed.hash());
    h.update(message);
    let mechanism = match composed.key_type() {
        KeyType::Rsa => Mechanism::RsaPkcs,
        KeyType::EcP256 => Mechanism::Ecdsa,
    };
    Ok(sign(key, mechanism, &sign_input(composed, &h))?)
}

fn rsa_public(key: &SecretSlice<u8>) -> Result<RsaPublicKey, Box<dyn Error>> {
    Ok(RsaPrivateKey::from_pkcs8_der(key.expose_secret())?.to_public_key())
}

fn p256_public(key: &SecretSlice<u8>) -> Result<p256::ecdsa::VerifyingKey, Box<dyn Error>> {
    use p256::pkcs8::DecodePrivateKey as _;
    Ok(*p256::ecdsa::SigningKey::from_pkcs8_der(key.expose_secret())?.verifying_key())
}

fn openssl_available() -> bool {
    Command::new("openssl")
        .arg("version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn openssl_verify(
    hash: &str,
    pubkey_pem: &str,
    sig: &[u8],
    msg: &[u8],
) -> Result<bool, Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let key = dir.path().join("pub.pem");
    let sigf = dir.path().join("sig.bin");
    std::fs::write(&key, pubkey_pem)?;
    std::fs::write(&sigf, sig)?;
    let mut child = Command::new("openssl")
        .args(["dgst", &format!("-{hash}"), "-verify"])
        .arg(&key)
        .arg("-signature")
        .arg(&sigf)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    child.stdin.take().ok_or("no stdin")?.write_all(msg)?;
    Ok(child.wait()?.success())
}

fn der_int(v: &[u8]) -> Vec<u8> {
    let start = v
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(v.len().saturating_sub(1));
    let v = v.get(start..).unwrap_or_default();
    let mut out = Vec::new();
    if v.first().is_some_and(|b| b & 0x80 != 0) {
        out.push(0);
    }
    out.extend_from_slice(v);
    let mut t = vec![0x02, u8::try_from(out.len()).unwrap_or(0)];
    t.extend(out);
    t
}

fn ecdsa_der(rs: &[u8]) -> Vec<u8> {
    let (r, s) = rs.split_at(rs.len() / 2);
    let mut body = der_int(r);
    body.extend(der_int(s));
    let mut out = vec![0x30, u8::try_from(body.len()).unwrap_or(0)];
    out.extend(body);
    out
}

#[test]
fn cross_verify_openssl() -> TestResult {
    if !openssl_available() {
        println!("SKIP cross_verify_openssl: openssl not found");
        return Ok(());
    }
    let rsa_key = fixture_key("rsa2048")?;
    let rsa_pem = rsa_public(&rsa_key)?.to_public_key_pem(rsa::pkcs8::LineEnding::LF)?;
    let ec_key = fixture_key("p256")?;
    let ec_pem = p256_public(&ec_key)?.to_public_key_pem(rsa::pkcs8::LineEnding::LF)?;
    for composed in ALL {
        let hash = match composed.hash() {
            Hash::Sha256 => "sha256",
            Hash::Sha384 => "sha384",
            Hash::Sha512 => "sha512",
        };
        if composed.key_type() == KeyType::Rsa {
            let sig = service_sign(composed, &rsa_key, MESSAGE)?;
            assert!(
                openssl_verify(hash, &rsa_pem, &sig, MESSAGE)?,
                "{composed:?}"
            );
            assert!(!openssl_verify(hash, &rsa_pem, &sig, b"another message")?);
        } else {
            let sig = ecdsa_der(&service_sign(composed, &ec_key, MESSAGE)?);
            assert!(
                openssl_verify(hash, &ec_pem, &sig, MESSAGE)?,
                "{composed:?}"
            );
            assert!(!openssl_verify(hash, &ec_pem, &sig, b"another message")?);
        }
    }
    Ok(())
}
