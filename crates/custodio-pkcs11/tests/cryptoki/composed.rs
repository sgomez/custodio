//! Composed mechanisms through the built module: what the service receives, and that the
//! signatures verify over the original message with code that shares nothing with the module.

use p256::ecdsa::Signature as EcSignature;
use p256::ecdsa::signature::hazmat::PrehashVerifier as _;
use rsa::pkcs1v15::{Signature as RsaSignature, VerifyingKey as RsaVerifyingKey};
use rsa::pkcs8::DecodePublicKey;
use rsa::sha2::{Digest, Sha256, Sha384, Sha512};
use rsa::signature::Verifier as _;
use rsa::{Pkcs1v15Sign, RsaPublicKey};
use x509_cert::Certificate;
use x509_cert::der::{Decode, Encode};

use super::*;

const CKM_RSA_PKCS: u32 = 0x1;
const CKM_ECDSA: u32 = 0x1041;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap_or_default())
        .collect()
}

/// `(label, name, bytes)` of every `tag` line, in the order the child printed them.
fn printed(stdout: &str, tag: &str) -> Vec<(String, String, Vec<u8>)> {
    let mut out = Vec::new();
    for l in lines(stdout, tag) {
        let name = if l.len() == 3 { l[1] } else { "" };
        out.push((l[0].to_owned(), name.to_owned(), unhex(l[l.len() - 1])));
    }
    out
}

fn digest(name: &str, msg: &[u8]) -> Vec<u8> {
    if name.ends_with("sha256") {
        Sha256::digest(msg).to_vec()
    } else if name.ends_with("sha384") {
        Sha384::digest(msg).to_vec()
    } else {
        Sha512::digest(msg).to_vec()
    }
}

/// What the service must have been sent for `name` over `msg`: the digest, or prefix + digest.
fn expected_input(name: &str, msg: &[u8]) -> Vec<u8> {
    let d = digest(name, msg);
    if !name.starts_with("rsa") {
        return d;
    }
    let scheme = if name.ends_with("sha256") {
        Pkcs1v15Sign::new::<Sha256>()
    } else if name.ends_with("sha384") {
        Pkcs1v15Sign::new::<Sha384>()
    } else {
        Pkcs1v15Sign::new::<Sha512>()
    };
    [scheme.prefix.as_ref(), &d].concat()
}

fn spki_der(cert: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let cert = Certificate::from_der(cert)?;
    Ok(cert.tbs_certificate().subject_public_key_info().to_der()?)
}

fn verify_rsa(cert: &[u8], name: &str, msg: &[u8], sig: &[u8]) -> Result<bool, Box<dyn Error>> {
    let key = RsaPublicKey::from_public_key_der(&spki_der(cert)?)?;
    let sig = RsaSignature::try_from(sig)?;
    Ok(if name.ends_with("sha256") {
        RsaVerifyingKey::<Sha256>::new(key)
            .verify(msg, &sig)
            .is_ok()
    } else if name.ends_with("sha384") {
        RsaVerifyingKey::<Sha384>::new(key)
            .verify(msg, &sig)
            .is_ok()
    } else {
        RsaVerifyingKey::<Sha512>::new(key)
            .verify(msg, &sig)
            .is_ok()
    })
}

fn verify_ec(cert: &[u8], name: &str, msg: &[u8], sig: &[u8]) -> Result<bool, Box<dyn Error>> {
    let spki = Certificate::from_der(cert)?
        .tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .raw_bytes()
        .to_vec();
    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&spki)?;
    Ok(key
        .verify_prehash(&digest(name, msg), &EcSignature::from_slice(sig)?)
        .is_ok())
}

/// Checks one signature: valid over `msg`, invalid over anything else.
fn check_signature(cert: &[u8], name: &str, msg: &[u8], sig: &[u8]) -> TestResult {
    let verify = if name.starts_with("rsa") {
        verify_rsa
    } else {
        verify_ec
    };
    assert!(verify(cert, name, msg, sig)?, "{name} over the message");
    let other = [msg, b"!"].concat();
    assert!(
        !verify(cert, name, &other, sig)?,
        "{name} over another message"
    );
    if name.starts_with("ecdsa") && !name.ends_with("sha256") {
        // FIPS 186: the leftmost 32 bytes of the digest are signed; the rightmost are not.
        let d = digest(name, msg);
        let key = {
            let spki = Certificate::from_der(cert)?
                .tbs_certificate()
                .subject_public_key_info()
                .subject_public_key
                .raw_bytes()
                .to_vec();
            p256::ecdsa::VerifyingKey::from_sec1_bytes(&spki)?
        };
        let sig = EcSignature::from_slice(sig)?;
        assert!(
            key.verify_prehash(&d[..32], &sig).is_ok(),
            "{name} leftmost 32 bytes"
        );
        assert!(
            key.verify_prehash(&d[d.len() - 32..], &sig).is_err(),
            "{name} rightmost 32 bytes"
        );
    }
    Ok(())
}

/// The recorded call matches the printed signature's entry: raw mechanism, no hash/salt
/// parameters, only the digest or `DigestInfo`, and the message nowhere in the message bytes.
fn check_recorded(rec: &Recorded, label: &str, name: &str, msg: &[u8]) {
    let raw = if name.starts_with("rsa") {
        CKM_RSA_PKCS
    } else {
        CKM_ECDSA
    };
    assert_eq!(rec.id, label);
    assert_eq!(
        (rec.mechanism, rec.hash, rec.salt_len),
        (raw, 0, 0),
        "{name}"
    );
    assert_eq!(rec.data, expected_input(name, msg), "{name}");
    assert!(rec.raw.len() < 1024, "{name}: {} bytes", rec.raw.len());
    assert!(
        !rec.raw.windows(MARKER.len()).any(|w| w == MARKER),
        "{name}: the message reached the service"
    );
}

/// Checks the child's `CERT` and `SIG` lines against the recorded calls, in order.
fn check_run(f: &Fixture, out: &str, msg: &[u8], expected: usize) -> TestResult {
    let certs: HashMap<String, Vec<u8>> = printed(out, "CERT")
        .into_iter()
        .map(|(l, _, c)| (l, c))
        .collect();
    let sigs = printed(out, "SIG");
    assert_eq!(sigs.len(), expected, "{out}");
    let recorded = f.signs(expected)?;
    assert!(!recorded.is_empty(), "the monitor saw no Sign call");
    assert_eq!(recorded.len(), expected, "exactly the expected Sign calls");
    for (rec, (label, name, sig)) in recorded.iter().zip(&sigs) {
        check_recorded(rec, label, name, msg);
        check_signature(&certs[label], name, msg, sig)?;
    }
    assert_eq!(f.asked(), expected);
    Ok(())
}

#[test]
fn composed_mechanism_lists() -> TestResult {
    let f = Fixture::start(true, true)?;
    assert!(f.run("mechanisms")?.0);
    assert_eq!(f.asked(), 0);
    Ok(())
}

#[test]
fn composed_sign_hashes_in_the_module_and_verifies() -> TestResult {
    let f = Fixture::start(true, true)?;
    let (ok, out) = f.run("composed_sign")?;
    assert!(ok);
    check_run(&f, &out, &message(COMPOSED_LEN), 6)
}

#[test]
fn composed_large_message_is_limited_by_memory_only() -> TestResult {
    let f = Fixture::start(true, true)?;
    let (ok, out) = f.run("composed_large")?;
    assert!(ok);
    check_run(&f, &out, &message(LARGE_LEN), 2)
}

#[test]
fn composed_refusals_do_not_reach_polkit() -> TestResult {
    let f = Fixture::start(true, true)?;
    assert!(f.run("composed_refusals")?.0);
    assert_eq!(f.asked(), 0);
    assert!(f.signs(0)?.is_empty());
    Ok(())
}

#[test]
fn composed_length_query_and_short_buffer_do_not_ask() -> TestResult {
    let f = Fixture::start(true, true)?;
    let (ok, out) = f.run("composed_retry")?;
    assert!(ok);
    // Two mechanisms, one polkit question and one `Sign` call each.
    let msg = message(COMPOSED_LEN);
    check_run(&f, &out, &msg, 2)
}

#[test]
fn composed_denied_returns_no_bytes_and_ends_the_operation() -> TestResult {
    let f = Fixture::start(false, true)?;
    let (ok, out) = f.run("composed_denied")?;
    assert!(ok);
    assert_eq!(lines(&out, "UNTOUCHED").count(), 2);
    assert!(lines(&out, "UNTOUCHED").all(|l| l[0] == "true"), "{out}");
    assert_eq!(f.asked(), 2);
    Ok(())
}
