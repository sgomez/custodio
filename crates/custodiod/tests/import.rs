//! `.p12` import tests, using the throwaway fixtures made by `tests/fixtures/gen.sh`.

use std::error::Error;

use custodiod::import::{
    ImportError, KeyKind, MAX_P12_LEN, ParsedP12, cert_id, check_archive, import_p12, parse_p12,
};
use custodiod::store::KeyStore;
use p12_keystore::{
    Certificate, KeyStore as P12KeyStore, KeyStoreEntry, LocalKeyId, Pkcs12Archive,
    Pkcs12ImportPolicy, PrivateKey, PrivateKeyBag, PrivateKeyChain,
};
use secrecy::{ExposeSecret, SecretSlice, SecretString};

type TestResult = Result<(), Box<dyn Error>>;

const PASSWORD: &str = "test-password";

fn pw(s: &str) -> SecretString {
    SecretString::from(s.to_owned())
}

fn fixture(name: &str) -> Result<Vec<u8>, std::io::Error> {
    std::fs::read(format!(
        "{}/tests/fixtures/{name}.p12",
        env!("CARGO_MANIFEST_DIR")
    ))
}

fn parse(name: &str) -> Result<ParsedP12, Box<dyn Error>> {
    Ok(parse_p12(&fixture(name)?, &pw(PASSWORD))?)
}

/// The error of a result that must be an error (`ParsedP12` and `KeyKind` have no `Debug` leaks).
fn err_of<T: std::fmt::Debug>(r: Result<T, ImportError>) -> Result<ImportError, Box<dyn Error>> {
    match r {
        Err(e) => Ok(e),
        Ok(v) => Err(format!("expected an error, got {v:?}").into()),
    }
}

fn unsupported(name: &str) -> Result<String, Box<dyn Error>> {
    match err_of(parse_p12(&fixture(name)?, &pw(PASSWORD)))? {
        ImportError::UnsupportedKey(why) => Ok(why),
        other => Err(format!("expected UnsupportedKey, got {other:?}").into()),
    }
}

/// Single private key chain of a fixture.
fn chain_of(name: &str) -> Result<PrivateKeyChain, Box<dyn Error>> {
    let ks = P12KeyStore::from_pkcs12(&fixture(name)?, PASSWORD, Pkcs12ImportPolicy::Relaxed)?;
    let (_, chain) = ks.private_key_chain().ok_or("no chain")?;
    Ok(chain.clone())
}

#[test]
fn accepts_rsa_2048() -> TestResult {
    let p = parse("rsa2048")?;
    assert_eq!(p.kind, KeyKind::Rsa2048);
    assert_eq!(p.certificate.first(), Some(&0x30)); // DER SEQUENCE
    Ok(())
}

#[test]
fn accepts_rsa_2048_with_legacy_encryption() -> TestResult {
    assert_eq!(parse("rsa2048-legacy")?.kind, KeyKind::Rsa2048);
    Ok(())
}

#[test]
fn accepts_p256() -> TestResult {
    assert_eq!(parse("p256")?.kind, KeyKind::EcdsaP256);
    Ok(())
}

#[test]
fn rejects_rsa_3072() -> TestResult {
    assert_eq!(unsupported("rsa3072")?, "RSA 3072");
    Ok(())
}

#[test]
fn rejects_p384() -> TestResult {
    assert!(unsupported("p384")?.contains("P-256"));
    Ok(())
}

#[test]
fn rejects_ed25519() -> TestResult {
    assert!(unsupported("ed25519")?.starts_with("algorithm "));
    Ok(())
}

#[test]
fn rejects_wrong_password() -> TestResult {
    let err = err_of(parse_p12(&fixture("rsa2048")?, &pw("nope")))?;
    assert!(matches!(err, ImportError::Parse(_)), "{err:?}");
    Ok(())
}

#[test]
fn rejects_garbage_empty_and_truncated() -> TestResult {
    let good = fixture("p256")?;
    let truncated = good.get(..40).ok_or("fixture too short")?;
    for data in [&b""[..], b"not a p12 at all", truncated] {
        let err = err_of(parse_p12(data, &pw(PASSWORD)))?;
        assert!(matches!(err, ImportError::Parse(_)), "{err:?}");
    }
    Ok(())
}

#[test]
fn rejects_oversized_input() -> TestResult {
    let big = vec![0_u8; MAX_P12_LEN + 1];
    let err = err_of(parse_p12(&big, &pw(PASSWORD)))?;
    assert!(matches!(err, ImportError::TooLarge), "{err:?}");
    Ok(())
}

/// Builds a `.p12` holding the keys of the given fixtures, with or without their certificates.
fn rebuilt(chains: &[(&str, &str, bool)]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut out = P12KeyStore::new();
    for (alias, source, with_cert) in chains {
        let chain = chain_of(source)?;
        let key = PrivateKey::from_der(chain.key().as_der())?;
        let certs: Vec<Certificate> = if *with_cert {
            chain.certs().to_vec()
        } else {
            vec![]
        };
        out.add_entry(
            alias,
            KeyStoreEntry::PrivateKeyChain(PrivateKeyChain::new(alias.as_bytes(), key, certs)),
        );
    }
    Ok(out.writer(PASSWORD).write()?)
}

#[test]
fn rejects_key_without_certificate() -> TestResult {
    let data = rebuilt(&[("a", "rsa2048", false)])?;
    let err = err_of(parse_p12(&data, &pw(PASSWORD)))?;
    assert!(matches!(err, ImportError::NoCertificate), "{err:?}");
    Ok(())
}

#[test]
fn rejects_two_keys() -> TestResult {
    let data = rebuilt(&[("a", "rsa2048", true), ("b", "p256", true)])?;
    let err = err_of(parse_p12(&data, &pw(PASSWORD)))?;
    assert!(matches!(err, ImportError::MultipleKeys), "{err:?}");
    Ok(())
}

#[test]
fn rejects_file_without_private_key() -> TestResult {
    let chain = chain_of("p256")?;
    let cert = chain.certs().first().ok_or("no cert")?.clone();
    let mut out = P12KeyStore::new();
    out.add_entry("c", KeyStoreEntry::Certificate(cert));
    let data = out.writer(PASSWORD).write()?;
    let err = err_of(parse_p12(&data, &pw(PASSWORD)))?;
    assert!(matches!(err, ImportError::NoPrivateKey), "{err:?}");
    Ok(())
}

#[test]
fn import_stores_key_and_certificate() -> TestResult {
    let dir = tempfile::tempdir()?;
    let store = KeyStore::open(dir.path().join("state"))?;
    let kind = import_p12(&store, "fnmt", &fixture("p256")?, &pw(PASSWORD))?;
    assert_eq!(kind, KeyKind::EcdsaP256);

    let parsed = parse("p256")?;
    assert_eq!(
        store.get("fnmt")?.expose_secret(),
        parsed.key.expose_secret()
    );
    assert_eq!(
        store.get(&cert_id("fnmt"))?.expose_secret(),
        &parsed.certificate
    );
    assert_eq!(store.list()?, ["fnmt", "fnmt-cert"]);
    Ok(())
}

#[test]
fn rejected_import_stores_nothing() -> TestResult {
    let dir = tempfile::tempdir()?;
    let store = KeyStore::open(dir.path().join("state"))?;
    err_of(import_p12(&store, "k", &fixture("rsa3072")?, &pw(PASSWORD)))?;
    assert_eq!(store.list()?.len(), 0);
    Ok(())
}

#[test]
fn import_does_not_overwrite() -> TestResult {
    let dir = tempfile::tempdir()?;
    let store = KeyStore::open(dir.path().join("state"))?;
    import_p12(&store, "k", &fixture("p256")?, &pw(PASSWORD))?;
    let err = err_of(import_p12(&store, "k", &fixture("rsa2048")?, &pw(PASSWORD)))?;
    assert!(matches!(err, ImportError::Store(_)), "{err:?}");
    Ok(())
}

#[test]
fn errors_and_debug_do_not_leak_secrets() -> TestResult {
    let secret = "very-secret-pass-0451";
    let err = err_of(parse_p12(&fixture("rsa2048")?, &pw(secret)))?;
    assert!(!format!("{err} {err:?}").contains(secret));

    let parsed = parse("p256")?;
    let debug = format!("{parsed:?}");
    assert!(debug.contains("[REDACTED]"), "{debug}");
    assert!(!debug.contains(&format!("{:?}", parsed.key.expose_secret())));
    Ok(())
}

/// A `.p12` with the key of `key_from` and the certificate of `cert_from`, under one `localKeyId`.
fn crossed(key_from: &str, cert_from: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let key = PrivateKey::from_der(chain_of(key_from)?.key().as_der())?;
    let certs = chain_of(cert_from)?.certs().to_vec();
    let mut out = P12KeyStore::new();
    out.add_entry(
        "x",
        KeyStoreEntry::PrivateKeyChain(PrivateKeyChain::new(&b"same-id"[..], key, certs)),
    );
    Ok(out.writer(PASSWORD).write()?)
}

#[test]
fn rejects_rsa_key_with_another_rsa_certificate() -> TestResult {
    let data = crossed("rsa2048", "rsa2048-legacy")?;
    let err = err_of(parse_p12(&data, &pw(PASSWORD)))?;
    assert!(matches!(err, ImportError::CertificateMismatch), "{err:?}");
    Ok(())
}

#[test]
fn rejects_p256_key_with_another_p256_certificate() -> TestResult {
    let data = crossed("p256", "p256-other")?;
    let err = err_of(parse_p12(&data, &pw(PASSWORD)))?;
    assert!(matches!(err, ImportError::CertificateMismatch), "{err:?}");
    Ok(())
}

#[test]
fn rejects_key_with_certificate_of_another_type() -> TestResult {
    for (key, cert) in [("p256", "rsa2048"), ("rsa2048", "p256")] {
        let err = err_of(parse_p12(&crossed(key, cert)?, &pw(PASSWORD)))?;
        assert!(matches!(err, ImportError::CertificateMismatch), "{err:?}");
    }
    Ok(())
}

#[test]
fn matching_certificate_is_found_among_several() -> TestResult {
    let mut archive = Pkcs12Archive::default();
    for name in ["p256-other", "p256"] {
        let chain = chain_of(name)?;
        if name == "p256" {
            archive.keys.push(bag(&chain, None)?);
        }
        archive.certs.push(cert_bag(&chain)?);
    }
    let parsed = check_archive(&archive)?;
    assert_eq!(parsed.certificate, parse("p256")?.certificate);
    Ok(())
}

fn bag(chain: &PrivateKeyChain, kid: Option<&[u8]>) -> Result<PrivateKeyBag, Box<dyn Error>> {
    Ok(PrivateKeyBag {
        friendly_name: None,
        local_key_id: kid.map(|k| LocalKeyId(k.to_vec())),
        key: PrivateKey::from_der(chain.key().as_der())?,
    })
}

fn cert_bag(chain: &PrivateKeyChain) -> Result<p12_keystore::CertificateBag, Box<dyn Error>> {
    Ok(p12_keystore::CertificateBag {
        friendly_name: None,
        local_key_id: None,
        trusted: false,
        cert: chain.certs().first().ok_or("no cert")?.clone(),
    })
}

#[test]
fn accepts_single_key_without_local_key_id() -> TestResult {
    assert_eq!(parse("p256-nokid")?.kind, KeyKind::EcdsaP256);
    Ok(())
}

#[test]
fn counts_keys_without_local_key_id() -> TestResult {
    let (p, r) = (chain_of("p256")?, chain_of("rsa2048")?);
    let mut archive = Pkcs12Archive::default();
    archive.keys.push(bag(&p, Some(b"id"))?);
    archive.keys.push(bag(&r, None)?);
    archive.certs.push(cert_bag(&p)?);
    let err = err_of(check_archive(&archive))?;
    assert!(matches!(err, ImportError::MultipleKeys), "{err:?}");

    archive.keys.clear();
    archive.keys.push(bag(&p, None)?);
    archive.keys.push(bag(&r, None)?);
    let err = err_of(check_archive(&archive))?;
    assert!(matches!(err, ImportError::MultipleKeys), "{err:?}");
    Ok(())
}

#[test]
fn failed_key_write_leaves_no_certificate() -> TestResult {
    let dir = tempfile::tempdir()?;
    let store = KeyStore::open(dir.path().join("state"))?;
    let existing = SecretSlice::from(b"other".to_vec());
    store.put("k", &existing)?;
    let err = err_of(import_p12(&store, "k", &fixture("p256")?, &pw(PASSWORD)))?;
    assert!(matches!(err, ImportError::Store(_)), "{err:?}");
    assert_eq!(store.list()?, ["k"]);
    Ok(())
}
