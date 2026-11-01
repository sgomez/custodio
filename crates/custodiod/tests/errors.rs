//! Every failure of the service answers with its own `com.rfirma.Custodio1.Error.*` name and a fixed
//! message that repeats nothing the caller sent. A private `dbus-daemon`, a fake polkit.

// The shared helpers are used in full by the audit tests; this file uses part of them.
#[allow(dead_code, unused_imports)]
#[path = "audit/bus.rs"]
mod bus;
#[allow(dead_code, unused_imports)]
#[path = "audit/common.rs"]
mod common;

use std::error::Error;
use std::sync::Arc;

use custodio_client::{
    ERROR_AUDIT_UNAVAILABLE, ERROR_AUTHORIZATION_UNAVAILABLE, ERROR_CERTIFICATE_MISMATCH,
    ERROR_INTERNAL, ERROR_INVALID_ARGS, ERROR_KEY_ID_TAKEN, ERROR_NO_SUCH_KEY, ERROR_POLKIT_DENIED,
    ERROR_UNSUPPORTED_KEY_TYPE, ERROR_WRONG_PASSWORD_OR_BAD_P12, MAX_P12_LEN,
};
use custodiod::audit::{FailingSink, MemorySink};
use custodiod::error::ServiceError;
use p12_keystore::{
    Certificate, KeyStore as P12KeyStore, KeyStoreEntry, Pkcs12ImportPolicy, PrivateKey,
    PrivateKeyChain,
};
use zbus::{Connection, block_on};

use bus::{Answer, Fixture, TestResult, call};
use common::{CKM_ECDSA, CKM_RSA_PKCS, EC_P12, NoCredentials, PASSWORD, RSA_P12, import};

type SignCase<'a> = (&'a str, (u32, u32, u32), &'a [u8]);
const CKM_RSA_PKCS_PSS: u32 = 0x000D;
const CKM_SHA256: u32 = 0x0250;
const SENTINEL_ID: &str = "LEAK-id-sentinel/../x";
const SENTINEL_PASSWORD: &str = "LEAK-password-sentinel-4711";
const SENTINEL_BYTES: &[u8] = b"LEAK-p12-sentinel-bytes";

fn fx(name: &str) -> Result<Vec<u8>, std::io::Error> {
    std::fs::read(format!(
        "{}/tests/fixtures/{name}.p12",
        env!("CARGO_MANIFEST_DIR")
    ))
}

/// The error name and message of a reply that must be an error.
fn failure<T>(r: zbus::Result<T>) -> Result<(String, String), Box<dyn Error>> {
    match r {
        Err(zbus::Error::MethodError(name, message, _)) => {
            Ok((name.as_str().to_owned(), message.unwrap_or_default()))
        }
        Err(other) => Err(format!("not a method error: {other}").into()),
        Ok(_) => Err("the call succeeded".into()),
    }
}

async fn import_call(f: &Fixture, id: &str, data: &[u8], pw: &str) -> zbus::Result<String> {
    call(&f.client, "ImportP12", &(id, data.to_vec(), pw))
        .await?
        .body()
        .deserialize()
}

async fn sign_call(
    f: &Fixture,
    id: &str,
    (mechanism, hash, salt): (u32, u32, u32),
    data: &[u8],
) -> zbus::Result<Vec<u8>> {
    call(
        &f.client,
        "Sign",
        &(id, mechanism, hash, salt, data.to_vec()),
    )
    .await?
    .body()
    .deserialize()
}

async fn start(answer: Answer) -> Result<Fixture, Box<dyn Error>> {
    common::fixture(answer, &Arc::new(MemorySink::default())).await
}

fn is(got: &(String, String), want: ServiceError) {
    assert_eq!(got.0, want.error_name(), "{got:?}");
    assert_eq!(got.1, want.message(), "{got:?}");
}

fn ec_sign() -> (u32, u32, u32) {
    (CKM_ECDSA, 0, 0)
}

#[test]
fn import_arguments_are_invalid_args() -> TestResult {
    block_on(async {
        let f = start(Answer::Yes).await?;
        let big = vec![0u8; MAX_P12_LEN + 1];
        let long_pw = "p".repeat(1025);
        for (id, data, pw) in [
            ("../etc", EC_P12, PASSWORD),
            ("k-cert", EC_P12, PASSWORD),
            ("k", &big[..], PASSWORD),
            ("k", EC_P12, long_pw.as_str()),
        ] {
            is(
                &failure(import_call(&f, id, data, pw).await)?,
                ServiceError::InvalidArgs,
            );
        }
        Ok(())
    })
}

#[test]
fn import_failures_have_their_names() -> TestResult {
    block_on(async {
        let f = start(Answer::Yes).await?;
        import(&f, "taken", EC_P12).await?;
        is(
            &failure(import_call(&f, "taken", EC_P12, PASSWORD).await)?,
            ServiceError::KeyIdTaken,
        );
        let cases: Vec<(Vec<u8>, &str, ServiceError)> = vec![
            (
                EC_P12.to_vec(),
                "wrong",
                ServiceError::WrongPasswordOrBadP12,
            ),
            (
                b"not a p12".to_vec(),
                PASSWORD,
                ServiceError::WrongPasswordOrBadP12,
            ),
            (
                rebuilt(&[("rsa2048", false)])?,
                PASSWORD,
                ServiceError::WrongPasswordOrBadP12,
            ),
            (
                rebuilt(&[("rsa2048", true), ("p256", true)])?,
                PASSWORD,
                ServiceError::WrongPasswordOrBadP12,
            ),
            (
                no_private_key()?,
                PASSWORD,
                ServiceError::WrongPasswordOrBadP12,
            ),
            (fx("ed25519")?, PASSWORD, ServiceError::UnsupportedKeyType),
            (fx("rsa3072")?, PASSWORD, ServiceError::UnsupportedKeyType),
            (fx("p384")?, PASSWORD, ServiceError::UnsupportedKeyType),
            (
                crossed("p256", "p256-other")?,
                PASSWORD,
                ServiceError::CertificateMismatch,
            ),
            (
                crossed("rsa2048", "p256")?,
                PASSWORD,
                ServiceError::CertificateMismatch,
            ),
        ];
        for (n, (data, pw, want)) in cases.iter().enumerate() {
            let got = failure(import_call(&f, &format!("k{n}"), data, pw).await)?;
            is(&got, *want);
        }
        Ok(())
    })
}

/// Makes the caller's area unusable (a loose mode is refused, never repaired).
fn break_area(f: &Fixture) -> TestResult {
    use std::os::unix::fs::PermissionsExt;
    let area = f.store_dir().join(common::uid().to_string());
    std::fs::set_permissions(area, std::fs::Permissions::from_mode(0o755))?;
    Ok(())
}

#[test]
fn store_failures_are_internal() -> TestResult {
    block_on(async {
        let f = start(Answer::Yes).await?;
        import(&f, "ec", EC_P12).await?;
        break_area(&f)?;
        is(
            &failure(call(&f.client, "ListKeys", &()).await)?,
            ServiceError::Internal,
        );
        is(
            &failure(call(&f.client, "ListCertificates", &()).await)?,
            ServiceError::Internal,
        );
        is(
            &failure(import_call(&f, "k", EC_P12, PASSWORD).await)?,
            ServiceError::Internal,
        );
        Ok(())
    })
}

#[test]
fn sign_arguments_are_invalid_args() -> TestResult {
    block_on(async {
        let f = start(Answer::Yes).await?;
        import(&f, "ec", EC_P12).await?;
        let big = vec![0u8; 1025];
        let d = [7u8; 32];
        let cases: Vec<SignCase> = vec![
            ("../etc", ec_sign(), &d),
            ("ec-cert", ec_sign(), &d),
            ("ec", (0x9999, 0, 0), &d),
            ("ec", (CKM_RSA_PKCS_PSS, 0, 0), &d),
            ("ec", (CKM_ECDSA, CKM_SHA256, 0), &d),
            ("ec", (CKM_ECDSA, 0, 1), &d),
            ("ec", ec_sign(), &big),
            // The key is not an RSA key.
            ("ec", (CKM_RSA_PKCS, 0, 0), &d),
        ];
        for (id, mech, data) in cases {
            is(
                &failure(sign_call(&f, id, mech, data).await)?,
                ServiceError::InvalidArgs,
            );
        }
        Ok(())
    })
}

#[test]
fn sign_refusals_have_their_names() -> TestResult {
    block_on(async {
        let f = start(Answer::Yes).await?;
        is(
            &failure(sign_call(&f, "missing", ec_sign(), &[7; 32]).await)?,
            ServiceError::NoSuchKey,
        );
        import(&f, "ec", EC_P12).await?;
        for answer in [Answer::No, Answer::Challenge] {
            f.set_answer(answer);
            is(
                &failure(sign_call(&f, "ec", ec_sign(), &[7; 32]).await)?,
                ServiceError::PolkitDenied,
            );
        }
        f.set_answer(Answer::Fail);
        is(
            &failure(sign_call(&f, "ec", ec_sign(), &[7; 32]).await)?,
            ServiceError::AuthorizationUnavailable,
        );
        f.set_answer(Answer::Yes);
        f.polkit.release_name("org.freedesktop.PolicyKit1").await?;
        is(
            &failure(sign_call(&f, "ec", ec_sign(), &[7; 32]).await)?,
            ServiceError::AuthorizationUnavailable,
        );
        Ok(())
    })
}

#[test]
fn credentials_failure_is_authorization_unavailable() -> TestResult {
    block_on(async {
        let sink = Arc::new(MemorySink::default());
        let f = Fixture::start(Answer::Yes, |_: &Connection| NoCredentials, sink).await?;
        import(&f, "ec", EC_P12).await?;
        is(
            &failure(sign_call(&f, "ec", ec_sign(), &[7; 32]).await)?,
            ServiceError::AuthorizationUnavailable,
        );
        Ok(())
    })
}

#[test]
fn audit_failure_is_audit_unavailable() -> TestResult {
    block_on(async {
        let f = Fixture::start(
            Answer::Yes,
            |c: &Connection| custodiod::credentials::BusCredentials::new(c.clone()),
            Arc::new(FailingSink),
        )
        .await?;
        import(&f, "ec", EC_P12).await?;
        is(
            &failure(sign_call(&f, "ec", ec_sign(), &[7; 32]).await)?,
            ServiceError::AuditUnavailable,
        );
        Ok(())
    })
}

#[test]
fn a_bad_key_file_is_internal() -> TestResult {
    block_on(async {
        let f = start(Answer::Yes).await?;
        import(&f, "ec", EC_P12).await?;
        std::fs::write(
            f.store_dir().join(common::uid().to_string()).join("ec"),
            b"not a pkcs8 key",
        )?;
        is(
            &failure(sign_call(&f, "ec", ec_sign(), &[7; 32]).await)?,
            ServiceError::Internal,
        );
        Ok(())
    })
}

#[test]
fn the_wire_names_are_the_client_constants() -> TestResult {
    block_on(async {
        let f = start(Answer::Yes).await?;
        let (name, _) = failure(sign_call(&f, "missing", ec_sign(), &[7; 32]).await)?;
        assert_eq!(name, ERROR_NO_SUCH_KEY);
        let (name, _) = failure(import_call(&f, "../x", EC_P12, PASSWORD).await)?;
        assert_eq!(name, ERROR_INVALID_ARGS);
        // Every constant is a variant's name, and nothing else is.
        let all = [
            ERROR_AUDIT_UNAVAILABLE,
            ERROR_AUTHORIZATION_UNAVAILABLE,
            ERROR_CERTIFICATE_MISMATCH,
            ERROR_INTERNAL,
            ERROR_INVALID_ARGS,
            ERROR_KEY_ID_TAKEN,
            ERROR_NO_SUCH_KEY,
            ERROR_POLKIT_DENIED,
            ERROR_UNSUPPORTED_KEY_TYPE,
            ERROR_WRONG_PASSWORD_OR_BAD_P12,
        ];
        for e in ServiceError::ALL {
            assert!(all.contains(&e.error_name()), "{e:?}");
        }
        Ok(())
    })
}

/// Triggers every kind of failure with recognizable input; returns `(input texts, replies)`.
async fn sentinel_replies() -> Result<(Vec<String>, Vec<(String, String)>), Box<dyn Error>> {
    let mut out = Vec::new();
    let f = start(Answer::Yes).await?;
    let store_path = f.store_dir().display().to_string();
    import(&f, "ec", EC_P12).await?;
    let mut garbage = SENTINEL_BYTES.to_vec();
    garbage.extend_from_slice(store_path.as_bytes());
    out.push(failure(
        import_call(&f, SENTINEL_ID, EC_P12, SENTINEL_PASSWORD).await,
    )?);
    out.push(failure(
        import_call(&f, "ec", EC_P12, SENTINEL_PASSWORD).await,
    )?);
    out.push(failure(
        import_call(&f, "s1", &garbage, SENTINEL_PASSWORD).await,
    )?);
    out.push(failure(
        import_call(&f, "s2", RSA_P12, SENTINEL_PASSWORD).await,
    )?);
    out.push(failure(
        import_call(&f, "s3", &fx("ed25519")?, SENTINEL_PASSWORD).await,
    )?);
    out.push(failure(
        sign_call(&f, SENTINEL_ID, ec_sign(), &garbage).await,
    )?);
    out.push(failure(
        sign_call(&f, "LEAK-id-missing", ec_sign(), &[7; 32]).await,
    )?);
    f.set_answer(Answer::No);
    out.push(failure(sign_call(&f, "ec", ec_sign(), &[7; 32]).await)?);
    f.set_answer(Answer::Fail);
    out.push(failure(sign_call(&f, "ec", ec_sign(), &[7; 32]).await)?);
    break_area(&f)?;
    out.push(failure(call(&f.client, "ListKeys", &()).await)?);
    out.push(failure(
        import_call(&f, "s4", EC_P12, SENTINEL_PASSWORD).await,
    )?);
    let inputs = vec![
        SENTINEL_ID.to_owned(),
        "LEAK-id-missing".to_owned(),
        SENTINEL_PASSWORD.to_owned(),
        String::from_utf8_lossy(SENTINEL_BYTES).into_owned(),
        store_path,
        "sentinel".to_owned(),
    ];
    Ok((inputs, out))
}

#[test]
fn replies_leak_nothing_and_are_fixed() -> TestResult {
    block_on(async {
        let (inputs, replies) = sentinel_replies().await?;
        assert_eq!(replies.len(), 11);
        for (name, message) in &replies {
            let want = ServiceError::ALL
                .iter()
                .find(|e| e.error_name() == name)
                .ok_or("a name that is not a variant")?;
            assert_eq!(message, want.message(), "{name}");
            assert!(!message.contains('/'), "{message}");
            for text in &inputs {
                assert!(!message.contains(text.as_str()), "{message} has {text}");
                assert!(!name.contains(text.as_str()), "{name} has {text}");
            }
        }
        Ok(())
    })
}

#[test]
fn the_message_is_the_same_for_different_inputs() -> TestResult {
    block_on(async {
        let f = start(Answer::Yes).await?;
        let a = failure(import_call(&f, "../one", EC_P12, "x").await)?;
        let b = failure(import_call(&f, "two words", EC_P12, "y").await)?;
        assert_eq!(a, b);
        let a = failure(import_call(&f, "a1", b"one", "x").await)?;
        let b = failure(import_call(&f, "a2", b"two, longer", "y").await)?;
        assert_eq!(a, b);
        Ok(())
    })
}

// --- .p12 builders, as in `import.rs` -----------------------------------------------------------

fn chain_of(name: &str) -> Result<PrivateKeyChain, Box<dyn Error>> {
    let ks = P12KeyStore::from_pkcs12(&fx(name)?, PASSWORD, Pkcs12ImportPolicy::Relaxed)?;
    let (_, chain) = ks.private_key_chain().ok_or("no chain")?;
    Ok(chain.clone())
}

fn rebuilt(chains: &[(&str, bool)]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut out = P12KeyStore::new();
    for (source, with_cert) in chains {
        let chain = chain_of(source)?;
        let key = PrivateKey::from_der(chain.key().as_der())?;
        let certs: Vec<Certificate> = if *with_cert {
            chain.certs().to_vec()
        } else {
            vec![]
        };
        out.add_entry(
            source,
            KeyStoreEntry::PrivateKeyChain(PrivateKeyChain::new(source.as_bytes(), key, certs)),
        );
    }
    Ok(out.writer(PASSWORD).write()?)
}

fn no_private_key() -> Result<Vec<u8>, Box<dyn Error>> {
    let cert = chain_of("p256")?.certs().first().ok_or("no cert")?.clone();
    let mut out = P12KeyStore::new();
    out.add_entry("c", KeyStoreEntry::Certificate(cert));
    Ok(out.writer(PASSWORD).write()?)
}

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
