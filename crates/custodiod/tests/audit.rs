//! One audit entry per `Sign` call that reaches authorization, failing closed. A private
//! `dbus-daemon`, a fake polkit, the real `BusCredentials` and replaced sinks.

#[path = "audit/bus.rs"]
mod bus;
#[path = "audit/common.rs"]
mod common;
#[path = "audit/leaks.rs"]
mod leaks;
#[path = "audit/scan.rs"]
mod scan;
#[path = "audit/timing.rs"]
mod timing;

use std::sync::{Arc, Mutex, PoisonError};

use custodiod::audit::{AuditMechanism, Entry, FailingSink, JournalSink, MemorySink, Outcome};
use custodiod::credentials::{BusCredentials, CallerCredentials};
use pkcs8::DecodePrivateKey;
use zbus::{Connection, block_on};

use bus::{Answer, Fixture, TestResult, call, error_name, sign};
use common::{
    ACCESS_DENIED, CKM_ECDSA, CKM_RSA_PKCS, EC_P12, MissingPid, NoCredentials, RSA_P12, Recording,
    assert_entry, digest, digest_info, fixture, import, uid,
};

const ECDSA: AuditMechanism = AuditMechanism::Ecdsa;

fn failed(r: zbus::Result<Vec<u8>>) -> Result<zbus::Error, &'static str> {
    r.err().ok_or("a signature was returned")
}

#[test]
fn sign_entry_has_test_process_uid_and_pid() -> TestResult {
    block_on(async {
        let sink = Arc::new(MemorySink::default());
        let f = fixture(Answer::Yes, &sink).await?;
        import(&f, "ec", EC_P12).await?;
        sign(&f.client, "ec", CKM_ECDSA, &digest()).await?;
        let [e] = sink
            .entries()
            .try_into()
            .map_err(|_| "expected one entry")?;
        assert_entry(&e, "ec", ECDSA, Outcome::Signed);
        assert_ne!(e.caller().map(|c| c.pid), Some(0));
        assert_eq!(e.caller().map(|c| c.uid), Some(uid()));
        Ok(())
    })
}

#[test]
fn outcome_signed() -> TestResult {
    block_on(async {
        let sink = Arc::new(MemorySink::default());
        let f = fixture(Answer::Yes, &sink).await?;
        import(&f, "rsa", RSA_P12).await?;
        let sig = sign(&f.client, "rsa", CKM_RSA_PKCS, &digest_info()).await?;
        assert_eq!(sig.len(), 256);
        // Verify with the public key of the fixture certificate, not with the service's own code.
        let key = custodiod::import::parse_p12(
            RSA_P12,
            &secrecy::SecretString::from(common::PASSWORD.to_owned()),
        )?
        .key;
        let public =
            rsa::RsaPrivateKey::from_pkcs8_der(secrecy::ExposeSecret::expose_secret(&key))?
                .to_public_key();
        public.verify(rsa::Pkcs1v15Sign::new::<sha2::Sha256>(), &digest(), &sig)?;
        let entries = sink.entries();
        assert_eq!(entries.len(), 1);
        assert_entry(
            entries.first().ok_or("no entry")?,
            "rsa",
            AuditMechanism::RsaPkcs,
            Outcome::Signed,
        );
        Ok(())
    })
}

#[test]
fn outcome_signing_failed() -> TestResult {
    block_on(async {
        let sink = Arc::new(MemorySink::default());
        let f = fixture(Answer::Yes, &sink).await?;
        import(&f, "rsa", RSA_P12).await?;
        // An RSA key with an ECDSA mechanism.
        failed(sign(&f.client, "rsa", CKM_ECDSA, &digest()).await)?;
        // A well-formed id that is not in the store.
        failed(sign(&f.client, "missing", CKM_ECDSA, &digest()).await)?;
        let entries = sink.entries();
        assert_eq!(entries.len(), 2);
        assert_entry(
            entries.first().ok_or("no entry")?,
            "rsa",
            ECDSA,
            Outcome::SigningFailed,
        );
        assert_entry(
            entries.get(1).ok_or("no entry")?,
            "missing",
            ECDSA,
            Outcome::SigningFailed,
        );
        Ok(())
    })
}

#[test]
fn outcome_denied() -> TestResult {
    block_on(async {
        for answer in [Answer::No, Answer::Challenge] {
            let sink = Arc::new(MemorySink::default());
            let f = fixture(answer, &sink).await?;
            // No key file: a read would give `SigningFailed`, not `Denied`.
            let err = failed(sign(&f.client, "ec", CKM_ECDSA, &digest()).await)?;
            assert_eq!(error_name(&err), ACCESS_DENIED);
            let entries = sink.entries();
            assert_eq!(entries.len(), 1);
            assert_entry(
                entries.first().ok_or("no entry")?,
                "ec",
                ECDSA,
                Outcome::Denied,
            );
        }
        Ok(())
    })
}

#[test]
fn outcome_authorization_unavailable() -> TestResult {
    block_on(async {
        // polkit answers with an error.
        let sink = Arc::new(MemorySink::default());
        let f = fixture(Answer::Fail, &sink).await?;
        let err = failed(sign(&f.client, "ec", CKM_ECDSA, &digest()).await)?;
        assert_eq!(error_name(&err), ACCESS_DENIED);
        // polkit is not on the bus.
        f.polkit.release_name("org.freedesktop.PolicyKit1").await?;
        let err = failed(sign(&f.client, "ec", CKM_ECDSA, &digest()).await)?;
        assert_eq!(error_name(&err), ACCESS_DENIED);
        let entries = sink.entries();
        assert_eq!(entries.len(), 2);
        for e in &entries {
            assert_entry(e, "ec", ECDSA, Outcome::AuthorizationUnavailable);
        }
        Ok(())
    })
}

#[test]
fn exactly_one_entry_per_call() -> TestResult {
    block_on(async {
        let sink = Arc::new(MemorySink::default());
        let f = fixture(Answer::Yes, &sink).await?;
        import(&f, "ec", EC_P12).await?;
        import(&f, "rsa", RSA_P12).await?;
        assert_eq!(sink.entries(), Vec::new());
        let rsa_data = digest_info();
        let plan: [(Answer, &str, u32, Outcome); 8] = [
            (Answer::Yes, "ec", CKM_ECDSA, Outcome::Signed),
            (Answer::No, "ec", CKM_ECDSA, Outcome::Denied),
            (
                Answer::Fail,
                "rsa",
                CKM_RSA_PKCS,
                Outcome::AuthorizationUnavailable,
            ),
            (Answer::Yes, "rsa", CKM_ECDSA, Outcome::SigningFailed),
            (Answer::Yes, "rsa", CKM_RSA_PKCS, Outcome::Signed),
            (Answer::Challenge, "rsa", CKM_RSA_PKCS, Outcome::Denied),
            (
                Answer::Fail,
                "ec",
                CKM_ECDSA,
                Outcome::AuthorizationUnavailable,
            ),
            (Answer::Yes, "gone", CKM_ECDSA, Outcome::SigningFailed),
        ];
        for (n, (answer, id, mechanism, outcome)) in plan.iter().enumerate() {
            f.set_answer(*answer);
            let data = if id.starts_with("rsa") && *mechanism == CKM_RSA_PKCS {
                &rsa_data
            } else {
                &digest()
            };
            let reply = sign(&f.client, id, *mechanism, data).await;
            assert_eq!(
                reply.is_ok(),
                *outcome == Outcome::Signed,
                "reply of call {n}"
            );
            let entries = sink.entries();
            assert_eq!(entries.len(), n + 1);
            let want = if *mechanism == CKM_RSA_PKCS {
                AuditMechanism::RsaPkcs
            } else {
                ECDSA
            };
            assert_entry(entries.get(n).ok_or("no entry")?, id, want, *outcome);
            // Other methods add nothing.
            call(&f.client, "ListKeys", &()).await?;
            call(&f.client, "ListCertificates", &()).await?;
            assert_eq!(sink.entries().len(), n + 1);
        }
        import(&f, "again", EC_P12).await?;
        assert_eq!(sink.entries().len(), 8);
        Ok(())
    })
}

#[test]
fn failing_sink_withholds_the_signature() -> TestResult {
    block_on(async {
        let sink = Arc::new(MemorySink::default());
        let f = fixture(Answer::Yes, &sink).await?;
        import(&f, "rsa", RSA_P12).await?;
        let data = digest_info();
        let signature = sign(&f.client, "rsa", CKM_RSA_PKCS, &data).await?;

        let failing = Fixture::start(
            Answer::Yes,
            |c: &Connection| BusCredentials::new(c.clone()),
            Arc::new(FailingSink),
        )
        .await?;
        import(&failing, "rsa", RSA_P12).await?;
        let reply = call(
            &failing.client,
            "Sign",
            &("rsa", CKM_RSA_PKCS, 0u32, 0u32, data.clone()),
        )
        .await;
        let err = reply.err().ok_or("a reply came back")?;
        assert_eq!(error_name(&err), "org.freedesktop.DBus.Error.Failed");
        let text = format!("{err:?} {err}");
        assert!(text.contains("audit unavailable"));
        for value in [&signature, &data] {
            assert_eq!(scan::leaks(text.as_bytes(), value), Vec::<&str>::new());
        }
        Ok(())
    })
}

#[test]
fn failing_sink_fails_every_outcome() -> TestResult {
    block_on(async {
        for answer in [Answer::Yes, Answer::No, Answer::Fail] {
            let f = Fixture::start(
                answer,
                |c: &Connection| BusCredentials::new(c.clone()),
                Arc::new(FailingSink),
            )
            .await?;
            import(&f, "ec", EC_P12).await?;
            for (id, mechanism) in [("ec", CKM_ECDSA), ("ec", CKM_RSA_PKCS), ("gone", CKM_ECDSA)] {
                let err = failed(sign(&f.client, id, mechanism, &digest()).await)?;
                assert!(format!("{err}").contains("audit unavailable"), "{err}");
            }
        }
        let f = Fixture::start(
            Answer::Yes,
            |_: &Connection| NoCredentials,
            Arc::new(FailingSink),
        )
        .await?;
        import(&f, "ec", EC_P12).await?;
        let err = failed(sign(&f.client, "ec", CKM_ECDSA, &digest()).await)?;
        assert!(format!("{err}").contains("audit unavailable"), "{err}");
        Ok(())
    })
}

#[test]
fn missing_journal_socket_withholds_the_signature() -> TestResult {
    block_on(async {
        let dir = tempfile::tempdir()?;
        let sink = Arc::new(JournalSink::new(dir.path().join("none.sock")));
        let f = Fixture::start(
            Answer::Yes,
            |c: &Connection| BusCredentials::new(c.clone()),
            sink,
        )
        .await?;
        import(&f, "ec", EC_P12).await?;
        let err = failed(sign(&f.client, "ec", CKM_ECDSA, &digest()).await)?;
        assert!(format!("{err}").contains("audit unavailable"));
        Ok(())
    })
}

#[test]
fn credentials_unavailable_refuses_and_records() -> TestResult {
    block_on(async {
        let sink = Arc::new(MemorySink::default());
        let f = Fixture::start(Answer::Yes, |_: &Connection| NoCredentials, sink.clone()).await?;
        // The key file is absent: no key is read.
        let err = failed(sign(&f.client, "ec", CKM_ECDSA, &digest()).await)?;
        assert_eq!(error_name(&err), ACCESS_DENIED);
        assert_eq!(f.asked(), Vec::<String>::new());
        let entries = sink.entries();
        assert_eq!(entries.len(), 1);
        let e = entries.first().ok_or("no entry")?;
        assert_eq!(
            (e.outcome(), e.caller()),
            (Outcome::AuthorizationUnavailable, None)
        );
        assert_eq!(e.key_id().as_str(), "ec");
        assert_eq!(e.mechanism(), Some(ECDSA));

        let sink = Arc::new(MemorySink::default());
        let f = Fixture::start(Answer::Yes, |_: &Connection| MissingPid, sink.clone()).await?;
        let err = failed(sign(&f.client, "ec", CKM_ECDSA, &digest()).await)?;
        assert_eq!(error_name(&err), ACCESS_DENIED);
        assert_eq!(f.asked(), Vec::<String>::new());
        let entries = sink.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries.first().map(Entry::outcome),
            Some(Outcome::AuthorizationUnavailable)
        );
        assert_eq!(entries.first().and_then(Entry::caller), None);
        Ok(())
    })
}

#[test]
fn credentials_for_unknown_name_is_an_error() -> TestResult {
    block_on(async {
        let sink = Arc::new(MemorySink::default());
        let f = fixture(Answer::Yes, &sink).await?;
        let creds = BusCredentials::new(f.client.clone());
        assert!(creds.credentials(":1.99999").await.is_err());
        assert!(
            creds
                .credentials(f.client.unique_name().ok_or("no name")?.as_str())
                .await
                .is_ok()
        );
        Ok(())
    })
}

#[test]
fn credentials_and_polkit_see_the_same_sender() -> TestResult {
    block_on(async {
        let sink = Arc::new(MemorySink::default());
        let names = Arc::new(Mutex::new(Vec::new()));
        let seen = names.clone();
        let f = Fixture::start(
            Answer::Yes,
            move |c: &Connection| Recording {
                inner: BusCredentials::new(c.clone()),
                names: seen,
            },
            sink,
        )
        .await?;
        import(&f, "ec", EC_P12).await?;
        let second = f.bus.connect().await?;
        let mut want = Vec::new();
        for client in [&f.client, &second] {
            sign(client, "ec", CKM_ECDSA, &digest()).await?;
            want.push(client.unique_name().ok_or("no name")?.to_string());
        }
        assert_ne!(want.first(), want.get(1));
        assert_eq!(f.asked(), want);
        assert_eq!(*names.lock().unwrap_or_else(PoisonError::into_inner), want);
        Ok(())
    })
}
