use super::*;

#[test]
fn ids_are_checked() {
    for ok in ["a", "my-key_1", &"a".repeat(MAX_ID_LEN)] {
        assert!(check_id(ok).is_ok(), "{ok}");
    }
    for bad in [
        "",
        "a b",
        "../x",
        "a/b",
        "k-cert",
        &"a".repeat(MAX_ID_LEN + 1),
        "é",
    ] {
        assert_eq!(check_id(bad), Err(RequestError::BadId), "{bad}");
    }
}

#[test]
fn sign_mechanisms_map() {
    let req = |m, h, s| parse_sign_request("k", m, h, s, b"x").map(|r| r.mechanism);
    assert_eq!(req(CKM_RSA_PKCS, 0, 0), Ok(Mechanism::RsaPkcs));
    assert_eq!(req(CKM_ECDSA, 0, 0), Ok(Mechanism::Ecdsa));
    assert_eq!(
        req(CKM_RSA_PKCS_PSS, CKM_SHA384, 48),
        Ok(Mechanism::RsaPkcsPss {
            hash: PssHash::Sha384,
            salt_len: 48
        })
    );
    assert_eq!(req(CKM_RSA_PKCS_PSS, 0, 0), Err(RequestError::BadHash));
    assert_eq!(req(CKM_RSA_PKCS, CKM_SHA256, 0), Err(RequestError::BadHash));
    assert_eq!(req(CKM_ECDSA, 0, 1), Err(RequestError::BadSaltLength));
    assert_eq!(req(0x9999, 0, 0), Err(RequestError::BadMechanism));
}

#[test]
fn sizes_are_capped() {
    let big = vec![0; MAX_SIGN_DATA_LEN + 1];
    assert_eq!(
        parse_sign_request("k", CKM_ECDSA, 0, 0, &big),
        Err(RequestError::DataTooLarge)
    );
    let big = vec![0; MAX_P12_LEN + 1];
    assert!(matches!(
        parse_import_request("k", &big, ""),
        Err(RequestError::DataTooLarge)
    ));
    assert!(matches!(
        parse_import_request("k", b"", &"p".repeat(MAX_PASSWORD_LEN + 1)),
        Err(RequestError::PasswordTooLarge)
    ));
}

#[test]
fn import_request_debug_hides_password() -> Result<(), RequestError> {
    let r = parse_import_request("k", b"", "hunter2")?;
    assert!(!format!("{r:?}").contains("hunter2"));
    Ok(())
}

#[test]
fn id_length_limit_is_exact() {
    assert_eq!(MAX_ID_LEN, 59);
    assert_eq!(check_id(&"a".repeat(59)), Ok(()));
    assert_eq!(check_id(&"a".repeat(60)), Err(RequestError::BadId));
}

#[test]
fn size_limits_are_exact() {
    let ok = vec![0; MAX_SIGN_DATA_LEN];
    assert!(parse_sign_request("k", CKM_ECDSA, 0, 0, &ok).is_ok());
    let ok = vec![0; MAX_P12_LEN];
    assert!(parse_import_request("k", &ok, &"p".repeat(MAX_PASSWORD_LEN)).is_ok());
}

#[test]
fn pss_accepts_every_hash() {
    for (ckm, hash) in [
        (CKM_SHA256, PssHash::Sha256),
        (CKM_SHA384, PssHash::Sha384),
        (CKM_SHA512, PssHash::Sha512),
    ] {
        let r = parse_sign_request("k", CKM_RSA_PKCS_PSS, ckm, 20, b"x");
        assert_eq!(
            r.map(|r| r.mechanism),
            Ok(Mechanism::RsaPkcsPss { hash, salt_len: 20 })
        );
    }
}

#[test]
fn request_errors_display() {
    for (e, want) in [
        (RequestError::BadId, "invalid key id"),
        (RequestError::BadMechanism, "unsupported mechanism"),
        (
            RequestError::BadHash,
            "unsupported or unexpected hash for the mechanism",
        ),
        (
            RequestError::BadSaltLength,
            "unexpected salt length for the mechanism",
        ),
        (RequestError::DataTooLarge, "data too large"),
        (RequestError::PasswordTooLarge, "password too large"),
    ] {
        assert_eq!(e.to_string(), want);
    }
}

#[test]
fn import_request_debug_shows_id() -> Result<(), RequestError> {
    let r = parse_import_request("my-id", b"", "hunter2")?;
    let d = format!("{r:?}");
    assert!(d.contains("ImportRequest") && d.contains("my-id") && d.contains("REDACTED"));
    Ok(())
}

#[test]
fn store_errors_map_to_distinct_dbus_errors() {
    assert!(matches!(
        store_error(&StoreError::InvalidId),
        fdo::Error::InvalidArgs(_)
    ));
    let msg = |e: StoreError| match store_error(&e) {
        fdo::Error::Failed(m) => m,
        other => format!("unexpected {other:?}"),
    };
    assert_eq!(msg(StoreError::AlreadyExists), "key already exists");
    assert_eq!(msg(StoreError::NotFound), "no such key");
    assert_eq!(msg(StoreError::TooLarge), "key store error");
}

mod sign_call {
    use std::future::{Future, ready};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::audit::{FailingSink, MemorySink};
    use crate::credentials::CredentialsError;

    struct Counting {
        result: fn() -> Result<(), AuthError>,
        calls: Arc<AtomicUsize>,
    }

    impl Authorizer for Counting {
        fn authorize(&self, _: &str) -> impl Future<Output = Result<(), AuthError>> + Send {
            self.calls.fetch_add(1, Ordering::SeqCst);
            ready((self.result)())
        }
    }

    struct Creds(Arc<AtomicUsize>);

    impl CallerCredentials for Creds {
        fn credentials(
            &self,
            _: &str,
        ) -> impl Future<Output = Result<Caller, CredentialsError>> + Send {
            self.0.fetch_add(1, Ordering::SeqCst);
            ready(Ok(Caller { uid: 11, pid: 22 }))
        }
    }

    struct Rig {
        service: Custodio<Counting, Creds>,
        sink: Arc<MemorySink>,
        auth_calls: Arc<AtomicUsize>,
        cred_calls: Arc<AtomicUsize>,
        _dir: tempfile::TempDir,
    }

    fn rig(result: fn() -> Result<(), AuthError>) -> Result<Rig, Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let store = Arc::new(KeyStore::open(dir.path().join("keys"))?);
        let auth_calls = Arc::new(AtomicUsize::new(0));
        let cred_calls = Arc::new(AtomicUsize::new(0));
        let sink = Arc::new(MemorySink::default());
        let service = Custodio::new(
            store,
            Counting {
                result,
                calls: auth_calls.clone(),
            },
            Creds(cred_calls.clone()),
            sink.clone(),
        );
        Ok(Rig {
            service,
            sink,
            auth_calls,
            cred_calls,
            _dir: dir,
        })
    }

    fn err_name(e: &fdo::Error) -> &str {
        match e {
            fdo::Error::AccessDenied(_) => "denied",
            fdo::Error::Failed(_) => "failed",
            fdo::Error::InvalidArgs(_) => "invalid",
            _ => "other",
        }
    }

    #[test]
    fn sign_without_sender_records_unavailable() -> Result<(), Box<dyn std::error::Error>> {
        let r = rig(|| Ok(()))?;
        let got = zbus::block_on(r.service.sign_call(None, "k", CKM_ECDSA, 0, 0, b"x"));
        assert_eq!(got.as_ref().map_err(err_name), Err("denied"));
        assert_eq!(r.auth_calls.load(Ordering::SeqCst), 0);
        assert_eq!(r.cred_calls.load(Ordering::SeqCst), 0);
        let entries = r.sink.entries();
        assert_eq!(entries.len(), 1);
        let e = entries.first().ok_or("no entry")?;
        assert_eq!(e.outcome(), Outcome::AuthorizationUnavailable);
        assert_eq!(e.caller(), None);
        assert_eq!(e.key_id().as_str(), "k");
        assert_eq!(e.mechanism(), Some(AuditMechanism::Ecdsa));
        Ok(())
    }

    #[test]
    fn bad_sender_and_unavailable_are_unavailable() -> Result<(), Box<dyn std::error::Error>> {
        for result in [
            (|| Err(AuthError::BadSender)) as fn() -> Result<(), AuthError>,
            || Err(AuthError::Unavailable("x".into())),
        ] {
            let r = rig(result)?;
            let got = zbus::block_on(
                r.service
                    .sign_call(Some(":1.1"), "k", CKM_ECDSA, 0, 0, b"x"),
            );
            assert_eq!(got.as_ref().map_err(err_name), Err("denied"));
            let entries = r.sink.entries();
            let e = entries.first().ok_or("no entry")?;
            assert_eq!(entries.len(), 1);
            assert_eq!(e.outcome(), Outcome::AuthorizationUnavailable);
            assert_eq!(e.caller(), Some(Caller { uid: 11, pid: 22 }));
        }
        Ok(())
    }

    #[test]
    fn denied_and_missing_key_are_distinct() -> Result<(), Box<dyn std::error::Error>> {
        let r = rig(|| Err(AuthError::Denied))?;
        let got = zbus::block_on(
            r.service
                .sign_call(Some(":1.1"), "k", CKM_ECDSA, 0, 0, b"x"),
        );
        assert_eq!(got.as_ref().map_err(err_name), Err("denied"));
        let r2 = rig(|| Ok(()))?;
        let got = zbus::block_on(
            r2.service
                .sign_call(Some(":1.1"), "k", CKM_ECDSA, 0, 0, b"x"),
        );
        assert!(got.is_err());
        let outcomes = |r: &Rig| {
            r.sink
                .entries()
                .iter()
                .map(Entry::outcome)
                .collect::<Vec<_>>()
        };
        assert_eq!(outcomes(&r), [Outcome::Denied]);
        assert_eq!(outcomes(&r2), [Outcome::SigningFailed]);
        Ok(())
    }

    #[test]
    fn refused_arguments_never_reach_credentials() -> Result<(), Box<dyn std::error::Error>> {
        let r = rig(|| Ok(()))?;
        let got = zbus::block_on(
            r.service
                .sign_call(Some(":1.1"), "a/b", CKM_ECDSA, 0, 0, b"x"),
        );
        assert_eq!(got.as_ref().map_err(err_name), Err("invalid"));
        assert_eq!(r.cred_calls.load(Ordering::SeqCst), 0);
        assert_eq!(r.auth_calls.load(Ordering::SeqCst), 0);
        Ok(())
    }

    #[test]
    fn sign_with_unconstructible_key_id_is_refused() {
        let got = audit_parts("bad/id", &Mechanism::Ecdsa);
        assert_eq!(got.as_ref().map_err(err_name).err(), Some("failed"));
        let ok = audit_parts("good", &Mechanism::RsaPkcs).map(|(k, m)| (k.as_str().to_owned(), m));
        assert_eq!(ok.ok(), Some(("good".to_owned(), AuditMechanism::RsaPkcs)));
    }

    #[test]
    fn a_failing_sink_replaces_the_error() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let store = Arc::new(KeyStore::open(dir.path().join("keys"))?);
        let service = Custodio::new(
            store,
            Counting {
                result: || Err(AuthError::Denied),
                calls: Arc::default(),
            },
            Creds(Arc::default()),
            Arc::new(FailingSink),
        );
        let got = zbus::block_on(service.sign_call(Some(":1.1"), "k", CKM_ECDSA, 0, 0, b"x"));
        assert_eq!(got.as_ref().map_err(err_name), Err("failed"));
        Ok(())
    }
}
