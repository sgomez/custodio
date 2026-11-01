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

mod sign_call {
    use std::future::{Future, ready};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::audit::{FailingSink, MemorySink};
    use crate::credentials::CredentialsError;
    use crate::import::import_p12;
    use crate::store::StoreError;

    struct Counting {
        result: fn() -> Result<(), AuthError>,
        calls: Arc<AtomicUsize>,
    }

    impl Authorizer for Counting {
        fn authorize(
            &self,
            _: &str,
            _: &str,
        ) -> impl Future<Output = Result<(), AuthError>> + Send {
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
        store: Arc<KeyStore>,
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
            store.clone(),
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
            store,
            auth_calls,
            cred_calls,
            _dir: dir,
        })
    }

    #[test]
    fn sign_without_sender_records_unavailable() -> Result<(), Box<dyn std::error::Error>> {
        let r = rig(|| Ok(()))?;
        let got = zbus::block_on(r.service.sign_call(None, "k", CKM_ECDSA, 0, 0, b"x"));
        assert_eq!(got, Err(ServiceError::AuthorizationUnavailable));
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
            seed(&r, "k")?;
            let got = zbus::block_on(
                r.service
                    .sign_call(Some(":1.1"), "k", CKM_ECDSA, 0, 0, b"x"),
            );
            assert_eq!(got, Err(ServiceError::AuthorizationUnavailable));
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
        seed(&r, "k")?;
        let got = zbus::block_on(
            r.service
                .sign_call(Some(":1.1"), "k", CKM_ECDSA, 0, 0, b"x"),
        );
        assert_eq!(got, Err(ServiceError::PolkitDenied));
        let r2 = rig(|| Ok(()))?;
        let got = zbus::block_on(
            r2.service
                .sign_call(Some(":1.1"), "k", CKM_ECDSA, 0, 0, b"x"),
        );
        assert_eq!(got, Err(ServiceError::NoSuchKey));
        let outcomes = |r: &Rig| {
            r.sink
                .entries()
                .iter()
                .map(Entry::outcome)
                .collect::<Vec<_>>()
        };
        assert_eq!(outcomes(&r), [Outcome::Denied]);
        // A missing key is refused before polkit and leaves no entry.
        assert_eq!(outcomes(&r2), []);
        assert_eq!(r2.auth_calls.load(Ordering::SeqCst), 0);
        Ok(())
    }

    #[test]
    fn refused_arguments_never_reach_credentials() -> Result<(), Box<dyn std::error::Error>> {
        let r = rig(|| Ok(()))?;
        let got = zbus::block_on(
            r.service
                .sign_call(Some(":1.1"), "a/b", CKM_ECDSA, 0, 0, b"x"),
        );
        assert_eq!(got, Err(ServiceError::InvalidArgs));
        assert_eq!(r.cred_calls.load(Ordering::SeqCst), 0);
        assert_eq!(r.auth_calls.load(Ordering::SeqCst), 0);
        Ok(())
    }

    #[test]
    fn sign_with_unconstructible_key_id_is_refused() {
        let got = audit_parts("bad/id", &Mechanism::Ecdsa);
        assert_eq!(got.as_ref().err(), Some(&ServiceError::AuditUnavailable));
        let ok = audit_parts("good", &Mechanism::RsaPkcs).map(|(k, m)| (k.as_str().to_owned(), m));
        assert_eq!(ok.ok(), Some(("good".to_owned(), AuditMechanism::RsaPkcs)));
    }

    const P12: &[u8] = include_bytes!("../../tests/fixtures/p256.p12");
    const SENDER: Option<&str> = Some(":1.1");

    /// Owner 11 is the fake caller; the test process must be none of the two uids used here.
    fn other_uid() -> u32 {
        let euid = rustix::process::geteuid().as_raw();
        assert_ne!(euid, 11);
        assert_ne!(euid, 12);
        12
    }

    /// Puts the key straight into the store, for tests whose authorizer refuses.
    fn seed(r: &Rig, id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let password = SecretString::from("test-password".to_owned());
        import_p12(&r.store, 11, id, P12, &password)?;
        Ok(())
    }

    fn import(r: &Rig, id: &str) -> Result<String, ServiceError> {
        zbus::block_on(r.service.import_call(SENDER, id, P12, "test-password"))
    }

    #[test]
    fn import_stores_key_and_certificate_under_the_bus_uid()
    -> Result<(), Box<dyn std::error::Error>> {
        let r = rig(|| Ok(()))?;
        let euid = rustix::process::geteuid().as_raw();
        assert_ne!(euid, 11);
        assert_eq!(import(&r, "mine")?, "ecdsa-p256");
        assert_ne!(r.store.get(11, "mine")?.expose_secret().len(), 0);
        assert_ne!(r.store.get(11, &cert_id("mine"))?.expose_secret().len(), 0);
        for uid in [euid, 0, other_uid()] {
            assert!(matches!(
                r.store.get(uid, "mine"),
                Err(StoreError::NotFound)
            ));
            assert!(matches!(
                r.store.get(uid, &cert_id("mine")),
                Err(StoreError::NotFound)
            ));
        }
        Ok(())
    }

    #[test]
    fn list_reads_the_area_of_the_bus_uid() -> Result<(), Box<dyn std::error::Error>> {
        let r = rig(|| Ok(()))?;
        assert_eq!(import(&r, "mine")?, "ecdsa-p256");
        // Another owner's key with a certificate, which must not show.
        let key = r.store.get(11, "mine")?;
        r.store.put(other_uid(), "theirs", &key)?;
        r.store.put(other_uid(), &cert_id("theirs"), &key)?;
        let cert = r.store.get(11, &cert_id("mine"))?;
        let got = zbus::block_on(r.service.list_keys_call(SENDER))?;
        assert_eq!(
            got,
            [(
                "mine".to_owned(),
                "ecdsa-p256".to_owned(),
                cert.expose_secret().to_vec()
            )]
        );
        Ok(())
    }

    #[test]
    fn sign_uses_the_area_of_the_bus_uid() -> Result<(), Box<dyn std::error::Error>> {
        let r = rig(|| Ok(()))?;
        import(&r, "mine")?;
        let got = zbus::block_on(r.service.sign_call(SENDER, "mine", CKM_ECDSA, 0, 0, b"x"));
        assert!(got.is_ok(), "{got:?}");
        // The same key stored only under another uid is not found.
        let key = r.store.get(11, "mine")?;
        r.store.put(other_uid(), "theirs", &key)?;
        let got = zbus::block_on(r.service.sign_call(SENDER, "theirs", CKM_ECDSA, 0, 0, b"x"));
        assert_eq!(got, Err(ServiceError::from(&StoreError::NotFound)));
        Ok(())
    }

    #[test]
    fn owner_needs_a_sender() -> Result<(), Box<dyn std::error::Error>> {
        let r = rig(|| Ok(()))?;
        assert_eq!(
            zbus::block_on(r.service.list_keys_call(None)),
            Err(ServiceError::AuthorizationUnavailable)
        );
        Ok(())
    }

    #[test]
    fn a_failing_sink_replaces_the_error() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let store = Arc::new(KeyStore::open(dir.path().join("keys"))?);
        let password = SecretString::from("test-password".to_owned());
        import_p12(&store, 11, "k", P12, &password)?;
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
        assert_eq!(got, Err(ServiceError::AuditUnavailable));
        Ok(())
    }

    /// A decoder that counts and always fails.
    struct FailingDecoder(Arc<AtomicUsize>);

    impl crate::import::P12Decoder for FailingDecoder {
        fn decode(
            &self,
            _: &[u8],
            _: &SecretString,
        ) -> Result<crate::import::ParsedP12, crate::import::ImportError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(crate::import::ImportError::NoPrivateKey)
        }
    }

    type Answer = fn() -> Result<(), AuthError>;

    /// The reply of an import, the polkit calls and the decoder calls.
    type Imported = (Result<String, ServiceError>, usize, usize);

    fn import_with(
        result: fn() -> Result<(), AuthError>,
        sender: Option<&str>,
    ) -> Result<Imported, Box<dyn std::error::Error>> {
        let mut r = rig(result)?;
        let decoded = Arc::new(AtomicUsize::new(0));
        r.service = r
            .service
            .with_decoder(Arc::new(FailingDecoder(decoded.clone())));
        let got = zbus::block_on(r.service.import_call(sender, "k", b"x", "pw"));
        Ok((
            got,
            r.auth_calls.load(Ordering::SeqCst),
            decoded.load(Ordering::SeqCst),
        ))
    }

    #[test]
    fn import_without_sender_asks_and_decodes_nothing() -> Result<(), Box<dyn std::error::Error>> {
        let (got, polkit, decoded) = import_with(|| Ok(()), None)?;
        assert_eq!(got, Err(ServiceError::AuthorizationUnavailable));
        assert_eq!((polkit, decoded), (0, 0));
        Ok(())
    }

    #[test]
    fn import_refusals_never_decode() -> Result<(), Box<dyn std::error::Error>> {
        let cases: [(Answer, ServiceError); 3] = [
            (|| Err(AuthError::Denied), ServiceError::PolkitDenied),
            (
                || Err(AuthError::BadSender),
                ServiceError::AuthorizationUnavailable,
            ),
            (
                || Err(AuthError::Unavailable("x".into())),
                ServiceError::AuthorizationUnavailable,
            ),
        ];
        for (result, want) in cases {
            let (got, polkit, decoded) = import_with(result, Some(":1.1"))?;
            assert_eq!(got, Err(want));
            assert_eq!((polkit, decoded), (1, 0));
        }
        // Control: approval reaches the decoder.
        let (got, polkit, decoded) = import_with(|| Ok(()), Some(":1.1"))?;
        assert_eq!(got, Err(ServiceError::WrongPasswordOrBadP12));
        assert_eq!((polkit, decoded), (1, 1));
        Ok(())
    }
}
