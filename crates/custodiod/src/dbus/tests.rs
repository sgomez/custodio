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
