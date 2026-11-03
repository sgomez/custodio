use super::*;

#[test]
fn the_key_is_removed_before_the_certificate() {
    let mut seen = Vec::new();
    let r = rollback_with("my-key", |name| {
        seen.push(name.to_owned());
        Ok(())
    });
    assert!(r.is_ok());
    assert_eq!(seen, ["my-key", "my-key-cert"]);
}

#[test]
fn the_certificate_stays_when_the_key_cannot_be_removed() {
    let mut seen = Vec::new();
    let r = rollback_with("k", |name| {
        seen.push(name.to_owned());
        Err(StoreError::TooLarge)
    });
    assert!(matches!(r, Err(StoreError::TooLarge)));
    assert_eq!(seen, ["k"]);
}

#[test]
fn a_certificate_failure_is_reported() {
    let r = rollback_with("k", |name| {
        if name == "k" {
            Ok(())
        } else {
            Err(StoreError::TooLarge)
        }
    });
    assert!(matches!(r, Err(StoreError::TooLarge)));
}

#[test]
fn rollback_import_removes_both_files_and_nothing_else() -> Result<(), StoreError> {
    let tmp = tempfile::tempdir()?;
    let store = KeyStore::open(tmp.path().join("s"))?;
    let one = SecretSlice::from(vec![1_u8]);
    for id in ["a", "a-cert", "b", "b-cert"] {
        store.put(7, id, &one)?;
    }
    rollback_import(&store, 7, "a")?;
    assert_eq!(store.list(7)?, ["b", "b-cert"]);
    Ok(())
}

#[test]
fn every_import_error_has_its_own_message() {
    let cases = [
        (ImportError::TooLarge, "larger than"),
        (
            ImportError::Parse("bad mac".into()),
            "wrong password): bad mac",
        ),
        (ImportError::NoPrivateKey, "no private key"),
        (ImportError::MultipleKeys, "more than one private key"),
        (ImportError::NoCertificate, "has no certificate"),
        (ImportError::CertificateMismatch, "matches the private key"),
        (
            ImportError::UnsupportedKey("RSA 4096".into()),
            "unsupported key: RSA 4096;",
        ),
        (
            ImportError::Store(StoreError::AlreadyExists),
            "cannot store the key: ",
        ),
    ];
    for (error, expected) in cases {
        let message = error.to_string();
        assert!(message.contains(expected), "{message:?} lacks {expected:?}");
    }
}
