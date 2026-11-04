use super::*;
use crate::creds::seal;
use crate::store::Protected;

#[test]
fn rollback_import_removes_the_record_and_nothing_else() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempfile::tempdir()?;
    let store = KeyStore::open(tmp.path().join("s"))?;
    let creds = crate::creds::memory::MemoryCreds::host();
    let key = SecretSlice::from(vec![1_u8]);
    for id in ["a", "b"] {
        let sealed = seal(&creds, &credential_name(7, id), &key)?;
        let protected = Protected::from_sealed(&sealed);
        let kind = protected.natural_kind();
        store.put(&Record::new(7, id, kind, b"cert", protected)?)?;
    }
    rollback_import(&store, 7, "a")?;
    assert_eq!(store.list(7)?, ["b"]);
    // Rolling back what is not there is not an error.
    rollback_import(&store, 7, "a")?;
    assert_eq!(store.list(7)?, ["b"]);
    Ok(())
}

#[test]
fn the_credential_name_binds_owner_and_id() {
    assert_eq!(credential_name(1000, "my-key"), "custodio-1000-my-key");
    assert_ne!(credential_name(1, "a"), credential_name(2, "a"));
    assert_ne!(credential_name(1, "a"), credential_name(1, "b"));
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
