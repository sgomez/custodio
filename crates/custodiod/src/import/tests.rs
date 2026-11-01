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
