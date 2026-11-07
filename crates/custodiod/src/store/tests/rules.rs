//! Rules of the new records that the ported tests do not name: owners, replace and remove.

use super::records::one_of_each;
use super::*;

#[test]
fn rejects_file_of_other_owner() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let mut store = KeyStore::open(tmp.path().join("s"))?;
    store.put(&rec(OWNER, "k", b"cert"))?;
    store.file_uid = Some(store.uid.wrapping_add(1));
    assert!(matches!(
        store.get(OWNER, "k"),
        Err(StoreError::BadOwner(_))
    ));
    assert!(matches!(
        store.contains(OWNER, "k"),
        Err(StoreError::BadOwner(_))
    ));
    assert!(matches!(
        store.remove_existing(OWNER, "k"),
        Err(StoreError::BadOwner(_))
    ));
    assert!(matches!(
        store.replace_certificate(OWNER, "k", b"new"),
        Err(StoreError::BadOwner(_))
    ));
    Ok(())
}

#[test]
fn rejects_area_of_other_owner() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let mut store = KeyStore::open(tmp.path().join("s"))?;
    store.put(&rec(OWNER, "k", b"cert"))?;
    store.uid = store.uid.wrapping_add(1);
    assert!(matches!(
        store.get(OWNER, "k"),
        Err(StoreError::BadOwner(_))
    ));
    assert!(matches!(
        store.put(&rec(OWNER, "j", b"c")),
        Err(StoreError::BadOwner(_))
    ));
    assert!(matches!(store.list(OWNER), Err(StoreError::BadOwner(_))));
    assert!(matches!(
        store.remove_existing(OWNER, "k"),
        Err(StoreError::BadOwner(_))
    ));
    Ok(())
}

#[test]
fn replace_keeps_kind_and_protected_key_byte_for_byte() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let store = KeyStore::open(tmp.path().join("s"))?;
    for record in one_of_each() {
        store.put(&record)?;
        let old = store.replace_certificate(OWNER, record.id(), b"another certificate")?;
        assert_eq!(old, record.certificate());
        let got = store.get(OWNER, record.id())?;
        assert_eq!(got.certificate(), b"another certificate");
        assert_eq!(got.kind(), record.kind());
        assert_eq!(got.protected(), record.protected());
        assert_eq!((got.owner(), got.id()), (OWNER, record.id()));
    }
    Ok(())
}

#[test]
fn replace_failure_keeps_old_and_leaves_no_tmp() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let store = KeyStore::open(tmp.path().join("s"))?;
    let old = rec(OWNER, "k", b"old certificate");
    store.put(&old)?;
    let got = store.replace_with(OWNER, "k", b"new certificate", || {
        Err(io::Error::other("injected"))
    });
    assert!(matches!(got, Err(StoreError::Io(_))));
    assert_eq!(store.get(OWNER, "k")?, old);
    assert_eq!(store.list(OWNER)?, ["k"]);
    assert_eq!(fs::read_dir(area(&store))?.count(), 1);
    // A certificate over its bound is refused before anything is written; the old record stays.
    let big = vec![1_u8; record::MAX_CERTIFICATE + 1];
    assert!(matches!(
        store.replace_certificate(OWNER, "k", &big),
        Err(StoreError::Record(RecordError::Oversized(
            Field::Certificate
        )))
    ));
    assert_eq!(store.get(OWNER, "k")?, old);
    assert_eq!(fs::read_dir(area(&store))?.count(), 1);
    Ok(())
}

#[test]
fn remove_deletes_unparsable_record() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let store = KeyStore::open(tmp.path().join("s"))?;
    store.put(&rec(OWNER, "k", b"cert"))?;
    // A good magic and a bad body: it does not parse, and it can still be removed.
    let path = area(&store).join("k");
    let mut bytes = fs::read(&path)?;
    bytes.truncate(record::MAGIC.len() + 3);
    fs::write(&path, bytes)?;
    assert!(matches!(store.get(OWNER, "k"), Err(StoreError::Record(_))));
    assert!(store.remove_existing(OWNER, "k")?);
    assert!(!store.remove_existing(OWNER, "k")?);
    assert_eq!(store.list(OWNER)?, Vec::<String>::new());
    // A record under a loose mode, and a symlink, are refused and stay.
    store.put(&rec(OWNER, "loose", b"cert"))?;
    fs::set_permissions(
        area(&store).join("loose"),
        fs::Permissions::from_mode(0o644),
    )?;
    assert!(matches!(
        store.remove_existing(OWNER, "loose"),
        Err(StoreError::BadPermissions(_))
    ));
    std::os::unix::fs::symlink("/nonexistent", area(&store).join("link"))?;
    assert!(matches!(
        store.remove_existing(OWNER, "link"),
        Err(StoreError::BadFileType(_))
    ));
    assert!(area(&store).join("loose").exists());
    assert!(fs::symlink_metadata(area(&store).join("link")).is_ok());
    Ok(())
}

#[test]
fn a_replace_waits_for_the_area_lock_and_never_recreates() -> TestResult {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    let tmp = tempfile::tempdir()?;
    let store = KeyStore::open(tmp.path().join("s"))?;
    store.put(&rec(OWNER, "k", b"cert"))?;
    // A second handle, as another process would be: it removes the record while the replace is
    // between its temporary file and its rename.
    let other = Arc::new(KeyStore::open(store.dir())?);
    let finished = Arc::new(AtomicBool::new(false));
    let mut remover = None;
    store.replace_certificate(OWNER, "k", b"first")?;
    store.replace_with(OWNER, "k", b"new", || {
        let (peer, done) = (Arc::clone(&other), Arc::clone(&finished));
        remover = Some(std::thread::spawn(move || {
            let got = peer.remove_existing(OWNER, "k");
            done.store(true, Ordering::SeqCst);
            got
        }));
        std::thread::sleep(std::time::Duration::from_millis(300));
        // The replace holds the area lock, so the removal is still waiting.
        assert!(
            !finished.load(Ordering::SeqCst),
            "the removal went past the held lock"
        );
        Ok(())
    })?;
    // Once the replace is over the removal runs and removes the whole record: nothing is recreated.
    let was_removed = remover.ok_or("no thread")?.join().map_err(|_| "panic")??;
    assert!(was_removed);
    assert_eq!(store.list(OWNER)?, Vec::<String>::new());
    assert_eq!(fs::read_dir(area(&store))?.count(), 0);
    Ok(())
}
