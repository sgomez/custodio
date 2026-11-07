//! Modes, owners, atomic writes, never overwriting.

use std::fs;

use super::*;
use custodiod::store::StoreError;

#[test]
fn modes_are_exact() -> TestResult {
    for umask in [0o000, 0o077, 0o022] {
        let old = rustix::process::umask(rustix::fs::Mode::from_raw_mode(umask));
        let tmp = tempfile::tempdir()?;
        let result = KeyStore::open(tmp.path().join("state")).and_then(|store| {
            store.put(&host("k", b"cert"))?;
            Ok(store)
        });
        rustix::process::umask(old);
        let store = result?;
        assert_eq!(mode(store.dir()), 0o700, "root, umask {umask:o}");
        assert_eq!(mode(&area(&store, OWNER)), 0o700, "area, umask {umask:o}");
        assert_eq!(
            mode(&area(&store, OWNER).join("k")),
            0o600,
            "record, umask {umask:o}"
        );
    }
    Ok(())
}

#[test]
fn record_of_another_owner_path_is_refused() -> TestResult {
    let (_tmp, store) = fresh();
    store.put(&host("k", b"cert"))?;
    store.put(&encrypted(OWNER + 1, "z", Kind::EncryptedHost, b"cert"))?;
    let copy = area(&store, OWNER + 1).join("k");
    fs::copy(area(&store, OWNER).join("k"), &copy)?;
    set_mode(&copy, 0o600);
    assert!(matches!(
        store.get(OWNER + 1, "k"),
        Err(StoreError::Mismatch(_))
    ));
    // Under another id of the same owner too.
    let copy = area(&store, OWNER).join("renamed");
    fs::copy(area(&store, OWNER).join("k"), &copy)?;
    set_mode(&copy, 0o600);
    assert!(matches!(
        store.get(OWNER, "renamed"),
        Err(StoreError::Mismatch(_))
    ));
    Ok(())
}

#[test]
fn put_never_overwrites() -> TestResult {
    let (_tmp, store) = fresh();
    store.put(&host("k", b"first"))?;
    let before = fs::read(area(&store, OWNER).join("k"))?;
    for kind in [Kind::EncryptedHost, Kind::EncryptedTpm] {
        let err = store
            .put(&encrypted(OWNER, "k", kind, b"second"))
            .unwrap_err();
        assert!(matches!(err, StoreError::AlreadyExists), "{err:?}");
    }
    assert_eq!(fs::read(area(&store, OWNER).join("k"))?, before);
    assert_eq!(names(&area(&store, OWNER)), ["k"]);
    Ok(())
}

#[test]
fn put_failure_leaves_no_partial_or_tmp() -> TestResult {
    let (_tmp, store) = fresh();
    let err = store
        .put_with_hook(&host("k", b"cert"), |_| {
            Err(std::io::Error::other("injected"))
        })
        .unwrap_err();
    assert!(matches!(err, StoreError::Io(_)), "{err:?}");
    assert!(matches!(store.get(OWNER, "k"), Err(StoreError::NotFound)));
    assert_eq!(names(&area(&store, OWNER)), Vec::<String>::new());
    store.put(&host("k", b"cert"))?;
    Ok(())
}

#[test]
fn a_reader_never_sees_a_partial_record() -> TestResult {
    use std::sync::atomic::{AtomicBool, Ordering};
    let (_tmp, store) = fresh();
    let reader = KeyStore::open(store.dir())?;
    let done = AtomicBool::new(false);
    let ids: Vec<String> = (0..150).map(|i| format!("k{i}")).collect();
    std::thread::scope(|s| {
        let watcher = s.spawn(|| {
            let mut seen = 0_usize;
            while !done.load(Ordering::SeqCst) {
                for id in &ids {
                    match reader.get(OWNER, id) {
                        Ok(record) => {
                            assert_eq!(record.id(), id);
                            seen += 1;
                        }
                        Err(StoreError::NotFound) => {}
                        Err(e) => panic!("a partial or bad record: {e:?}"),
                    }
                }
            }
            seen
        });
        for id in &ids {
            store.put(&host(id, b"cert")).unwrap();
        }
        done.store(true, Ordering::SeqCst);
        watcher.join().unwrap();
    });
    assert_eq!(reader.list(OWNER)?.len(), ids.len());
    Ok(())
}

#[test]
fn leftover_tmp_files_are_removed_at_open() -> TestResult {
    let (_tmp, store) = fresh();
    store.put(&host("k", b"cert"))?;
    let root_tmp = store.dir().join(".tmp-root");
    let area_tmp = area(&store, OWNER).join(".tmp-area");
    fs::write(&root_tmp, b"x")?;
    fs::write(&area_tmp, b"x")?;
    let again = KeyStore::open(store.dir())?;
    assert!(!root_tmp.exists() && !area_tmp.exists());
    assert_eq!(again.list(OWNER)?, ["k"]);
    Ok(())
}
