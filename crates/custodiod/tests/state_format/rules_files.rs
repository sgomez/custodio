//! Symlinks, FIFOs, loose modes, unparsable records.

use std::fs;
use std::os::unix::fs::symlink;
use std::process::Command;
use std::sync::mpsc;
use std::time::Duration;

use super::*;
use custodiod::store::StoreError;

/// Runs `f` and fails if it does not return within five seconds (a FIFO must never block).
fn within<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(Duration::from_secs(5))
        .expect("the call blocked")
}

fn refused<T>(r: &Result<T, StoreError>) -> bool {
    matches!(r, Err(StoreError::BadFileType(_)))
}

#[test]
fn symlink_record() -> TestResult {
    let (tmp, store) = fresh();
    store.put(&host("other", b"cert"))?;
    let target = tmp.path().join("target");
    fs::write(&target, b"untouched")?;
    set_mode(&target, 0o600);
    let link = area(&store, OWNER).join("k");
    symlink(&target, &link)?;
    assert!(store.list(OWNER)?.contains(&"k".to_owned()));
    assert!(refused(&store.get(OWNER, "k")));
    assert!(refused(&store.replace_certificate(OWNER, "k", b"new")));
    assert!(refused(&store.remove_existing(OWNER, "k")));
    assert!(fs::symlink_metadata(&link)?.file_type().is_symlink());
    assert_eq!(fs::read(&target)?, b"untouched");
    Ok(())
}

#[test]
fn symlink_area() -> TestResult {
    let (tmp, store) = fresh();
    let target = tmp.path().join("elsewhere");
    fs::create_dir(&target)?;
    set_mode(&target, 0o700);
    symlink(&target, area(&store, OWNER))?;
    assert!(refused(&store.get(OWNER, "k")));
    assert!(refused(&store.put(&host("k", b"cert"))));
    assert!(refused(&store.list(OWNER)));
    assert!(refused(&store.remove_existing(OWNER, "k")));
    assert_eq!(names(&target), Vec::<String>::new());
    Ok(())
}

#[test]
fn symlink_root() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let real = tmp.path().join("real");
    fs::create_dir(&real)?;
    set_mode(&real, 0o700);
    let link = tmp.path().join("link");
    symlink(&real, &link)?;
    assert!(refused(&KeyStore::open(&link)));
    Ok(())
}

#[test]
fn fifo_record() -> TestResult {
    let (_tmp, store) = fresh();
    store.put(&host("other", b"cert"))?;
    let fifo = area(&store, OWNER).join("k");
    assert!(Command::new("mkfifo").arg(&fifo).status()?.success());
    set_mode(&fifo, 0o600);
    let dir = store.dir().to_owned();
    let results = within(move || {
        let store = KeyStore::open(dir).unwrap();
        let listed = store.list(OWNER).unwrap().contains(&"k".to_owned());
        (
            listed,
            refused(&store.get(OWNER, "k")),
            refused(&store.replace_certificate(OWNER, "k", b"new")),
            refused(&store.remove_existing(OWNER, "k")),
        )
    });
    assert_eq!(results, (true, true, true, true));
    assert!(fifo.exists(), "the FIFO was removed");
    Ok(())
}

#[test]
fn loose_modes_are_not_repaired() -> TestResult {
    let (_tmp, store) = fresh();
    store.put(&host("k", b"cert"))?;
    let record = area(&store, OWNER).join("k");
    let bad = |r: Result<(), StoreError>| matches!(r, Err(StoreError::BadPermissions(_)));

    set_mode(&record, 0o644);
    assert!(bad(store.get(OWNER, "k").map(drop)));
    assert!(bad(store.replace_certificate(OWNER, "k", b"new").map(drop)));
    assert!(bad(store.remove_existing(OWNER, "k").map(drop)));
    assert_eq!(mode(&record), 0o644);
    set_mode(&record, 0o600);

    set_mode(&area(&store, OWNER), 0o755);
    assert!(bad(store.get(OWNER, "k").map(drop)));
    assert!(bad(store.put(&host("j", b"cert"))));
    assert!(bad(store.replace_certificate(OWNER, "k", b"new").map(drop)));
    assert!(bad(store.remove_existing(OWNER, "k").map(drop)));
    assert_eq!(mode(&area(&store, OWNER)), 0o755);
    set_mode(&area(&store, OWNER), 0o700);

    set_mode(store.dir(), 0o755);
    assert!(bad(store.get(OWNER, "k").map(drop)) || bad(KeyStore::open(store.dir()).map(drop)));
    assert!(bad(KeyStore::open(store.dir()).map(drop)));
    assert_eq!(mode(store.dir()), 0o755);
    set_mode(store.dir(), 0o700);
    Ok(())
}

#[test]
fn remove_deletes_unparsable_record() -> TestResult {
    let (_tmp, store) = fresh();
    let mut bad = b"CUSTODIO".to_vec();
    bad.extend([1, 2, 3, 4, 5]);
    plant(&store, OWNER, "broken", &bad);
    assert!(matches!(
        store.get(OWNER, "broken"),
        Err(StoreError::Record(_))
    ));
    assert!(store.remove_existing(OWNER, "broken")?);
    assert!(!store.remove_existing(OWNER, "broken")?);
    assert_eq!(names(&area(&store, OWNER)), Vec::<String>::new());

    let loose = plant(&store, OWNER, "loose", &bad);
    set_mode(&loose, 0o644);
    assert!(matches!(
        store.remove_existing(OWNER, "loose"),
        Err(StoreError::BadPermissions(_))
    ));
    symlink(&loose, area(&store, OWNER).join("link"))?;
    assert!(refused(&store.remove_existing(OWNER, "link")));
    assert!(loose.exists());
    Ok(())
}
