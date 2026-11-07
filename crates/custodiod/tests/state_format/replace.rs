//! Replace certificate: atomic, never creates, never resurrects.

use std::sync::atomic::{AtomicBool, Ordering};

use super::*;
use custodiod::store::StoreError;

#[test]
fn replace_certificate_is_atomic() -> TestResult {
    let (_tmp, store) = fresh();
    let original = host("k", b"cert-A");
    store.put(&original)?;
    let reader = KeyStore::open(store.dir())?;
    let done = AtomicBool::new(false);
    std::thread::scope(|s| {
        let watcher = s.spawn(|| {
            let mut reads = 0_u32;
            while !done.load(Ordering::SeqCst) {
                let record = reader.get(OWNER, "k").expect("a whole record");
                assert!(
                    [b"cert-A".as_slice(), b"cert-B".as_slice()].contains(&record.certificate())
                );
                assert_eq!(record.kind(), original.kind());
                assert_eq!(record.protected(), original.protected());
                reads += 1;
            }
            reads
        });
        for i in 0..300 {
            let next: &[u8] = if i % 2 == 0 { b"cert-B" } else { b"cert-A" };
            store.replace_certificate(OWNER, "k", next).unwrap();
        }
        done.store(true, Ordering::SeqCst);
        assert!(watcher.join().unwrap() > 0);
    });
    assert_eq!(names(&area(&store, OWNER)), ["k"]);
    Ok(())
}

#[test]
fn replace_missing_creates_nothing_and_a_bad_certificate_keeps_the_record() -> TestResult {
    let (_tmp, store) = fresh();
    assert!(matches!(
        store.replace_certificate(OWNER, "k", b"new"),
        Err(StoreError::NotFound)
    ));
    store.put(&host("other", b"cert"))?;
    assert!(matches!(
        store.replace_certificate(OWNER, "k", b"new"),
        Err(StoreError::NotFound)
    ));
    assert_eq!(names(&area(&store, OWNER)), ["other"]);

    let before = std::fs::read(area(&store, OWNER).join("other"))?;
    let over = vec![0_u8; custodiod::store::MAX_RECORD];
    assert!(matches!(
        store.replace_certificate(OWNER, "other", &over),
        Err(StoreError::Record(_))
    ));
    assert!(matches!(
        store.replace_certificate(OWNER, "other", b""),
        Err(StoreError::Record(_))
    ));
    assert_eq!(std::fs::read(area(&store, OWNER).join("other"))?, before);
    assert_eq!(names(&area(&store, OWNER)), ["other"]);
    Ok(())
}

#[test]
fn replace_racing_remove() -> TestResult {
    for round in 0..200 {
        let (_tmp, store) = fresh();
        store.put(&host("k", b"cert-A"))?;
        let remover = KeyStore::open(store.dir())?;
        let barrier = std::sync::Barrier::new(2);
        std::thread::scope(|s| {
            s.spawn(|| {
                barrier.wait();
                remover.remove_existing(OWNER, "k").unwrap();
            });
            barrier.wait();
            for _ in 0..5 {
                match store.replace_certificate(OWNER, "k", b"cert-B") {
                    Ok(_) | Err(StoreError::NotFound) => {}
                    Err(e) => panic!("{e:?}"),
                }
            }
        });
        // The id ends gone (a replace never creates), and no temporary file is left.
        assert!(
            matches!(store.get(OWNER, "k"), Err(StoreError::NotFound)),
            "round {round}"
        );
        assert_eq!(
            names(&area(&store, OWNER)),
            Vec::<String>::new(),
            "round {round}"
        );
    }
    Ok(())
}
