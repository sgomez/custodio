//! Two concurrent imports of one id; two removers.

use std::sync::{Arc, Barrier};

use super::*;
use custodiod::store::StoreError;

#[test]
fn concurrent_put_one_id() -> TestResult {
    for threads in [2_usize, 16] {
        for round in 0..200 {
            let (_tmp, first) = fresh();
            let stores: Vec<KeyStore> = (0..threads)
                .map(|_| KeyStore::open(first.dir()).unwrap())
                .collect();
            let barrier = Arc::new(Barrier::new(threads));
            let handles: Vec<_> = stores
                .into_iter()
                .enumerate()
                .map(|(i, store)| {
                    let barrier = Arc::clone(&barrier);
                    std::thread::spawn(move || {
                        let kind = if i % 2 == 0 {
                            Kind::EncryptedHost
                        } else {
                            Kind::EncryptedTpm
                        };
                        let record =
                            encrypted(OWNER, "k", kind, format!("certificate-{i}").as_bytes());
                        barrier.wait();
                        (record.clone(), store.put(&record))
                    })
                })
                .collect();
            let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
            let winners: Vec<_> = results.iter().filter(|(_, r)| r.is_ok()).collect();
            assert_eq!(winners.len(), 1, "{threads} threads, round {round}");
            for (_, r) in &results {
                assert!(
                    matches!(r, Ok(()) | Err(StoreError::AlreadyExists)),
                    "{r:?}"
                );
            }
            assert_eq!(
                first.get(OWNER, "k")?,
                winners[0].0,
                "the stored record is the winner's, whole"
            );
            assert_eq!(names(&area(&first, OWNER)), ["k"]);
        }
    }
    Ok(())
}

#[test]
fn concurrent_remove_one_winner() -> TestResult {
    for round in 0..100 {
        let (_tmp, first) = fresh();
        first.put(&host("k", b"cert"))?;
        let barrier = Arc::new(Barrier::new(8));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let store = KeyStore::open(first.dir()).unwrap();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    store.remove_existing(OWNER, "k")
                })
            })
            .collect();
        let oks = handles
            .into_iter()
            .map(|h| h.join().unwrap().unwrap())
            .filter(|won| *won)
            .count();
        assert_eq!(oks, 1, "round {round}");
        assert_eq!(
            names(&area(&first, OWNER)),
            Vec::<String>::new(),
            "record and certificate are one file"
        );
    }
    Ok(())
}
