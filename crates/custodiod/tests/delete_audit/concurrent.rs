//! Deletes of one id at once run one after the other, and each leaves one entry.

use std::sync::atomic::Ordering;
use std::thread;
use std::time::{Duration, Instant};

use custodio_client::{ERROR_AUDIT_UNAVAILABLE, ERROR_NO_SUCH_KEY};
use zbus::block_on;

use super::bus::{Answer, Fixture, TestResult};
use super::{area, delete, put_rsa, rsa_public, sign_rsa, snapshot, start, verifies};

fn wait_for_asks(f: &Fixture, n: usize) -> TestResult {
    let start = Instant::now();
    while f.asked().len() < n {
        if start.elapsed() > Duration::from_secs(5) {
            return Err(format!("polkit was asked {} times, not {n}", f.asked().len()).into());
        }
        thread::sleep(Duration::from_millis(5));
    }
    Ok(())
}

#[test]
fn concurrent_deletes_one_entry() -> TestResult {
    let (f, sink) = block_on(start(Answer::Yes))?;
    let other = block_on(f.bus.connect())?;
    for round in 0..20_usize {
        let id = format!("r{round}");
        put_rsa(&f, &id)?;
        let asked = f.asked().len();
        f.hold.store(usize::MAX, Ordering::SeqCst);
        let (c1, i1) = (f.client.clone(), id.clone());
        let first = thread::spawn(move || block_on(delete(&c1, &i1)));
        wait_for_asks(&f, asked + 1)?;
        let (c2, i2) = (other.clone(), id.clone());
        let second = thread::spawn(move || block_on(delete(&c2, &i2)));
        // The second delete waits for the first; it does not reach polkit.
        thread::sleep(Duration::from_millis(150));
        assert_eq!(f.asked().len(), asked + 1, "round {round}");
        assert_eq!(sink.attempts(), round, "round {round}");
        f.hold.store(0, Ordering::SeqCst);
        let mut got = [
            first.join().map_err(|_| "panic")?,
            second.join().map_err(|_| "panic")?,
        ];
        got.sort();
        assert_eq!(
            got,
            [Ok(()), Err(ERROR_NO_SUCH_KEY.to_owned())],
            "round {round}"
        );
        assert_eq!(f.asked().len(), asked + 1, "round {round}");
        // Entries equal polkit asks, and this id has exactly one `deleted`.
        assert_eq!(sink.inner.operation_entries().len(), round + 1);
        assert_eq!(f.asked().len(), round + 1);
        assert_eq!(sink.deleted(), round + 1);
        assert_eq!(snapshot(&area(&f))?, []);
    }
    Ok(())
}

#[test]
fn concurrent_deletes_with_a_failing_sink_run_one_after_the_other() -> TestResult {
    let public = rsa_public()?;
    let (f, sink) = block_on(start(Answer::Yes))?;
    let other = block_on(f.bus.connect())?;
    put_rsa(&f, "k")?;
    let before = snapshot(&area(&f))?;
    sink.failing(true);
    for round in 0..20_usize {
        let asked = f.asked().len();
        f.hold.store(usize::MAX, Ordering::SeqCst);
        let c1 = f.client.clone();
        let first = thread::spawn(move || block_on(delete(&c1, "k")));
        wait_for_asks(&f, asked + 1)?;
        let c2 = other.clone();
        let second = thread::spawn(move || block_on(delete(&c2, "k")));
        thread::sleep(Duration::from_millis(100));
        assert_eq!(f.asked().len(), asked + 1, "round {round}");
        f.hold.store(0, Ordering::SeqCst);
        // The first fails on the sink and restores the key; the second then runs on its own.
        assert_eq!(
            first.join().map_err(|_| "panic")?,
            Err(ERROR_AUDIT_UNAVAILABLE.to_owned())
        );
        assert_eq!(
            second.join().map_err(|_| "panic")?,
            Err(ERROR_AUDIT_UNAVAILABLE.to_owned())
        );
        assert_eq!(f.asked().len(), asked + 2, "round {round}");
        assert_eq!(
            sink.attempts(),
            super::delete_asks(&f),
            "attempts equal asks"
        );
        assert_eq!(sink.deleted(), 0);
        assert_eq!(snapshot(&area(&f))?, before);
        verifies(&public, &block_on(sign_rsa(&f.client, "k"))?)?;
    }
    Ok(())
}

#[test]
fn deletes_of_different_ids_do_not_block_each_other() -> TestResult {
    let (f, sink) = block_on(start(Answer::Yes))?;
    let other = block_on(f.bus.connect())?;
    put_rsa(&f, "a")?;
    put_rsa(&f, "b")?;
    // Each polkit ask waits for the other: both are past the lock together, or the test fails.
    f.hold.store(2, Ordering::SeqCst);
    let c1 = f.client.clone();
    let first = thread::spawn(move || block_on(delete(&c1, "a")));
    let second = thread::spawn(move || block_on(delete(&other, "b")));
    assert_eq!(first.join().map_err(|_| "panic")?, Ok(()));
    assert_eq!(second.join().map_err(|_| "panic")?, Ok(()));
    assert_eq!(sink.deleted(), 2);
    Ok(())
}
