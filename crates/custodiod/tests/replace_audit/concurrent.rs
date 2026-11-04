//! Replaces and deletes of one id at once run one after the other, and each leaves one entry.

use std::sync::atomic::Ordering;
use std::thread;
use std::time::{Duration, Instant};

use custodio_client::{ERROR_AUDIT_UNAVAILABLE, ERROR_NO_SUCH_KEY};
use zbus::block_on;

use super::bus::{Answer, Fixture, TestResult};
use super::{NEW, NEWER, area, cert_of, delete, put_rsa, replace, replace_asks, snapshot, start};

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

fn settle() {
    thread::sleep(Duration::from_millis(200));
}

#[test]
fn replace_entry_is_submitted_under_the_key_lock() -> TestResult {
    let (f, sink) = block_on(start(Answer::Yes))?;
    let other = block_on(f.bus.connect())?;
    put_rsa(&f, "k")?;
    put_rsa(&f, "free")?;
    let (entered, release) = sink.arm_gate();
    let c1 = f.client.clone();
    let first = thread::spawn(move || block_on(replace(&c1, "k", NEW)));
    entered.recv_timeout(Duration::from_secs(10))?;
    // The first replace is stored and waits for its entry. A second replace and a delete of the
    // same id wait for the lock and have not reached polkit.
    assert_eq!(cert_of(&f, "k")?, NEW);
    let c2 = other.clone();
    let second = thread::spawn(move || block_on(replace(&c2, "k", NEWER)));
    let c3 = other.clone();
    let third = thread::spawn(move || block_on(delete(&c3, "k")));
    settle();
    assert_eq!(f.asked().len(), 1);
    assert_eq!(replace_asks(&f), 1);
    // Another id is not blocked.
    block_on(replace(&other, "free", NEW))?;
    assert_eq!(f.asked().len(), 2);
    release.send(())?;
    assert_eq!(first.join().map_err(|_| "panic")?, Ok(()));
    let results = [
        second.join().map_err(|_| "panic")?,
        third.join().map_err(|_| "panic")?,
    ];
    // Whichever of the two went first: a replace after the delete is `NoSuchKey`.
    assert!(results.contains(&Ok(())), "{results:?}");
    assert_eq!(f.asked().len(), sink.inner.operation_entries().len());
    assert_eq!(sink.attempts(), f.asked().len());
    Ok(())
}

#[test]
fn replace_failing_sink_serializes_and_restores() -> TestResult {
    let (f, sink) = block_on(start(Answer::Yes))?;
    let other = block_on(f.bus.connect())?;
    put_rsa(&f, "k")?;
    let before = snapshot(&area(&f))?;
    sink.failing(true);
    let (entered, release) = sink.arm_gate();
    let c1 = f.client.clone();
    let first = thread::spawn(move || block_on(replace(&c1, "k", NEW)));
    entered.recv_timeout(Duration::from_secs(10))?;
    let c2 = other.clone();
    let second = thread::spawn(move || block_on(replace(&c2, "k", NEWER)));
    settle();
    assert_eq!(f.asked().len(), 1);
    release.send(())?;
    for r in [first, second] {
        assert_eq!(
            r.join().map_err(|_| "panic")?,
            Err(ERROR_AUDIT_UNAVAILABLE.to_owned())
        );
    }
    // The second one ran after the restore: it saw the old certificate and made its own ask.
    assert_eq!(f.asked().len(), 2);
    assert_eq!(sink.attempts(), 2);
    assert_eq!(sink.inner.operation_entries().len(), 0);
    assert_eq!(snapshot(&area(&f))?, before);
    Ok(())
}

#[test]
fn concurrent_replaces_one_entry_each() -> TestResult {
    let (f, sink) = block_on(start(Answer::Yes))?;
    let other = block_on(f.bus.connect())?;
    for round in 0..20_usize {
        let id = format!("r{round}");
        put_rsa(&f, &id)?;
        let asked = f.asked().len();
        f.hold.store(usize::MAX, Ordering::SeqCst);
        let (c1, i1) = (f.client.clone(), id.clone());
        let first = thread::spawn(move || block_on(replace(&c1, &i1, NEW)));
        wait_for_asks(&f, asked + 1)?;
        let (c2, i2) = (other.clone(), id.clone());
        let second = thread::spawn(move || block_on(replace(&c2, &i2, NEWER)));
        // The second replace waits for the first; it does not reach polkit.
        settle();
        assert_eq!(f.asked().len(), asked + 1, "round {round}");
        f.hold.store(0, Ordering::SeqCst);
        assert_eq!(first.join().map_err(|_| "panic")?, Ok(()));
        assert_eq!(second.join().map_err(|_| "panic")?, Ok(()));
        // Entries equal polkit asks, one `replaced` per success.
        assert_eq!(f.asked().len(), 2 * (round + 1), "round {round}");
        assert_eq!(sink.inner.operation_entries().len(), f.asked().len());
        assert_eq!(sink.replaced(), f.asked().len());
        // The one that ran last won, whole: never a mix.
        assert_eq!(cert_of(&f, &id)?, NEWER, "round {round}");
    }
    Ok(())
}

#[test]
fn replace_and_delete_each_leave_one_entry() -> TestResult {
    let (f, sink) = block_on(start(Answer::Yes))?;
    let other = block_on(f.bus.connect())?;
    let mut replaced = 0;
    let mut missing = 0;
    for round in 0..20_usize {
        let id = format!("r{round}");
        put_rsa(&f, &id)?;
        // Polkit waits a moment so the two calls overlap; the lock lets only one ask at a time.
        f.hold.store(usize::MAX, Ordering::SeqCst);
        let (c1, i1) = (f.client.clone(), id.clone());
        let (c2, i2) = (other.clone(), id.clone());
        let (asked, entries) = (f.asked().len(), sink.inner.operation_entries().len());
        let (r, d) = if round % 2 == 0 {
            let r = thread::spawn(move || block_on(replace(&c1, &i1, NEW)));
            wait_for_asks(&f, asked + 1)?;
            (r, thread::spawn(move || block_on(delete(&c2, &i2))))
        } else {
            let d = thread::spawn(move || block_on(delete(&c2, &i2)));
            wait_for_asks(&f, asked + 1)?;
            (thread::spawn(move || block_on(replace(&c1, &i1, NEW))), d)
        };
        settle();
        f.hold.store(0, Ordering::SeqCst);
        let (r, d) = (
            r.join().map_err(|_| "panic")?,
            d.join().map_err(|_| "panic")?,
        );
        assert_eq!(d, Ok(()), "round {round}");
        let grew = f.asked().len() - asked;
        if r == Ok(()) {
            replaced += 1;
            assert_eq!(grew, 2, "round {round}");
            assert_eq!(sink.inner.operation_entries().len() - entries, 2);
        } else {
            missing += 1;
            assert_eq!(r, Err(ERROR_NO_SUCH_KEY.to_owned()), "round {round}");
            assert_eq!(grew, 1, "round {round}");
            assert_eq!(sink.inner.operation_entries().len() - entries, 1);
        }
        assert_eq!(
            snapshot(&area(&f))?.len(),
            0,
            "no certificate without its key"
        );
    }
    assert_eq!(sink.replaced(), replaced);
    assert_eq!(replaced + missing, 20);
    assert_eq!(sink.inner.operation_entries().len(), f.asked().len());
    Ok(())
}
