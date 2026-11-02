use super::super::limiter::Limiter;
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};
use zbus::block_on;

/// Dropping it lets the blocked calls of a test end, so no thread outlives the test.
struct Release {
    _tx: mpsc::Sender<()>,
}

fn blocker() -> (Release, impl FnOnce() -> u8 + Send + 'static) {
    let (tx, rx) = mpsc::channel::<()>();
    (Release { _tx: tx }, move || {
        let _ = rx.recv();
        0
    })
}

/// Runs a test body on its own thread and fails the test if it does not end in 20 s, so a limiter that never
/// wakes its task fails instead of hanging the run.
fn within(body: impl FnOnce() + Send + 'static) {
    let (tx, rx) = mpsc::channel::<()>();
    std::thread::spawn(move || {
        body();
        let _ = tx.send(());
    });
    assert!(
        rx.recv_timeout(Duration::from_secs(20)).is_ok(),
        "the body panicked or hung"
    );
}

fn wait_for(mut done: impl FnMut() -> bool) {
    let until = Instant::now() + Duration::from_secs(10);
    while !done() {
        assert!(Instant::now() < until, "timed out");
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn a_fast_call_returns_its_value() {
    within(|| {
        let limiter = Limiter::new(Duration::from_secs(5), 2);
        assert_eq!(block_on(limiter.run(|| 7)), Some(7));
        assert_eq!(limiter.live(), 0);
    });
}

#[test]
fn a_panic_is_none_and_holds_no_slot() {
    within(|| {
        let limiter = Limiter::new(Duration::from_secs(5), 1);
        let got = block_on(limiter.run(|| -> u8 { std::panic::resume_unwind(Box::new("boom")) }));
        assert_eq!(got, None);
        assert_eq!(limiter.live(), 0);
        assert_eq!(block_on(limiter.run(|| 1)), Some(1));
    });
}

#[test]
fn blocked_reader_returns_undetermined_within_bound() {
    within(|| {
        let limiter = Limiter::new(Duration::from_millis(60), 2);
        let (_release, blocked) = blocker();
        let started = Instant::now();
        assert_eq!(block_on(limiter.run(blocked)), None);
        let took = started.elapsed();
        assert!(took >= Duration::from_millis(60), "{took:?}");
        assert!(took < Duration::from_millis(1500), "{took:?}");
        assert_eq!(limiter.live(), 1);
    });
}

#[test]
fn stuck_lookups_are_capped() {
    within(|| {
        let limiter = Limiter::new(Duration::from_millis(100), 2);
        let started_threads = Arc::new(AtomicUsize::new(0));
        let mut releases = Vec::new();
        for _ in 0..2 {
            let (release, blocked) = blocker();
            releases.push(release);
            let counter = Arc::clone(&started_threads);
            let t = Instant::now();
            let got = block_on(limiter.run(move || {
                counter.fetch_add(1, Ordering::SeqCst);
                blocked()
            }));
            assert_eq!(got, None);
            assert!(t.elapsed() >= Duration::from_millis(100));
        }
        assert_eq!(limiter.live(), 2);
        let counter = Arc::clone(&started_threads);
        let t = Instant::now();
        let got = block_on(limiter.run(move || counter.fetch_add(1, Ordering::SeqCst)));
        assert_eq!(got, None);
        assert!(t.elapsed() < Duration::from_millis(50), "{:?}", t.elapsed());
        wait_for(|| started_threads.load(Ordering::SeqCst) == 2);
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(
            started_threads.load(Ordering::SeqCst),
            2,
            "no thread for the refused call"
        );
        assert_eq!(limiter.live(), 2);
    });
}

#[test]
fn released_stuck_thread_frees_its_slot() {
    within(|| {
        let limiter = Limiter::new(Duration::from_millis(40), 1);
        let (release, blocked) = blocker();
        assert_eq!(block_on(limiter.run(blocked)), None);
        assert_eq!(block_on(limiter.run(|| 5)), None, "at the cap");
        drop(release);
        wait_for(|| limiter.live() == 0);
        assert_eq!(block_on(limiter.run(|| 5)), Some(5));
    });
}

#[test]
fn limiters_do_not_share_slots() {
    within(|| {
        let a = Limiter::new(Duration::from_millis(30), 1);
        let b = Limiter::new(Duration::from_millis(30), 1);
        let (_release, blocked) = blocker();
        assert_eq!(block_on(a.run(blocked)), None);
        assert_eq!(a.live(), 1);
        assert_eq!(b.live(), 0);
        assert_eq!(block_on(b.run(|| 2)), Some(2));
    });
}

#[test]
fn concurrent_lookups_cannot_exceed_the_cap() {
    within(|| {
        let cap = 3;
        let limiter = Arc::new(Limiter::new(Duration::from_millis(300), cap));
        let started = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(std::sync::Barrier::new(cap + 4));
        let (release, rx) = {
            let (tx, rx) = mpsc::channel::<()>();
            (Release { _tx: tx }, Arc::new(std::sync::Mutex::new(rx)))
        };
        let handles: Vec<_> = (0..cap + 4)
            .map(|_| {
                let (limiter, started, barrier, rx) = (
                    Arc::clone(&limiter),
                    Arc::clone(&started),
                    Arc::clone(&barrier),
                    Arc::clone(&rx),
                );
                std::thread::spawn(move || {
                    barrier.wait();
                    block_on(limiter.run(move || {
                        started.fetch_add(1, Ordering::SeqCst);
                        let _ = rx.lock().map(|r| r.recv());
                    }))
                })
            })
            .collect();
        for h in handles {
            assert_eq!(h.join().ok(), Some(None));
        }
        assert_eq!(started.load(Ordering::SeqCst), cap, "workers started");
        assert!(limiter.live() <= cap, "{}", limiter.live());
        drop(release);
        wait_for(|| limiter.live() == 0);
    });
}

#[test]
fn a_dropped_future_keeps_its_slot_until_the_worker_ends() {
    within(|| {
        let limiter = Limiter::new(Duration::from_secs(5), 1);
        let (release, blocked) = blocker();
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        let mut fut = Box::pin(limiter.run(blocked));
        assert!(fut.as_mut().poll(&mut cx).is_pending());
        drop(fut);
        assert_eq!(limiter.live(), 1);
        assert_eq!(block_on(limiter.run(|| 5)), None, "at the cap");
        drop(release);
        wait_for(|| limiter.live() == 0);
        assert_eq!(block_on(limiter.run(|| 5)), Some(5));
    });
}
