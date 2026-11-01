//! Runs a blocking call on a thread under a deadline, and bounds the number of threads left behind.

use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};
use std::thread;
use std::time::{Duration, Instant};

const RUNNING: u8 = 0;
const ABANDONED: u8 = 1;
const FINISHED: u8 = 2;

struct State<T> {
    value: Option<T>,
    done: bool,
    waker: Option<Waker>,
}

struct Shared<T> {
    state: Mutex<State<T>>,
    wake_watchdog: Condvar,
    phase: AtomicU8,
}

fn lock<T>(m: &Mutex<State<T>>) -> MutexGuard<'_, State<T>> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Resolves to the value, or to `None` once the deadline has passed or the call panicked.
struct Waiting<T> {
    shared: Arc<Shared<T>>,
    deadline: Instant,
    stuck: Arc<AtomicUsize>,
}

impl<T> Future for Waiting<T> {
    type Output = Option<T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<T>> {
        let mut state = lock(&self.shared.state);
        if state.done {
            return Poll::Ready(state.value.take());
        }
        if Instant::now() >= self.deadline {
            drop(state);
            // The slot is counted before the phase changes, so the worker never subtracts first.
            self.stuck.fetch_add(1, Ordering::SeqCst);
            let abandoned = self
                .shared
                .phase
                .compare_exchange(RUNNING, ABANDONED, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok();
            if !abandoned {
                // The worker finished in between: nothing is stuck, and its value is there.
                self.stuck.fetch_sub(1, Ordering::SeqCst);
                return Poll::Ready(lock(&self.shared.state).value.take());
            }
            return Poll::Ready(None);
        }
        state.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

/// Bounds blocking calls: each one has `deadline` to answer, and at most `cap` calls that missed their
/// deadline may still be running. At the cap a new call is refused at once, so hostile input cannot pile up
/// threads. One limiter counts its own stuck threads; there is no global state.
#[derive(Debug)]
pub(super) struct Limiter {
    deadline: Duration,
    cap: usize,
    stuck: Arc<AtomicUsize>,
}

impl Limiter {
    pub(super) fn new(deadline: Duration, cap: usize) -> Self {
        Self {
            deadline,
            cap,
            stuck: Arc::new(AtomicUsize::new(0)),
        }
    }

    #[cfg(test)]
    pub(super) fn cap(&self) -> usize {
        self.cap
    }

    /// Threads that missed their deadline and are still running.
    #[cfg(test)]
    pub(super) fn stuck(&self) -> usize {
        self.stuck.load(Ordering::SeqCst)
    }

    /// Runs `f` on a new thread. `None` when the cap is reached (no thread is started), the thread cannot be
    /// started, `f` panics or does not return within the deadline (the thread is left; it gives its slot back
    /// when it ends).
    pub(super) async fn run<T, F>(&self, f: F) -> Option<T>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        if self.stuck.load(Ordering::SeqCst) >= self.cap {
            return None;
        }
        let deadline = Instant::now() + self.deadline;
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                value: None,
                done: false,
                waker: None,
            }),
            wake_watchdog: Condvar::new(),
            phase: AtomicU8::new(RUNNING),
        });
        let (worker_shared, worker_stuck) = (Arc::clone(&shared), Arc::clone(&self.stuck));
        let worker = thread::Builder::new().spawn(move || {
            let value = catch_unwind(AssertUnwindSafe(f)).ok();
            if worker_shared
                .phase
                .compare_exchange(RUNNING, FINISHED, Ordering::SeqCst, Ordering::SeqCst)
                .is_err()
            {
                worker_stuck.fetch_sub(1, Ordering::SeqCst);
            }
            let waker = {
                let mut state = lock(&worker_shared.state);
                state.done = true;
                state.value = value;
                state.waker.take()
            };
            worker_shared.wake_watchdog.notify_all();
            if let Some(w) = waker {
                w.wake();
            }
        });
        if worker.is_err() {
            return None;
        }
        // The watchdog wakes the waiting task at the deadline; it ends as soon as the worker is done.
        let dog = Arc::clone(&shared);
        let watchdog = thread::Builder::new().spawn(move || {
            let mut state = lock(&dog.state);
            while !state.done {
                let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                    break;
                };
                state = dog
                    .wake_watchdog
                    .wait_timeout(state, left)
                    .unwrap_or_else(PoisonError::into_inner)
                    .0;
            }
            if let Some(w) = state.waker.take() {
                drop(state);
                w.wake();
            }
        });
        if watchdog.is_err() {
            // Without the watchdog nothing would wake the task at the deadline.
            self.stuck.fetch_add(1, Ordering::SeqCst);
            if shared
                .phase
                .compare_exchange(RUNNING, ABANDONED, Ordering::SeqCst, Ordering::SeqCst)
                .is_err()
            {
                self.stuck.fetch_sub(1, Ordering::SeqCst);
            }
            return None;
        }
        Waiting {
            shared,
            deadline,
            stuck: Arc::clone(&self.stuck),
        }
        .await
    }
}
