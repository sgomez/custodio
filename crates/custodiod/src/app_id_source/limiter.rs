//! Runs a blocking call on a thread under a deadline, and bounds the number of threads left behind.

use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};
use std::thread;
use std::time::{Duration, Instant};

struct State<T> {
    value: Option<T>,
    done: bool,
    waker: Option<Waker>,
}

struct Shared<T> {
    state: Mutex<State<T>>,
    wake_watchdog: Condvar,
}

fn lock<T>(m: &Mutex<State<T>>) -> MutexGuard<'_, State<T>> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Resolves to the value, or to `None` once the deadline has passed or the call panicked.
struct Waiting<T> {
    shared: Arc<Shared<T>>,
    deadline: Instant,
}

impl<T> Future for Waiting<T> {
    type Output = Option<T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<T>> {
        let mut state = lock(&self.shared.state);
        if state.done {
            return Poll::Ready(state.value.take());
        }
        if Instant::now() >= self.deadline {
            return Poll::Ready(None);
        }
        state.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

/// Gives the slot back when the worker ends, however it ends.
struct Slot(Arc<AtomicUsize>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Bounds blocking calls: each one has `deadline` to answer, and at most `cap` workers exist at a time,
/// whether they are still within their deadline, past it, or abandoned by a dropped future. A slot is taken
/// before the worker starts (so concurrent calls cannot all pass the check) and given back by the worker when
/// it ends. At the cap a new call is refused at once, so hostile input cannot pile up threads. One limiter
/// counts its own workers; there is no global state.
#[derive(Debug)]
pub(super) struct Limiter {
    deadline: Duration,
    cap: usize,
    live: Arc<AtomicUsize>,
}

impl Limiter {
    pub(super) fn new(deadline: Duration, cap: usize) -> Self {
        Self {
            deadline,
            cap,
            live: Arc::new(AtomicUsize::new(0)),
        }
    }

    #[cfg(test)]
    pub(super) fn cap(&self) -> usize {
        self.cap
    }

    /// Workers still running (within or past their deadline).
    #[cfg(test)]
    pub(super) fn live(&self) -> usize {
        self.live.load(Ordering::SeqCst)
    }

    /// Runs `f` on a new thread. `None` when the cap is reached (no thread is started), the thread cannot be
    /// started, `f` panics or does not return within the deadline (the thread is left; it gives its slot back
    /// when it ends).
    pub(super) async fn run<T, F>(&self, f: F) -> Option<T>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        let taken = self
            .live
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                (n < self.cap).then_some(n + 1)
            });
        if taken.is_err() {
            return None;
        }
        let slot = Slot(Arc::clone(&self.live));
        let deadline = Instant::now() + self.deadline;
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                value: None,
                done: false,
                waker: None,
            }),
            wake_watchdog: Condvar::new(),
        });
        let worker_shared = Arc::clone(&shared);
        // On a failed spawn the closure, and with it the slot, is dropped.
        let worker = thread::Builder::new().spawn(move || {
            let value = catch_unwind(AssertUnwindSafe(f)).ok();
            // Before `done`, so a caller that got the value sees the slot free.
            drop(slot);
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
            // Without the watchdog nothing would wake the task at the deadline. The worker ends on its own
            // and gives its slot back.
            return None;
        }
        Waiting { shared, deadline }.await
    }
}
