//! Runs a blocking call on its own thread and awaits it, so a slow call (an audit sink) cannot
//! stall the connection's executor.

use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll, Waker};
use std::thread;

struct Slot<T> {
    done: bool,
    value: Option<T>,
    waker: Option<Waker>,
}

struct Offloaded<T>(Arc<Mutex<Slot<T>>>);

impl<T> Future for Offloaded<T> {
    type Output = Option<T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<T>> {
        let mut slot = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if slot.done {
            return Poll::Ready(slot.value.take());
        }
        slot.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

/// Runs `f` on a new thread. `None` if the thread could not be started or `f` panicked.
pub(crate) async fn run_on_thread<T, F>(f: F) -> Option<T>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let slot = Arc::new(Mutex::new(Slot {
        done: false,
        value: None,
        waker: None,
    }));
    let theirs = Arc::clone(&slot);
    let spawned = thread::Builder::new().spawn(move || {
        let value = catch_unwind(AssertUnwindSafe(f)).ok();
        let waker = {
            let mut s = theirs.lock().unwrap_or_else(PoisonError::into_inner);
            s.done = true;
            s.value = value;
            s.waker.take()
        };
        if let Some(w) = waker {
            w.wake();
        }
    });
    if spawned.is_err() {
        return None;
    }
    Offloaded(slot).await
}

#[cfg(test)]
mod tests;
