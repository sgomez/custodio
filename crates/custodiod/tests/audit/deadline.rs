//! A deadline for calls that must not hang: a lock that is never released would otherwise stop a
//! test run instead of failing it.

use std::future::Future;
use std::task::Poll;
use std::time::{Duration, Instant};

/// `f`'s output, or `None` if it is not done after `limit`.
pub async fn within<T>(limit: Duration, f: impl Future<Output = T>) -> Option<T> {
    let mut f = Box::pin(f);
    let started = Instant::now();
    let mut timer = false;
    std::future::poll_fn(move |cx| {
        if let Poll::Ready(v) = f.as_mut().poll(cx) {
            return Poll::Ready(Some(v));
        }
        if started.elapsed() >= limit {
            return Poll::Ready(None);
        }
        if !timer {
            timer = true;
            let waker = cx.waker().clone();
            std::thread::spawn(move || {
                std::thread::sleep(limit + Duration::from_millis(100));
                waker.wake();
            });
        }
        Poll::Pending
    })
    .await
}
