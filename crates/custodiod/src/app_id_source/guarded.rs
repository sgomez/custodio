//! The service's way of asking a source: any [`AppIdSource`] behind one type, under the lookup deadline.
//!
//! A source promises to be quick and never to panic, but the service does not depend on the promise: the
//! question is asked on a thread of its own, the caller waits at most [`LOOKUP_DEADLINE`], and a source that
//! panics, does not return or cannot be started gives [`AppIdOutcome::Undetermined`]. At most [`MAX_STUCK`]
//! such threads exist at a time.

use std::future::Future;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use super::limiter::Limiter;
use super::{AppIdSource, LOOKUP_DEADLINE, MAX_STUCK};
use crate::app_id::AppIdOutcome;

/// A boxed answer of a source.
type Answer<'a> = Pin<Box<dyn Future<Output = AppIdOutcome> + Send + 'a>>;

/// [`AppIdSource`] without the `impl Future`, so that it can be a trait object.
pub trait ErasedAppIdSource: Send + Sync {
    /// As [`AppIdSource::app_id`].
    fn app_id_boxed<'a>(&'a self, pidfd: BorrowedFd<'a>, uid: u32) -> Answer<'a>;
}

impl<S: AppIdSource> ErasedAppIdSource for S {
    fn app_id_boxed<'a>(&'a self, pidfd: BorrowedFd<'a>, uid: u32) -> Answer<'a> {
        Box::pin(self.app_id(pidfd, uid))
    }
}

/// A source asked under a deadline.
#[derive(Clone)]
pub struct GuardedSource {
    source: Arc<dyn ErasedAppIdSource>,
    limiter: Arc<Limiter>,
}

impl GuardedSource {
    /// `source`, asked with the documented deadline and cap.
    #[must_use]
    pub fn new(source: impl AppIdSource + 'static) -> Self {
        Self::with_limits(source, LOOKUP_DEADLINE, MAX_STUCK)
    }

    /// `source`, asked with another deadline and cap (tests).
    #[must_use]
    pub fn with_limits(source: impl AppIdSource + 'static, deadline: Duration, cap: usize) -> Self {
        Self {
            source: Arc::new(source),
            limiter: Arc::new(Limiter::new(deadline, cap)),
        }
    }

    /// The app-id of the process `pidfd` pins, `uid` being the caller's. Never an error and never later than
    /// the deadline.
    pub async fn app_id(&self, pidfd: &OwnedFd, uid: u32) -> AppIdOutcome {
        let Ok(owned) = pidfd.as_fd().try_clone_to_owned() else {
            return AppIdOutcome::Undetermined;
        };
        let source = Arc::clone(&self.source);
        self.limiter
            .run(move || zbus::block_on(source.app_id_boxed(owned.as_fd(), uid)))
            .await
            .unwrap_or(AppIdOutcome::Undetermined)
    }
}
