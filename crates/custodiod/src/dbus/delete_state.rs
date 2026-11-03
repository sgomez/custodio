//! What `DeleteKey` shares between calls: which keys are unusable, and the one-at-a-time rule for
//! deletes of the same owner and key id. Both live in memory only, so setting and undoing them
//! cannot fail.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};

type Key = (u32, String);

/// Unusable keys and the delete locks.
#[derive(Default)]
pub(super) struct DeleteState {
    unusable: Mutex<HashSet<Key>>,
    /// A key that is present is locked; the wakers wait for it. Entries are removed on release,
    /// so the table only holds the deletes in progress.
    locks: Mutex<HashMap<Key, Vec<Waker>>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl DeleteState {
    /// From now on `Sign` and `ListKeys` do not see the key and a delete fails `NoSuchKey`.
    pub(super) fn mark_unusable(&self, owner: u32, id: &str) {
        lock(&self.unusable).insert((owner, id.to_owned()));
    }

    /// Undoes [`Self::mark_unusable`].
    pub(super) fn restore(&self, owner: u32, id: &str) {
        lock(&self.unusable).remove(&(owner, id.to_owned()));
    }

    pub(super) fn is_unusable(&self, owner: u32, id: &str) -> bool {
        lock(&self.unusable).contains(&(owner, id.to_owned()))
    }

    /// Waits until no other delete of this owner and id is running.
    pub(super) fn lock_key<'a>(&'a self, owner: u32, id: &str) -> Acquire<'a> {
        Acquire {
            state: self,
            key: (owner, id.to_owned()),
        }
    }

    #[cfg(test)]
    pub(super) fn locked(&self) -> usize {
        lock(&self.locks).len()
    }
}

pub(super) struct Acquire<'a> {
    state: &'a DeleteState,
    key: Key,
}

impl<'a> Future for Acquire<'a> {
    type Output = KeyLock<'a>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<KeyLock<'a>> {
        let mut table = lock(&self.state.locks);
        if let Some(waiters) = table.get_mut(&self.key) {
            if !waiters.iter().any(|w| w.will_wake(cx.waker())) {
                waiters.push(cx.waker().clone());
            }
            return Poll::Pending;
        }
        table.insert(self.key.clone(), Vec::new());
        Poll::Ready(KeyLock {
            state: self.state,
            key: self.key.clone(),
        })
    }
}

/// Held by a delete from the lookup to the end; released on every exit path, also on a drop.
pub(super) struct KeyLock<'a> {
    state: &'a DeleteState,
    key: Key,
}

impl Drop for KeyLock<'_> {
    fn drop(&mut self) {
        let waiters = lock(&self.state.locks).remove(&self.key);
        for w in waiters.into_iter().flatten() {
            w.wake();
        }
    }
}

#[cfg(test)]
mod tests;
