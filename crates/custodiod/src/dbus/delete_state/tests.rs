use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Wake;

use super::*;

struct Counter(AtomicUsize);

impl Wake for Counter {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn poll<F: Future + Unpin>(f: &mut F, c: &Arc<Counter>) -> Poll<F::Output> {
    let waker = Waker::from(Arc::clone(c));
    Pin::new(f).poll(&mut Context::from_waker(&waker))
}

#[test]
fn unusable_is_per_owner_and_id_and_can_be_restored() {
    let s = DeleteState::default();
    assert!(!s.is_unusable(1, "k"));
    s.mark_unusable(1, "k");
    assert!(s.is_unusable(1, "k"));
    assert!(!s.is_unusable(2, "k"));
    assert!(!s.is_unusable(1, "other"));
    s.restore(1, "k");
    assert!(!s.is_unusable(1, "k"));
    s.mark_unusable(1, "k");
    s.restore(2, "k");
    s.restore(1, "other");
    assert!(
        s.is_unusable(1, "k"),
        "restoring another key changes nothing"
    );
}

#[test]
fn a_second_lock_waits_until_the_first_is_dropped_and_is_woken() {
    let s = DeleteState::default();
    let c = Arc::new(Counter(AtomicUsize::new(0)));
    let mut first = s.lock_key(1, "k");
    let guard = poll(&mut first, &c);
    assert!(guard.is_ready(), "a free key is locked at once");
    let mut second = s.lock_key(1, "k");
    assert!(poll(&mut second, &c).is_pending());
    assert!(poll(&mut second, &c).is_pending());
    assert_eq!(c.0.load(Ordering::SeqCst), 0);
    drop(guard);
    assert_eq!(c.0.load(Ordering::SeqCst), 1, "woken once, not per poll");
    assert!(poll(&mut second, &c).is_ready());
}

#[test]
fn other_keys_and_owners_are_not_blocked_and_the_table_empties() {
    let state = DeleteState::default();
    let count = Arc::new(Counter(AtomicUsize::new(0)));
    let mut same = state.lock_key(1, "k");
    let mut other_id = state.lock_key(1, "other");
    let mut other_owner = state.lock_key(2, "k");
    let guards = (
        poll(&mut same, &count),
        poll(&mut other_id, &count),
        poll(&mut other_owner, &count),
    );
    assert!(guards.0.is_ready() && guards.1.is_ready() && guards.2.is_ready());
    assert_eq!(state.locked(), 3);
    drop(guards);
    assert_eq!(state.locked(), 0);
}
