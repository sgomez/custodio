use std::sync::atomic::Ordering;

use super::*;

#[test]
fn sign_counter_counts() {
    let _lock = crate::ffi::tests::SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let backend = FakeBackend;
    let params = SignParams {
        mechanism: 0,
        hash: 0,
        salt_len: 0,
    };
    let before = SIGN_CALLS.load(Ordering::SeqCst);
    backend.sign("ec", params, b"a").unwrap();
    backend.sign("ec", params, b"b").unwrap();
    assert_eq!(SIGN_CALLS.load(Ordering::SeqCst) - before, 2);
    backend.list_certificates().unwrap();
    assert_eq!(SIGN_CALLS.load(Ordering::SeqCst) - before, 2);
}
