use super::*;
use std::time::Duration;
use zbus::block_on;

#[test]
fn returns_the_value() {
    assert_eq!(block_on(run_on_thread(|| 7)), Some(7));
}

#[test]
fn a_slow_call_still_completes() {
    let got = block_on(run_on_thread(|| {
        thread::sleep(Duration::from_millis(100));
        "done"
    }));
    assert_eq!(got, Some("done"));
}

#[test]
fn a_panic_is_none() {
    // `resume_unwind` panics without calling the panic hook.
    let got = block_on(run_on_thread(|| -> u8 {
        std::panic::resume_unwind(Box::new("boom"))
    }));
    assert_eq!(got, None);
}
