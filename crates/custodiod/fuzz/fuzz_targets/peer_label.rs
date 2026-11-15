#![no_main]

use custodiod::peer_label::{MAX_LABEL_LEN, check};
use libfuzzer_sys::fuzz_target;

// Arbitrary bytes as the `SO_PEERSEC` value. Accepting anything but the one label must fail the target, and a
// refusal must have a short fixed text, so the target can fail without a crash.
fuzz_target!(|bytes: &[u8]| {
    match check(bytes) {
        Ok(()) => assert_eq!(bytes, b"snap.firefox.firefox (enforce)"),
        Err(reason) => {
            assert!(reason.to_string().len() < 64);
            assert_ne!(bytes, b"snap.firefox.firefox (enforce)");
            if bytes.len() > MAX_LABEL_LEN {
                assert!(check(bytes).is_err());
            }
        }
    }
});
