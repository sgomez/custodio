#![no_main]

use custodiod::app_id::{AppIdOutcome, MAX_APP_ID_LEN, classify, validate};
use libfuzzer_sys::fuzz_target;

// Arbitrary bytes as an application id and as a scope name. What is accepted must pass `validate`
// again and stay within the bound, so the target can fail without a crash.
fuzz_target!(|input: (&[u8], bool)| {
    let (bytes, absent) = input;
    if let Some(id) = validate(bytes) {
        assert!(id.as_str().len() <= MAX_APP_ID_LEN);
        assert_eq!(id.as_str().as_bytes(), bytes);
        assert!(validate(id.as_str().as_bytes()).is_some());
    }
    if let AppIdOutcome::Read(id) = classify((!absent).then_some(bytes)) {
        assert!(id.as_str().len() <= MAX_APP_ID_LEN);
        assert!(validate(id.as_str().as_bytes()).is_some());
    }
});
