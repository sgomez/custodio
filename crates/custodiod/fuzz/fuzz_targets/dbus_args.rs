#![no_main]

use custodiod::dbus::{parse_import_request, parse_sign_request};
use libfuzzer_sys::fuzz_target;

// The method arguments must be accepted or refused, never panic, whatever the caller sends.
fuzz_target!(|input: (&str, u32, u32, u32, &[u8], &str)| {
    let (id, mechanism, hash, salt_len, data, password) = input;
    let _ = parse_sign_request(id, mechanism, hash, salt_len, data);
    let _ = parse_import_request(id, data, password);
});
