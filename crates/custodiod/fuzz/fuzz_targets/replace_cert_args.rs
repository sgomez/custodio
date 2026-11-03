#![no_main]

use custodiod::dbus::parse_replace_request;
use libfuzzer_sys::fuzz_target;

// The id and the certificate of `ReplaceCertificate` reach the id check, the size bound and the DER
// parse, as in `replace_call`. Whatever the caller sends is accepted or refused, never a panic.
fuzz_target!(|input: (&str, &[u8])| {
    let (id, certificate) = input;
    let _ = parse_replace_request(id, certificate);
});
