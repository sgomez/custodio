#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Any bytes as a certificate: the fields must be safe to print, or the entry point panics.
    let _ = custodio_cli::cert_text::fuzz_cert_fields(data);
});
