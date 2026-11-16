#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = custodio_cli::fingerprint_decide::fuzz_pam_file(data);
});
