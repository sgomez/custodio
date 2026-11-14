#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    custodio_cli::browser_files::fuzz_profile_index(data);
});
