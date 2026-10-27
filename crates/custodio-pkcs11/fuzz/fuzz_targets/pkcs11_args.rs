#![no_main]

use libfuzzer_sys::fuzz_target;

// Arbitrary PKCS#11 arguments through the function list, against a fake service.
fuzz_target!(|data: &[u8]| {
    custodio_pkcs11::fuzzing::run(data);
});
