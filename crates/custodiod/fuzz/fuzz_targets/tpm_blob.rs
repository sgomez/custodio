#![no_main]

use custodiod::tpm::blob::Blob;
use libfuzzer_sys::fuzz_target;

// The stored TPM blob is parsed from disk: whatever `parse` or `from_parts` accepts re-serialises to bytes that parse to
// an equal blob, and its public area parses. Nothing panics.
fn check(blob: &Blob) {
    assert!(blob.public_area().is_ok());
    let bytes = blob.to_bytes();
    let again = Blob::parse(&bytes).expect("a serialised blob parses");
    assert!(again == *blob);
    assert_eq!(again.to_bytes(), bytes);
}

fuzz_target!(|input: (&[u8], &[u8])| {
    let (first, second) = input;
    if let Ok(blob) = Blob::parse(first) {
        check(&blob);
    }
    if let Ok(blob) = Blob::from_parts(first, second) {
        check(&blob);
    }
});
