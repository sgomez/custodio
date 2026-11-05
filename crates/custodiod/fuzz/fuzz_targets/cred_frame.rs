#![no_main]

use custodiod::creds::header::{HeaderError, inspect};
use libfuzzer_sys::fuzz_target;

// The key ids of `creds::header` (not exported), which decide the answer before the PCR mask is read.
const HOST_ID: [u8; 16] = [
    0x5a, 0x1c, 0x6a, 0x86, 0xdf, 0x9d, 0x40, 0x96, 0xb1, 0xd5, 0xa6, 0x5e, 0x08, 0x62, 0xf1, 0x9a,
];
const HOST_SCOPED_ID: [u8; 16] = [
    0x55, 0xb9, 0xed, 0x1d, 0x38, 0x59, 0x4d, 0x43, 0xa8, 0x31, 0x9d, 0x2e, 0xbb, 0x33, 0x2a, 0xc6,
];
const NULL_ID: [u8; 16] = [
    0x05, 0x84, 0x69, 0xda, 0xf6, 0xf5, 0x43, 0x24, 0x80, 0x05, 0x49, 0xda, 0x0f, 0x8e, 0xa2, 0xfb,
];
// The PCR mask is read at this offset, 8 bytes (`MASK_OFFSET` in `creds::header`).
const MASK_END: usize = 48 + 8;

// The header read back after `Encrypt` is a binding or a refusal, never a panic. An input that is too short for the
// mask is refused, unless its first 16 bytes are a known key id, which is decided before the mask is read.
fuzz_target!(|data: &[u8]| {
    let result = inspect(data);
    let id = data.get(..16);
    let decided_early = id.is_some_and(|i| i == HOST_ID || i == HOST_SCOPED_ID || i == NULL_ID);
    if data.len() < MASK_END && !decided_early {
        assert!(result.is_err());
        if data.len() < 16 {
            assert_eq!(result, Err(HeaderError::TooShort));
        }
    }
});
