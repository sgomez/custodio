#![no_main]

use custodiod::import::parse_p12;
use libfuzzer_sys::fuzz_target;
use secrecy::SecretString;

// The parser must return an error, never panic, on any bytes or password.
fuzz_target!(|input: (&[u8], &str)| {
    let (data, password) = input;
    let _ = parse_p12(data, &SecretString::from(password.to_owned()));
});
