#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Each NUL-separated piece is one argument; the parser and the help lookup return values and
    // take no writer, so they cannot print.
    let args = data
        .split(|b| *b == 0)
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect();
    let _ = custodio_cli::fuzz_cli_args(args);
});
