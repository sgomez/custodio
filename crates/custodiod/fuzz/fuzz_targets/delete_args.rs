#![no_main]

use custodiod::dbus::parse_delete_request;
use libfuzzer_sys::fuzz_target;

// The id of `DeleteKey` is accepted or refused, never a panic. `delete_call` runs the same check.
fuzz_target!(|id: &str| {
    let _ = parse_delete_request(id);
});
