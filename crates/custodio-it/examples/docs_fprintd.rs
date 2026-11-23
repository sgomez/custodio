//! Test-only fake of `net.reactivated.Fprint` (and of the Custodio service and polkit authority doctor asks) for the
//! documents' script tests (`test-docs-fingerprint.sh`, `test-docs-guide.sh`). It is the fixture of the CLI's own tests,
//! shared by `#[path]`, not copied. Usage: `docs_fprintd BUS_ADDRESS [DEVICES] [FINGERS] [STORAGE] [REASON]` where DEVICES
//! is the number of readers (default 1), FINGERS is `list` (one enrolled finger, default), `none` or `refused`, STORAGE
//! the answer of `StateStorage` (default `encrypted`) and REASON that of `StateStorageReason` (default empty). It prints
//! `ready` on stdout once the bus names are owned, then serves until it is killed.
#![allow(
    clippy::print_stdout,
    reason = "the caller waits for the word `ready` on standard output"
)]

#[path = "../../custodio-cli/tests/fprint_fixture/mod.rs"]
mod fprint_fixture;

use fprint_fixture::{Fake, Fingers, Svc, serve_all};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let address = args
        .first()
        .expect("usage: docs_fprintd BUS_ADDRESS [DEVICES] [FINGERS] [STORAGE] [REASON]");
    let devices = args
        .get(1)
        .map_or(1, |d| d.parse().expect("DEVICES is a number"));
    let fingers = match args.get(2).map_or("list", String::as_str) {
        "list" => Fingers::List(&["right-index-finger"]),
        "none" => Fingers::NoPrints,
        "refused" => Fingers::Refused,
        other => panic!("unknown FINGERS {other:?}"),
    };
    // The answers live as long as the process: leaking two short strings is the cheapest way to get `'static`.
    let storage: &'static str = Box::leak(
        args.get(3)
            .cloned()
            .unwrap_or_else(|| "encrypted".into())
            .into_boxed_str(),
    );
    let reason: &'static str = Box::leak(args.get(4).cloned().unwrap_or_default().into_boxed_str());
    let fake = Fake {
        service: Some(Svc::answering(storage, Some(reason))),
        fingers,
        ..Fake::new(devices)
    };
    let _served = serve_all(address, fake);
    println!("ready");
    loop {
        std::thread::park();
    }
}
