//! The completions of bash, zsh and fish, and the hidden `custodio __key-ids` they call.
//! The service is the real one on a private `dbus-daemon` (the `list` rig); the shells are real.

use std::time::{Duration, Instant};

use custodio_client::{BUS_NAME, OBJECT_PATH};

mod completions_rig;
mod list_rig;
use completions_rig::{key_ids, snapshot, state_dir};
use list_rig::{P256_OTHER_P12, P256_P12, Rig, TestResult};

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn key_ids_prints_the_sorted_ids_and_calls_list_keys_only() -> TestResult {
    let rig = Rig::start(true)?;
    rig.import("zed", P256_P12)?;
    rig.import("alpha", P256_OTHER_P12)?;
    // The counting is live: the two imports asked polkit.
    assert_eq!(rig.polkit_calls(), 2);
    let imports = rig.calls(2).len();
    completions_rig::binary()?;
    let state = snapshot(&state_dir(&rig))?;

    let out = key_ids(&rig.bus.address)?;
    assert_eq!(text(&out.stdout), "alpha\nzed\n");
    assert_eq!(text(&out.stderr), "");
    assert!(out.status.success());

    assert_eq!(rig.polkit_calls(), 2, "no polkit request");
    let all = rig.calls(imports + 1);
    let new: Vec<_> = all[imports..]
        .iter()
        .filter(|c| c.0 == BUS_NAME || c.1 == OBJECT_PATH)
        .map(|c| c.3.as_str())
        .collect();
    assert_eq!(new, ["ListKeys"], "{:?}", &all[imports..]);
    // Besides the bus's own `Hello` of the new connection, nothing else was called.
    let others = all[imports..].iter().filter(|c| c.3 != "Hello").count();
    assert_eq!(others, 1, "{:?}", &all[imports..]);
    assert_eq!(snapshot(&state_dir(&rig))?, state, "nothing written");
    Ok(())
}

#[test]
fn key_ids_with_no_keys_prints_nothing_and_succeeds() -> TestResult {
    let rig = Rig::start(true)?;
    let out = key_ids(&rig.bus.address)?;
    assert!(out.status.success());
    assert!(out.stdout.is_empty() && out.stderr.is_empty());
    Ok(())
}

#[test]
fn key_ids_without_the_service_or_the_bus_prints_nothing_and_exits_1() -> TestResult {
    let rig = Rig::start(false)?;
    completions_rig::binary()?; // built before the clock starts
    for address in [rig.bus.address.as_str(), "unix:path=/nonexistent/bus"] {
        let start = Instant::now();
        let out = key_ids(address)?;
        assert_eq!(out.status.code(), Some(1), "{address}");
        assert!(out.stdout.is_empty() && out.stderr.is_empty(), "{address}");
        assert!(start.elapsed() < Duration::from_secs(1), "{address}");
    }
    Ok(())
}

#[test]
fn key_ids_with_a_service_that_never_answers_gives_up_at_its_limit() -> TestResult {
    let rig = Rig::start(false)?;
    // A peer owns the name and never replies.
    let peer = rig.client_connection()?;
    zbus::block_on(peer.request_name(BUS_NAME))?;
    let start = Instant::now();
    let out = key_ids(&rig.bus.address)?;
    let took = start.elapsed();
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty() && out.stderr.is_empty());
    assert!(took >= Duration::from_secs(2), "{took:?}");
    assert!(took < Duration::from_secs(4), "{took:?}");
    Ok(())
}
