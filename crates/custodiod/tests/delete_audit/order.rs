//! The order of a delete: unusable, then the entry, then the files. And signs that overlap.

use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

use custodio_client::{ERROR_AUDIT_UNAVAILABLE, ERROR_KEY_ID_TAKEN, ERROR_NO_SUCH_KEY};
use zbus::block_on;

use super::bus::{Answer, TestResult, call, error_name};
use super::common::{PASSWORD, RSA_P12};
use super::{area, delete, listed, put_rsa, rsa_public, sign_rsa, snapshot, start, verifies};

const NONE: [String; 0] = [];
const WAIT: Duration = Duration::from_secs(5);

#[test]
fn delete_sign_during_entry_fails_no_such_key() -> TestResult {
    let (f, sink) = block_on(start(Answer::Yes))?;
    put_rsa(&f, "k")?;
    let (entered, release) = sink.arm_gate();
    let client = f.client.clone();
    let deleting = thread::spawn(move || block_on(delete(&client, "k")));
    entered.recv_timeout(WAIT)?;
    // The entry is submitted and held. Everything below happens while it is pending.
    let other = block_on(f.bus.connect())?;
    let asked = f.asked().len();
    assert_eq!(
        block_on(sign_rsa(&other, "k")),
        Err(ERROR_NO_SUCH_KEY.to_owned())
    );
    assert_eq!(
        block_on(delete(&other, "k")),
        Err(ERROR_NO_SUCH_KEY.to_owned())
    );
    assert_eq!(block_on(listed(&other))?, NONE);
    let import = block_on(call(
        &other,
        "ImportP12",
        &("k", RSA_P12.to_vec(), PASSWORD),
    ));
    assert_eq!(
        import.map_err(|e| error_name(&e)).err(),
        Some(ERROR_KEY_ID_TAKEN.to_owned())
    );
    // No polkit ask for the refusals, and the files are still there: removal comes after.
    assert_eq!(f.asked().len(), asked);
    assert_eq!(snapshot(&area(&f))?.len(), 2);
    assert_eq!(sink.attempts(), 1);
    assert_eq!(sink.sign_attempts.load(Ordering::SeqCst), 0);
    release.send(())?;
    assert_eq!(deleting.join().map_err(|_| "panic")?, Ok(()));
    assert_eq!(snapshot(&area(&f))?, []);
    assert_eq!(sink.attempts(), 1);
    assert_eq!(sink.sign_attempts.load(Ordering::SeqCst), 0);
    // The id is free again.
    block_on(call(
        &f.client,
        "ImportP12",
        &("k", RSA_P12.to_vec(), PASSWORD),
    ))?;
    assert_eq!(block_on(listed(&f.client))?, ["k"]);
    Ok(())
}

#[test]
fn sign_in_progress_survives_delete_audit() -> TestResult {
    let public = rsa_public()?;
    for failing in [false, true] {
        let (f, sink) = block_on(start(Answer::Yes))?;
        put_rsa(&f, "k")?;
        sink.failing(failing);
        // The sign is held in polkit after its lookup until the delete asks too.
        f.hold.store(2, Ordering::SeqCst);
        let client = f.client.clone();
        let signing = thread::spawn(move || block_on(sign_rsa(&client, "k")));
        let start = std::time::Instant::now();
        while f.asked().is_empty() {
            assert!(start.elapsed() < WAIT, "the sign never reached polkit");
            thread::sleep(Duration::from_millis(5));
        }
        let other = block_on(f.bus.connect())?;
        let deleted = block_on(delete(&other, "k"));
        let sig = signing.join().map_err(|_| "panic")?;
        verifies(&public, &sig.map_err(|e| format!("sign failed: {e}"))?)?;
        if failing {
            assert_eq!(deleted, Err(ERROR_AUDIT_UNAVAILABLE.to_owned()));
            f.hold.store(0, Ordering::SeqCst);
            verifies(&public, &block_on(sign_rsa(&f.client, "k"))?)?;
        } else {
            assert_eq!(deleted, Ok(()));
            assert_eq!(sink.deleted(), 1);
        }
    }
    Ok(())
}
