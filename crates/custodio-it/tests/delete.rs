//! `custodio delete` as the real binary, on a pseudo-terminal, against the real service on a
//! private `dbus-daemon` with a fake polkit. Needs `dbus-daemon` (`/usr/bin/dbus-daemon` in the
//! dev container); a missing one fails the tests.
//!
//! The binary is run as a child that has the slave end of the pseudo-terminal as its controlling
//! terminal (new session, `TIOCSCTTY`), which is what lets it open `/dev/tty`. In the dev
//! container this works: `/dev/tty` opens, takes the prompt and gives back what the master
//! writes. The "no terminal" child is a new session without one.

#[path = "delete/rig.rs"]
mod rig;
#[path = "delete/run.rs"]
mod run;

use std::error::Error;
use std::os::unix::process::ExitStatusExt;
use std::sync::PoisonError;
use std::sync::atomic::Ordering;

use custodio_cli::ServiceFailure;
use custodio_cli::USAGE;
use custodio_cli::delete::question;
use custodio_client::{BUS_NAME, OBJECT_PATH};
use custodiod::polkit::DELETE_ACTION_ID;

use rig::*;
use run::*;

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn the_pseudo_terminal_is_the_controlling_terminal_of_the_child() -> TestResult {
    // The premise of every test below: the child opens `/dev/tty` and the master hears it.
    let rig = Rig::start(true)?;
    let mut run = Run::start(&rig, &["delete", "x"], &[], true, b"")?;
    run.wait_for(&question("x"))?;
    run.send(b"n\n")?;
    run.finish()?;
    Ok(())
}

#[test]
fn confirming_asks_before_the_service_and_deletes_after_the_answer() -> TestResult {
    let rig = Rig::start(true)?;
    rig.import("old-key")?;
    rig.import("keep")?;
    rig.forget();
    let mut run = Run::start(&rig, &delete_args("old-key"), &[], true, b"")?;
    run.wait_for(&question("old-key"))?;
    let shown = run.screen();
    assert!(shown.contains("'old-key'") && shown.contains("cannot be recovered"));
    // Nothing reached the service while the question stands.
    assert_eq!(rig.service_calls(), []);
    assert_eq!(rig.polkit_asked(), Vec::<String>::new());
    assert_eq!(rig.keys()?.len(), 2);
    rig.forget();

    run.send(b"yes\n")?;
    let done = run.finish()?;
    assert_eq!(done.status.code(), Some(0), "{}", done.stderr);
    assert_eq!(done.stdout, "Deleted key 'old-key'.\n");
    assert_eq!(done.stderr, "");
    assert_eq!(rig.polkit_asked(), [DELETE_ACTION_ID.to_owned()]);
    // One call, `DeleteKey(s)` to the documented name, path and interface.
    assert_eq!(
        rig.service_calls(),
        [(
            OBJECT_PATH.to_owned(),
            BUS_NAME.to_owned(),
            "DeleteKey".to_owned(),
            "s".to_owned()
        )]
    );
    assert_eq!(rig.keys()?, ["keep"]);
    Ok(())
}

/// Answers the question with `answer` (or hangs up) and checks that nothing was deleted and
/// nothing was asked of the service or polkit.
fn declined(answer: Option<&[u8]>) -> Result<Finished, Box<dyn Error>> {
    let rig = Rig::start(true)?;
    rig.import("k")?;
    rig.forget();
    let mut run = Run::start(&rig, &delete_args("k"), &[], true, b"")?;
    run.wait_for(&question("k"))?;
    match answer {
        Some(bytes) => run.send(bytes)?,
        None => run.hang_up(),
    }
    let done = run.finish()?;
    assert_ne!(done.status.code(), Some(0), "{}", done.stderr);
    assert_eq!(done.stdout, "");
    assert_eq!(rig.service_calls(), []);
    assert_eq!(rig.polkit_asked(), Vec::<String>::new());
    assert_eq!(rig.keys()?, ["k"]);
    Ok(done)
}

const DECLINE: &str = "custodio: not confirmed; nothing was deleted\n";

#[test]
fn answering_no_deletes_nothing_and_calls_nothing() -> TestResult {
    let done = declined(Some(b"n\n"))?;
    assert_eq!(done.status.code(), Some(1));
    assert_eq!(done.stderr, DECLINE);
    Ok(())
}

#[test]
fn end_of_input_declines() -> TestResult {
    let done = declined(Some(b"\x04"))?;
    assert_eq!(done.status.code(), Some(1));
    assert_eq!(done.stderr, DECLINE);
    Ok(())
}

#[test]
fn a_hangup_of_the_terminal_deletes_nothing() -> TestResult {
    // The session leader gets SIGHUP, or reads the end of input: either way, non-zero.
    declined(None)?;
    Ok(())
}

#[test]
fn a_denied_polkit_deletes_nothing() -> TestResult {
    let rig = Rig::start(true)?;
    rig.import("k")?;
    rig.polkit(Polkit::Deny);
    rig.forget();
    let mut run = Run::start(&rig, &delete_args("k"), &[], true, b"")?;
    run.wait_for(&question("k"))?;
    run.send(b"yes\n")?;
    let done = run.finish()?;
    assert_eq!(done.status.code(), Some(1));
    assert_eq!(done.stdout, "");
    assert_eq!(done.stderr, message(&ServiceFailure::PolkitDenied));
    assert_eq!(rig.polkit_asked(), [DELETE_ACTION_ID.to_owned()]);
    assert_eq!(rig.keys()?, ["k"]);
    Ok(())
}

#[test]
fn a_missing_id_is_no_such_key_without_asking_polkit() -> TestResult {
    let rig = Rig::start(true)?;
    rig.import("other")?;
    rig.forget();
    let mut run = Run::start(&rig, &delete_args("missing"), &[], true, b"")?;
    run.wait_for(&question("missing"))?;
    run.send(b"y\n")?;
    let done = run.finish()?;
    assert_eq!(done.status.code(), Some(1));
    assert_eq!(done.stdout, "");
    assert_eq!(done.stderr, message(&ServiceFailure::NoSuchKey));
    assert_eq!(rig.polkit_asked(), Vec::<String>::new());
    assert_eq!(rig.service_calls().len(), 1);
    assert_eq!(rig.keys()?, ["other"]);
    Ok(())
}

#[test]
fn without_a_terminal_it_refuses_and_reads_no_answer_from_stdin() -> TestResult {
    let rig = Rig::start(true)?;
    rig.import("k")?;
    rig.forget();
    let run = Run::start(&rig, &delete_args("k"), &[], false, b"yes\ny\nyes\n")?;
    let done = run.finish()?;
    assert_eq!(done.status.code(), Some(1));
    assert_eq!(done.stdout, "");
    assert_eq!(
        done.stderr,
        "custodio: deleting a key must be confirmed on a terminal and there is none; nothing was deleted\n"
    );
    assert_eq!(rig.service_calls(), []);
    assert_eq!(rig.polkit_asked(), Vec::<String>::new());
    assert_eq!(rig.keys()?, ["k"]);
    Ok(())
}

#[test]
fn no_environment_variable_removes_the_question() -> TestResult {
    let rig = Rig::start(true)?;
    rig.import("k")?;
    rig.forget();
    let env = [
        ("CUSTODIO_YES", "1"),
        ("YES", "1"),
        ("FORCE", "1"),
        ("CUSTODIO_FORCE", "yes"),
    ];
    let mut run = Run::start(&rig, &delete_args("k"), &env, true, b"yes\n")?;
    run.wait_for(&question("k"))?;
    assert_eq!(rig.service_calls(), []);
    assert_eq!(rig.polkit_asked(), Vec::<String>::new());
    run.send(b"no\n")?;
    let done = run.finish()?;
    assert_eq!(done.status.code(), Some(1));
    assert_eq!(done.stderr, DECLINE);
    assert_eq!(rig.keys()?, ["k"]);
    Ok(())
}

#[test]
fn options_are_usage_errors_before_any_question() -> TestResult {
    let rig = Rig::start(true)?;
    rig.import("k")?;
    rig.forget();
    for args in [
        &["delete", "--yes", "k"][..],
        &["delete", "-y", "k"],
        &["delete"],
    ] {
        let run = Run::start(&rig, args, &[], true, b"")?;
        let screen = run.screen.clone();
        let done = run.finish()?;
        let shown = screen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        assert_eq!(done.status.code(), Some(2), "{args:?}");
        assert_eq!(done.stdout, "");
        assert_eq!(done.stderr.trim_end(), USAGE);
        assert!(shown.is_empty(), "{shown:?}");
    }
    assert_eq!(rig.service_calls(), []);
    assert_eq!(rig.keys()?, ["k"]);
    Ok(())
}

#[test]
fn an_unidentifiable_caller_shows_authorization_unavailable_without_service_text() -> TestResult {
    let rig = Rig::start(true)?;
    rig.import("k")?;
    rig.broken.store(true, Ordering::SeqCst);
    rig.forget();
    let mut run = Run::start(&rig, &delete_args("k"), &[], true, b"")?;
    run.wait_for(&question("k"))?;
    run.send(b"yes\n")?;
    let done = run.finish()?;
    assert_eq!(done.status.code(), Some(1));
    assert_eq!(
        done.stderr,
        message(&ServiceFailure::AuthorizationUnavailable)
    );
    assert!(!done.stderr.contains(FREE_TEXT));
    rig.broken.store(false, Ordering::SeqCst);
    assert_eq!(rig.keys()?, ["k"]);
    Ok(())
}

#[test]
fn an_absent_service_is_status_1_with_the_cannot_talk_message() -> TestResult {
    let rig = Rig::start(false)?;
    let mut run = Run::start(&rig, &delete_args("k"), &[], true, b"")?;
    run.wait_for(&question("k"))?;
    run.send(b"yes\n")?;
    let done = run.finish()?;
    assert_eq!(done.status.code(), Some(1));
    assert_eq!(done.stdout, "");
    assert_eq!(done.stderr, message(&ServiceFailure::ServiceAbsent));
    assert!(done.status.signal().is_none());
    Ok(())
}
