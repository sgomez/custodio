//! `custodio import` and `custodio delete` against the real service on a private `dbus-daemon` (the rig of
//! `list.rs`), with the `.p12` fixtures of F195: each failure about the file is its own two-line message with its own
//! next step, and a successful import or delete says that running programs see the change only after a restart.

use std::io;

use custodio_cli::delete::RESTART_NOTE;
use custodio_cli::{
    CliError, Confirmation, ImportArgs, PasswordPrompt, exit_status, finish, next_steps,
    run_delete, run_import,
};
use secrecy::SecretString;

#[path = "../../custodio-cli/tests/import_view/mod.rs"]
mod import_view;
mod list_rig;
use list_rig::{Rig, TestResult};

const RIGHT: &str = "test-password";
const WRONG: &str = "wrong";

struct Typed(&'static str);

impl PasswordPrompt for Typed {
    fn password(&mut self, _prompt: &str) -> io::Result<SecretString> {
        Ok(SecretString::from(self.0))
    }
}

struct Says(Option<&'static str>);

impl Confirmation for Says {
    fn answer(&mut self, _question: &str) -> io::Result<String> {
        self.0
            .map(str::to_owned)
            .ok_or_else(|| io::Error::other("no terminal"))
    }
}

struct Seen {
    stdout: String,
    stderr: String,
    status: u8,
}

fn seen(result: &Result<(), CliError>, stdout: &[u8]) -> Seen {
    let mut stderr = Vec::new();
    let status = finish(result, &mut stderr, false);
    assert_eq!(status, exit_status(result));
    Seen {
        stdout: String::from_utf8_lossy(stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
        status,
    }
}

fn import(
    rig: &Rig,
    name: &str,
    password: &'static str,
) -> Result<Seen, Box<dyn std::error::Error>> {
    let file = rig.dir.path().join(name);
    std::fs::copy(
        format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR")),
        &file,
    )?;
    let args = ImportArgs {
        file,
        id: "k".to_owned(),
    };
    let mut out = Vec::new();
    let result =
        run_import(&args, &mut Typed(password), &rig.client, &mut out).map_err(CliError::Import);
    Ok(seen(&result, &out))
}

fn delete(rig: &Rig, id: &str, answer: Option<&'static str>) -> Seen {
    let mut out = Vec::new();
    let result = run_delete(id, &mut Says(answer), &rig.client, &mut out).map_err(CliError::Delete);
    seen(&result, &out)
}

/// Checks a failed import: standard output empty, exactly two lines on standard error, the next step in the second.
fn failed(got: &Seen, first: &str, next: &[&str], not_next: &[&str]) {
    assert_eq!(got.status, 1, "{}", got.stderr);
    assert_eq!(got.stdout, "");
    let lines: Vec<&str> = got.stderr.lines().collect();
    assert_eq!(lines.len(), 2, "{}", got.stderr);
    assert!(lines[0].contains(first), "{}", got.stderr);
    for want in next {
        assert!(lines[1].contains(want), "{}", got.stderr);
    }
    for not in not_next {
        assert!(!lines[1].contains(not), "{}", got.stderr);
    }
    assert!(!got.stdout.contains("restart"));
}

#[test]
fn a_wrong_password_of_a_file_with_a_mac_says_to_retype_it() -> TestResult {
    let rig = Rig::start(true)?;
    let got = import(&rig, "p256.p12", WRONG)?;
    failed(
        &got,
        "wrong password for the .p12 file",
        &["retype the password"],
        &["xport"],
    );
    Ok(())
}

#[test]
fn a_file_that_cannot_be_used_says_to_export_it_again() -> TestResult {
    let rig = Rig::start(true)?;
    for (name, password) in [
        ("notp12.bin", RIGHT),
        ("nokey.p12", RIGHT),
        ("twokeys.p12", RIGHT),
    ] {
        let got = import(&rig, name, password)?;
        failed(
            &got,
            "the .p12 file cannot be used",
            &["Export the file again", "Your Certificates, Backup"],
            &["password"],
        );
    }
    Ok(())
}

#[test]
fn a_file_without_a_mac_that_does_not_decrypt_says_both() -> TestResult {
    let rig = Rig::start(true)?;
    let got = import(&rig, "good-nomac.p12", WRONG)?;
    failed(
        &got,
        "wrong password, or the .p12 file is damaged",
        &["Retype the password", "export the file again"],
        &[],
    );
    Ok(())
}

#[test]
fn a_successful_import_and_delete_say_that_programs_must_restart() -> TestResult {
    let rig = Rig::start(true)?;
    let imported = import(&rig, "p256.p12", RIGHT)?;
    assert_eq!(imported.status, 0, "{}", imported.stderr);
    let view = import_view::parse(&imported.stdout);
    assert_eq!(view.cells[0], "k", "{}", imported.stdout);
    let restart = &next_steps(std::path::Path::new(""), None)[1];
    assert_eq!(view.under.last(), Some(restart), "{}", imported.stdout);
    let deleted = delete(&rig, "k", Some("yes\n"));
    assert_eq!(deleted.status, 0, "{}", deleted.stderr);
    assert_eq!(
        deleted.stdout,
        custodio_cli::report::render(&[custodio_cli::delete::deleted_line("k")], false)
    );
    Ok(())
}

#[test]
fn a_refused_or_failed_delete_does_not_say_it() -> TestResult {
    let rig = Rig::start(true)?;
    import(&rig, "p256.p12", RIGHT)?;
    for answer in [Some("n\n"), None] {
        let got = delete(&rig, "k", answer);
        assert_eq!(got.status, 1);
        assert_eq!(got.stdout, "");
    }
    // A key that is not there: the service refuses.
    let got = delete(&rig, "absent", Some("yes\n"));
    assert_eq!(got.status, 1);
    assert_eq!(got.stdout, "");
    assert!(!got.stderr.contains(RESTART_NOTE));
    Ok(())
}
