use std::ffi::OsString;
use std::io;
use std::path::PathBuf;

use custodio_client::ERROR_NAMES;

use super::*;
use crate::browser_files::FileError;

const ESC: &str = "\u{1b}[31m\nSENTINEL-LINE";
const PASSWORD: &str = "hunter2-sentinel";

fn io_err() -> io::Error {
    io::Error::other(ESC)
}

/// One sample of every variant. Each `match` has no wildcard, so a variant added to an enum fails
/// to compile here until it is listed.
fn samples() -> Vec<CliError> {
    let mut all = Vec::new();
    for a in [
        ArgError::Usage,
        ArgError::CommandUsage("list"),
        ArgError::BadId,
    ] {
        match &a {
            ArgError::Usage | ArgError::CommandUsage(_) | ArgError::BadId => {}
        }
        all.push(CliError::Args(a));
    }
    all.push(CliError::SystemBus(ESC.into()));
    for f in [
        ImportFailure::Read(io_err()),
        ImportFailure::TooLarge,
        ImportFailure::Password(io_err()),
    ] {
        match &f {
            ImportFailure::Read(_)
            | ImportFailure::TooLarge
            | ImportFailure::Password(_)
            | ImportFailure::Service(_) => {}
        }
        all.push(CliError::Import(f));
    }
    for f in services() {
        all.push(CliError::Import(ImportFailure::Service(f.clone())));
        all.push(CliError::List(ListFailure::Service(f.clone())));
        all.push(CliError::Delete(DeleteFailure::Service(f)));
    }
    for f in [
        ListFailure::Unreadable(3),
        ListFailure::Output(io_err()),
        ListFailure::UnknownId("a\nSENTINEL-LINE b\u{1b}[31m".into()),
    ] {
        match &f {
            ListFailure::Service(_)
            | ListFailure::Unreadable(_)
            | ListFailure::Output(_)
            | ListFailure::UnknownId(_) => {}
        }
        all.push(CliError::List(f));
    }
    for f in [
        DeleteFailure::Declined,
        DeleteFailure::NoTerminal,
        DeleteFailure::Output(io_err()),
    ] {
        match &f {
            DeleteFailure::Declined
            | DeleteFailure::NoTerminal
            | DeleteFailure::Service(_)
            | DeleteFailure::Output(_) => {}
        }
        all.push(CliError::Delete(f));
    }
    let bad_path = PathBuf::from(format!("/tmp/{ESC}"));
    for e in [
        RegisterError::Refused(Refusal::Root),
        RegisterError::Refused(Refusal::Sudo),
        RegisterError::Run(RunError::Discover(FileError::new(ESC, ESC))),
        RegisterError::Run(RunError::MissingModule(bad_path)),
        RegisterError::Run(RunError::NoModutil(OsString::from(ESC))),
        RegisterError::Run(RunError::NoHome),
        RegisterError::Skipped(2),
        RegisterError::Refresh(ESC.into()),
    ] {
        match &e {
            RegisterError::Refused(r) => match r {
                Refusal::Root | Refusal::Sudo => {}
            },
            RegisterError::Run(r) => match r {
                RunError::Discover(_)
                | RunError::MissingModule(_)
                | RunError::NoModutil(_)
                | RunError::NoHome => {}
            },
            RegisterError::Skipped(_) | RegisterError::Refresh(_) => {}
        }
        all.push(CliError::Register(e));
    }
    match all.first() {
        Some(
            CliError::Args(_)
            | CliError::SystemBus(_)
            | CliError::Import(_)
            | CliError::List(_)
            | CliError::Delete(_)
            | CliError::Register(_),
        )
        | None => {}
    }
    all
}

fn services() -> Vec<ServiceFailure> {
    let mut all: Vec<_> = ERROR_NAMES
        .iter()
        .map(|n| ServiceFailure::from_name(n))
        .collect();
    for name in [
        "org.freedesktop.DBus.Error.ServiceUnknown",
        "org.freedesktop.DBus.Error.NameHasNoOwner",
        "org.freedesktop.DBus.Error.AccessDenied",
        "com.rfirma.Custodio1.Error.From\u{1b}[31mTheFuture\nx",
        "",
    ] {
        all.push(ServiceFailure::from_name(name));
    }
    match all.first() {
        Some(
            ServiceFailure::InvalidArgs
            | ServiceFailure::NoSuchKey
            | ServiceFailure::KeyIdTaken
            | ServiceFailure::PolkitDenied
            | ServiceFailure::AuthorizationUnavailable
            | ServiceFailure::WrongPasswordOrBadP12
            | ServiceFailure::UnsupportedKeyType
            | ServiceFailure::CertificateMismatch
            | ServiceFailure::AuditUnavailable
            | ServiceFailure::Internal
            | ServiceFailure::TpmFailed
            | ServiceFailure::CredentialsUnavailable
            | ServiceFailure::KeyLost
            | ServiceFailure::TemporarilyUnavailable
            | ServiceFailure::ServiceAbsent
            | ServiceFailure::Transport
            | ServiceFailure::Unknown(_),
        )
        | None => {}
    }
    all
}

/// The rules every message obeys.
fn check(text: &str) {
    let lines: Vec<&str> = text.lines().collect();
    assert!(lines.len() >= 2, "one line only: {text:?}");
    assert!(!lines[1].trim().is_empty(), "empty next step: {text:?}");
    assert_ne!(lines[0], lines[1], "{text:?}");
    assert!(
        !text.chars().any(|c| c.is_control() && c != '\n'),
        "control character: {text:?}"
    );
    assert!(
        !text.lines().any(|l| l.starts_with("SENTINEL-LINE")),
        "{text:?}"
    );
    assert!(!text.contains(PASSWORD), "{text:?}");
    assert!(!text.ends_with('\n'), "{text:?}");
}

#[test]
fn every_error_is_two_lines_with_a_next_step_and_no_raw_untrusted_text() {
    for e in samples() {
        check(&render(&e));
    }
}

#[test]
fn untrusted_text_is_escaped_not_dropped() {
    let text = render(&CliError::SystemBus("a\u{1b}b".into()));
    assert!(text.contains("a\\x1bb"), "{text}");
    let unknown = render(&CliError::List(ListFailure::Service(
        ServiceFailure::from_name("x.y\u{1b}z"),
    )));
    assert!(unknown.contains("x.y\\x1bz"), "{unknown}");
}

#[test]
fn polkit_denial_and_absent_service_keep_the_strings_scripts_read() {
    let denied = render(&CliError::Delete(DeleteFailure::Service(
        ServiceFailure::PolkitDenied,
    )));
    assert!(denied.contains("not authorized"), "{denied}");
    let absent = render(&CliError::List(ListFailure::Service(
        ServiceFailure::ServiceAbsent,
    )));
    assert!(absent.contains("cannot talk to the service"), "{absent}");
    let root = render(&CliError::Register(RegisterError::Refused(Refusal::Root)));
    assert!(root.contains("refused to run as root"), "{root}");
}

const API: &str = include_str!("../../../../docs/api.md");

/// The error names under "Errors" in `api` that `ServiceFailure` does not map.
fn unmapped(api: &str) -> Vec<String> {
    let section = api.split("\n## Errors").nth(1).unwrap_or("");
    let section = section.split("\n## ").next().unwrap_or("");
    section
        .lines()
        .filter_map(|l| l.strip_prefix("- error `"))
        .filter_map(|l| l.split('`').next())
        .filter(|name| {
            !ERROR_NAMES.contains(name)
                || matches!(
                    ServiceFailure::from_name(name),
                    ServiceFailure::Unknown(_) | ServiceFailure::Transport
                )
        })
        .map(str::to_owned)
        .collect()
}

#[test]
fn every_error_name_of_the_api_document_is_mapped_and_rendered() {
    assert!(unmapped(API).is_empty(), "{:?}", unmapped(API));
    let named = API
        .matches("\n- error `com.rfirma.Custodio1.Error.")
        .count();
    assert_eq!(named, ERROR_NAMES.len());
    for name in ERROR_NAMES {
        let f = ServiceFailure::from_name(name);
        check(&render(&CliError::Import(ImportFailure::Service(f))));
    }
}

#[test]
fn a_name_the_cli_does_not_map_fails_the_checker() {
    let fixture = "\n## Errors\n\n- error `com.rfirma.Custodio1.Error.Brand`: new.\n- error `com.rfirma.Custodio1.Error.KeyLost`: x.\n\n## Next\n";
    assert_eq!(unmapped(fixture), ["com.rfirma.Custodio1.Error.Brand"]);
}

#[test]
fn the_service_absent_and_bus_errors_pass_the_checks() {
    for name in [
        "org.freedesktop.DBus.Error.ServiceUnknown",
        "org.freedesktop.DBus.Error.NameHasNoOwner",
        "org.freedesktop.DBus.Error.NoReply",
    ] {
        check(&render(&CliError::List(ListFailure::Service(
            ServiceFailure::from_name(name),
        ))));
    }
}

#[test]
fn import_errors_say_what_failed_and_what_to_do() {
    let read = render(&CliError::Import(ImportFailure::Read(io::Error::other(
        "boom",
    ))));
    assert!(
        read.starts_with("custodio: cannot read the file: boom\n"),
        "{read}"
    );
    assert!(read.contains("Check the path"), "{read}");
    let big = render(&CliError::Import(ImportFailure::TooLarge));
    assert!(
        big.starts_with("custodio: the file is larger than "),
        "{big}"
    );
    let pw = render(&CliError::Import(ImportFailure::Password(
        io::Error::other("no tty"),
    )));
    assert!(
        pw.starts_with("custodio: cannot read the password: no tty\n"),
        "{pw}"
    );
    assert!(pw.contains("from a terminal"), "{pw}");
}

#[test]
fn an_unknown_key_id_is_two_lines_naming_list_with_the_id_escaped() {
    let text = render(&CliError::List(ListFailure::UnknownId(
        "a\nb\u{1b}[31m".into(),
    )));
    assert_eq!(
        text,
        "custodio: you have no key with the id 'a\\x0ab\\x1b[31m'\nRun 'custodio list' to see the ids of your keys."
    );
}
