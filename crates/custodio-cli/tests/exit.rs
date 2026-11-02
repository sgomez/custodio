//! Exit status: 0 on success, 1 on every failure, 2 on a usage error. The function is the one
//! `main` calls (`finish`), and the binary is run for what needs no terminal.

use std::io;
use std::process::{Command, Output};

use custodio_cli::{
    ArgError, CliError, DeleteFailure, ImportFailure, ListFailure, ServiceFailure, exit_status,
    finish,
};

fn every_failure() -> Vec<CliError> {
    let mut all = vec![
        CliError::SystemBus("no socket".into()),
        CliError::Import(ImportFailure::Read(io::Error::other("x"))),
        CliError::Import(ImportFailure::TooLarge),
        CliError::Import(ImportFailure::Password(io::Error::other("no terminal"))),
        CliError::List(ListFailure::Unreadable(2)),
        CliError::List(ListFailure::Output(io::Error::other("closed"))),
        CliError::Delete(DeleteFailure::Declined),
        CliError::Delete(DeleteFailure::NoTerminal),
        CliError::Delete(DeleteFailure::Output(io::Error::other("closed"))),
    ];
    for name in [
        "com.rfirma.Custodio1.Error.InvalidArgs",
        "com.rfirma.Custodio1.Error.NoSuchKey",
        "com.rfirma.Custodio1.Error.KeyIdTaken",
        "com.rfirma.Custodio1.Error.PolkitDenied",
        "com.rfirma.Custodio1.Error.AuthorizationUnavailable",
        "com.rfirma.Custodio1.Error.WrongPasswordOrBadP12",
        "com.rfirma.Custodio1.Error.UnsupportedKeyType",
        "com.rfirma.Custodio1.Error.CertificateMismatch",
        "com.rfirma.Custodio1.Error.AuditUnavailable",
        "com.rfirma.Custodio1.Error.Internal",
        "com.rfirma.Custodio1.Error.Other",
        "org.freedesktop.DBus.Error.ServiceUnknown",
        "org.freedesktop.DBus.Error.AccessDenied",
    ] {
        all.push(CliError::Import(ImportFailure::Service(
            ServiceFailure::from_name(name),
        )));
        all.push(CliError::List(ListFailure::Service(
            ServiceFailure::from_name(name),
        )));
        all.push(CliError::Delete(DeleteFailure::Service(
            ServiceFailure::from_name(name),
        )));
    }
    all
}

#[test]
fn success_is_0_every_failure_is_1_usage_is_2() {
    assert_eq!(exit_status(&Ok(())), 0);
    for e in every_failure() {
        assert_eq!(exit_status(&Err(e)), 1);
    }
    assert_eq!(exit_status(&Err(CliError::Args(ArgError::Usage))), 2);
    assert_eq!(exit_status(&Err(CliError::Args(ArgError::BadId))), 2);
}

#[test]
fn finish_writes_the_diagnostic_of_a_failure_only() {
    let mut err = Vec::new();
    assert_eq!(finish(&Ok(()), &mut err), 0);
    assert_eq!(err, b"" as &[u8]);
    for e in every_failure() {
        let mut err = Vec::new();
        assert_eq!(finish(&Err(e), &mut err), 1);
        assert_ne!(err, b"" as &[u8]);
    }
    let mut err = Vec::new();
    assert_eq!(finish(&Err(CliError::Args(ArgError::Usage)), &mut err), 2);
    assert_eq!(
        String::from_utf8_lossy(&err).trim_end(),
        custodio_cli::USAGE
    );
}

fn run(args: &[&str]) -> io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_custodio-cli"))
        .args(args)
        .env(
            "DBUS_SYSTEM_BUS_ADDRESS",
            "unix:path=/nonexistent/custodio-test-bus",
        )
        .env_remove("DBUS_SESSION_BUS_ADDRESS")
        .stdin(std::process::Stdio::null())
        .output()
}

#[test]
fn the_binary_exits_2_on_usage_errors_with_nothing_on_stdout() -> Result<(), io::Error> {
    for args in [
        &[][..],
        &["import"],
        &["import", "--password", "x", "a.p12"],
        &["import", "--id", "a", "--id", "b", "a.p12"],
        &["import", "my cert.p12"],
        &["list", "extra"],
        &["list", "--id", "x"],
        &["delete"],
        &["delete", "a", "b"],
        &["delete", "--yes", "a"],
        &["delete", "-y", "a"],
        &["delete", "--force", "a"],
    ] {
        let out = run(args)?;
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert_eq!(out.stdout, b"" as &[u8], "{args:?}");
        assert_ne!(out.stderr, b"" as &[u8], "{args:?}");
    }
    Ok(())
}

#[test]
fn the_binary_exits_1_when_the_bus_is_unreachable() -> Result<(), io::Error> {
    // A valid command line; it fails in `DbusImporter::system`, before `run_import`.
    let out = run(&["import", "--id", "k", "a.p12"])?;
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(out.stdout, b"" as &[u8]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("cannot reach the system bus"), "{err}");
    Ok(())
}

#[test]
fn the_binary_exits_1_not_2_for_list_when_the_bus_is_unreachable() -> Result<(), io::Error> {
    let out = run(&["list"])?;
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(out.stdout, b"" as &[u8]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("cannot reach the system bus"), "{err}");
    Ok(())
}
