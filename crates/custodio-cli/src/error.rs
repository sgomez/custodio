//! The one place that turns an error into text for standard error.
//!
//! Every message is at least two lines: what went wrong, then the next step (a command, a
//! documented section, or "report a bug" with where). Text that does not come from this crate
//! (a key id, a path, a file name, the service's unknown error name, an I/O error) has its control
//! characters escaped, so it cannot move the cursor or start a line of its own. A password and key
//! bytes are never in an error value, so they cannot reach a message.

use crate::cert_text::escape;
use crate::delete::DeleteFailure;
use crate::list::ListFailure;
use crate::register_cli::{Refusal, RegisterError};
use crate::register_native::RunError;
use crate::{ArgError, CliError, ImportFailure, ServiceFailure};

const REPORT: &str = "report a bug (see README.md)";

/// What went wrong and the next step, as one text of at least two lines, without a final newline.
#[must_use]
pub fn render(error: &CliError) -> String {
    if let CliError::Args(a) = error {
        return args(a);
    }
    let (what, next) = lines(error);
    format!("{}\n{}", escape(&what), escape(&next))
}

fn args(error: &ArgError) -> String {
    match error {
        ArgError::Usage => format!(
            "custodio: unknown command or wrong arguments\n{}",
            crate::usage()
        ),
        ArgError::CommandUsage(name) => {
            format!("custodio: wrong arguments for '{name}'\n{error}")
        }
        ArgError::BadId => format!(
            "custodio: {error}\nRun 'custodio import --id <key id> <file.p12>', or 'custodio import --help' for help."
        ),
    }
}

fn service(failure: &ServiceFailure) -> (String, String) {
    (
        format!("custodio: {}", failure.message()),
        failure.next_step().to_owned(),
    )
}

fn lines(error: &CliError) -> (String, String) {
    match error {
        CliError::Args(_) => unreachable!("handled by render"),
        CliError::SystemBus(why) => (
            format!("custodio: cannot reach the system bus: {why}"),
            "Check that the system bus runs (systemctl status dbus) and that DBUS_SYSTEM_BUS_ADDRESS is unset or right.".to_owned(),
        ),
        CliError::Import(e) => import(e),
        CliError::List(e) => list(e),
        CliError::Delete(e) => delete(e),
        CliError::Register(e) => register(e),
        CliError::Fingerprint(e) => fingerprint(e),
        CliError::Doctor(e) => doctor(e),
    }
}

fn import(error: &ImportFailure) -> (String, String) {
    match error {
        ImportFailure::Read(e) => (
            format!("custodio: cannot read the file: {e}"),
            "Check the path and that you may read the file, then run the command again.".to_owned(),
        ),
        ImportFailure::TooLarge => (
            format!(
                "custodio: the file is larger than {} bytes",
                custodio_client::MAX_P12_LEN
            ),
            "A .p12 file with one key and its certificate is far smaller: check that this is the right file.".to_owned(),
        ),
        ImportFailure::Password(e) => (
            format!("custodio: cannot read the password: {e}"),
            "Run the command from a terminal: the password is asked there, never read from arguments or the environment.".to_owned(),
        ),
        ImportFailure::Service(f) => service(f),
    }
}

fn list(error: &ListFailure) -> (String, String) {
    match error {
        ListFailure::Service(f) => service(f),
        ListFailure::Unreadable(n) => (
            format!("custodio: {n} certificate(s) could not be read"),
            format!(
                "The keys are intact: run 'custodio list' again, and if it persists, {REPORT}."
            ),
        ),
        ListFailure::UnknownId(id) => (
            format!("custodio: you have no key with the id '{id}'"),
            "Run 'custodio list' to see the ids of your keys.".to_owned(),
        ),
        ListFailure::Output(e) => (
            format!("custodio: cannot write the list: {e}"),
            "Check that the output is open and has room, then run 'custodio list' again."
                .to_owned(),
        ),
    }
}

fn delete(error: &DeleteFailure) -> (String, String) {
    match error {
        DeleteFailure::Declined => (
            "custodio: not confirmed; nothing was deleted".to_owned(),
            "Run 'custodio delete <key id>' again and type yes to delete the key.".to_owned(),
        ),
        DeleteFailure::NoTerminal => (
            "custodio: deleting a key must be confirmed on a terminal and there is none; nothing was deleted".to_owned(),
            "Run 'custodio delete <key id>' from a terminal.".to_owned(),
        ),
        DeleteFailure::Service(f) => service(f),
        DeleteFailure::Output(e) => (
            format!("custodio: the key was deleted but the output failed: {e}"),
            "Nothing more to do: run 'custodio list' to see the keys that are left.".to_owned(),
        ),
    }
}

fn doctor(error: &crate::doctor_cmd::Failure) -> (String, String) {
    use crate::doctor_cmd::Failure;
    match error {
        Failure::Root => (
            "custodio doctor: refused to run as root".to_owned(),
            "Run it as the person who will use the finger: the answers are about that person."
                .to_owned(),
        ),
        Failure::Unsatisfied(names) => (
            format!("custodio doctor: did not pass: {}", names.join(", ")),
            "Do what their fix lines say, then run 'custodio doctor' again.".to_owned(),
        ),
        Failure::BrokenInclude => (
            "custodio doctor: a polkit include is broken (the first line of the report)".to_owned(),
            "Do what its fix says, then run 'custodio doctor' again.".to_owned(),
        ),
    }
}

fn fingerprint(error: &crate::fingerprint_cmd::Failure) -> (String, String) {
    use crate::fingerprint_cmd::Failure;
    match error {
        Failure::Refused(r) => {
            let (what, next) = r.lines();
            (what.to_owned(), next.to_owned())
        }
        Failure::Io { what, error } => (
            format!("custodio fingerprint: {what}: {error}"),
            "Check with ls -l /etc/pam.d/polkit-1 whether the file is there, fix /etc/pam.d (free space, read-only mount, SELinux) and run the command again.".to_owned(),
        ),
    }
}

fn register(error: &RegisterError) -> (String, String) {
    match error {
        RegisterError::Refused(Refusal::Root) => (
            "custodio register: refused to run as root".to_owned(),
            "Run it as the user whose browsers should see Custodio.".to_owned(),
        ),
        RegisterError::Refused(Refusal::Sudo) => (
            "custodio register: refused to run under sudo (SUDO_USER or SUDO_UID is set)"
                .to_owned(),
            "Run it as the user whose browsers should see Custodio.".to_owned(),
        ),
        RegisterError::Run(e) => run(e),
        RegisterError::Skipped { count, remove } => (
            format!(
                "custodio: {} skipped",
                crate::register_cli::profiles(*count)
            ),
            format!(
                "Fix what is named above and run 'custodio register{}' again.",
                if *remove { " --remove" } else { "" }
            ),
        ),
        RegisterError::Refresh(why) => (
            format!("custodio: {why}"),
            format!("Run 'custodio register --refresh-only' again, and if it persists, {REPORT}."),
        ),
    }
}

fn run(error: &RunError) -> (String, String) {
    match error {
        RunError::Discover(e) => (
            format!("custodio: {e}"),
            "Fix or remove that file, then run 'custodio register' again.".to_owned(),
        ),
        RunError::MissingModule(p) => (
            format!(
                "custodio: the module {} does not exist; nothing was registered",
                p.display()
            ),
            "Install the custodio package, or name an existing library with --module <path>."
                .to_owned(),
        ),
        RunError::NoModutil(p) => (
            format!("custodio: {} was not found", p.to_string_lossy()),
            "Install NSS's tools (libnss3-tools or nss-tools) and run 'custodio register' again."
                .to_owned(),
        ),
        RunError::NoHome => (
            "custodio: HOME is not set; cannot find the browser profiles".to_owned(),
            "Set HOME to your home directory and run 'custodio register' again.".to_owned(),
        ),
    }
}

#[cfg(test)]
mod tests;
