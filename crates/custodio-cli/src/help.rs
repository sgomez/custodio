//! The commands of the tool and their help. One table feeds the parser, the help text and the
//! tests (the man page parity among them), so a command added to it is in all of them.
//!
//! Nothing here prints: the functions return text, and `main` writes it.

use std::fmt::Write as _;

/// One option of a command.
#[derive(Debug)]
pub struct OptionSpec {
    /// The long form, for example `--id`.
    pub flag: &'static str,
    /// The short form, for example `-v`, if there is one.
    pub short: Option<&'static str>,
    /// The name of its value, if it takes one.
    pub value: Option<&'static str>,
    pub text: &'static str,
}

/// One command of the tool.
#[derive(Debug)]
pub struct CommandSpec {
    pub name: &'static str,
    /// One line, for the list of commands.
    pub summary: &'static str,
    /// The arguments as written in the usage line, after the command and its options.
    pub usage: &'static str,
    /// What the command does.
    pub description: &'static str,
    /// Each argument and what it is.
    pub args: &'static [(&'static str, &'static str)],
    pub options: &'static [OptionSpec],
    /// A command line that the parser accepts.
    pub example: &'static str,
}

/// Every command, in the order of the help.
pub const COMMANDS: &[CommandSpec] = &[
    CommandSpec {
        name: "import",
        summary: "store the key of a PKCS#12 file in the service",
        usage: "[--id <key id>] <file.p12>",
        description: "Reads the file, asks for its password on the terminal and sends both to the service.\n\
The password is never taken from arguments or the environment. Then a polkit dialog asks for your login password \
(or a finger, after 'custodio fingerprint enable').\n\
Only RSA 2048 and ECDSA P-256 keys are accepted. If the file cannot be used the error says whether to retype the password or to export the file again. \
After a successful import it says that Firefox and any other running program that loaded the module see the key only after they restart.",
        args: &[(
            "<file.p12>",
            "the PKCS#12 file with one private key and its certificate",
        )],
        options: &[OptionSpec {
            flag: "--id",
            short: None,
            value: Some("<key id>"),
            text: "name the stored key: 1 to 64 letters, digits, _ or - (default: the file name without its extension)",
        }],
        example: "custodio import --id work work.p12",
    },
    CommandSpec {
        name: "list",
        summary: "show your keys, or one key in full",
        usage: "[-v] [[--] <key id>]",
        description: "Shows one row for each of your keys, in order of key id: key id, key type, storage kind, subject and the day \
its certificate expires, marked expired, or expires soon within 30 days. The subject is the common name of the certificate, or the \
whole subject if it has none. On a terminal a header row comes first. A note at the foot explains the kinds encrypted-tpm and \
encrypted-host, which are weaker than tpm.\n\
With a key id, or with -v for every key, it shows each key in full: the whole subject and issuer, the serial number, the start \
and end of validity and the SHA-256 fingerprint. Write -- before a key id that starts with a dash. Text from a certificate is \
shown with its control characters escaped (\\x1b). It asks for no authorization.",
        args: &[("<key id>", "show this key in full, not as a row")],
        options: &[OptionSpec {
            flag: "--verbose",
            short: Some("-v"),
            value: None,
            text: "show every key in full",
        }],
        example: "custodio list work",
    },
    CommandSpec {
        name: "delete",
        summary: "delete one of your keys",
        usage: "[--] <key id>",
        description: "Asks on the terminal to confirm, then a polkit dialog asks for your login password (or a finger), then it deletes \
the key and its certificate. It cannot be recovered.\n\
Write -- before a key id that starts with a dash. \
After a successful delete it says that Firefox and any other running program that loaded the module see the change only after they restart.",
        args: &[("<key id>", "the key to delete")],
        options: &[],
        example: "custodio delete work",
    },
    CommandSpec {
        name: "register",
        summary: "make the module visible to the native browsers",
        usage: "",
        description: "Adds the module to the profiles of Firefox, Thunderbird and the browsers like them, for the user who runs it.\n\
Run it once after installing, and again after creating a browser profile; restart the browser afterwards.\n\
It refuses to run as root, needs no authorization and does not use the service.",
        args: &[],
        options: &[
            OptionSpec {
                flag: "--module",
                short: None,
                value: Some("<path>"),
                text: "register this library instead of the installed one",
            },
            OptionSpec {
                flag: "--remove",
                short: None,
                value: None,
                text: "remove the entries of every Custodio module file",
            },
            OptionSpec {
                flag: "--refresh-only",
                short: None,
                value: None,
                text: "only update the copy of the module that the Firefox snap loads, if it differs",
            },
        ],
        example: "custodio register --module /usr/lib/custodio/libcustodio_pkcs11.so",
    },
    CommandSpec {
        name: "fingerprint",
        summary: "let a finger answer polkit dialogs (enable) or stop that (disable)",
        usage: "enable | disable",
        description: "enable writes /etc/pam.d/polkit-1 so that every polkit dialog, Custodio's among them, first accepts a finger \
and falls back to the password after a wrong finger or 10 s without a touch. sudo and the login are unchanged.\n\
It refuses, and changes nothing, when it is not run as root, when that file is not Custodio's, when pam_fprintd.so or fprintd is not installed \
(it names the packages), or when fingerprint is already on for the whole system. With no reader it writes the file and warns. \
Running it twice changes nothing. On GNOME it says that an enrolled finger may also unlock the lock screen; it changes no setting.\n\
disable removes the file, only if it is Custodio's.",
        args: &[
            ("enable", "write the polkit override"),
            ("disable", "remove it"),
        ],
        options: &[],
        example: "sudo custodio fingerprint enable",
    },
    CommandSpec {
        name: "doctor",
        summary: "check the fingerprint, the browsers, the journal and the state directory",
        usage: "",
        description: "Prints one line per check, with its state (ok, not ok, could not check) and, under every check that is not ok, what to do. It only reads: \
it changes nothing, and it never opens a polkit dialog, a password prompt or a browser. It refuses to run as root, because the answers are about the person who runs it.\n\
The checks: fprintd lists a fingerprint reader (or is not installed, and the line names the packages); you have an enrolled finger \
(over ssh fprintd refuses to say, and the line says could not check, not missing); fingerprint is active for polkit, through Custodio's \
override, another /etc/pam.d/polkit-1 or the whole system (then sudo uses the finger too). A polkit include that does not resolve is reported first; \
so is a warning when the override and common-auth both ask for the finger.\n\
Three more checks: the Custodio module is registered in each browser profile (one line per profile, the snap's copy of the module included; \
a system where NSS loads the p11-kit proxy needs no registration; the fix is custodio register); the systemd journal is persistent, read from \
journald.conf and its drop-ins and /var/log/journal, never from journalctl (the line names the file and line that set it); and the service's \
state directory is on an encrypted device (not-encrypted or unknown is not ok, the fix points to full-disk encryption; the service not answering is could not check).\n\
Exit status: 0 only when no polkit include is broken and the last three checks (the browsers, the journal, the state directory) are ok; could not check counts there. \
A missing reader or finger does not count: the fingerprint is optional.",
        args: &[],
        options: &[],
        example: "custodio doctor",
    },
];

/// The command named `name`.
#[must_use]
pub fn command(name: &str) -> Option<&'static CommandSpec> {
    COMMANDS.iter().find(|c| c.name == name)
}

impl CommandSpec {
    /// The usage line, without the program name's indentation.
    #[must_use]
    pub fn usage_line(&self) -> String {
        let mut line = format!("custodio {}", self.name);
        if self.name == "register" {
            line.push_str(" [--module <path>] [--remove | --refresh-only]");
        } else if !self.usage.is_empty() {
            line.push(' ');
            line.push_str(self.usage);
        }
        line
    }
}

/// The help of the whole tool.
#[must_use]
pub fn global() -> String {
    let mut text = String::from(
        "custodio - import, list and delete keys of the custodio signing service\n\n\
Usage:\n  custodio <command> [arguments]\n\nCommands:\n",
    );
    for c in COMMANDS {
        let _ = writeln!(text, "  {:<13}{}", c.name, c.summary);
    }
    text.push_str(
        "\nOptions:\n  -h, --help  show this help\n\n\
Run 'custodio <command> --help' for the arguments and options of a command.\n\n\
Example:\n  custodio list\n",
    );
    text
}

/// The help of one command, or `None` if there is no such command.
#[must_use]
pub fn for_command(name: &str) -> Option<String> {
    let c = command(name)?;
    let mut text = format!(
        "custodio {} - {}\n\nUsage:\n  {}\n\n{}\n",
        c.name,
        c.summary,
        c.usage_line(),
        c.description
    );
    if !c.args.is_empty() {
        text.push_str("\nArguments:\n");
        for (arg, what) in c.args {
            let _ = writeln!(text, "  {arg:<16}{what}");
        }
    }
    text.push_str("\nOptions:\n");
    for o in c.options {
        let long = o
            .value
            .map_or_else(|| o.flag.to_owned(), |v| format!("{} {v}", o.flag));
        let flag = o
            .short
            .map_or(long.clone(), |short| format!("{short}, {long}"));
        let _ = writeln!(text, "  {flag:<22}{}", o.text);
    }
    let _ = writeln!(text, "  {:<22}show this help", "-h, --help");
    let _ = write!(text, "\nExample:\n  {}\n", c.example);
    Some(text)
}

/// The help for a topic: a command, or the whole tool for `None`.
#[must_use]
pub fn text(topic: Option<&str>) -> String {
    topic.and_then(for_command).unwrap_or_else(global)
}

#[cfg(test)]
mod tests;
