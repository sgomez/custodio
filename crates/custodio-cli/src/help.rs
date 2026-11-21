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
        description: "Asks for the file's password on the terminal, then a polkit dialog asks for yours.\n\
Restart Firefox afterwards to see the key.",
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
        description: "Shows your keys, one per row. With a key id, or -v for all of them, shows each key in full.\n\
The subject is the certificate's common name, or the whole subject if it has none.",
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
        description: "Deletes a key and its certificate, after you confirm and a polkit dialog. It cannot be undone.\n\
Restart Firefox afterwards to see the change.",
        args: &[("<key id>", "the key to delete")],
        options: &[],
        example: "custodio delete work",
    },
    CommandSpec {
        name: "register",
        summary: "make the module visible to the native browsers",
        usage: "",
        description: "Adds the module to your browser profiles. Run it after installing and after creating a profile, then restart the browser.",
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
        description: "enable lets a finger answer polkit dialogs, with the password as fallback; disable undoes it.\n\
sudo and the login do not change. Run it as root.",
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
        description: "Checks what Custodio needs and says how to fix what is not ok. It changes nothing.",
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
        "custodio {} - {}\n\nUsage:\n  {}\n\n{}\nSee 'man custodio' for details.\n",
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
        let _ = writeln!(text, "  {:<22}{}", flag(o), o.text);
    }
    let _ = writeln!(text, "  {:<22}show this help", "-h, --help");
    let _ = write!(text, "\nExample:\n  {}\n", c.example);
    Some(text)
}

/// The short help of one command, for when it is run without the arguments it needs: usage,
/// summary, one row per argument and option, the example, and where the full help is.
#[must_use]
pub fn short(name: &str) -> Option<String> {
    let c = command(name)?;
    let mut rows: Vec<(String, &str)> = c.args.iter().map(|(a, t)| ((*a).to_owned(), *t)).collect();
    rows.extend(c.options.iter().map(|o| (flag(o), o.text)));
    let width = rows.iter().map(|(r, _)| r.len()).max().unwrap_or(0);
    let mut summary = c.summary.to_owned();
    if let Some(first) = summary.get_mut(..1) {
        first.make_ascii_uppercase();
    }
    let mut text = format!("Usage: {}\n\n{summary}.\n\n", c.usage_line());
    for (row, what) in rows {
        let _ = writeln!(text, "  {row:<width$}  {what}");
    }
    let _ = write!(
        text,
        "\nExample:\n  {}\n\nRun 'custodio {name} --help' for more.",
        c.example
    );
    Some(text)
}

/// How an option is written in the help: `-v, --verbose`, `--id <key id>`.
fn flag(o: &OptionSpec) -> String {
    let long = o
        .value
        .map_or_else(|| o.flag.to_owned(), |v| format!("{} {v}", o.flag));
    o.short
        .map_or(long.clone(), |short| format!("{short}, {long}"))
}

/// The help for a topic: a command, or the whole tool for `None`.
#[must_use]
pub fn text(topic: Option<&str>) -> String {
    topic.and_then(for_command).unwrap_or_else(global)
}

#[cfg(test)]
mod tests;
