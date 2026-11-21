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
    /// The word that names it under its parent.
    pub name: &'static str,
    /// The words from the program name down to it, for example `setup browsers enable`.
    pub path: &'static str,
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
    /// The commands one level down, when this one only groups them.
    pub children: &'static [CommandSpec],
}

/// The topics of `custodio setup`, each with its actions.
const SETUP: &[CommandSpec] = &[
    CommandSpec {
        name: "browsers",
        path: "setup browsers",
        summary: "make the module visible to the native browsers",
        usage: "<action>",
        description: "Adds or removes the module in your browser profiles. Restart the browser afterwards.",
        args: &[],
        options: &[],
        example: "custodio setup browsers enable",
        children: &[
            CommandSpec {
                name: "enable",
                path: "setup browsers enable",
                summary: "add the module to your browser profiles",
                usage: "[--module <path>]",
                description: "Adds the module to your browser profiles. Run it after installing and after creating a profile, then restart the browser.",
                args: &[],
                options: &[MODULE],
                example: "custodio setup browsers enable --module /usr/lib/custodio/libcustodio_pkcs11.so",
                children: &[],
            },
            CommandSpec {
                name: "disable",
                path: "setup browsers disable",
                summary: "remove the entries of every Custodio module file",
                usage: "",
                description: "Removes the module from your browser profiles, whichever Custodio module file they name. It does not need the file to exist.",
                args: &[],
                options: &[],
                example: "custodio setup browsers disable",
                children: &[],
            },
            CommandSpec {
                name: "refresh",
                path: "setup browsers refresh",
                summary: "update the Firefox snap's copy of the module",
                usage: "[--module <path>]",
                description: "Only updates the copy of the module that the Firefox snap loads, if it differs. It changes no profile.",
                args: &[],
                options: &[OptionSpec {
                    text: "copy this library instead of the installed one",
                    ..MODULE
                }],
                example: "custodio setup browsers refresh",
                children: &[],
            },
        ],
    },
    CommandSpec {
        name: "fingerprint",
        path: "setup fingerprint",
        summary: "let a finger answer polkit dialogs (enable) or stop that (disable)",
        usage: "<action>",
        description: "enable lets a finger answer polkit dialogs, with the password as fallback; disable undoes it.\n\
sudo and the login do not change. Run it as root.",
        args: &[],
        options: &[],
        example: "sudo custodio setup fingerprint enable",
        children: &[
            CommandSpec {
                name: "enable",
                path: "setup fingerprint enable",
                summary: "let a finger answer polkit dialogs",
                usage: "",
                description: "Writes the polkit override that lets a finger answer polkit dialogs, with the password as fallback. sudo and the login do not change. Run it as root.",
                args: &[],
                options: &[],
                example: "sudo custodio setup fingerprint enable",
                children: &[],
            },
            CommandSpec {
                name: "disable",
                path: "setup fingerprint disable",
                summary: "stop a finger answering polkit dialogs",
                usage: "",
                description: "Removes the polkit override that enable wrote. Run it as root.",
                args: &[],
                options: &[],
                example: "sudo custodio setup fingerprint disable",
                children: &[],
            },
        ],
    },
];

const MODULE: OptionSpec = OptionSpec {
    flag: "--module",
    short: None,
    value: Some("<path>"),
    text: "add this library instead of the installed one",
};

/// Every command, in the order of the help.
pub const COMMANDS: &[CommandSpec] = &[
    CommandSpec {
        name: "import",
        path: "import",
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
        children: &[],
    },
    CommandSpec {
        name: "list",
        path: "list",
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
        children: &[],
    },
    CommandSpec {
        name: "delete",
        path: "delete",
        summary: "delete one of your keys",
        usage: "[--] <key id>",
        description: "Deletes a key and its certificate, after you confirm and a polkit dialog. It cannot be undone.\n\
Restart Firefox afterwards to see the change.",
        args: &[("<key id>", "the key to delete")],
        options: &[],
        example: "custodio delete work",
        children: &[],
    },
    CommandSpec {
        name: "setup",
        path: "setup",
        summary: "set Custodio up: the browsers, the fingerprint",
        usage: "<topic> <action>",
        description: "Groups what is done once, after installing: browsers (enable, disable, refresh) and fingerprint (enable, disable).\n\
Name a topic and an action; each has its own help.",
        args: &[],
        options: &[],
        example: "custodio setup browsers enable",
        children: SETUP,
    },
    CommandSpec {
        name: "doctor",
        path: "doctor",
        summary: "check the fingerprint, the browsers, the journal and the state directory",
        usage: "",
        description: "Checks what Custodio needs and says how to fix what is not ok. It changes nothing.",
        args: &[],
        options: &[],
        example: "custodio doctor",
        children: &[],
    },
];

/// The top-level command named `name`.
#[must_use]
pub fn command(name: &str) -> Option<&'static CommandSpec> {
    COMMANDS.iter().find(|c| c.name == name)
}

/// The command at `path`, words separated by spaces: `setup browsers enable`.
#[must_use]
pub fn find(path: &str) -> Option<&'static CommandSpec> {
    let mut words = path.split(' ');
    let mut node = command(words.next()?)?;
    for word in words {
        node = node.children.iter().find(|c| c.name == word)?;
    }
    Some(node)
}

/// Every command at every level, parents before their children.
#[must_use]
pub fn all() -> Vec<&'static CommandSpec> {
    fn walk(list: &'static [CommandSpec], out: &mut Vec<&'static CommandSpec>) {
        for c in list {
            out.push(c);
            walk(c.children, out);
        }
    }
    let mut out = Vec::new();
    walk(COMMANDS, &mut out);
    out
}

impl CommandSpec {
    /// The usage line, without the program name's indentation.
    #[must_use]
    pub fn usage_line(&self) -> String {
        let mut line = format!("custodio {}", self.path);
        if !self.usage.is_empty() {
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

/// The help of the command at `path`, or `None` if there is no such command.
#[must_use]
pub fn for_command(path: &str) -> Option<String> {
    let c = find(path)?;
    let mut text = format!(
        "custodio {} - {}\n\nUsage:\n  {}\n\n{}\nSee 'man custodio' for details.\n",
        c.path,
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
    if !c.children.is_empty() {
        text.push_str("\nCommands:\n");
        for child in c.children {
            let _ = writeln!(text, "  {:<13}{}", child.name, child.summary);
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

/// The short help of the command at `path`, for when it is run without what it needs: usage,
/// summary, one row per argument, option or command one level down, the example, and where the
/// full help is.
#[must_use]
pub fn short(path: &str) -> Option<String> {
    let c = find(path)?;
    let mut rows: Vec<(String, &str)> = c.args.iter().map(|(a, t)| ((*a).to_owned(), *t)).collect();
    rows.extend(c.children.iter().map(|k| (k.name.to_owned(), k.summary)));
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
        "\nExample:\n  {}\n\nRun 'custodio {path} --help' for more.",
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
