//! The help the binary prints, its agreement with the manual page, and the rule that the
//! arguments are parsed by hand.

use std::error::Error;
use std::process::{Command, Output};

use custodio_cli::COMMANDS;

type Res = Result<(), Box<dyn Error>>;

fn run(args: &[&str]) -> Result<Output, Box<dyn Error>> {
    Ok(Command::new(env!("CARGO_BIN_EXE_custodio-cli"))
        .args(args)
        .env("DBUS_SYSTEM_BUS_ADDRESS", "unix:path=/nonexistent/custodio")
        .output()?)
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn root(path: &str) -> String {
    format!("{}/../../{path}", env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn every_command_prints_its_help() -> Res {
    let mut forms: Vec<Vec<&str>> = vec![vec!["--help"], vec!["-h"]];
    for c in COMMANDS {
        forms.push(vec![c.name, "--help"]);
        forms.push(vec![c.name, "-h"]);
    }
    for form in forms {
        let out = run(&form)?;
        assert_eq!(out.status.code(), Some(0), "{form:?}");
        assert!(out.stderr.is_empty(), "{form:?}: {}", text(&out.stderr));
        let help = text(&out.stdout);
        if let [name, _] = form.as_slice() {
            {
                let c = custodio_cli::help::command(name).ok_or("no such command")?;
                assert!(help.contains(c.description), "{form:?}");
                assert!(help.contains("Arguments:") != c.args.is_empty(), "{form:?}");
                assert!(help.contains("Options:"), "{form:?}");
                assert!(help.lines().any(|l| l.trim() == c.example), "{form:?}");
                for o in c.options {
                    assert!(help.contains(o.flag), "{form:?}: {}", o.flag);
                }
            }
        } else {
            {
                for c in COMMANDS {
                    assert!(
                        help.contains(c.name) && help.contains(c.summary),
                        "{form:?}"
                    );
                }
                assert!(help.contains("Example:"), "{form:?}");
            }
        }
    }
    Ok(())
}

#[test]
fn usage_errors_go_to_stderr_and_say_how_to_get_help() -> Res {
    let mut lines: Vec<Vec<&str>> = vec![
        vec!["nosuch"],
        vec!["--nosuch"],
        vec!["--help", "list"],
        vec!["list", "--nosuch"],
        vec!["import", "--nosuch"],
        vec!["register", "--nosuch"],
        vec!["delete", "--nosuch"],
    ];
    for c in COMMANDS {
        lines.push(vec![c.name, "--help", "extra"]);
    }
    // a missing argument for each command that needs one
    lines.push(vec!["import"]);
    lines.push(vec!["delete"]);
    for line in lines {
        let out = run(&line)?;
        assert_eq!(out.status.code(), Some(2), "{line:?}");
        assert!(out.stdout.is_empty(), "{line:?}");
        let err = text(&out.stderr);
        assert!(err.contains("--help"), "{line:?}: {err}");
        if let Some(c) = line.first().and_then(|n| custodio_cli::help::command(n)) {
            assert!(
                err.contains(&format!("custodio {} --help", c.name)),
                "{line:?}: {err}"
            );
        }
    }
    Ok(())
}

// ---- the manual page ----

/// The long options in a text, with the manual's escaped dashes undone.
fn long_options(text: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for word in text
        .replace("\\-", "-")
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
    {
        let named = word
            .strip_prefix("--")
            .is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_lowercase()));
        if named && !found.iter().any(|f| f == word) {
            found.push(word.to_owned());
        }
    }
    found.sort();
    found
}

/// The commands the page's SYNOPSIS starts a line with (`.B custodio <command>`).
fn page_commands(page: &str) -> Vec<String> {
    let mut found: Vec<String> = page
        .lines()
        .filter_map(|l| l.strip_prefix(".B custodio "))
        .map(|rest| rest.trim().to_owned())
        .collect();
    found.sort();
    found
}

/// The commands the global help lists under `Commands:`.
fn help_commands(help: &str) -> Vec<String> {
    let mut found: Vec<String> = help
        .lines()
        .skip_while(|l| *l != "Commands:")
        .skip(1)
        .take_while(|l| l.starts_with("  "))
        .filter_map(|l| l.split_whitespace().next().map(str::to_owned))
        .collect();
    found.sort();
    found
}

/// What differs between the help and the page, as lines that say what is missing where.
fn disagreements(help_all: &str, global: &str, page: &str) -> Vec<String> {
    let mut problems = Vec::new();
    let (hc, pc) = (help_commands(global), page_commands(page));
    let (ho, po) = (long_options(help_all), long_options(page));
    for c in hc.iter().filter(|c| !pc.contains(c)) {
        problems.push(format!("command {c} is in the help, not in the page"));
    }
    for c in pc.iter().filter(|c| !hc.contains(c)) {
        problems.push(format!("command {c} is in the page, not in the help"));
    }
    for o in ho.iter().filter(|o| !po.contains(o)) {
        problems.push(format!("option {o} is in the help, not in the page"));
    }
    for o in po.iter().filter(|o| !ho.contains(o)) {
        problems.push(format!("option {o} is in the page, not in the help"));
    }
    problems
}

fn every_help() -> Result<(String, String), Box<dyn Error>> {
    let global = text(&run(&["--help"])?.stdout);
    let mut all = global.clone();
    for c in COMMANDS {
        all.push_str(&text(&run(&[c.name, "--help"])?.stdout));
    }
    Ok((all, global))
}

#[test]
fn man_page_and_help_agree() -> Res {
    let page = std::fs::read_to_string(root("packaging/custodio.1"))?;
    let (all, global) = every_help()?;
    assert_eq!(disagreements(&all, &global, &page), Vec::<String>::new());
    // what the help read from the binary has is what the table has
    let mut table: Vec<String> = COMMANDS.iter().map(|c| c.name.to_owned()).collect();
    table.sort();
    assert_eq!(help_commands(&global), table);
    Ok(())
}

const FIXTURE_HELP: &str = "Commands:\n  alpha     a\n\n  --one  x\n  --two  y\n";
const FIXTURE_PAGE: &str =
    ".SH SYNOPSIS\n.B custodio alpha\n.SH OPTIONS\n.B \\-\\-one\n.B \\-\\-two\n";

#[test]
fn the_parity_check_accepts_agreeing_fixtures() {
    assert_eq!(
        disagreements(FIXTURE_HELP, FIXTURE_HELP, FIXTURE_PAGE),
        Vec::<String>::new()
    );
}

#[test]
fn the_parity_check_fails_for_a_page_missing_an_option() {
    let page = FIXTURE_PAGE.replace(".B \\-\\-two\n", "");
    let found = disagreements(FIXTURE_HELP, FIXTURE_HELP, &page);
    assert_eq!(found, ["option --two is in the help, not in the page"]);
}

#[test]
fn the_parity_check_fails_for_a_page_with_an_extra_option() {
    let page = format!("{FIXTURE_PAGE}.B \\-\\-three\n");
    let found = disagreements(FIXTURE_HELP, FIXTURE_HELP, &page);
    assert_eq!(found, ["option --three is in the page, not in the help"]);
}

// ---- no argument-parsing crate ----

const BANNED: &[&str] = &[
    "clap",
    "clap_complete",
    "clap_builder",
    "clap_derive",
    "clap_lex",
    "clap_mangen",
    "structopt",
    "argh",
    "lexopt",
    "pico-args",
    "bpaf",
    "gumdrop",
    "argparse",
    "getopts",
    "docopt",
    "argp",
];

/// The banned crates a `Cargo.lock` names.
fn banned_in(lock: &str) -> Vec<&'static str> {
    BANNED
        .iter()
        .copied()
        .filter(|name| {
            lock.lines()
                .any(|l| l.trim() == format!("name = \"{name}\""))
        })
        .collect()
}

#[test]
fn no_argument_parser_crate_in_the_graph() -> Res {
    let lock = std::fs::read_to_string(root("Cargo.lock"))?;
    assert_eq!(banned_in(&lock), Vec::<&str>::new());
    Ok(())
}

#[test]
fn the_dependency_check_sees_a_parser_crate_in_a_fixture_lock() {
    let lock = "[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\n\n[[package]]\nname = \"clap\"\nversion = \"4.0.0\"\n";
    assert_eq!(banned_in(lock), ["clap"]);
}
