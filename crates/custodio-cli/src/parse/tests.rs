use super::*;
use crate::register_native::RegisterArgs;

fn args(list: &[&str]) -> Result<Command, ArgError> {
    parse_command(list.iter().map(|s| (*s).to_owned()))
}

#[test]
fn help_flags_ask_for_the_help_of_the_whole_tool_or_of_a_command() {
    assert_eq!(args(&["--help"]), Ok(Command::Help(None)));
    assert_eq!(args(&["-h"]), Ok(Command::Help(None)));
    for spec in help::all() {
        for flag in ["--help", "-h"] {
            let mut line: Vec<&str> = spec.path.split(' ').collect();
            line.push(flag);
            assert_eq!(
                args(&line),
                Ok(Command::Help(Some(spec.path))),
                "{} {flag}",
                spec.path
            );
        }
    }
}

#[test]
fn help_flag_with_anything_else_is_a_usage_error() {
    assert_eq!(args(&["--help", "list"]), Err(ArgError::Usage));
    assert_eq!(args(&["-h", "-h"]), Err(ArgError::Usage));
    assert_eq!(args(&["nosuch", "--help"]), Err(ArgError::Usage));
    for name in ["list", "delete"] {
        assert!(
            matches!(args(&[name, "--help", "x"]), Err(ArgError::CommandUsage(n, _)) if n == name),
            "{name}"
        );
    }
}

#[test]
fn a_bad_line_of_a_known_command_says_what_is_wrong() {
    use Wrong::{Missing, NoValue, Twice, Unexpected, UnknownOption};
    let o = |s: &str| UnknownOption(s.to_owned());
    let u = |s: &str| Unexpected(s.to_owned());
    for (line, wrong) in [
        (&["import", "--bogus", "a.p12"][..], o("--bogus")),
        (&["import", "a.p12", "b.p12"], u("b.p12")),
        (&["import", "--id"], NoValue("--id")),
        (
            &["import", "--id", "a", "--id", "b", "x.p12"],
            Twice("--id"),
        ),
        (&["import", "--id", "a"], Missing("<file.p12>")),
        (&["list", "x", "y"], u("y")),
        (&["list", "-x"], o("-x")),
        (&["list", "-v", "--verbose"], Twice("-v")),
        (&["list", "--"], Missing("<key id>")),
        (&["delete", "-x"], o("-x")),
        (&["delete", "--"], Missing("<key id>")),
        (&["delete", "a", "b"], u("b")),
        (&["doctor", "-x"], o("-x")),
    ] {
        assert_eq!(
            args(line),
            Err(ArgError::CommandUsage(
                help::command(line[0]).map_or("", |c| c.path),
                wrong
            )),
            "{line:?}"
        );
    }
    // below `setup` the error names the level it was found at
    for (line, level, wrong) in [
        (&["setup", "on"][..], "setup", u("on")),
        (&["setup", "-x"], "setup", o("-x")),
        (&["setup", "browsers", "on"], "setup browsers", u("on")),
        (
            &["setup", "fingerprint", "on"],
            "setup fingerprint",
            u("on"),
        ),
        (
            &["setup", "fingerprint", "enable", "x"],
            "setup fingerprint enable",
            u("x"),
        ),
        (
            &["setup", "browsers", "enable", "--nope"],
            "setup browsers enable",
            o("--nope"),
        ),
        (
            &["setup", "browsers", "enable", "--module"],
            "setup browsers enable",
            NoValue("--module"),
        ),
        (
            &[
                "setup", "browsers", "refresh", "--module", "a", "--module", "b",
            ],
            "setup browsers refresh",
            Twice("--module"),
        ),
        (
            &["setup", "browsers", "disable", "--module", "a"],
            "setup browsers disable",
            o("--module"),
        ),
        (&["register"], "", u("")),
    ] {
        if line[0] == "register" {
            assert_eq!(args(line), Err(ArgError::Usage));
            continue;
        }
        assert_eq!(
            args(line),
            Err(ArgError::CommandUsage(level, wrong)),
            "{line:?}"
        );
    }
    assert_eq!(args(&["fingerprint", "enable"]), Err(ArgError::Usage));
    assert_eq!(Missing("x").to_string(), "missing x");
    assert_eq!(args(&[]), Ok(Command::Help(None)));
    assert_eq!(args(&["nosuch"]), Err(ArgError::Usage));
}

#[test]
fn a_command_that_needs_arguments_and_got_none_is_answered_with_its_short_help() {
    let needs = ["import", "delete", "setup"];
    for spec in help::COMMANDS {
        let got = args(&[spec.name]);
        if needs.contains(&spec.name) {
            assert_eq!(got, Err(ArgError::Bare(spec.path)));
        } else {
            assert!(got.is_ok(), "{}: {got:?}", spec.name);
        }
    }
    for topic in ["browsers", "fingerprint"] {
        let path = format!("setup {topic}");
        assert_eq!(
            args(&["setup", topic]),
            Err(ArgError::Bare(help::find(&path).map_or("", |c| c.path)))
        );
    }
}

/// The error names the command, carries the offending word escaped, and says where the help is.
#[test]
fn a_usage_error_names_its_command_and_the_help_and_escapes_the_word() {
    let word = "--x\u{1b}[31m\nSENTINEL";
    for spec in help::COMMANDS {
        let err = args(&[spec.name, "a", "b", "c", word]).unwrap_err();
        let text = err.to_string();
        let lines: Vec<&str> = text.lines().collect();
        assert!(
            lines[0].starts_with(&format!("custodio {}:", spec.path)),
            "{text}"
        );
        assert!(
            lines
                .last()
                .is_some_and(|l| l.contains(&format!("custodio {} --help", spec.path))),
            "{text}"
        );
        assert!(
            !text.chars().any(|c| c.is_control() && c != '\n'),
            "{text:?}"
        );
        assert!(!text.lines().any(|l| l.starts_with("SENTINEL")), "{text:?}");
    }
}

#[test]
fn the_commands_parse_as_before() {
    assert_eq!(
        args(&["list"]),
        Ok(Command::List(crate::list::ListArgs::default()))
    );
    assert_eq!(
        args(&["delete", "--", "-k"]),
        Ok(Command::Delete("-k".into()))
    );
    assert_eq!(args(&["delete", "k"]), Ok(Command::Delete("k".into())));
    let register = |line: &[&str]| match args(line) {
        Ok(Command::Register(r)) => Some(r),
        _ => None,
    };
    let none = RegisterArgs::default();
    assert_eq!(
        register(&["setup", "browsers", "enable"]),
        Some(none.clone())
    );
    assert_eq!(
        register(&["setup", "browsers", "enable", "--module", "/x.so"]),
        Some(RegisterArgs {
            module: Some("/x.so".into()),
            ..none.clone()
        })
    );
    assert_eq!(
        register(&["setup", "browsers", "disable"]),
        Some(RegisterArgs {
            remove: true,
            ..none.clone()
        })
    );
    assert_eq!(
        register(&["setup", "browsers", "refresh", "--module", "/x.so"]),
        Some(RegisterArgs {
            module: Some("/x.so".into()),
            refresh_only: true,
            ..none
        })
    );
    assert_eq!(
        args(&["setup", "fingerprint", "enable"]),
        Ok(Command::Fingerprint(Action::Enable))
    );
    assert_eq!(
        args(&["setup", "fingerprint", "disable"]),
        Ok(Command::Fingerprint(Action::Disable))
    );
    assert!(matches!(args(&["import", "a.p12"]), Ok(Command::Import(i)) if i.id == "a"));
    assert_eq!(args(&["import", "my cert.p12"]), Err(ArgError::BadId));
}

#[test]
fn the_fuzz_entry_point_survives_odd_input() {
    assert!(fuzz_cli_args(vec![]));
    assert!(fuzz_cli_args(vec!["--help".into()]));
    assert!(!fuzz_cli_args(vec!["--help".into(), String::new()]));
    assert!(fuzz_cli_args(vec!["import".into(), "a.p12".into()]));
    assert!(!fuzz_cli_args(vec!["import".into(), "\u{0}".into()]));
}

#[test]
fn parse_args_wants_import_and_derives_ids_from_plain_stems() {
    let list = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    assert_eq!(parse_args(list(&["list"])), Err(ArgError::Usage));
    assert_eq!(
        parse_args(list(&["import"])),
        Err(ArgError::CommandUsage(
            "import",
            Wrong::Missing("<file.p12>")
        ))
    );
    for (file, id) in [
        ("my_key.p12", "my_key"),
        ("my-key.p12", "my-key"),
        ("K9.p12", "K9"),
    ] {
        let parsed = parse_args(list(&["import", file]));
        assert_eq!(parsed.map(|a| a.id), Ok(id.to_owned()), "{file}");
    }
    assert_eq!(
        parse_args(list(&["import", "a b.p12"])),
        Err(ArgError::BadId)
    );
}

#[test]
fn the_hidden_key_ids_command_takes_no_argument_and_is_not_in_the_help() {
    assert_eq!(args(&["__key-ids"]), Ok(Command::KeyIds));
    assert_eq!(args(&["__key-ids", "x"]), Err(ArgError::Usage));
    assert_eq!(args(&["__key-ids", "--help"]), Err(ArgError::Usage));
    assert!(help::command("__key-ids").is_none());
    let mut rendered = help::global();
    for c in help::all() {
        rendered.push_str(&help::text(Some(c.path)));
    }
    assert!(!rendered.contains("__key-ids"));
    assert!(!crate::usage().contains("__key-ids"));
}
