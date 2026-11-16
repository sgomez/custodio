use super::*;

fn args(list: &[&str]) -> Result<Command, ArgError> {
    parse_command(list.iter().map(|s| (*s).to_owned()))
}

#[test]
fn help_flags_ask_for_the_help_of_the_whole_tool_or_of_a_command() {
    assert_eq!(args(&["--help"]), Ok(Command::Help(None)));
    assert_eq!(args(&["-h"]), Ok(Command::Help(None)));
    for spec in help::COMMANDS {
        for flag in ["--help", "-h"] {
            assert_eq!(
                args(&[spec.name, flag]),
                Ok(Command::Help(Some(spec.name))),
                "{} {flag}",
                spec.name
            );
        }
    }
}

#[test]
fn help_flag_with_anything_else_is_a_usage_error() {
    assert_eq!(args(&["--help", "list"]), Err(ArgError::Usage));
    assert_eq!(args(&["-h", "-h"]), Err(ArgError::Usage));
    assert_eq!(args(&["nosuch", "--help"]), Err(ArgError::Usage));
    assert_eq!(
        args(&["list", "--help", "x"]),
        Err(ArgError::CommandUsage("list"))
    );
    assert_eq!(
        args(&["delete", "--help", "x"]),
        Err(ArgError::CommandUsage("delete"))
    );
}

#[test]
fn a_bad_line_of_a_known_command_names_the_command() {
    for bad in [
        &["list", "x", "y"][..],
        &["delete"],
        &["delete", "-x"],
        &["register", "--nope"],
        &["import"],
        &["import", "--id"],
    ] {
        let err = args(bad).unwrap_err();
        assert!(matches!(err, ArgError::CommandUsage(_)), "{bad:?}");
        let text = err.to_string();
        assert!(
            text.contains(&format!("custodio {} --help", bad[0])),
            "{text}"
        );
    }
    assert_eq!(args(&[]), Ok(Command::Help(None)));
    assert_eq!(args(&["nosuch"]), Err(ArgError::Usage));
    assert!(ArgError::Usage.to_string().contains("custodio --help"));
}

#[test]
fn the_commands_parse_as_before() {
    assert_eq!(args(&["list"]), Ok(Command::List(None)));
    assert_eq!(
        args(&["delete", "--", "-k"]),
        Ok(Command::Delete("-k".into()))
    );
    assert_eq!(args(&["delete", "k"]), Ok(Command::Delete("k".into())));
    assert!(matches!(
        args(&["register", "--remove"]),
        Ok(Command::Register(_))
    ));
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
    for c in help::COMMANDS {
        rendered.push_str(&help::text(Some(c.name)));
    }
    assert!(!rendered.contains("__key-ids"));
    assert!(!crate::usage().contains("__key-ids"));
}
