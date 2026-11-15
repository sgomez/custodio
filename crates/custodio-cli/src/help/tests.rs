use super::*;
use crate::{Command, parse_command};

/// The long options named in a text.
fn options_in(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    for word in text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-')) {
        if word.starts_with("--") && word.len() > 2 {
            found.push(word.to_owned());
        }
    }
    found
}

fn all_helps() -> String {
    let mut all = global();
    for c in COMMANDS {
        all.push_str(&for_command(c.name).unwrap_or_default());
    }
    all
}

#[test]
fn every_command_has_its_own_help_with_every_part() {
    for c in COMMANDS {
        let text = for_command(c.name).unwrap_or_default();
        for part in ["Usage:", "Options:", "Example:", c.summary, c.description] {
            assert!(text.contains(part), "{}: no {part:?}", c.name);
        }
        assert_eq!(
            c.args.is_empty(),
            !text.contains("Arguments:"),
            "{}",
            c.name
        );
        for o in c.options {
            assert!(text.contains(o.flag) && text.contains(o.text), "{}", o.flag);
        }
        assert!(global().contains(c.name) && global().contains(c.summary));
    }
    assert_eq!(for_command("nosuch"), None);
    assert_eq!(text(Some("nosuch")), global());
    assert_eq!(text(None), global());
    assert_ne!(text(Some("list")), global());
}

#[test]
fn the_help_names_no_option_that_is_not_in_the_table() {
    let mut known: Vec<&str> = vec!["--help"];
    known.extend(
        COMMANDS
            .iter()
            .flat_map(|c| c.options.iter().map(|o| o.flag)),
    );
    for found in options_in(&all_helps()) {
        assert!(
            known.contains(&found.as_str()),
            "{found} is not in the table"
        );
    }
}

#[test]
fn every_example_starts_with_its_command_and_is_accepted_by_the_parser() {
    for c in COMMANDS {
        let words: Vec<String> = c.example.split(' ').map(str::to_owned).collect();
        assert_eq!(words[..2], ["custodio".to_owned(), c.name.to_owned()]);
        let parsed = parse_command(words[1..].iter().cloned());
        assert!(
            matches!(parsed, Ok(ref cmd) if !matches!(cmd, Command::Help(_))),
            "{}: {parsed:?}",
            c.example
        );
    }
}

#[test]
fn the_parser_accepts_every_option_of_the_table() {
    for c in COMMANDS {
        for o in c.options {
            let mut line = vec![c.name.to_owned(), o.flag.to_owned()];
            if o.value.is_some() {
                line.push("x.p12".to_owned());
            }
            if c.name == "import" {
                line.push("a.p12".to_owned());
            }
            assert!(parse_command(line.clone()).is_ok(), "{line:?}");
        }
    }
}

#[test]
fn the_usage_line_of_each_command_starts_with_it() {
    for c in COMMANDS {
        assert!(c.usage_line().starts_with(&format!("custodio {}", c.name)));
    }
    assert_eq!(
        command("list").map(CommandSpec::usage_line),
        Some("custodio list".to_owned())
    );
    assert!(command("delete").is_some_and(|c| c.usage_line() == "custodio delete [--] <key id>"));
}
